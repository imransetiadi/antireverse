// @vitest-environment node
import { ProblemSchema, SLO_CATALOG, SloReportSchema } from "@antireverse/protocol";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { opsRoutes } from "../../api/src/routes/ops.ts";
import type { SloService } from "../../api/src/slo/service.ts";
import { createOpsStore } from "../scripts/stub-ops.mjs";

// Slice 18d: the stand-in API answers `GET /v1/ops/slo` as the API does — 404 without an operator token configured,
// 401 for any other bearer (an admin key included), the report in the shape of the protocol for the token — with
// made-up figures that show every state of the dashboard.

const TOKEN = "stub-operator-token-".padEnd(40, "z");
const T0 = Date.parse("2026-11-14T09:30:00.000Z");

interface Answer {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

/** The real operator routes of the API, with a stand-in SLO service: what the stub's refusals must equal. */
async function real(token: string | undefined, authorization?: string): Promise<Answer> {
  const app = new Hono();
  app.route("/", opsRoutes({ slo: { report: async () => ({}) } as unknown as SloService, token }));
  const response = await app.request("/v1/ops/slo", {
    headers: authorization === undefined ? {} : { authorization },
  });
  const challenge = response.headers.get("www-authenticate");
  return {
    status: response.status,
    body: await response.json(),
    ...(challenge === null ? {} : { headers: { "www-authenticate": challenge } }),
  };
}
const get = (store: ReturnType<typeof createOpsStore>, authorization?: string): Answer => {
  const answer = store.handle("GET", "/v1/ops/slo", authorization);
  if (answer === null) throw new Error("no answer");
  return answer as Answer;
};

describe("stub operator SLOs", () => {
  it("answers 404 when no operator token is configured", () => {
    const store = createOpsStore({ token: undefined, now: () => T0 });
    const answer = get(store, `Bearer ${TOKEN}`);
    expect(answer.status).toBe(404);
    ProblemSchema.parse(answer.body);
  });

  it("answers 401 for a missing or other bearer, an admin key included", () => {
    const store = createOpsStore({ token: TOKEN, now: () => T0 });
    for (const authorization of [undefined, "", `Bearer ${TOKEN}x`, "Bearer aro_0123456789abcdef", TOKEN]) {
      const answer = get(store, authorization);
      expect(answer.status).toBe(401);
      ProblemSchema.parse(answer.body);
    }
  });

  it("answers the report for the token: ten SLOs in catalog order, every dashboard state present", () => {
    const store = createOpsStore({ token: TOKEN, now: () => T0 });
    const answer = get(store, `Bearer ${TOKEN}`);
    expect(answer.status).toBe(200);
    const report = SloReportSchema.parse(answer.body);
    expect(report.generated_at).toBe("2026-11-14T09:30:00.000Z");
    expect(report.slos.map((slo) => slo.id)).toEqual(SLO_CATALOG.map((def) => def.id));
    for (const [index, slo] of report.slos.entries()) {
      const def = SLO_CATALOG[index];
      expect(slo.name).toBe(def?.name);
      expect(slo.objective).toBe(def?.objective);
      expect(slo.runbook).toBe(def?.runbook);
      expect(slo.measured).toBe(def?.measured);
      if (!slo.measured) expect(slo.not_measured_reason).toBe(def?.not_measured_reason);
      if (slo.total > 0) expect(slo.attainment).toBeCloseTo(slo.good / slo.total, 12);
    }
    const states = report.slos;
    expect(states.some((slo) => slo.alerts.some((alert) => alert.state === "firing"))).toBe(true);
    expect(states.some((slo) => (slo.budget_remaining ?? 0) < 0)).toBe(true);
    expect(states.some((slo) => slo.measured && slo.total === 0)).toBe(true);
    expect(states.some((slo) => slo.latency.some((row) => row.met === false))).toBe(true);
    // Objective missed without any alert firing (review M2).
    expect(
      states.some((slo) => (slo.budget_remaining ?? 0) < 0 && slo.alerts.every((alert) => alert.state === "ok")),
    ).toBe(true);
  });

  it("refuses exactly as the API's operator routes do: status, problem body and challenge (review L3)", async () => {
    const off = createOpsStore({ token: undefined, now: () => T0 });
    expect(get(off, `Bearer ${TOKEN}`)).toEqual(await real(undefined, `Bearer ${TOKEN}`));
    const on = createOpsStore({ token: TOKEN, now: () => T0 });
    for (const authorization of [undefined, `Bearer ${TOKEN}x`, "Bearer aro_0123456789abcdef", TOKEN]) {
      expect(get(on, authorization)).toEqual(await real(TOKEN, authorization));
    }
  });

  it("leaves other paths alone", () => {
    const store = createOpsStore({ token: TOKEN, now: () => T0 });
    expect(store.handle("GET", "/v1/apps", `Bearer ${TOKEN}`)).toBeNull();
    expect(store.handle("POST", "/v1/ops/slo", `Bearer ${TOKEN}`)).toBeNull();
  });
});
