// @vitest-environment node
import {
  ProblemSchema,
  RetentionResponseSchema,
  RetentionRunSchema,
  UpdateRetentionResponseSchema,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createDataStore } from "../scripts/stub-data.mjs";

// Slice 18c: the stand-in API answers the retention routes in the shape of the protocol and in the API's order — the
// body is validated first, then a shortening needs the reason — so that the Console can be looked at against it.

const ORG = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };
const T0 = Date.parse("2026-11-14T09:00:00.000Z");
const DAY_MS = 86_400_000;
const REASON = "Storage policy";

interface Answer {
  status: number;
  body: unknown;
  audit?: { action: string; target: { kind: string; id: string }; summary: string };
}

function store() {
  const data = createDataStore({
    now: () => T0,
    tables: () => ({}),
    subject: {
      rows: () => ({ events: [], containments: [] }),
      erase: () => ({ events_erased: 0, containments_erased: 0, active_containments: [] }),
    },
  });
  const call = (method: string, body?: unknown, reason?: string): Answer => {
    const answer = data.handle(ORG, method, "/v1/organization/retention", body, reason);
    if (answer === null) throw new Error(`no answer for ${method}`);
    return answer as Answer;
  };
  return { data, call };
}
const problemType = (answer: Answer) => ProblemSchema.parse(answer.body).type;

describe("stub retention", () => {
  it("reads 30 days for a new Organization, the fixed periods, and no run yet", () => {
    const { call } = store();
    const answer = call("GET");
    expect(answer.status).toBe(200);
    expect(RetentionResponseSchema.parse(answer.body)).toEqual({
      retention: { event_retention_days: 30, guard_days: 30, evidence_days: 395, artifact_days: 30 },
      last_run: null,
    });
  });

  it("validates the body before it asks for a reason", () => {
    const { call } = store();
    for (const body of [
      { event_retention_days: 14 },
      { event_retention_days: "7" },
      { event_retention_days: 7, x: 1 },
      {},
    ]) {
      const answer = call("PUT", body);
      expect(answer.status).toBe(400);
      expect(problemType(answer)).toMatch(/\/validation$/);
    }
  });

  it("needs a reason to shorten, none to lengthen or keep; answers from when older Events go, and audits", () => {
    const { call } = store();
    let answer = call("PUT", { event_retention_days: 7 });
    expect(answer.status).toBe(400);
    expect(problemType(answer)).toMatch(/\/reason-required$/);
    expect(answer.audit).toBeUndefined();

    answer = call("PUT", { event_retention_days: 7 }, REASON);
    expect(answer.status).toBe(200);
    const shortened = UpdateRetentionResponseSchema.parse(answer.body);
    expect(shortened.retention.event_retention_days).toBe(7);
    expect(shortened.events_removed_before).toBe(new Date(T0 - 7 * DAY_MS).toISOString());
    expect(answer.audit).toEqual({
      action: "organization.retention.update",
      target: { kind: "organization", id: ORG.id },
      summary: "Changed the Event retention from 30 to 7 days.",
    });

    answer = call("PUT", { event_retention_days: 90 });
    expect(answer.status).toBe(200);
    expect(UpdateRetentionResponseSchema.parse(answer.body).retention.event_retention_days).toBe(90);
    expect(call("PUT", { event_retention_days: 90 }).status).toBe(200);
    expect(RetentionResponseSchema.parse(call("GET").body).retention.event_retention_days).toBe(90);
    expect(call("POST", { event_retention_days: 90 }).status).toBe(405);
  });

  it("shows a run recorded for the Organization as its last run", () => {
    const { call, data } = store();
    const run = { ran_at: "2026-11-14T03:00:00.000Z", complete: false, counts: { events: 12 } };
    data.recordRetentionRun(ORG.id, run);
    expect(RetentionRunSchema.parse(RetentionResponseSchema.parse(call("GET").body).last_run)).toEqual(run);
  });

  it("is refused while the Organization's deletion is pending, as the API does", () => {
    const { data } = store();
    data.handle(ORG, "POST", "/v1/organization/deletion", { confirm_name: "Acme" }, REASON);
    for (const method of ["GET", "PUT"]) {
      const refused = data.gate(ORG.id, method, "/v1/organization/retention") as Answer;
      expect(refused.status).toBe(403);
      expect(problemType(refused)).toMatch(/\/organization-deletion-pending$/);
    }
  });
});
