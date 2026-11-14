import {
  AUDIT_REASON_HEADER,
  type AuditEntry,
  AuditExportLineSchema,
  RetentionResponseSchema,
  UpdateRetentionResponseSchema,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRetentionJob } from "../src/data/retention.ts";
import { type RunningApi, startApi } from "../src/server.ts";
import { auditEntriesAfter } from "../src/stores/audit.ts";
import {
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  expectProblem,
  json,
  makeTestApi,
  put,
  type TestApi,
  tick,
  withReason,
} from "./helpers.ts";

// Slice 18c: `GET` and `PUT /v1/organization/retention`, and the job started with the server.

const T0 = Date.parse("2026-11-14T09:00:00.000Z");
const DAY = 86_400_000;
const FIXED = { guard_days: 30, evidence_days: 395, artifact_days: 30 };

describe("retention routes", () => {
  let api: TestApi;
  const now = () => new Date(T0);
  let organizationId = "";
  let admin = "";
  let shield = "";

  const get = (key = admin) => api.app.request("/v1/organization/retention", { headers: bearer(key) });
  const change = (days: unknown, headers: Record<string, string> = {}, key = admin) =>
    api.app.request("/v1/organization/retention", put({ event_retention_days: days }, { ...bearer(key), ...headers }));
  const entries = async (): Promise<AuditEntry[]> =>
    (await api.db.tx({ organizationId }, (q) => auditEntriesAfter(q, 0, 10_000))).map((entry) =>
      AuditExportLineSchema.parse(entry),
    );

  beforeAll(async () => {
    api = await makeTestApi({ now });
    const created = await createOrganization(api, "Acme");
    organizationId = created.organization.id;
    admin = created.admin_key.key;
    shield = (await createAppFor(api, admin)).shield_key.key;
  });
  afterAll(async () => {
    await api.close();
  });

  it("answers a new Organization's retention: Events 30 days, the fixed periods, no run yet", async () => {
    const res = await get();
    expect(res.status).toBe(200);
    expect(RetentionResponseSchema.parse(await res.json())).toEqual({
      retention: { event_retention_days: 30, ...FIXED },
      last_run: null,
    });
  });

  it("takes the admin key only", async () => {
    await expectProblem(await api.app.request("/v1/organization/retention"), 401);
    await expectProblem(await get(shield), 403);
    await expectProblem(await change(90, {}, shield), 403);
  });

  it("lengthens without a reason, audited before → after, and says from when older Events go", async () => {
    const before = await entries();
    const res = await change(90);
    expect(res.status, await res.clone().text()).toBe(200);
    expect(UpdateRetentionResponseSchema.parse(await res.json())).toEqual({
      retention: { event_retention_days: 90, ...FIXED },
      last_run: null,
      events_removed_before: new Date(T0 - 90 * DAY).toISOString(),
    });
    const after = await entries();
    expect(after).toHaveLength(before.length + 1);
    const entry = after.at(-1) as AuditEntry;
    expect(entry).toMatchObject({
      action: "organization.retention.update",
      target: { kind: "organization", id: organizationId },
    });
    expect(entry.summary).toContain("30");
    expect(entry.summary).toContain("90");
    expect(entry.reason).toBeUndefined();
    expect(entry.request_id).toBe(res.headers.get("x-request-id"));
  });

  it("refuses to shorten without a reason, and shortens with one", async () => {
    const before = await entries();
    const refused = await expectProblem(await change(7), 400);
    expect(refused.type).toBe("https://antireverse.dev/problems/reason-required");
    expect(await entries()).toEqual(before);
    const res = await change(7, withReason());
    expect(res.status).toBe(200);
    const body = UpdateRetentionResponseSchema.parse(await res.json());
    expect(body.retention.event_retention_days).toBe(7);
    expect(body.events_removed_before).toBe(new Date(T0 - 7 * DAY).toISOString());
    const entry = (await entries()).at(-1) as AuditEntry;
    expect(entry.action).toBe("organization.retention.update");
    expect(entry.reason).toBe("Test change");
    expect(entry.summary).toContain("90");
    expect(entry.summary).toContain("7");
  });

  it("refuses a value that is not one of the choices with the validation problem", async () => {
    for (const bad of [14, 0, "30", null]) {
      const problem = await expectProblem(await change(bad, withReason()), 400);
      expect(problem.type).toBe("https://antireverse.dev/problems/validation");
    }
    const extra = await api.app.request(
      "/v1/organization/retention",
      put({ event_retention_days: 30, guard_days: 7 }, bearer(admin)),
    );
    await expectProblem(extra, 400);
    expect(RetentionResponseSchema.parse(await (await get()).json()).retention.event_retention_days).toBe(7);
  });

  it("answers the Organization's last run", async () => {
    const job = createRetentionJob({ db: api.db, now, logger: captureLogger() });
    expect(await job.runOnce()).toMatchObject({ complete: true, failed: 0 });
    const res = await get();
    expect(RetentionResponseSchema.parse(await res.json()).last_run).toEqual({
      ran_at: new Date(T0).toISOString(),
      complete: true,
      counts: {},
    });
  });

  it("refuses both routes while the Organization's deletion is pending", async () => {
    const res = await api.app.request(
      "/v1/organization/deletion",
      json({ confirm_name: "Acme" }, { ...bearer(admin), [AUDIT_REASON_HEADER]: "Leaving" }),
    );
    expect(res.status, await res.clone().text()).toBe(201);
    for (const refused of [await get(), await change(395)]) {
      const problem = await expectProblem(refused, 403);
      expect(problem.type).toBe("https://antireverse.dev/problems/organization-deletion-pending");
    }
  });
});

describe("retention job in the server", () => {
  let api: RunningApi | undefined;
  afterAll(async () => {
    await api?.close();
  });

  it("starts with the server and records a run; closing waits for it", async () => {
    const logger = captureLogger();
    api = await startApi({ port: 0, logger, smtp: null, retention: { firstRunMs: 10 } });
    const created = await fetch(`${api.url}/v1/organizations`, json({ name: "Acme" }));
    const { admin_key } = (await created.json()) as { admin_key: { key: string } };
    for (let i = 0; i < 200 && !logger.lines.some((line) => line.startsWith("retention run")); i++) await tick(10);
    expect(logger.lines.some((line) => line.startsWith("retention run"))).toBe(true);
    expect(api.retention).toBeDefined();
    await api.retention.flush();
    const res = await fetch(`${api.url}/v1/organization/retention`, { headers: bearer(admin_key.key) });
    expect(res.status).toBe(200);
    const body = RetentionResponseSchema.parse(await res.json());
    // The Organization may have been created before or after the first run: either no run, or a complete one.
    if (body.last_run !== null) expect(body.last_run.complete).toBe(true);
    await api.close();
    api = undefined;
  });
});
