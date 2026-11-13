import {
  AUDIT_REASON_HEADER,
  AuditPublicKeyResponseSchema,
  DeletionResponseSchema,
  DeletionStatusResponseSchema,
  deletionReportSignedText,
  ListAuditResponseSchema,
  SignedDeletionReportSchema,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPurgeJob, PURGE_DEFAULTS, type PurgeJob } from "../src/data/purge.ts";
import { startApi } from "../src/server.ts";
import { DELETION_TABLE } from "../src/stores/deletions.ts";
import { makeDataApi, requestDeletion, rowsOf, type Seeded, seedOrganization, tenantTables } from "./data-seed.ts";
import {
  batchOf,
  bearer,
  captureLogger,
  expectNoKeyLogged,
  expectProblem,
  json,
  shieldEvent,
  verifySignature,
  withReason,
} from "./helpers.ts";

// Slice 18b: the Organization deletion — request with the typed name and a reason, the gate on every key while it is
// pending, cancel, the daily purge after the 7-day grace and its signed report.

const T0 = Date.parse("2026-11-13T09:00:00.000Z");
const DAY = 86_400_000;
const PENDING = "https://antireverse.dev/problems/organization-deletion-pending";
/** The only routes a key of an Organization pending deletion may still call. */
const STILL_ALLOWED = new Set([
  "GET /v1/organization/deletion",
  "DELETE /v1/organization/deletion",
  "GET /v1/organization/export",
]);

describe("organization deletion", () => {
  let api: Awaited<ReturnType<typeof makeDataApi>>;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let a: Seeded;
  let b: Seeded;
  let job: PurgeJob;

  beforeAll(async () => {
    api = await makeDataApi(now);
    a = await seedOrganization(api, "Acme Shop", { now });
    b = await seedOrganization(api, "Bravo", { now });
    job = createPurgeJob({ db: api.db, signer: api.auditSigner, now, logger: captureLogger() });
  });
  afterAll(async () => {
    expectNoKeyLogged(api);
    await api.close();
  });

  const status = async (key: string) => {
    const res = await api.app.request("/v1/organization/deletion", { headers: bearer(key) });
    expect(res.status).toBe(200);
    return DeletionStatusResponseSchema.parse(await res.json()).deletion;
  };
  const cancel = (key: string, headers: Record<string, string> = withReason()) =>
    api.app.request("/v1/organization/deletion", { method: "DELETE", headers: { ...bearer(key), ...headers } });

  it("has no pending deletion at first", async () => {
    expect(await status(a.admin)).toBeNull();
  });

  it("refuses a request without a reason or without the exact name, and keeps nothing", async () => {
    const path = "/v1/organization/deletion";
    const noReason = await expectProblem(
      await api.app.request(path, json({ confirm_name: a.name }, bearer(a.admin))),
      400,
    );
    expect(noReason.type).toBe("https://antireverse.dev/problems/reason-required");
    for (const confirm of ["acme shop", "Acme", " Acme Shop", "Bravo"]) {
      const wrong = await expectProblem(
        await api.app.request(path, json({ confirm_name: confirm }, withReason(bearer(a.admin)))),
        400,
      );
      expect(wrong.errors?.[0]?.path).toBe("confirm_name");
    }
    await expectProblem(await api.app.request(path, json({}, withReason(bearer(a.admin)))), 400);
    // A Shield key is not an admin key.
    await expectProblem(await api.app.request(path, json({ confirm_name: a.name }, withReason(bearer(a.shield)))), 403);
    expect(await status(a.admin)).toBeNull();
  });

  let deletionId = "";
  it("marks the Organization pending with purge_after 7 days on, and audits it with the reason", async () => {
    const res = await api.app.request(
      "/v1/organization/deletion",
      json({ confirm_name: a.name }, withReason(bearer(a.admin))),
    );
    expect(res.status).toBe(201);
    const { deletion } = DeletionResponseSchema.parse(await res.json());
    deletionId = deletion.id;
    expect(deletion).toEqual({
      id: deletion.id,
      organization_id: a.organizationId,
      status: "pending",
      requested_at: new Date(T0).toISOString(),
      purge_after: new Date(T0 + 7 * DAY).toISOString(),
      cancelled_at: null,
      purged_at: null,
    });
    expect(await status(a.admin)).toEqual(deletion);
    const entry = await api.db.owner(async (q) => {
      const { rows } = await q.query<Record<string, string>>(
        "SELECT action, target_kind, target_id, reason, request_id FROM audit_entries WHERE organization_id = $1 ORDER BY seq DESC LIMIT 1",
        [a.organizationId],
      );
      return rows[0];
    });
    expect(entry).toEqual({
      action: "organization.deletion.request",
      target_kind: "organization_deletion",
      target_id: deletion.id,
      reason: "Test change",
      request_id: res.headers.get("x-request-id"),
    });
  });

  it("refuses every key of the Organization on every other route with organization-deletion-pending", async () => {
    const routes = new Map<string, { method: string; path: string }>();
    for (const route of api.app.routes) {
      if (!/^[A-Z]+$/.test(route.method) || route.path.includes("*")) continue;
      routes.set(`${route.method} ${route.path}`, route);
    }
    let gated = 0;
    for (const [name, route] of routes) {
      const path = route.path.replace(/:[A-Za-z]+/g, "x");
      // A public route answers without a key; it is no key's route.
      const anonymous = await api.app.request(path, { method: route.method });
      if (anonymous.status !== 401) continue;
      for (const key of [a.admin, a.shield]) {
        const res = await api.app.request(path, { method: route.method, headers: bearer(key) });
        if (STILL_ALLOWED.has(name)) {
          // The admin key passes the gate; a Shield key is the wrong kind of key there.
          if (key === a.admin) expect(res.status, `${name} is still allowed`).not.toBe(403);
          else expect((await expectProblem(res, 403)).type).toBe("https://antireverse.dev/problems/forbidden");
          continue;
        }
        const problem = await expectProblem(res, 403);
        expect(problem.type, name).toBe(PENDING);
        gated++;
      }
    }
    expect(gated).toBeGreaterThan(60);
    // The exceptions answer the admin key.
    expect((await api.app.request("/v1/organization/export", { headers: bearer(a.admin) })).status).toBe(200);
    // No new data while pending: ingest is refused.
    const ingest = await api.app.request("/v1/events", json(batchOf([shieldEvent(T0)]), bearer(a.shield)));
    expect((await expectProblem(ingest, 403)).type).toBe(PENDING);
    // The other Organization is not affected.
    expect((await api.app.request("/v1/organization", { headers: bearer(b.admin) })).status).toBe(200);
    expect((await api.app.request("/v1/policy-bundle", { headers: bearer(b.shield) })).status).toBe(200);
  });

  it("isolates tenants: another Organization neither sees nor cancels the deletion nor reads a report", async () => {
    expect(await status(b.admin)).toBeNull();
    await expectProblem(await cancel(b.admin), 404);
    expect((await status(a.admin))?.status).toBe("pending");
    for (const key of [b.admin, undefined]) {
      const res = await api.app.request(`/v1/deletions/${deletionId}/report`, {
        headers: key === undefined ? {} : bearer(key),
      });
      await expectProblem(res, 404);
    }
    const listed = await api.app.request("/v1/audit?limit=200", { headers: bearer(b.admin) });
    expect(JSON.stringify(ListAuditResponseSchema.parse(await listed.json()))).not.toContain(deletionId);
  });

  it("cancels only with a reason; everything works again; the cancel is audited", async () => {
    const refused = await expectProblem(await cancel(a.admin, {}), 400);
    expect(refused.type).toBe("https://antireverse.dev/problems/reason-required");
    clock.ms += DAY;
    const res = await cancel(a.admin);
    expect(res.status).toBe(200);
    const { deletion } = DeletionResponseSchema.parse(await res.json());
    expect(deletion).toMatchObject({ id: deletionId, status: "cancelled", cancelled_at: now().toISOString() });
    expect(await status(a.admin)).toBeNull();
    await expectProblem(await cancel(a.admin), 404);
    expect((await api.app.request("/v1/organization", { headers: bearer(a.admin) })).status).toBe(200);
    expect((await api.app.request("/v1/policy-bundle", { headers: bearer(a.shield) })).status).toBe(200);
    const ingest = await api.app.request("/v1/events", json(batchOf([shieldEvent(now().getTime())]), bearer(a.shield)));
    expect(ingest.status).toBe(202);
    const listed = await api.app.request("/v1/audit?limit=2", { headers: bearer(a.admin) });
    const [last] = ListAuditResponseSchema.parse(await listed.json()).entries;
    expect(last).toMatchObject({
      action: "organization.deletion.cancel",
      target: { kind: "organization_deletion", id: deletionId },
      reason: "Test change",
    });
    // A cancelled deletion is never purged and has no report.
    clock.ms += 30 * DAY;
    expect(await job.runOnce()).toMatchObject({ due: 0, purged: 0 });
    await expectProblem(await api.app.request(`/v1/deletions/${deletionId}/report`), 404);
  });

  let second = "";
  let expected: Record<string, number> = {};
  it("purges only after purge_after, writes a signed report, and is idempotent", async () => {
    second = await requestDeletion(api, a);
    expect(second).not.toBe(deletionId);
    const requestedAt = clock.ms;
    clock.ms = requestedAt + 7 * DAY - 1;
    expect(await job.runOnce()).toMatchObject({ due: 0, purged: 0 });
    expect((await status(a.admin))?.status).toBe("pending");
    await expectProblem(await api.app.request(`/v1/deletions/${second}/report`), 404);
    const tables = (await tenantTables(api)).filter((table) => table !== DELETION_TABLE);
    expected = Object.fromEntries(
      Object.entries(await rowsOf(api, a.organizationId, [...tables, "organizations"])).filter(([, n]) => n > 0),
    );
    clock.ms = requestedAt + 7 * DAY;
    expect(await job.runOnce()).toMatchObject({ due: 1, purged: 1, failed: 0 });
    expect(await job.runOnce()).toMatchObject({ due: 0, purged: 0, failed: 0 });
    expect(Object.values(await rowsOf(api, a.organizationId, [...tables, "organizations"])).every((n) => n === 0)).toBe(
      true,
    );

    const res = await api.app.request(`/v1/deletions/${second}/report`);
    expect(res.status).toBe(200);
    const signed = SignedDeletionReportSchema.parse(await res.json());
    expect(signed.report).toEqual({
      deletion_id: second,
      organization_id: a.organizationId,
      requested_at: new Date(requestedAt).toISOString(),
      purge_after: new Date(requestedAt + 7 * DAY).toISOString(),
      purged_at: now().toISOString(),
      rows: expected,
      total_rows: Object.values(expected).reduce((sum, n) => sum + n, 0),
    });
    const key = AuditPublicKeyResponseSchema.parse(await (await api.app.request("/v1/audit/public-key")).json());
    expect(signed.key_id).toBe(key.key_id);
    expect(verifySignature(key.public_key, deletionReportSignedText(signed.report), signed.signature)).toBe(true);
    expect(JSON.stringify(signed)).not.toContain(a.name);
    // The first, cancelled deletion still has none; a malformed id is a plain 404.
    await expectProblem(await api.app.request(`/v1/deletions/${deletionId}/report`), 404);
    await expectProblem(await api.app.request("/v1/deletions/nope/report"), 404);
  });

  it("refuses the purged Organization's keys as unknown, and leaves the other Organization working", async () => {
    await expectProblem(await api.app.request("/v1/organization/deletion", { headers: bearer(a.admin) }), 401);
    await expectProblem(await api.app.request("/v1/organization/export", { headers: bearer(a.admin) }), 401);
    expect((await api.app.request("/v1/organization", { headers: bearer(b.admin) })).status).toBe(200);
  });

  it("does not take a reason header for the gate's sake: a malformed one is still a 400 first", async () => {
    const res = await api.app.request("/v1/organization/deletion", {
      ...json({ confirm_name: b.name }, { ...bearer(b.admin), [AUDIT_REASON_HEADER]: "%zz" }),
    });
    await expectProblem(res, 400);
  });
});

describe("purge job wiring", () => {
  it("runs daily by default, is started by startApi and flushed on close", async () => {
    expect(PURGE_DEFAULTS.everyMs).toBe(86_400_000);
    const running = await startApi({ logger: captureLogger(), smtp: null });
    try {
      expect(await running.purge.runOnce()).toEqual({ due: 0, purged: 0, failed: 0 });
    } finally {
      await running.close();
    }
  });
});
