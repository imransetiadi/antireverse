import { USAGE_DEVICE_DAILY_CAP, UsageResponseSchema } from "@antireverse/protocol";
import { deviceSubject } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createRetentionJob } from "../src/data/retention.ts";
import { claimAssessment, finishAssessment } from "../src/stores/assessments.ts";
import { deviceRef, recordDevice } from "../src/stores/usage.ts";
import { createUsageSalts } from "../src/usage/salts.ts";
import { artifactFor } from "./fake-assessor.ts";
import {
  batchOf,
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  expectProblem,
  json,
  makeTestApi,
  put,
  shieldEvent,
  type TestApi,
  withReason,
} from "./helpers.ts";

vi.setConfig({ testTimeout: 30_000, hookTimeout: 30_000 });

// Slice 17a: `GET /v1/usage?month=YYYY-MM` (admin key): totals and per-App requests, Guard devices and sandbox
// minutes, every day's requests, the Apps count and the Event retention; months in the future or older than 13 months
// refused; reads share the per-Organization budget of audit reads; refused while a deletion is pending.

const T0 = Date.parse("2026-11-14T09:00:00.000Z");

describe("GET /v1/usage", () => {
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let api: TestApi;
  let organizationId = "";
  let admin = "";
  let appId = "";
  let shield = "";
  let stagingAppId = "";
  let stagingShield = "";
  let otherAdmin = "";
  const salts = createUsageSalts();

  const usage = (query = "", key = admin) => api.app.request(`/v1/usage${query}`, { headers: bearer(key) });
  const read = async (query = "") => {
    const res = await usage(query);
    expect(res.status, await res.clone().text()).toBe(200);
    return UsageResponseSchema.parse(await res.json());
  };

  beforeAll(async () => {
    api = await makeTestApi({ now, auditReadsPerMinute: 10_000 });
    const created = await createOrganization(api, "Acme");
    organizationId = created.organization.id;
    admin = created.admin_key.key;
    const app = await createAppFor(api, admin, { name: "Storefront" });
    appId = app.app.id;
    shield = app.shield_key.key;
    const staging = await createAppFor(api, admin, { name: "Back office", environment: "staging" });
    stagingAppId = staging.app.id;
    stagingShield = staging.shield_key.key;
    const other = await createOrganization(api, "Bravo");
    otherAdmin = other.admin_key.key;
    const otherShield = (await createAppFor(api, otherAdmin)).shield_key.key;

    // November: 3 + 2 requests on the 14th, 1 on the 30th; the other Organization's 7 are not ours.
    const send = (key: string, ms: number, n: number) =>
      api.app.request(
        "/v1/events",
        json(batchOf(Array.from({ length: n }, (_, i) => shieldEvent(ms + i))), bearer(key)),
      );
    expect((await send(shield, T0, 3)).status).toBe(202);
    expect((await send(stagingShield, T0 + 10, 2)).status).toBe(202);
    expect((await send(otherShield, T0 + 20, 7)).status).toBe(202);
    clock.ms = Date.parse("2026-11-30T23:00:00.000Z");
    expect((await send(shield, clock.ms, 1)).status).toBe(202);
    // October: 4 requests.
    clock.ms = Date.parse("2026-10-02T12:00:00.000Z");
    expect((await send(shield, clock.ms, 4)).status).toBe(202);
    clock.ms = T0;

    // Guard devices: two on the Storefront in November, one in October.
    for (const [device, at] of [
      ["AAECAwQFBgcICQoLDA0ODw", T0],
      ["BBECAwQFBgcICQoLDA0ODw", T0],
      ["AAECAwQFBgcICQoLDA0ODw", Date.parse("2026-10-05T00:00:00.000Z")],
    ] as const) {
      const ref = deviceRef(salts.saltFor(new Date(at).toISOString().slice(0, 7)), deviceSubject(appId, device));
      await api.db.tx("none", (q) => recordDevice(q, appId, ref, new Date(at), USAGE_DEVICE_DAILY_CAP));
    }

    // One Assessment of 95 seconds on the Storefront, finished on 14 November.
    const { manifest, files } = artifactFor(appId);
    expect((await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)))).status).toBe(201);
    const queued = await api.app.request(
      `/v1/apps/${appId}/builds/${manifest.build_id}/assessments`,
      json({ tier: "T1", files }, bearer(admin)),
    );
    const assessmentId = ((await queued.json()) as { assessment: { id: string } }).assessment.id;
    await api.db.tx({ organizationId }, (q) => claimAssessment(q, assessmentId, new Date(T0)));
    await api.db.tx({ organizationId }, (q) =>
      finishAssessment(q, assessmentId, { status: "failed", results: [], reason: "Stopped." }, new Date(T0 + 95_000)),
    );
  });
  afterAll(async () => {
    await api.close();
  });

  it("answers the current UTC month by default: totals, per App, every day, Apps count, retention, no seats", async () => {
    const body = await read();
    expect(body.month).toBe("2026-11");
    expect(body.closed).toBe(false);
    expect(body.totals).toEqual({
      requests: 6,
      guard_devices: 2,
      guard_devices_capped: false,
      sandbox_seconds: 95,
      sandbox_minutes: 1.58,
    });
    expect(body.apps).toEqual([
      {
        app_id: appId,
        name: "Storefront",
        requests: 4,
        guard_devices: 2,
        guard_devices_capped: false,
        sandbox_seconds: 95,
        sandbox_minutes: 1.58,
      },
      {
        app_id: stagingAppId,
        name: "Back office",
        requests: 2,
        guard_devices: 0,
        guard_devices_capped: false,
        sandbox_seconds: 0,
        sandbox_minutes: 0,
      },
    ]);
    expect(body.daily).toHaveLength(30);
    expect(body.daily[0]).toEqual({ day: "2026-11-01", requests: 0 });
    expect(body.daily[13]).toEqual({ day: "2026-11-14", requests: 5 });
    expect(body.daily[29]).toEqual({ day: "2026-11-30", requests: 1 });
    expect(body.daily.reduce((sum, day) => sum + day.requests, 0)).toBe(6);
    expect(body.apps_count).toBe(2);
    expect(body.event_retention_days).toBe(30);
    expect(body.seats).toBeNull();
    expect(body.seats_note).toBe("not applicable");
  });

  it("answers a past month, with its Guard devices rolled up once the job closed it", async () => {
    const live = await read("?month=2026-10");
    expect(live).toMatchObject({ month: "2026-10", closed: true });
    expect(live.totals).toEqual({
      requests: 4,
      guard_devices: 1,
      guard_devices_capped: false,
      sandbox_seconds: 0,
      sandbox_minutes: 0,
    });
    expect(live.daily).toHaveLength(31);
    expect(live.daily[1]).toEqual({ day: "2026-10-02", requests: 4 });

    const job = createRetentionJob({ db: api.db, now, logger: captureLogger() });
    const result = await job.runOnce();
    expect(result.rows.usage_devices).toBe(1);
    const closed = await read("?month=2026-10");
    expect(closed.totals.guard_devices).toBe(1);
    expect(closed.apps[0]?.guard_devices).toBe(1);
    // The references are gone; the total is what remains.
    const left = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM usage_devices WHERE month = '2026-10-01'",
      );
      return rows[0]?.n;
    });
    expect(left).toBe(0);
  });

  it("flags an App whose recording stopped at the daily cap, before and after the month is rolled up", async () => {
    const at = new Date("2026-10-20T00:00:00.000Z");
    const ref = deviceRef(salts.saltFor("2026-10"), deviceSubject(stagingAppId, "CCECAwQFBgcICQoLDA0ODw"));
    expect(await api.db.tx("none", (q) => recordDevice(q, stagingAppId, ref, at, 0))).toBe("capped");
    const october = await read("?month=2026-10");
    expect(october.apps.find((app) => app.app_id === stagingAppId)?.guard_devices_capped).toBe(true);
    expect(october.apps.find((app) => app.app_id === appId)?.guard_devices_capped).toBe(false);
    expect(october.totals.guard_devices_capped).toBe(true);
    expect((await read()).totals.guard_devices_capped).toBe(false);
    await createRetentionJob({ db: api.db, now, logger: captureLogger(), usageSalts: salts }).runOnce();
    const closed = await read("?month=2026-10");
    expect(closed.apps.find((app) => app.app_id === stagingAppId)?.guard_devices_capped).toBe(true);
    expect(closed.totals.guard_devices_capped).toBe(true);
  });

  it("states the current Event retention", async () => {
    const res = await api.app.request("/v1/organization/retention", put({ event_retention_days: 90 }, bearer(admin)));
    expect(res.status).toBe(200);
    expect((await read()).event_retention_days).toBe(90);
  });

  it("refuses months in the future and older than 13 months with the validation problem", async () => {
    expect((await read("?month=2025-10")).month).toBe("2025-10");
    for (const month of ["2026-12", "2025-09", "2026-13", "2026-1", "x"]) {
      const problem = await expectProblem(await usage(`?month=${month}`), 400);
      expect(problem.type).toBe("https://antireverse.dev/problems/validation");
      expect(problem.errors?.[0]?.path).toBe("month");
    }
  });

  it("isolates Organizations", async () => {
    const res = await usage("", otherAdmin);
    const body = UsageResponseSchema.parse(await res.json());
    expect(body.totals.requests).toBe(7);
    expect(body.apps.map((app) => app.app_id)).not.toContain(appId);
  });

  it("takes the admin key only", async () => {
    await expectProblem(await usage("", shield), 403);
    await expectProblem(await api.app.request("/v1/usage"), 401);
  });

  it("refuses while the Organization's deletion is pending", async () => {
    const res = await api.app.request(
      "/v1/organization/deletion",
      json({ confirm_name: "Bravo" }, withReason(bearer(otherAdmin))),
    );
    expect(res.status).toBe(201);
    const problem = await expectProblem(await usage("", otherAdmin), 403);
    expect(problem.type).toBe("https://antireverse.dev/problems/organization-deletion-pending");
  });
});

describe("GET /v1/usage minutes", () => {
  it("gives total minutes that are the sum of the Apps' rounded minutes; seconds stay exact", async () => {
    const api = await makeTestApi({ now: () => new Date(T0) });
    try {
      const created = await createOrganization(api, "Acme");
      const organizationId = created.organization.id;
      const key = created.admin_key.key;
      for (const name of ["One", "Two", "Three"]) {
        const app = (await createAppFor(api, key, { name })).app.id;
        await api.db.owner((q) =>
          q.query(
            `INSERT INTO usage_daily (organization_id, app_id, environment, day, sandbox_seconds)
             VALUES ($1, $2, 'development', '2026-11-14', 1)`,
            [organizationId, app],
          ),
        );
      }
      const body = UsageResponseSchema.parse(
        await (await api.app.request("/v1/usage", { headers: bearer(key) })).json(),
      );
      expect(body.apps.map((app) => app.sandbox_minutes)).toEqual([0.02, 0.02, 0.02]);
      expect(body.totals.sandbox_seconds).toBe(3);
      expect(body.totals.sandbox_minutes).toBe(0.06);
    } finally {
      await api.close();
    }
  });
});

describe("GET /v1/usage rate limit", () => {
  it("shares the per-Organization budget of audit reads", async () => {
    const api = await makeTestApi({ now: () => new Date(T0), auditReadsPerMinute: 2 });
    try {
      const created = await createOrganization(api, "Acme");
      const key = created.admin_key.key;
      const other = (await createOrganization(api, "Bravo")).admin_key.key;
      expect((await api.app.request("/v1/usage", { headers: bearer(key) })).status).toBe(200);
      expect((await api.app.request("/v1/audit/verify", { headers: bearer(key) })).status).toBe(200);
      const limited = await expectProblem(await api.app.request("/v1/usage", { headers: bearer(key) }), 429);
      expect(limited.type).toBe("https://antireverse.dev/problems/too-many-requests");
      // A neutral detail: the budget is shared by usage reads, audit verifications and exports.
      expect(limited.detail).not.toMatch(/audit/i);
      expect(limited.detail).toMatch(/reads for this Organization/);
      // Another Organization has its own budget.
      expect((await api.app.request("/v1/usage", { headers: bearer(other) })).status).toBe(200);
    } finally {
      await api.close();
    }
  });
});
