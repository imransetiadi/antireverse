import { createHmac, randomBytes } from "node:crypto";
import { TIER_IDS, TIERS, USAGE_DEVICE_DAILY_CAP } from "@antireverse/protocol";
import { deviceSubject } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { RUNNER_DEFAULTS } from "../src/assess/runner.ts";
import { createRetentionJob } from "../src/data/retention.ts";
import { claimAssessment, finishAssessment, interruptRunning } from "../src/stores/assessments.ts";
import { addRequests, deviceRef, recordDevice, rollupUsage } from "../src/stores/usage.ts";
import { createUsageSalts } from "../src/usage/salts.ts";
import { artifactFor } from "./fake-assessor.ts";
import { bearer, captureLogger, createAppFor, createOrganization, json, makeTestApi, type TestApi } from "./helpers.ts";

vi.setConfig({ testTimeout: 60_000, hookTimeout: 30_000 });

// Slice 17a: migration 0036 at the SQL level. The usage tables (row-level security, read-only to the request role),
// the definers the request role writes through, the Assessment-end trigger, and the owner-only monthly rollup. The
// month salts are not in the database (review M3): the references arrive as HMACs computed by the API process.

const T0 = Date.parse("2026-11-14T09:00:00.000Z");
const DAY = 86_400_000;
const TENANT_TABLES = ["usage_daily", "usage_device_days", "usage_devices", "usage_monthly_devices"];
const CAP = USAGE_DEVICE_DAILY_CAP;

describe("migration 0036: usage", () => {
  let api: TestApi;
  let organizationId = "";
  let otherOrganizationId = "";
  let admin = "";
  let appId = "";
  let otherAppId = "";
  const salts = createUsageSalts();

  const owner = <T>(sql: string, params: unknown[] = []) =>
    api.db.owner(async (q) => (await q.query<T>(sql, params)).rows);
  const daily = () =>
    owner<{ app_id: string; environment: string; day: string; requests: number; sandbox_seconds: number }>(
      `SELECT app_id, environment, to_char(day, 'YYYY-MM-DD') AS day, requests::int AS requests,
         sandbox_seconds::int AS sandbox_seconds
       FROM usage_daily WHERE organization_id = $1 ORDER BY app_id, environment, day`,
      [organizationId],
    );
  /** Records a device as the attest route does: the reference under the month's salt, then the definer. */
  const record = (app: string, device: string, at: Date, cap = CAP) =>
    api.db.tx("none", (q) =>
      recordDevice(q, app, deviceRef(salts.saltFor(at.toISOString().slice(0, 7)), deviceSubject(app, device)), at, cap),
    );

  beforeAll(async () => {
    api = await makeTestApi({ now: () => new Date(T0) });
    const created = await createOrganization(api, "Acme");
    organizationId = created.organization.id;
    admin = created.admin_key.key;
    appId = (await createAppFor(api, admin)).app.id;
    const other = await createOrganization(api, "Bravo");
    otherOrganizationId = other.organization.id;
    otherAppId = (await createAppFor(api, other.admin_key.key)).app.id;
  });
  afterAll(async () => {
    await api.close();
  });

  describe("tables and rights", () => {
    it("forces row-level security on the tenant usage tables", async () => {
      const rows = await owner<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean }>(
        `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
         WHERE relname = ANY($1) AND relkind = 'r' ORDER BY relname`,
        [TENANT_TABLES],
      );
      expect(rows).toEqual(
        TENANT_TABLES.map((relname) => ({ relname, relrowsecurity: true, relforcerowsecurity: true })),
      );
    });

    it("keeps no salt in the database: no salt table, no HMAC function", async () => {
      const tables = await owner<{ n: number }>(
        "SELECT count(*)::int AS n FROM pg_class WHERE relname LIKE '%salt%' AND relkind = 'r'",
      );
      expect(tables[0]?.n).toBe(0);
      const functions = await owner<{ n: number }>(
        "SELECT count(*)::int AS n FROM pg_proc WHERE proname = 'usage_hmac'",
      );
      expect(functions[0]?.n).toBe(0);
    });

    it("lets the request role only read the usage tables", async () => {
      const grants = await owner<{ table_name: string; privilege_type: string }>(
        `SELECT table_name, privilege_type FROM information_schema.role_table_grants
         WHERE grantee = 'ar_app' AND table_name = ANY($1) ORDER BY table_name, privilege_type`,
        [TENANT_TABLES],
      );
      expect(grants).toEqual(TENANT_TABLES.map((table_name) => ({ table_name, privilege_type: "SELECT" })));
      const columns = await owner<{ n: number }>(
        `SELECT count(*)::int AS n FROM information_schema.column_privileges
         WHERE grantee = 'ar_app' AND privilege_type <> 'SELECT' AND table_name = ANY($1)`,
        [TENANT_TABLES],
      );
      expect(columns[0]?.n).toBe(0);
      const scope = { organizationId };
      for (const sql of [
        "INSERT INTO usage_daily (organization_id, app_id, environment, day, requests) VALUES ($1, $2, 'development', '2026-11-14', 5)",
        "UPDATE usage_daily SET requests = 0",
        "DELETE FROM usage_daily",
        "DELETE FROM usage_devices",
        "UPDATE usage_device_days SET new_refs = 0",
        "INSERT INTO usage_monthly_devices (organization_id, app_id, month, devices) VALUES ($1, $2, '2026-10-01', 9)",
      ]) {
        await expect(
          api.db.tx(scope, (q) => q.query(sql, sql.includes("$1") ? [organizationId, appId] : [])),
          sql,
        ).rejects.toMatchObject({ code: "42501" });
      }
      for (const scoped of [scope, "none" as const]) {
        await expect(api.db.tx(scoped, (q) => q.query("SELECT usage_rollup(now(), 10)"))).rejects.toMatchObject({
          code: "42501",
        });
      }
    });
  });

  describe("requests", () => {
    it("adds a count to the transaction's own Organization's App, Environment and day", async () => {
      const origin = (iso: string | number, environment: "staging" | "production" = "staging") => ({
        organizationId,
        appId,
        environment,
        receivedAt: new Date(iso),
      });
      await api.db.tx({ organizationId }, (q) => addRequests(q, origin(T0), 7));
      await api.db.tx({ organizationId }, (q) => addRequests(q, origin(T0 + 1000), 3));
      await api.db.tx({ organizationId }, (q) => addRequests(q, origin("2026-11-14T23:59:59.999Z"), 1));
      await api.db.tx({ organizationId }, (q) => addRequests(q, origin("2026-11-15T00:00:00.000Z"), 2));
      await api.db.tx({ organizationId }, (q) => addRequests(q, origin(T0, "production"), 0));
      expect(await daily()).toEqual([
        { app_id: appId, environment: "staging", day: "2026-11-14", requests: 11, sandbox_seconds: 0 },
        { app_id: appId, environment: "staging", day: "2026-11-15", requests: 2, sandbox_seconds: 0 },
      ]);
      await owner("DELETE FROM usage_daily");
    });

    it("refuses without a tenant, for another Organization's App, and a negative count", async () => {
      const origin = { organizationId, appId, environment: "staging" as const, receivedAt: new Date(T0) };
      await expect(api.db.tx("none", (q) => addRequests(q, origin, 1))).rejects.toMatchObject({ code: "42501" });
      await expect(
        api.db.tx({ organizationId }, (q) => addRequests(q, { ...origin, appId: otherAppId }, 1)),
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        api.db.tx({ organizationId: otherOrganizationId }, (q) => addRequests(q, origin, 1)),
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        api.db.tx({ organizationId }, (q) =>
          q.query("SELECT usage_add_requests($1, 'staging', '2026-11-14', -1)", [appId]),
        ),
      ).rejects.toMatchObject({ code: "22023" });
      expect(await daily()).toEqual([]);
    });
  });

  describe("Guard devices", () => {
    const refs = () =>
      owner<{ app_id: string; month: string; device_ref: Uint8Array }>(
        `SELECT app_id, to_char(month, 'YYYY-MM') AS month, device_ref FROM usage_devices
         WHERE organization_id = $1 ORDER BY month, device_ref`,
        [organizationId],
      );

    it("the reference is HMAC-SHA-256 under the month's salt, computed in the process", () => {
      const salt = randomBytes(32);
      const sub = deviceSubject(appId, "AAECAwQFBgcICQoLDA0ODw");
      expect(deviceRef(salt, sub).equals(createHmac("sha256", salt).update(sub, "utf8").digest())).toBe(true);
    });

    it("records a reference once per device, App and month, without a tenant", async () => {
      const nov = new Date(T0);
      expect(await record(appId, "AAECAwQFBgcICQoLDA0ODw", nov)).toBe("recorded");
      expect(await record(appId, "AAECAwQFBgcICQoLDA0ODw", new Date(T0 + DAY))).toBe("known");
      expect(await record(appId, "BBECAwQFBgcICQoLDA0ODw", nov)).toBe("recorded");
      expect((await refs()).map((row) => row.month)).toEqual(["2026-11", "2026-11"]);
      // December: a new salt, and the same device is a new reference.
      expect(await record(appId, "AAECAwQFBgcICQoLDA0ODw", new Date("2026-12-01T00:00:00.000Z"))).toBe("recorded");
      expect((await refs()).map((row) => row.month)).toEqual(["2026-11", "2026-11", "2026-12"]);
      // No raw identifier in any row.
      const text = JSON.stringify(await owner("SELECT * FROM usage_devices"));
      expect(text).not.toContain(deviceSubject(appId, "AAECAwQFBgcICQoLDA0ODw").slice(4));
    });

    it("records nothing for an App that does not exist, and refuses a reference that is not 32 bytes", async () => {
      const before = (await refs()).length;
      expect(await record("app_000000000000000000000000", "AAECAwQFBgcICQoLDA0ODw", new Date(T0))).toBe("unknown_app");
      await expect(
        api.db.tx("none", (q) => recordDevice(q, appId, Buffer.from("dev_raw"), new Date(T0), CAP)),
      ).rejects.toMatchObject({ code: "22023" });
      expect((await refs()).length).toBe(before);
    });

    it("stops at the daily cap of new references per App and flags the day; known devices still pass", async () => {
      const at = new Date("2026-11-20T10:00:00.000Z");
      expect(await record(otherAppId, "c1".repeat(11), at, 2)).toBe("recorded");
      expect(await record(otherAppId, "c2".repeat(11), at, 2)).toBe("recorded");
      expect(await record(otherAppId, "c3".repeat(11), at, 2)).toBe("capped");
      expect(await record(otherAppId, "c1".repeat(11), at, 2)).toBe("known");
      // The next UTC day starts again.
      expect(await record(otherAppId, "c3".repeat(11), new Date("2026-11-21T00:00:00.000Z"), 2)).toBe("recorded");
      expect(
        await owner<{ day: string; new_refs: number; capped: boolean }>(
          `SELECT to_char(day, 'YYYY-MM-DD') AS day, new_refs, capped FROM usage_device_days
           WHERE app_id = $1 ORDER BY day`,
          [otherAppId],
        ),
      ).toEqual([
        { day: "2026-11-20", new_refs: 2, capped: true },
        { day: "2026-11-21", new_refs: 1, capped: false },
      ]);
    });

    it("the request role reads its own Organization's references only", async () => {
      const own = await api.db.tx({ organizationId }, (q) => q.query("SELECT * FROM usage_devices"));
      expect(own.rows.length).toBe(3);
      const other = await api.db.tx({ organizationId: otherOrganizationId }, (q) =>
        q.query("SELECT * FROM usage_devices"),
      );
      expect(other.rows.length).toBe(3);
    });
  });

  describe("sandbox seconds", () => {
    async function queuedAssessment(): Promise<string> {
      const { manifest, files } = artifactFor(appId);
      const build = await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)));
      expect(build.status, await build.clone().text()).toBe(201);
      const res = await api.app.request(
        `/v1/apps/${appId}/builds/${manifest.build_id}/assessments`,
        json({ tier: "T1", files }, bearer(admin)),
      );
      expect(res.status, await res.clone().text()).toBe(202);
      return ((await res.json()) as { assessment: { id: string } }).assessment.id;
    }
    const failed = { status: "failed" as const, results: [], reason: "Stopped." };
    const graceS = RUNNER_DEFAULTS.graceMs / 1000;

    it("caps a run at its tier's seconds plus the runner's grace, the runner's own constants", async () => {
      for (const tier of TIER_IDS) {
        const rows = await owner<{ cap: number }>("SELECT usage_sandbox_cap_seconds($1)::int AS cap", [tier]);
        expect(rows[0]?.cap, tier).toBe(TIERS[tier].seconds + graceS);
      }
    });

    it("records the run time from start to finish once, at the finish, on the finish's UTC day", async () => {
      await owner("DELETE FROM usage_daily");
      const id = await queuedAssessment();
      const scope = { organizationId };
      expect(
        await api.db.tx(scope, (q) => claimAssessment(q, id, new Date("2026-11-14T23:59:00.000Z"))),
      ).not.toBeNull();
      // 61.2 seconds: rounded up to 62.
      expect(await api.db.tx(scope, (q) => finishAssessment(q, id, failed, new Date("2026-11-15T00:00:01.200Z")))).toBe(
        true,
      );
      expect(await api.db.tx(scope, (q) => finishAssessment(q, id, failed, new Date("2026-11-15T01:00:00.000Z")))).toBe(
        false,
      );
      expect(await daily()).toEqual([
        { app_id: appId, environment: "development", day: "2026-11-15", requests: 0, sandbox_seconds: 62 },
      ]);
    });

    it("records an interrupted run at its interruption", async () => {
      await owner("DELETE FROM usage_daily");
      const id = await queuedAssessment();
      await api.db.tx({ organizationId }, (q) => claimAssessment(q, id, new Date(T0)));
      expect(await api.db.tx("none", (q) => interruptRunning(q, new Date(T0 + 30_000), "Interrupted."))).toBe(1);
      expect(await daily()).toEqual([
        { app_id: appId, environment: "development", day: "2026-11-14", requests: 0, sandbox_seconds: 30 },
      ]);
    });

    it("does not bill an outage: a run interrupted a day later counts at most the tier's seconds plus the grace", async () => {
      await owner("DELETE FROM usage_daily");
      const id = await queuedAssessment();
      await api.db.tx({ organizationId }, (q) => claimAssessment(q, id, new Date(T0)));
      expect(await api.db.tx("none", (q) => interruptRunning(q, new Date(T0 + DAY), "Interrupted."))).toBe(1);
      const [row] = await daily();
      expect(row?.sandbox_seconds).toBeLessThanOrEqual(TIERS.T1.seconds + graceS);
      expect(row?.sandbox_seconds).toBe(TIERS.T1.seconds + graceS);
    });

    it("prefers the call log's seconds for a failed run that has one, capped as well", async () => {
      await owner("DELETE FROM usage_daily");
      const id = await queuedAssessment();
      const scope = { organizationId };
      await api.db.tx(scope, (q) => claimAssessment(q, id, new Date(T0)));
      const log = { calls: [], totals: { count: 3, calls: 3, seconds: 40.5 } };
      await api.db.tx(scope, (q) => finishAssessment(q, id, { ...failed, log }, new Date(T0 + 5 * DAY)));
      expect((await daily())[0]?.sandbox_seconds).toBe(41);
    });

    it("without a start, takes the call log's seconds; without either, records nothing", async () => {
      await owner("DELETE FROM usage_daily");
      const logged = await queuedAssessment();
      await owner(
        `UPDATE assessments SET status = 'failed', failure_reason = 'x', finished_at = $2,
           calls = '[]', call_totals = '{"count": 0, "calls": 0, "seconds": 12.3}' WHERE id = $1`,
        [logged, new Date(T0)],
      );
      const bare = await queuedAssessment();
      await owner("UPDATE assessments SET status = 'failed', failure_reason = 'x', finished_at = $2 WHERE id = $1", [
        bare,
        new Date(T0),
      ]);
      expect(await daily()).toEqual([
        { app_id: appId, environment: "development", day: "2026-11-14", requests: 0, sandbox_seconds: 13 },
      ]);
    });
  });

  describe("monthly rollup", () => {
    const AT = new Date("2026-12-03T04:00:00.000Z");
    const monthly = () =>
      owner<{ organization_id: string; app_id: string; month: string; devices: number; capped: boolean }>(
        `SELECT organization_id, app_id, to_char(month, 'YYYY-MM') AS month, devices::int AS devices, capped
         FROM usage_monthly_devices ORDER BY organization_id, app_id, month`,
      );

    it("closes the months before the current one: totals (with the cap flag) written, references deleted", async () => {
      await owner("DELETE FROM usage_devices");
      await owner("DELETE FROM usage_device_days");
      for (let n = 0; n < 5; n++) await record(appId, `${n}`.repeat(22), new Date(T0));
      await record(otherAppId, "x".repeat(22), new Date(T0), 0);
      await record(otherAppId, "y".repeat(22), new Date(T0));
      // December, current at AT: left alone.
      await record(appId, "0".repeat(22), new Date("2026-12-02T00:00:00.000Z"));

      const first = await api.db.owner((q) => rollupUsage(q, AT, 4));
      expect(first.saturated).toBe(true);
      const removed = Object.values(first.rows).reduce((sum, tables) => sum + (tables.usage_devices ?? 0), 0);
      expect(removed).toBe(4);
      const second = await api.db.owner((q) => rollupUsage(q, AT, 4));
      expect(second.saturated).toBe(false);

      expect(await monthly()).toEqual(
        [
          { organization_id: organizationId, app_id: appId, month: "2026-11", devices: 5, capped: false },
          { organization_id: otherOrganizationId, app_id: otherAppId, month: "2026-11", devices: 1, capped: true },
        ].sort((x, y) => (x.organization_id < y.organization_id ? -1 : 1)),
      );
      expect(
        await owner<{ month: string }>("SELECT to_char(month, 'YYYY-MM') AS month FROM usage_devices ORDER BY 1"),
      ).toEqual([{ month: "2026-12" }]);
      expect(
        await owner<{ day: string }>("SELECT to_char(day, 'YYYY-MM-DD') AS day FROM usage_device_days ORDER BY 1"),
      ).toEqual([{ day: "2026-12-02" }]);
      const third = await api.db.owner((q) => rollupUsage(q, AT, 4));
      expect(third).toEqual({ rows: {}, saturated: false });
    });

    it("counts a closed month once, then only deletes: a call reads at most about a batch of references", async () => {
      await owner(
        `INSERT INTO usage_devices (organization_id, app_id, month, device_ref)
         SELECT $1, $2, '2026-10-01', sha256(convert_to(g::text, 'UTF8')) FROM generate_series(1, 30000) g`,
        [organizationId, appId],
      );
      await owner(
        "INSERT INTO usage_device_days (organization_id, app_id, day, new_refs) VALUES ($1, $2, '2026-10-05', 30000)",
        [organizationId, appId],
      );
      const BATCH = 1000;
      /** One rollup call and the reference rows it read (sequential and index fetches: the counters' difference). */
      const call = () =>
        api.db.owner(async (q) => {
          const reads = async () => {
            const { rows } = await q.query<{ n: number }>(
              `SELECT (COALESCE(seq_tup_read, 0) + COALESCE(idx_tup_fetch, 0))::int AS n
               FROM pg_stat_xact_user_tables WHERE relname = 'usage_devices'`,
            );
            return rows[0]?.n ?? 0;
          };
          const before = await reads();
          const result = await rollupUsage(q, AT, BATCH);
          return { result, read: (await reads()) - before };
        });
      const first = await call();
      expect(first.result.rows[organizationId]?.usage_devices).toBe(BATCH);
      // The first call counts the month: it reads its references once.
      expect(first.read).toBeGreaterThanOrEqual(30_000);
      const second = await call();
      expect(second.result.rows[organizationId]?.usage_devices).toBe(BATCH);
      // The count was taken once, by the first call; the second reads its batch, not the 29,000 left.
      expect(second.read).toBeLessThanOrEqual(2 * BATCH + 10);
      expect((await monthly()).find((row) => row.month === "2026-10")?.devices).toBe(30_000);
      await owner("DELETE FROM usage_devices WHERE month = '2026-10-01'");
    });

    it("waits an hour after a month ends before closing it", async () => {
      await record(appId, "z".repeat(22), AT);
      const early = await api.db.owner((q) => rollupUsage(q, new Date("2027-01-01T00:30:00.000Z"), 100));
      expect(early).toEqual({ rows: {}, saturated: false });
      const late = await api.db.owner((q) => rollupUsage(q, new Date("2027-01-01T01:00:00.000Z"), 100));
      expect(late.rows[organizationId]?.usage_devices).toBe(2);
      expect((await monthly()).find((row) => row.app_id === appId && row.month === "2026-12")?.devices).toBe(2);
    });

    it("removes usage older than 13 months before the current one", async () => {
      await owner("DELETE FROM usage_daily");
      await owner("DELETE FROM usage_monthly_devices");
      for (const day of ["2025-09-30", "2025-10-01", "2026-11-14"]) {
        await owner(
          `INSERT INTO usage_daily (organization_id, app_id, environment, day, requests, sandbox_seconds)
           VALUES ($1, $2, 'development', $3, 1, 0)`,
          [organizationId, appId, day],
        );
      }
      for (const month of ["2025-09-01", "2025-10-01"]) {
        await owner(
          "INSERT INTO usage_monthly_devices (organization_id, app_id, month, devices) VALUES ($1, $2, $3, 1)",
          [organizationId, appId, month],
        );
      }
      const swept = await api.db.owner((q) => rollupUsage(q, new Date(T0), 100));
      expect(swept.rows[organizationId]).toEqual({ usage_daily: 1, usage_monthly_devices: 1 });
      expect((await daily()).map((row) => row.day)).toEqual(["2025-10-01", "2026-11-14"]);
    });

    it("runs in the retention job with its own budget, then forgets the closed months' salts", async () => {
      const at = new Date("2027-03-02T00:00:00.000Z");
      for (const device of ["a", "b", "c"])
        await record(appId, device.repeat(22), new Date("2027-02-10T00:00:00.000Z"));
      salts.saltFor("2027-03");
      const logger = captureLogger();
      // The retention call cap does not limit the rollup: its own budget does.
      const cut = createRetentionJob({
        db: api.db,
        now: () => at,
        logger,
        maxCallsPerRun: 1000,
        usageSalts: salts,
        usageBatch: 1,
        usageMaxCallsPerRun: 2,
      });
      const first = await cut.runOnce();
      expect(first.complete).toBe(false);
      expect(first.rows.usage_devices).toBe(2);
      expect(logger.lines.some((line) => line.startsWith("retention run incomplete"))).toBe(true);
      // The counts are written by the first call: the salts of the closed months are gone already.
      expect(salts.months()).toEqual(["2027-03"]);
      const second = await createRetentionJob({ db: api.db, now: () => at, logger, usageSalts: salts }).runOnce();
      expect(second).toMatchObject({ complete: true, failed: 0 });
      expect(second.rows.usage_devices).toBe(1);
      expect((await monthly()).find((row) => row.month === "2027-02")?.devices).toBe(3);
    });
  });
});
