import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CreateAppResponseSchema, CreateOrganizationResponseSchema, SloReportSchema } from "@antireverse/protocol";
import { afterAll, describe, expect, it, vi } from "vitest";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { type RunningApi, startApi } from "../src/server.ts";
import { batchOf, bearer, captureLogger, json, shieldEvent } from "./helpers.ts";

// Slice 18g, independent review, inside a running API.
// F1: a transport that cannot be opened must not make new keys every cycle, and restarts must not pile key rows up.
// D-117: such a prober counts as failing from its fourth cycle. F2 / D-116: the probe's own requests and Events feed
// no SLI but its two measurements, and nothing is detected on them; a tenant's traffic counts as before.

vi.setConfig({ testTimeout: 90_000 });

const TOKEN = "ops-token-".padEnd(44, "R");
const FAST = { startDelayMs: 3_600_000, shield: { policyPollIntervalMs: 100, flushIntervalMs: 50 } };
const owned = (api: RunningApi): OwnedDb => api.db as OwnedDb;
const rows = async (db: OwnedDb, sql: string): Promise<number> =>
  db.owner(async (q) => (await q.query(sql)).rows.length);

async function report(api: RunningApi) {
  const res = await fetch(`${api.url}/v1/ops/slo`, { headers: bearer(TOKEN) });
  return SloReportSchema.parse(await res.json());
}
const totals = (r: Awaited<ReturnType<typeof report>>) => Object.fromEntries(r.slos.map((slo) => [slo.id, slo.total]));

describe("F1 and D-117: a probe whose transport cannot be opened", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-probe-review-"));
  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("keeps one pair of keys over ten failed cycles, and counts as failing from the fourth", async () => {
    let opens = 0;
    const logger = captureLogger();
    const api = await startApi({
      logger,
      smtp: null,
      ops: { token: TOKEN, webhook: null },
      probes: {
        enabled: true,
        ...FAST,
        open: async () => {
          opens++;
          throw new Error("no loopback port");
        },
      },
    });
    try {
      for (let i = 0; i < 10; i++) await api.probes?.runOnce();
      expect(opens).toBe(10);
      expect(await rows(owned(api), "SELECT 1 FROM api_keys")).toBe(2);
      expect(await rows(owned(api), "SELECT 1 FROM api_keys WHERE revoked_at IS NULL")).toBe(2);
      const r = await report(api);
      expect(r.probes).toMatchObject({ runs: 10, failures: 10, consecutive_failures: 10, setup_failures: 10 });
      // Cycles 4 to 10: seven bad samples, so the burn rules see a prober that cannot run.
      expect(r.slos.find((s) => s.id === "SLO-06")).toMatchObject({ measured: true, good: 0, total: 7, attainment: 0 });
      expect(logger.lines.filter((line) => line.includes("reason=setup") && line.includes("counted=bad"))).toHaveLength(
        7,
      );
    } finally {
      await api.close();
    }
  });

  it("keeps only the current pair of key rows across restarts", async () => {
    const dataDir = join(root, "pg");
    for (let start = 0; start < 3; start++) {
      const api = await startApi({ dataDir, logger: captureLogger(), smtp: null, probes: { enabled: true, ...FAST } });
      try {
        expect((await api.probes?.runOnce())?.enforcement.outcome, `start ${start}`).toBe("good");
      } finally {
        await api.close();
      }
    }
    const db = await openDb({ dataDir });
    try {
      expect(await rows(db, "SELECT 1 FROM api_keys")).toBe(2);
      expect(await rows(db, "SELECT 1 FROM api_keys WHERE revoked_at IS NULL")).toBe(2);
      expect(await rows(db, "SELECT 1 FROM organizations")).toBe(1);
      // The audit chain of the probe Organization is whole: one entry per creation and per publish, none removed.
      expect(await rows(db, "SELECT 1 FROM audit_entries")).toBe(2 + 3);
    } finally {
      await db.close();
    }
  });
});

describe("F2 / D-116: the probe's own traffic feeds no other SLI", () => {
  it("40 cycles on an empty instance leave SLO-02, -03, -05 and -07 at zero with 40 samples each in SLO-06 and SLO-04 and nothing detected; a tenant's requests and Events count as before", async () => {
    const api = await startApi({
      logger: captureLogger(),
      smtp: null,
      ops: { token: TOKEN, webhook: null },
      probes: { enabled: true, ...FAST },
    });
    try {
      for (let i = 0; i < 40; i++) await api.probes?.runOnce();
      const before = totals(await report(api));
      expect(before).toMatchObject({ "SLO-02": 0, "SLO-03": 0, "SLO-05": 0, "SLO-07": 0, "SLO-06": 40, "SLO-04": 40 });
      // 40 refused requests from one address in a few seconds: nothing is detected on a system Organization.
      for (const table of ["incidents", "detections", "alert_deliveries"]) {
        expect(await rows(owned(api), `SELECT 1 FROM ${table}`), table).toBe(0);
      }
      expect(await rows(owned(api), "SELECT 1 FROM events")).toBe(40);

      // A tenant: one write and one read of the Control API, one bundle fetch, one batch of two Events.
      const org = CreateOrganizationResponseSchema.parse(
        await (await fetch(`${api.url}/v1/organizations`, json({ name: "Acme" }))).json(),
      );
      const admin = org.admin_key.key;
      const app = CreateAppResponseSchema.parse(
        await (
          await fetch(`${api.url}/v1/apps`, json({ name: "Shop", environment: "production" }, bearer(admin)))
        ).json(),
      );
      expect((await fetch(`${api.url}/v1/apps`, { headers: bearer(admin) })).status).toBe(200);
      expect((await fetch(`${api.url}/v1/policy-bundle`, { headers: bearer(app.shield_key.key) })).status).toBe(200);
      const events = [shieldEvent(Date.now()), shieldEvent(Date.now() + 1)];
      const ingest = await fetch(`${api.url}/v1/events`, json(batchOf(events), bearer(app.shield_key.key)));
      expect(ingest.status).toBe(202);

      await api.slo.runOnce(); // a fresh aggregate, past the report's read cache
      const after = totals(await report(api));
      expect(after["SLO-02"]).toBe(1);
      expect(after["SLO-03"]).toBe(1);
      expect(after["SLO-04"]).toBe(40 + 2);
      expect(after["SLO-07"]).toBe(2);
      expect(after["SLO-06"]).toBe(40);
    } finally {
      await api.close();
    }
  });
});
