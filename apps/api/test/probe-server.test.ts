import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AUDIT_REASON_HEADER,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  PROBE_PATH_PREFIX,
  SignedBundleSchema,
  SloReportSchema,
} from "@antireverse/protocol";
import { afterAll, describe, expect, it } from "vitest";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { type RunningApi, startApi } from "../src/server.ts";
import { readSystemOrganization } from "../src/stores/system-organizations.ts";
import { bearer, captureLogger, json } from "./helpers.ts";

// Slice 18g: the probes inside a running API, over its real HTTP routes and a real Shield. The Shield's poll and flush
// timers are shortened (test options only; the environment cannot set them), so a real cycle takes well under a
// second; the timer of the cycles is pushed out of reach and the test asks for each cycle itself.

const TOKEN = "ops-token-".padEnd(44, "P");
const FAST = { startDelayMs: 3_600_000, shield: { policyPollIntervalMs: 100, flushIntervalMs: 50 } };
const KEY = /\b(aro_|ark_(prod|stg|dev)_)[A-Za-z0-9_-]{43}\b/;

/** The API's database with the owner's side: `startApi` opens an `OwnedDb` and hands it out as `Db`. */
const owned = (api: RunningApi): OwnedDb => api.db as OwnedDb;

async function report(api: RunningApi) {
  const res = await fetch(`${api.url}/v1/ops/slo`, { headers: bearer(TOKEN) });
  expect(res.status).toBe(200);
  return SloReportSchema.parse(await res.json());
}

/** A customer: an Organization, an App and its keys, made over HTTP. */
async function customer(api: RunningApi) {
  const org = CreateOrganizationResponseSchema.parse(
    await (await fetch(`${api.url}/v1/organizations`, json({ name: "Acme" }))).json(),
  );
  const admin = org.admin_key.key;
  const app = CreateAppResponseSchema.parse(
    await (await fetch(`${api.url}/v1/apps`, json({ name: "Shop", environment: "production" }, bearer(admin)))).json(),
  );
  return { organizationId: org.organization.id, appId: app.app.id, admin, shield: app.shield_key.key };
}

describe("synthetic probes in a running API", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-probe-"));
  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("is off by default: no prober, a null probe status and SLO-06 not measured, with the switch named", async () => {
    const api = await startApi({ logger: captureLogger(), smtp: null, ops: { token: TOKEN, webhook: null } });
    try {
      expect(api.probes).toBeNull();
      const r = await report(api);
      expect(r.probes).toBeNull();
      const slo06 = r.slos.find((s) => s.id === "SLO-06");
      expect(slo06).toMatchObject({ measured: false, total: 0, latency: [], alerts: [] });
      expect(slo06?.not_measured_reason).toContain("AR_PROBES=1");
      const count = await owned(api).owner(async (q) => (await q.query("SELECT 1 FROM organizations")).rows.length);
      expect(count).toBe(0);
    } finally {
      await api.close();
    }
  });

  it("refuses to start with an AR_PROBES that is neither on nor off", async () => {
    const before = process.env.AR_PROBES;
    process.env.AR_PROBES = "yes";
    try {
      await expect(startApi({ logger: captureLogger(), smtp: null })).rejects.toThrow(
        /^AR_PROBES must be 1 \(on\) or 0 \(off\)\.$/,
      );
    } finally {
      if (before === undefined) delete process.env.AR_PROBES;
      else process.env.AR_PROBES = before;
    }
  });

  it("runs a real cycle: the marked block is enforced by the probe's Shield and its Event becomes readable; SLO-06 and SLO-04 get the samples; no tenant sees any of it", async () => {
    const logger = captureLogger();
    const api = await startApi({
      logger,
      smtp: null,
      ops: { token: TOKEN, webhook: null },
      probes: { enabled: true, ...FAST },
    });
    try {
      const acme = await customer(api);
      const usage = async () => (await fetch(`${api.url}/v1/usage`, { headers: bearer(acme.admin) })).text();
      const usageBefore = await usage();

      expect(api.probes).not.toBeNull();
      const run = await api.probes?.runOnce();
      expect(run?.enforcement.outcome).toBe("good");
      expect(run?.freshness.outcome).toBe("good");
      // Monotonic and real: more than nothing, and far inside the bounds with the shortened timers.
      expect(run?.enforcement.ms).toBeGreaterThan(0);
      expect(run?.enforcement.ms).toBeLessThan(10_000);
      expect(run?.freshness.ms).toBeGreaterThanOrEqual(0);
      expect(run?.freshness.ms).toBeLessThan(5_000);

      const r = await report(api);
      expect(r.probes).toMatchObject({ interval_s: 60, runs: 1, failures: 0, consecutive_failures: 0 });
      expect(r.probes?.enforcement).toEqual(run?.enforcement);
      const slo06 = r.slos.find((s) => s.id === "SLO-06");
      expect(slo06).toMatchObject({ measured: true, not_measured_reason: null, good: 1, total: 1, attainment: 1 });
      expect(slo06?.latency.map((row) => [row.percentile, row.target_ms, row.met])).toEqual([
        [95, 30_000, true],
        [99, 60_000, true],
      ]);
      expect(slo06?.alerts.map((alert) => alert.state)).toEqual(["ok", "ok", "ok"]);
      // SLO-04: the probe's end-to-end sample only; its Event is not counted a second time in process (D-116).
      expect(r.slos.find((s) => s.id === "SLO-04")).toMatchObject({ good: 1, total: 1 });
      const metrics = await (await fetch(`${api.url}/metrics`, { headers: bearer(TOKEN) })).text();
      expect(metrics).toContain('airverse_slo_good{slo="SLO-06"} 1\n');

      // The probe's rows are in its registered Organization, and nowhere else.
      const probe = await owned(api).owner((q) => readSystemOrganization(q, "probe"));
      expect(probe).not.toBeNull();
      const owners = async (table: string) =>
        owned(api).owner(async (q) =>
          (await q.query<{ organization_id: string }>(`SELECT DISTINCT organization_id FROM ${table}`)).rows.map(
            (row) => row.organization_id,
          ),
        );
      expect(await owners("events")).toEqual([probe?.organizationId]);
      expect(await owners("policy_versions")).toEqual([probe?.organizationId]);
      const routes = await owned(api).owner(async (q) =>
        (await q.query<{ route: string }>("SELECT payload->'request'->>'route' AS route FROM events")).rows.map(
          (row) => row.route,
        ),
      );
      expect(routes).toHaveLength(1);
      expect(routes[0]?.startsWith(PROBE_PATH_PREFIX)).toBe(true);

      // The customer: no Event, the same usage, and a bundle without the marked Rule.
      const events = await (
        await fetch(`${api.url}/v1/apps/${acme.appId}/events`, { headers: bearer(acme.admin) })
      ).json();
      expect(events).toEqual({ events: [] });
      expect(await usage()).toBe(usageBefore);
      const bundle = await fetch(`${api.url}/v1/policy-bundle`, { headers: bearer(acme.shield) });
      const signed = SignedBundleSchema.parse(await bundle.json());
      expect(JSON.stringify(signed)).not.toContain("airverse-probe");
      // And the probe's keys do not open the customer's App, nor the customer's the probe's.
      const foreign = await fetch(`${api.url}/v1/apps/${probe?.appId}/events`, { headers: bearer(acme.admin) });
      expect(foreign.status).toBe(404);

      // Nothing of the probe's Organization in the report, and no key in any log line.
      expect(JSON.stringify(r)).not.toContain(probe?.organizationId);
      expect(logger.lines.join("\n")).not.toMatch(KEY);
      // The request log names the Organization of every request, the probe's like a tenant's; the probe's own lines
      // name nothing.
      const own = logger.lines.filter((line) => !line.startsWith("request "));
      expect(own.join("\n")).not.toContain(probe?.organizationId);
      expect(own.join("\n")).not.toContain(probe?.appId);
      expect(logger.lines.some((line) => line.startsWith("probes on"))).toBe(true);
      expect(logger.lines.filter((line) => line.startsWith("probe failed"))).toEqual([]);
    } finally {
      await api.close();
    }
  });

  it("keeps one probe Organization across restarts, and a block published by a tenant on the probe's path does not disturb it", async () => {
    const dataDir = join(root, "pg");
    for (let start = 0; start < 2; start++) {
      const api = await startApi({ dataDir, logger: captureLogger(), smtp: null, probes: { enabled: true, ...FAST } });
      try {
        if (start === 1) {
          // A tenant may publish whatever Rule it likes, the probe's prefix included: it reaches its own Shields only.
          const acme = await customer(api);
          const res = await fetch(`${api.url}/v1/apps/${acme.appId}/policies/production`, {
            method: "PUT",
            headers: { ...bearer(acme.admin), "content-type": "application/json", [AUDIT_REASON_HEADER]: "test" },
            body: JSON.stringify({
              rules: [{ name: "x", path: "/airverse-probe/**", action: "block", mode: "enforce" }],
            }),
          });
          expect(res.status).toBe(201);
        }
        const run = await api.probes?.runOnce();
        expect(run?.enforcement.outcome, `start ${start}`).toBe("good");
        expect(run?.freshness.outcome, `start ${start}`).toBe("good");
      } finally {
        await api.close();
      }
    }
    const db = await openDb({ dataDir });
    try {
      const counts = await db.owner(async (q) => ({
        registered: (await q.query("SELECT 1 FROM system_organizations")).rows.length,
        named: (await q.query("SELECT 1 FROM organizations WHERE name = 'Airverse synthetic probes'")).rows.length,
        activeKeys: (
          await q.query(
            "SELECT 1 FROM api_keys k JOIN system_organizations s ON s.org_id = k.organization_id WHERE k.revoked_at IS NULL",
          )
        ).rows.length,
        revokedKeys: (
          await q.query(
            "SELECT 1 FROM api_keys k JOIN system_organizations s ON s.org_id = k.organization_id WHERE k.revoked_at IS NOT NULL",
          )
        ).rows.length,
        samples: (await q.query<{ n: string }>("SELECT sum(total) AS n FROM slo_minutes WHERE slo = 'SLO-06'")).rows[0]
          ?.n,
      }));
      // The first start's keys are gone, not kept as revoked rows (review F1).
      expect(counts).toEqual({ registered: 1, named: 1, activeKeys: 2, revokedKeys: 0, samples: "2" });
    } finally {
      await db.close();
    }
  });

  it("closes while a cycle is in flight: the cycle is cut without a sample and the API closes", async () => {
    const api = await startApi({ logger: captureLogger(), smtp: null, probes: { enabled: true, ...FAST } });
    const run = api.probes?.runOnce();
    await api.close();
    expect(await run).toBeNull();
    expect(api.probes?.status()).toMatchObject({ runs: 0, failures: 0 });
  });
});
