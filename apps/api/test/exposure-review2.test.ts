import { readFileSync } from "node:fs";
import {
  type AdvisoryInput,
  type BuildManifest,
  BuildResponseSchema,
  type Component,
  EXAMPLE_BUILD_MANIFEST,
  type Finding,
  type Incident,
  ListFindingsResponseSchema,
  ListIncidentsResponseSchema,
} from "@antireverse/protocol";
import { componentsDigest, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { openDb } from "../src/db/db.ts";
import { createIncidentQueue, matchInventory, rematchAll } from "../src/exposure/match.ts";
import type { Notifier } from "../src/notify/notifier.ts";
import { FIXTURE_ADVISORIES_FILE, fixtureSource } from "../src/vulns/source.ts";
import { syncAdvisories } from "../src/vulns/sync.ts";
import { bearer, captureLogger, createAppFor, createOrganization, json, makeTestApi, type TestApi } from "./helpers.ts";

// The second independent review of the matching code: M-A, L-A, L-C, L-D and the definer functions, each mirroring
// the reviewer's script (rev/t2, t2b, t8; t3; t7; t8; t6).

const T0 = Date.parse("2026-11-11T09:00:00.000Z");
const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const FIXTURES = JSON.parse(readFileSync(FIXTURE_ADVISORIES_FILE, "utf8")) as AdvisoryInput[];
const c = (name: string, version: string, dev = false): Component => ({ name, version, dev });
const A = "a".repeat(32);

describe("exposure, second review", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const opened: Incident[] = [];
  const notifier: Notifier = {
    incidentOpened: (incident) => void opened.push(incident),
    test: async () => null,
    confirmations: () => {},
    drain: async () => {},
  };
  let admin: string;
  let organizationId: string;

  beforeAll(async () => {
    api = await makeTestApi({ now, notifier });
    const org = await createOrganization(api, "Second review");
    admin = org.admin_key.key;
    organizationId = org.organization.id;
    await syncAdvisories(api.db, fixtureSource(FIXTURES));
  });
  afterAll(async () => {
    await api.close();
  });

  async function newApp(name: string) {
    const created = await createAppFor(api, admin, { name, environment: "production" });
    return { appId: created.app.id, shield: created.shield_key.key };
  }
  async function register(appId: string, components: Component[]) {
    const manifest: BuildManifest = {
      ...EXAMPLE_BUILD_MANIFEST,
      build_id: newId("bld"),
      app_id: appId,
      environment: "production",
      component_count: components.length,
      components_digest: componentsDigest(components),
    };
    const res = await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest, components }, bearer(admin)));
    expect(res.status).toBe(201);
    return { buildId: manifest.build_id, body: BuildResponseSchema.parse(await res.json()) };
  }
  async function findings(query: string): Promise<Finding[]> {
    const res = await api.app.request(`/v1/findings${query}`, { headers: bearer(admin) });
    expect(res.status).toBe(200);
    return ListFindingsResponseSchema.parse(await res.json()).findings;
  }
  async function incidentsOf(appId: string): Promise<Incident[]> {
    await api.flushIncidents();
    const res = await api.app.request("/v1/incidents", { headers: bearer(admin) });
    return ListIncidentsResponseSchema.parse(await res.json()).incidents.filter((i) => i.app_id === appId);
  }
  function post(shield: string, components: Component[], instance?: string) {
    const body = instance === undefined ? { components } : { components, instance_id: instance };
    return Promise.resolve(api.app.request("/v1/inventory", json(body, bearer(shield))));
  }
  async function ignore(id: string, reason: string, untilMs: number) {
    const res = await api.app.request(
      `/v1/findings/${id}/ignore`,
      json({ reason, until: new Date(untilMs).toISOString() }, bearer(admin)),
    );
    expect(res.status).toBe(200);
  }

  describe("M-A: a build Finding moves to the newest Build that carries its identity (rev/t2, t2b, t8)", () => {
    it("keeps one open Finding per identity across 10 identical Builds, with its id and first_seen", async () => {
      clock.ms = T0;
      const { appId } = await newApp("ma");
      const comps = [c("vuln-range", "1.2.3"), c("@fixture/vuln-scoped", "4.0.0"), c("vuln-explicit", "3.0.0")];
      const first = await register(appId, comps);
      const original = await findings(`?build_id=${first.buildId}`);
      let last = first;
      for (let i = 0; i < 9; i++) {
        clock.ms += HOUR;
        last = await register(appId, comps);
        // Each registration still reports its own open matches.
        expect(last.body.findings?.open).toMatchObject({ critical: 1, high: 1, low: 1 });
      }
      const open = await findings(`?app_id=${appId}&status=open`);
      expect(open).toHaveLength(3);
      expect(new Set(open.map((f) => f.build_id))).toEqual(new Set([last.buildId]));
      expect(open.map((f) => f.id).sort()).toEqual(original.map((f) => f.id).sort());
      expect(open.every((f) => f.first_seen === new Date(T0).toISOString())).toBe(true);
      expect(open.every((f) => f.last_seen === new Date(clock.ms).toISOString())).toBe(true);
      expect(await findings(`?build_id=${first.buildId}`)).toEqual([]);
    });

    it("moves an ignored Finding with its ignore, out of the new Build's open counts", async () => {
      clock.ms = T0;
      const { appId } = await newApp("ma-ignored");
      const first = await register(appId, [c("vuln-range", "1.2.3")]);
      const [finding] = await findings(`?build_id=${first.buildId}`);
      if (finding === undefined) throw new Error("No Finding.");
      await ignore(finding.id, "accepted", clock.ms + 30 * DAY);
      clock.ms += HOUR;
      const second = await register(appId, [c("vuln-range", "1.2.3")]);
      expect(second.body.findings?.open.high).toBe(0);
      const moved = await findings(`?build_id=${second.buildId}`);
      expect(moved.map((f) => [f.id, f.status, f.ignore?.reason])).toEqual([[finding.id, "ignored", "accepted"]]);
    });

    it("leaves an older Build only the Findings that ended there, and opens a new one when the version returns (rev/t8)", async () => {
      clock.ms = T0;
      const { appId } = await newApp("ma-life");
      const b1 = await register(appId, [c("vuln-range", "1.2.3")]);
      clock.ms += HOUR;
      const b2 = await register(appId, [c("vuln-range", "1.2.4")]);
      clock.ms += HOUR;
      const b3 = await register(appId, [c("vuln-range", "1.2.3")]);
      const all = await findings(`?app_id=${appId}`);
      expect(all.map((f) => [f.build_id, f.status]).sort()).toEqual(
        [
          [b1.buildId, "fixed"],
          [b3.buildId, "open"],
        ].sort(),
      );
      expect(b2.body.findings?.open.high).toBe(0);
    });

    it("keeps the cap holding: identical Builds add no rows (rev/t2b)", async () => {
      clock.ms = T0;
      const { appId } = await newApp("ma-cap");
      const comps = [c("vuln-range", "1.2.3"), c("@fixture/vuln-scoped", "4.0.0"), c("vuln-explicit", "3.0.0")];
      for (let i = 0; i < 5; i++) {
        clock.ms += HOUR;
        await api.db.tx({ organizationId }, async (q) => {
          await q.query(
            `INSERT INTO builds (organization_id, app_id, build_id, environment, version, profile, manifest, registered_at)
             VALUES ($1, $2, $3, 'production', '1', 'light', '{}', now())`,
            [organizationId, appId, `bld_${String(i).repeat(24)}`],
          );
          await matchInventory(
            q,
            {
              organizationId,
              appId,
              environment: "production",
              source: "build",
              buildId: `bld_${String(i).repeat(24)}`,
              components: comps,
              at: now(),
            },
            { findingsMax: 6 },
          );
        });
      }
      const { rows } = await api.db.tx({ organizationId }, (q) =>
        q.query<{ n: number }>("SELECT count(*)::int AS n FROM findings WHERE app_id = $1", [appId]),
      );
      expect(rows[0]?.n).toBe(3);
    });
  });

  describe("L-A: a withdrawn Finding keeps its ignore (rev/t3)", () => {
    const withdraw = (iso: string) =>
      FIXTURES.map((a) => (a.id === "GHSA-fx01-0001-rang" ? { ...a, modified: iso, withdrawn: iso } : a));
    const restore = (iso: string) =>
      FIXTURES.map((a) => (a.id === "GHSA-fx01-0001-rang" ? { ...a, modified: iso } : a));
    const rematch = () => rematchAll({ db: api.db, notifier, now, logger: captureLogger() });

    it("restores an unexpired ignore when the advisory returns, and opens no Incident", async () => {
      clock.ms = T0 + 100 * DAY;
      const { appId, shield } = await newApp("la");
      await register(appId, [c("vuln-range", "1.2.3")]);
      expect((await post(shield, [c("vuln-range", "1.2.3")], A)).status).toBe(202);
      for (const f of await findings(`?app_id=${appId}`)) await ignore(f.id, "accepted", clock.ms + 60 * DAY);
      await api.flushIncidents();
      // The re-match also reopens other Apps' Findings of this advisory: count this App's alone.
      const ofApp = () => opened.filter((incident) => incident.app_id === appId).length;
      const before = ofApp();

      clock.ms += HOUR;
      await syncAdvisories(api.db, fixtureSource(withdraw("2027-02-20T10:00:00Z")));
      await rematch();
      const withdrawn = await findings(`?app_id=${appId}`);
      expect(withdrawn.map((f) => [f.status, f.ignore])).toEqual([
        ["withdrawn", null],
        ["withdrawn", null],
      ]);

      clock.ms += HOUR;
      await syncAdvisories(api.db, fixtureSource(restore("2027-02-20T11:00:00Z")));
      await rematch();
      const back = await findings(`?app_id=${appId}`);
      expect(back.map((f) => [f.source, f.status, f.ignore?.reason ?? null]).sort()).toEqual([
        ["build", "ignored", "accepted"],
        ["runtime", "ignored", "accepted"],
      ]);
      await api.flushIncidents();
      expect(ofApp()).toBe(before);
    });

    it("drops an ignore that expired while withdrawn: back to open, and it opens or joins an Incident", async () => {
      clock.ms = T0 + 200 * DAY;
      const { appId } = await newApp("la-expired");
      const b = await register(appId, [c("vuln-range", "1.2.3")]);
      const [finding] = await findings(`?build_id=${b.buildId}`);
      await ignore(finding?.id ?? "", "short", clock.ms + DAY);
      await api.flushIncidents();
      const detections = (await incidentsOf(appId))[0]?.detection_count ?? 0;

      clock.ms += HOUR;
      await syncAdvisories(api.db, fixtureSource(withdraw("2027-05-31T10:00:00Z")));
      await rematch();
      clock.ms += 2 * DAY;
      await syncAdvisories(api.db, fixtureSource(restore("2027-05-31T11:00:00Z")));
      await rematch();
      const back = await findings(`?app_id=${appId}`);
      expect(back.map((f) => [f.status, f.ignore])).toEqual([["open", null]]);
      expect((await incidentsOf(appId))[0]?.detection_count).toBe(detections + 1);
    });
  });

  describe("L-C: Incidents and alerts are written after the response (rev/t7)", () => {
    it("answers the registration before any Incident is written, and writes it once the queue runs", async () => {
      const held: (() => Promise<void>)[] = [];
      const db = await openDb();
      const local = await makeTestApi({
        db,
        now,
        notifier,
        exposureIncidents: createIncidentQueue({ db, notifier, schedule: (job) => void held.push(job) }),
      });
      try {
        await syncAdvisories(local.db, fixtureSource(FIXTURES));
        const org = await createOrganization(local, "Queued");
        const app = await createAppFor(local, org.admin_key.key, { name: "q", environment: "production" });
        const comps = [c("vuln-range", "1.2.3")];
        const manifest = {
          ...EXAMPLE_BUILD_MANIFEST,
          build_id: newId("bld"),
          app_id: app.app.id,
          environment: "production" as const,
          component_count: 1,
          components_digest: componentsDigest(comps),
        };
        const res = await local.app.request(
          `/v1/apps/${app.app.id}/builds`,
          json({ manifest, components: comps }, bearer(org.admin_key.key)),
        );
        expect(res.status).toBe(201);
        const list = async () =>
          ListIncidentsResponseSchema.parse(
            await (await local.app.request("/v1/incidents", { headers: bearer(org.admin_key.key) })).json(),
          ).incidents;
        expect(await list()).toEqual([]);
        expect(held).toHaveLength(1);
        for (const job of held.splice(0)) await job();
        expect((await list()).map((i) => i.advisory_id)).toEqual(["GHSA-fx01-0001-rang"]);
      } finally {
        await local.close();
      }
    });

    it("logs a failed Incident write by its kind only, and the request still succeeds", async () => {
      const logger = captureLogger();
      const failing = createIncidentQueue({
        db: { tx: () => Promise.reject(new Error("vuln-range GHSA-fx01-0001-rang secret")) } as never,
        notifier,
        logger,
      });
      failing.enqueue(organizationId, [
        {
          id: newId("fnd"),
          appId: "app_000000000000000000000000",
          environment: "production",
          buildId: null,
          advisoryId: "GHSA-fx01-0001-rang",
          severity: "high",
          at: now(),
        },
      ]);
      await failing.flush();
      expect(logger.lines).toEqual(["exposure incident failed Error"]);
    });
  });

  describe("L-D: the inventory rate limit survives a clock stepping back (rev/t8)", () => {
    it("never answers a retry-after longer than one refill", async () => {
      clock.ms = T0 + 300 * DAY;
      const { shield } = await newApp("ld");
      for (let i = 0; i < 5; i++) expect((await post(shield, [], A)).status).toBe(202);
      expect((await post(shield, [], A)).status).toBe(429);
      clock.ms -= 10 * MINUTE;
      const refused = await post(shield, [], A);
      expect(refused.status).toBe(429);
      expect(Number(refused.headers.get("retry-after"))).toBeLessThanOrEqual(60);
      clock.ms += 10 * MINUTE + MINUTE;
      expect((await post(shield, [], A)).status).toBe(202);
    });
  });

  describe("definer functions are the sync path's only (rev/t6)", () => {
    it("refuses advisory_upsert and exposure_inventory_organizations to the request role", async () => {
      await expect(
        api.db.tx({ organizationId }, (q) =>
          q.query(
            "SELECT advisory_upsert('GHSA-zzzz-zzzz-zzzz', '{}', 's', 'critical', NULL, '[]', '[]', now(), now(), NULL, ARRAY['react'])",
          ),
        ),
      ).rejects.toThrow(/permission denied/);
      await expect(
        api.db.tx("none", (q) => q.query("SELECT * FROM exposure_inventory_organizations()")),
      ).rejects.toThrow(/permission denied/);
    });

    it("still syncs and re-matches through the owner", async () => {
      const counts = await syncAdvisories(api.db, fixtureSource(FIXTURES.slice(0, 1)));
      expect(counts.received).toBe(1);
      const result = await rematchAll({ db: api.db, notifier, now, logger: captureLogger() });
      expect(result.organizations).toBeGreaterThanOrEqual(1);
    });
  });
});
