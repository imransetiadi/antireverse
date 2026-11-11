import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type AdvisoryInput,
  type BuildManifest,
  BuildResponseSchema,
  type Component,
  EXAMPLE_ADVISORY,
  EXAMPLE_BUILD_MANIFEST,
  type Finding,
  type Incident,
  ListFindingsResponseSchema,
  ListIncidentsResponseSchema,
} from "@antireverse/protocol";
import { componentsDigest, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FINDINGS_PER_SCOPE_MAX, matchInventory } from "../src/exposure/match.ts";
import type { Notifier } from "../src/notify/notifier.ts";
import { FIXTURE_ADVISORIES_FILE, fixtureSource, osvZipSource } from "../src/vulns/source.ts";
import { syncAdvisories } from "../src/vulns/sync.ts";
import { ZipError } from "../src/vulns/zip.ts";
import { bearer, createAppFor, createOrganization, expectProblem, json, makeTestApi, type TestApi } from "./helpers.ts";
import { buildZip } from "./zip-builder.ts";

// Plan amendment A7: the independent review's findings M1–M4 and L1, each mirroring the reviewer's reproduction
// script (rev/t1, t2, t3, t4, z2, z3).

const T0 = Date.parse("2026-11-11T09:00:00.000Z");
const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const FIXTURES = JSON.parse(readFileSync(FIXTURE_ADVISORIES_FILE, "utf8")) as AdvisoryInput[];
const c = (name: string, version: string, dev = false): Component => ({ name, version, dev });
const INSTANCE_A = "a".repeat(32);
const INSTANCE_B = "b".repeat(32);

describe("exposure review fixes (A7)", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const opened: Incident[] = [];
  const notifier: Notifier = {
    incidentOpened: (incident) => void opened.push(incident),
    test: async () => null,
    drain: async () => {},
  };
  let admin: string;
  let organizationId: string;

  beforeAll(async () => {
    api = await makeTestApi({ now, notifier });
    const org = await createOrganization(api, "Review");
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

  describe("M1: a new Build carries the ignore of the same identity (rev/t1)", () => {
    it("keeps an ignored Finding ignored in the next Build, out of the open counts", async () => {
      clock.ms = T0;
      const { appId } = await newApp("m1");
      const first = await register(appId, [c("vuln-range", "1.2.3")]);
      expect(first.body.findings?.open.high).toBe(1);
      const [finding] = await findings(`?build_id=${first.buildId}`);
      if (finding === undefined) throw new Error("No Finding.");
      const until = new Date(clock.ms + 30 * DAY).toISOString();
      const ignored = await api.app.request(
        `/v1/findings/${finding.id}/ignore`,
        json({ reason: "accepted risk", until }, bearer(admin)),
      );
      expect(ignored.status).toBe(200);

      clock.ms += HOUR;
      const second = await register(appId, [c("vuln-range", "1.2.3")]);
      expect(second.body.findings?.open).toEqual({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
      const [carried] = await findings(`?build_id=${second.buildId}`);
      expect(carried?.status).toBe("ignored");
      expect(carried?.ignore).toEqual({ reason: "accepted risk", until, by: finding.ignore?.by ?? expect.any(String) });
    });

    it("does not carry an ignore that has expired", async () => {
      clock.ms = T0;
      const { appId } = await newApp("m1-expired");
      const first = await register(appId, [c("vuln-range", "1.2.3")]);
      const [finding] = await findings(`?build_id=${first.buildId}`);
      const until = new Date(clock.ms + DAY).toISOString();
      await api.app.request(`/v1/findings/${finding?.id}/ignore`, json({ reason: "short", until }, bearer(admin)));
      clock.ms += 2 * DAY;
      const second = await register(appId, [c("vuln-range", "1.2.3")]);
      expect(second.body.findings?.open.high).toBe(1);
    });
  });

  describe("M2: Incidents by identity, not per Build (rev/t2)", () => {
    it("opens no new Incident when the next Builds ship the same vulnerable version, even after it was resolved", async () => {
      clock.ms = T0;
      const { appId } = await newApp("m2");
      await register(appId, [c("vuln-range", "1.2.3")]);
      const [incident] = await incidentsOf(appId);
      if (incident === undefined) throw new Error("No Incident.");
      const resolved = await api.app.request(`/v1/incidents/${incident.id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json", ...bearer(admin) },
        body: JSON.stringify({ status: "resolved" }),
      });
      expect(resolved.status).toBe(200);
      for (let i = 0; i < 3; i++) {
        clock.ms += HOUR;
        await register(appId, [c("vuln-range", "1.2.3")]);
      }
      expect((await incidentsOf(appId)).map((i) => i.status)).toEqual(["resolved"]);
    });

    it("counts a version that left the previous Build and came back as newly opened", async () => {
      clock.ms = T0;
      const { appId } = await newApp("m2-back");
      await register(appId, [c("vuln-range", "1.2.3")]);
      clock.ms += HOUR;
      await register(appId, [c("vuln-range", "1.2.4")]);
      clock.ms += HOUR;
      await register(appId, [c("vuln-range", "1.2.3")]);
      const [incident] = await incidentsOf(appId);
      expect(incident?.detection_count).toBe(2);
    });

    it("keeps one inventory per Shield instance: a Finding stays open while any live instance has the version", async () => {
      clock.ms = T0;
      const { appId, shield } = await newApp("m2-runtime");
      const statuses = async () => (await findings(`?app_id=${appId}&source=runtime`)).map((f) => f.status);
      expect((await post(shield, [c("vuln-range", "1.2.3")], INSTANCE_A)).status).toBe(202);
      expect(await statuses()).toEqual(["open"]);
      clock.ms += MINUTE;
      expect((await post(shield, [c("vuln-range", "1.2.5")], INSTANCE_B)).status).toBe(202);
      expect(await statuses()).toEqual(["open"]);
      // Instance A restarts with a new id and the same packages: still open, still one Incident, one Detection.
      clock.ms += MINUTE;
      expect((await post(shield, [c("vuln-range", "1.2.3")], "c".repeat(32))).status).toBe(202);
      expect(await statuses()).toEqual(["open"]);
      const incidents = await incidentsOf(appId);
      expect(incidents).toHaveLength(1);
      expect(incidents[0]?.detection_count).toBe(1);
    });

    it("drops an instance after 24 hours without a POST: then its versions are fixed", async () => {
      clock.ms = T0;
      const { appId, shield } = await newApp("m2-expiry");
      await post(shield, [c("vuln-range", "1.2.3")], INSTANCE_A);
      clock.ms += 25 * HOUR;
      await post(shield, [c("vuln-range", "1.2.5")], INSTANCE_B);
      expect((await findings(`?app_id=${appId}&source=runtime`)).map((f) => f.status)).toEqual(["fixed"]);
    });

    it("treats Shields without an instance id as one shared legacy instance", async () => {
      clock.ms = T0;
      const { appId, shield } = await newApp("m2-legacy");
      await post(shield, [c("vuln-range", "1.2.3")]);
      clock.ms += MINUTE;
      await post(shield, [c("vuln-range", "1.2.5")]);
      expect((await findings(`?app_id=${appId}&source=runtime`)).map((f) => f.status)).toEqual(["fixed"]);
    });
  });

  describe("M3: a sync stores all or nothing (rev/z3)", () => {
    it("stores no advisory from an archive with one bad entry after 600 good ones", async () => {
      const db = (await makeTestApi()).db;
      const dir = mkdtempSync(join(tmpdir(), "ar-partial-"));
      try {
        const advisory = (i: number) =>
          JSON.stringify({
            ...EXAMPLE_ADVISORY,
            id: `GHSA-${String(i).padStart(4, "0")}-bbbb-cccc`,
            affected: [
              {
                package: { ecosystem: "npm", name: `p${i}` },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
              },
            ],
          });
        const entries = Array.from({ length: 600 }, (_, i) => ({ name: `a${i}.json`, data: advisory(i) }));
        entries.push({ name: "bad.json", data: advisory(9999), crc: 1 } as (typeof entries)[number]);
        const path = join(dir, "partial.zip");
        writeFileSync(path, buildZip(entries));
        await expect(syncAdvisories(db, osvZipSource(path))).rejects.toThrow(ZipError);
        const { rows } = await db.tx("none", (q) =>
          q.query<{ n: number }>("SELECT count(*)::int AS n FROM advisories"),
        );
        expect(rows[0]?.n).toBe(0);
      } finally {
        rmSync(dir, { recursive: true, force: true });
        await db.close();
      }
    });
  });

  describe("M4: cost and growth (rev/t3, rev/t4)", () => {
    it("allows a burst of 5 inventories per Shield key, then 1 per minute, answering 429 with retry-after", async () => {
      clock.ms = T0;
      const { shield } = await newApp("m4-rate");
      for (let i = 0; i < 5; i++) expect((await post(shield, [], INSTANCE_A)).status).toBe(202);
      const refused = await post(shield, [], INSTANCE_A);
      const problem = await expectProblem(refused, 429);
      expect(problem.type).toBe("https://antireverse.dev/problems/too-many-requests");
      expect(Number(refused.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
      expect(Number(refused.headers.get("retry-after"))).toBeLessThanOrEqual(60);
      clock.ms += MINUTE;
      expect((await post(shield, [], INSTANCE_A)).status).toBe(202);
      expect((await post(shield, [], INSTANCE_A)).status).toBe(429);
    });

    it("deletes fixed and withdrawn runtime Findings 30 days after they closed", async () => {
      clock.ms = T0;
      const { appId, shield } = await newApp("m4-retention");
      await post(shield, [c("vuln-range", "1.2.3")], INSTANCE_A);
      clock.ms += MINUTE;
      await post(shield, [c("vuln-range", "1.2.5")], INSTANCE_A);
      expect((await findings(`?app_id=${appId}`)).map((f) => f.status)).toEqual(["fixed"]);
      clock.ms += 31 * DAY;
      await post(shield, [c("vuln-range", "1.2.5")], INSTANCE_A);
      expect(await findings(`?app_id=${appId}`)).toEqual([]);
    });

    it("keeps at most the cap of Findings per App Environment, dropping the oldest fixed first (rev/t4)", async () => {
      expect(FINDINGS_PER_SCOPE_MAX).toBe(20_000);
      clock.ms = T0;
      const { appId } = await newApp("m4-cap");
      const match = (versions: string[], at: number) =>
        api.db.tx({ organizationId }, (q) =>
          matchInventory(
            q,
            {
              organizationId,
              appId,
              environment: "production",
              source: "runtime",
              buildId: null,
              components: versions.map((v) => c("vuln-unknown", v)),
              at: new Date(at),
            },
            { findingsMax: 5 },
          ),
        );
      await match(["1.0.0", "1.0.1", "1.0.2"], T0);
      await match(["1.1.0", "1.1.1", "1.1.2"], T0 + 1_000);
      await match(["1.2.0", "1.2.1"], T0 + 2_000);
      const { rows } = await api.db.tx({ organizationId }, (q) =>
        q.query<{ version: string; status: string }>(
          "SELECT version, status FROM findings WHERE app_id = $1 ORDER BY version",
          [appId],
        ),
      );
      // 2 open (1.2.x) + the 3 newest fixed ones; the 1.0.x fixed rows, closed first, went first.
      expect(rows).toEqual([
        { version: "1.1.0", status: "fixed" },
        { version: "1.1.1", status: "fixed" },
        { version: "1.1.2", status: "fixed" },
        { version: "1.2.0", status: "open" },
        { version: "1.2.1", status: "open" },
      ]);
    });
  });
});
