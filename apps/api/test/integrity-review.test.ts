import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import {
  type BuildManifest,
  BuildResponseSchema,
  ChallengeResponseSchema,
  type Environment,
  EXAMPLE_BUILD_MANIFEST,
  INTEGRITY_LIMITS,
  type Incident,
  ListIncidentsResponseSchema,
} from "@antireverse/protocol";
import { jwkThumbprint, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Db, type OwnedDb, openDb } from "../src/db/db.ts";
import {
  createIntegrityRecorder,
  type IntegrityRecorder,
  type IntegrityRecorderDeps,
} from "../src/detect/integrity.ts";
import {
  bearer,
  type CapturedLogger,
  captureLogger,
  createAppFor,
  createOrganization,
  json,
  makeTestApi,
  type TestApi,
  withReason,
} from "./helpers.ts";

// Slice 21a, the independent review's findings (H1, M1–M3, L1, L3): what a forged or merely busy stream of
// integrity reports may cost the database and other tenants, and what the caps leave visible.

const T0 = Date.parse("2026-11-14T12:00:00.000Z");
const MINUTE = 60_000;
const HOUR = 3_600_000;
const ORIGIN = "https://shop.example";
const PEER = "203.0.113.77";
const PEER_HEADER = "x-test-peer";

const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const b64 = (hex: string) => Buffer.from(hex, "hex").toString("base64url");
const foreign = (label: string) => b64(sha(`tampered:${label}`));

interface Setup {
  admin: string;
  organizationId: string;
  appId: string;
  buildId: string;
  environment: Environment;
  /** Registered SHA-256 (hex) of each marker file, in the marker's order. */
  hashes: string[];
}

interface ReportFile {
  i: number;
  h: string;
}

describe("tamper detection: review findings", () => {
  let db: OwnedDb;
  let api: TestApi;
  let log: CapturedLogger;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const opened: Incident[] = [];
  /** What the recorders asked of the database. */
  const seen = { txs: 0, lookups: 0, scans: 0 };
  let versions = 0;

  function counting(inner: Db): Db {
    return {
      tx: (scope, fn) => {
        seen.txs++;
        return inner.tx(scope, (q) =>
          fn({
            query: (sql, params) => {
              if (typeof sql === "string" && sql.includes("integrity_lookup_build")) seen.lookups++;
              // Anything that reads Manifests: the stale check's source.
              if (typeof sql === "string" && sql.includes("manifest")) seen.scans++;
              return q.query(sql, params);
            },
          }),
        );
      },
      close: () => inner.close(),
    };
  }

  /** Every recorder made here: the API's registration hook reaches all of them, as it reaches the one of a process. */
  const made: IntegrityRecorder[] = [];

  function make(overrides: Partial<IntegrityRecorderDeps> = {}): IntegrityRecorder {
    const recorder = createIntegrityRecorder({
      db: counting(db),
      notifier: { incidentOpened: (incident) => void opened.push(incident) },
      now,
      logger: log,
      ...overrides,
    });
    made.push(recorder);
    return recorder;
  }

  function manifestFor(appId: string, environment: Environment, files: number, artifacts = files): BuildManifest {
    const buildId = newId("bld");
    versions++;
    const paths = Array.from({ length: artifacts }, (_, n) => `assets/chunk-${String(n).padStart(3, "0")}.js`);
    return {
      ...EXAMPLE_BUILD_MANIFEST,
      build_id: buildId,
      app_id: appId,
      environment,
      version: `21.1.${versions}`,
      artifacts: paths.map((path) => ({ path, sha256: sha(`${buildId}:${path}`), bytes: 1024 })),
      integrity: { files: paths.slice(0, files) },
    };
  }

  async function register(admin: string, manifest: BuildManifest): Promise<void> {
    const res = await api.app.request(`/v1/apps/${manifest.app_id}/builds`, json({ manifest }, bearer(admin)));
    expect(res.status, await res.clone().text()).toBe(201);
  }

  async function setUp(
    options: { from?: Setup; sameApp?: boolean; files?: number; artifacts?: number } = {},
  ): Promise<Setup> {
    let { admin, organizationId } = options.from ?? {};
    if (admin === undefined || organizationId === undefined) {
      const org = await createOrganization(api, `Org ${randomBytes(3).toString("hex")}`);
      admin = org.admin_key.key;
      organizationId = org.organization.id;
    }
    const appId =
      options.from !== undefined && options.sameApp ? options.from.appId : (await createAppFor(api, admin)).app.id;
    clock.ms += MINUTE;
    const manifest = manifestFor(appId, "production", options.files ?? 3, options.artifacts);
    await register(admin, manifest);
    return {
      admin,
      organizationId,
      appId,
      buildId: manifest.build_id,
      environment: "production",
      hashes: manifest.artifacts.slice(0, options.files ?? 3).map((artifact) => artifact.sha256),
    };
  }

  const matching = (s: Setup): ReportFile[] => s.hashes.map((hash, i) => ({ i, h: b64(hash) }));

  function fire(on: IntegrityRecorder, s: Pick<Setup, "appId" | "buildId">, files: ReportFile[], peer = PEER): void {
    on.report({ appId: s.appId, report: { build: s.buildId, files, skipped: 0 }, originHeader: ORIGIN, address: peer });
  }

  async function send(on: IntegrityRecorder, s: Pick<Setup, "appId" | "buildId">, files: ReportFile[], peer = PEER) {
    fire(on, s, files, peer);
    await on.flush();
  }

  async function tampered(admin: string): Promise<Incident[]> {
    const res = await api.app.request("/v1/incidents", { headers: bearer(admin) });
    expect(res.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await res.json()).incidents.filter((i) => i.rule === "tampered-build");
  }

  const detectionCount = async (admin: string) =>
    (await tampered(admin)).reduce((total, incident) => total + incident.detection_count, 0);

  beforeAll(async () => {
    db = await openDb();
    log = captureLogger();
    const first = make();
    api = await makeTestApi({
      db,
      now,
      integrity: {
        ...first,
        buildRegistered: (...registered) => {
          for (const recorder of made) recorder.buildRegistered(...registered);
        },
      },
      clientAddress: (c) => c.req.header(PEER_HEADER),
    });
  });
  afterAll(async () => {
    await api.close();
  });

  describe("H1: a forged stream costs the database nothing once the caps are spent", () => {
    it("F2: after the hourly cap, 300 distinct mismatches start no transaction at all", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const recorder = make();
      await send(recorder, s, matching(s));
      for (let n = 0; n < INTEGRITY_LIMITS.newHashesPerHour + 2; n++)
        await send(recorder, s, [{ i: 0, h: foreign(`f2-${n}`) }]);
      expect(await detectionCount(s.admin)).toBe(INTEGRITY_LIMITS.newHashesPerHour);
      const before = { ...seen };
      for (let n = 0; n < 300; n++)
        fire(recorder, s, [{ i: n % 3, h: foreign(`f2-flood-${n}`) }], `198.51.${n % 250}.9`);
      await recorder.flush();
      expect(seen.scans - before.scans).toBe(0);
      expect(seen.txs - before.txs).toBe(0);
      expect(await detectionCount(s.admin)).toBe(INTEGRITY_LIMITS.newHashesPerHour);
    });

    it("the stale check reads no Manifest per report: the recent Builds' hashes are loaded once per App Environment", async () => {
      clock.ms += 2 * HOUR;
      const older = await setUp();
      const newer = await setUp({ from: older, sameApp: true });
      const recorder = make();
      await send(recorder, newer, matching(newer));
      const before = seen.scans;
      // Ten pages of the new deploy still get the old deploy's file: stale, and one load answers all of them.
      for (let n = 0; n < 10; n++)
        await send(recorder, newer, [{ i: 1, h: b64(older.hashes[1] ?? "") }], `198.51.${n}.9`);
      expect(await tampered(newer.admin)).toEqual([]);
      expect(seen.scans - before).toBe(1);
      expect(recorder.dropped().stale).toBe(10);
    });

    it("coalesces the load: concurrent reports of one App Environment wait for one load, and a registration refreshes it", async () => {
      clock.ms += 2 * HOUR;
      const older = await setUp();
      const newer = await setUp({ from: older, sameApp: true });
      const recorder = make();
      await send(recorder, newer, matching(newer));
      const before = seen.scans;
      for (let n = 0; n < 8; n++) fire(recorder, newer, [{ i: n % 3, h: foreign(`coalesce-${n}`) }], `198.51.${n}.9`);
      await recorder.flush();
      expect(seen.scans - before).toBe(1);
      expect(await detectionCount(newer.admin)).toBe(8);
      // A Build registered just now is seen by the very next report: the registration refreshes the index.
      const next = manifestFor(newer.appId, "production", 3);
      await register(newer.admin, next);
      await send(recorder, newer, [{ i: 2, h: b64(next.artifacts[2]?.sha256 ?? "") }]);
      expect(await detectionCount(newer.admin)).toBe(8);
      expect(seen.scans - before).toBe(2);
    });

    it("F7: an unrelated transaction behind 100 in-flight 32-hash reports waits less than 250 ms (30 Builds of 200 artifacts)", async () => {
      clock.ms += 2 * HOUR;
      const first = await setUp({ files: 32, artifacts: 200 });
      for (let n = 0; n < 28; n++) await register(first.admin, manifestFor(first.appId, "production", 32, 200));
      const s = await setUp({ from: first, sameApp: true, files: 32, artifacts: 200 });
      const recorder = make();
      await send(recorder, s, matching(s));
      for (let n = 0; n < 100; n++) {
        fire(
          recorder,
          s,
          Array.from({ length: 32 }, (_, i) => ({ i, h: foreign(`f7-${n}-${i}`) })),
          `198.51.${n}.9`,
        );
      }
      const started = performance.now();
      await db.tx("none", (q) => q.query("SELECT 1"));
      const waited = performance.now() - started;
      await recorder.flush();
      expect(waited).toBeLessThan(250);
      expect(await detectionCount(s.admin)).toBe(INTEGRITY_LIMITS.newHashesPerHour);
    });
  });

  describe("M1: the caps never blind a Build for good, and say when they hide something", () => {
    it("has the documented numbers: 20 new pairs an hour and 50 a day per Build, no lifetime cap", () => {
      expect(INTEGRITY_LIMITS).toMatchObject({ newHashesPerHour: 20, hashesPerDay: 50 });
      expect(INTEGRITY_LIMITS).not.toHaveProperty("hashesPerBuild");
    });

    it("F1: 50 forged pairs over hours, the Incident resolved; 24 hours later a real mismatch opens a new Incident", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const recorder = make();
      await send(recorder, s, matching(s));
      for (let hour = 0; hour < 3; hour++) {
        for (let n = 0; n < 20; n++) await send(recorder, s, [{ i: n % 3, h: foreign(`f1-${hour}-${n}`) }]);
        clock.ms += HOUR;
      }
      const [incident] = await tampered(s.admin);
      expect(incident).toMatchObject({ detection_count: 50, detections_capped: true });
      expect(recorder.dropped()["hash-cap"]).toBe(10);
      // Within the day nothing new is recorded for the Build, from this recorder or a restarted one.
      const restarted = make();
      await send(restarted, s, [{ i: 0, h: foreign("f1-same-day") }]);
      expect(await detectionCount(s.admin)).toBe(50);
      expect(restarted.dropped()["hash-cap"]).toBe(1);

      const patch = await api.app.request(`/v1/incidents/${incident?.id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json", ...withReason(bearer(s.admin)) },
        body: JSON.stringify({ status: "resolved" }),
      });
      expect(patch.status, await patch.clone().text()).toBe(200);
      clock.ms += 24 * HOUR;
      const before = opened.length;
      await send(recorder, s, [{ i: 1, h: foreign("f1-real") }]);
      const incidents = await tampered(s.admin);
      expect(incidents.map((i) => i.status).sort()).toEqual(["open", "resolved"]);
      expect(incidents.find((i) => i.status === "open")).toMatchObject({
        build_id: s.buildId,
        detection_count: 1,
        detections_capped: false,
        observed_sha256: sha("tampered:f1-real"),
      });
      expect(opened.slice(before)).toHaveLength(1);
    });

    it("marks an open Incident when the hourly cap hides distinct hashes, and not before", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const recorder = make();
      await send(recorder, s, matching(s));
      for (let n = 0; n < 20; n++) await send(recorder, s, [{ i: 0, h: foreign(`mark-${n}`) }]);
      expect((await tampered(s.admin))[0]).toMatchObject({ detection_count: 20, detections_capped: false });
      await send(recorder, s, [{ i: 0, h: foreign("mark-over") }]);
      expect((await tampered(s.admin))[0]).toMatchObject({ detection_count: 20, detections_capped: true });
      // A repeat is not a hidden hash.
      const other = await setUp();
      await send(recorder, other, matching(other));
      for (let n = 0; n < 3; n++) await send(recorder, other, [{ i: 0, h: foreign("same") }]);
      expect((await tampered(other.admin))[0]).toMatchObject({ detection_count: 1, detections_capped: false });
    });

    it("one Build's forgery does not silence the other Builds of its App Environment", async () => {
      clock.ms += 2 * HOUR;
      const forged = await setUp();
      const honest = await setUp({ from: forged, sameApp: true });
      const recorder = make();
      for (const s of [forged, honest]) await send(recorder, s, matching(s));
      for (let n = 0; n < 25; n++) await send(recorder, forged, [{ i: 0, h: foreign(`silence-${n}`) }]);
      await send(recorder, honest, [{ i: 0, h: foreign("honest") }]);
      const incidents = await tampered(forged.admin);
      expect(incidents.find((i) => i.build_id === honest.buildId)).toMatchObject({ detection_count: 1 });
      expect(incidents.find((i) => i.build_id === forged.buildId)).toMatchObject({ detection_count: 20 });
    });
  });

  describe("M2: matching reports are free", () => {
    it("F8: 700 matching reports of an armed Build in an hour do not stop its mismatch from being recorded", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const recorder = make();
      await send(recorder, s, matching(s));
      for (let n = 0; n < 700; n++) fire(recorder, s, matching(s), `198.51.${n % 250}.9`);
      await recorder.flush();
      await send(recorder, s, [{ i: 0, h: foreign("f8") }]);
      expect(await detectionCount(s.admin)).toBe(1);
      expect(recorder.dropped()["report-limit"]).toBe(0);
    });

    it("still caps the reports that carry a mismatch that is neither stale nor a repeat at 600 per Build per hour", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const recorder = make();
      await send(recorder, s, matching(s));
      for (let n = 0; n < 600; n++) fire(recorder, s, [{ i: 0, h: foreign(`cap-${n}`) }], `198.51.${n % 250}.9`);
      await recorder.flush();
      expect(await detectionCount(s.admin)).toBe(INTEGRITY_LIMITS.newHashesPerHour);
      expect(recorder.dropped()).toMatchObject({ "hash-limit": 580, "report-limit": 0 });
      await send(recorder, s, [{ i: 1, h: foreign("over") }]);
      expect(recorder.dropped()["report-limit"]).toBe(1);
    });
  });

  describe("M3: lookups are coalesced, a known Build is never dropped for a refresh, and one App cannot starve the others", () => {
    it("coalesces concurrent lookups of one Build", async () => {
      const s = await setUp();
      const recorder = make();
      const before = seen.lookups;
      for (let n = 0; n < 10; n++) fire(recorder, s, matching(s), `198.51.${n}.9`);
      await recorder.flush();
      expect(seen.lookups - before).toBe(1);
    });

    it("F3: another Organization's genuine mismatch is recorded during a 240-report unknown-Build flood", async () => {
      clock.ms += 2 * HOUR;
      const victim = await setUp();
      await send(make(), victim, matching(victim));
      const attacked = await setUp();
      const recorder = make();
      for (let n = 0; n < 240; n++) {
        fire(
          recorder,
          { appId: attacked.appId, buildId: newId("bld") },
          [{ i: 0, h: foreign("x") }],
          `198.${18 + (n % 2)}.${n % 250}.9`,
        );
      }
      fire(recorder, victim, [{ i: 0, h: foreign("f3") }]);
      await recorder.flush();
      expect(await detectionCount(victim.admin)).toBe(1);
      // The flood itself was held to its App's share of the lookups.
      expect(recorder.dropped()["app-limit"]).toBeGreaterThan(200);
    });

    it("serves a known Build from its expired cache entry while it refreshes, even with no lookup budget left", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const recorder = make();
      await send(recorder, s, matching(s));
      clock.ms += 11 * MINUTE;
      // The reporter's prefix has spent its lookups of this minute on unknown Builds.
      for (let n = 0; n < 80; n++)
        fire(recorder, { appId: s.appId, buildId: newId("bld") }, [{ i: 0, h: foreign("x") }]);
      await recorder.flush();
      await send(recorder, s, [{ i: 0, h: foreign("stale-while-refresh") }]);
      expect(await detectionCount(s.admin)).toBe(1);
    });
  });

  describe("L1: a Build armed during a burst stays armed in memory", () => {
    it("F9: a match and a mismatch arriving together on an uncached Build: the Build is armed and its mismatches count", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const recorder = make();
      fire(recorder, s, matching(s));
      fire(recorder, s, [{ i: 0, h: foreign("f9-with") }], "198.51.100.9");
      await recorder.flush();
      await send(recorder, s, [{ i: 1, h: foreign("f9-after") }]);
      const [incident] = await tampered(s.admin);
      expect(incident?.detection_count).toBe(2);
      expect(recorder.dropped().unarmed).toBe(0);
    });
  });

  describe("L3: one log line per report", () => {
    it("F5: a report with 32 mismatches writes one line, with the counts per reason", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp({ files: 32 });
      const recorder = make();
      await send(recorder, s, matching(s));
      const before = log.lines.length;
      await send(
        recorder,
        s,
        Array.from({ length: 32 }, (_, i) => ({ i, h: foreign(`f5-${i}`) })),
      );
      const lines = log.lines.slice(before);
      expect(lines).toHaveLength(1);
      expect(lines[0]).toMatch(
        /^integrity report organization=org_[0-9a-f]{24} build=bld_[0-9a-f]{24} recorded=20 incident=inc_[0-9a-f]{24} dropped=hash-limit:12$/,
      );
      // The repeat of the same report: one line again, nothing recorded.
      await send(
        recorder,
        s,
        Array.from({ length: 32 }, (_, i) => ({ i, h: foreign(`f5-${i}`) })),
      );
      expect(log.lines.slice(before + 1)).toEqual([
        `integrity report organization=${s.organizationId} build=${s.buildId} recorded=0 dropped=repeat:20,hash-limit:12`,
      ]);
    });
  });

  describe("second review", () => {
    const DAY = 24 * HOUR;

    async function armedAt(buildId: string): Promise<Date | null> {
      return db.owner(async (q) => {
        const { rows } = await q.query<{ at: Date | null }>(
          "SELECT integrity_first_match_at AS at FROM builds WHERE build_id = $1",
          [buildId],
        );
        return rows[0]?.at ?? null;
      });
    }

    const detectionsOf = async (s: Setup) =>
      (await tampered(s.admin)).filter((i) => i.build_id === s.buildId).reduce((n, i) => n + i.detection_count, 0);

    it("M1: 600 stale-only reports do not use the Build's report budget; the real mismatch after them is recorded", async () => {
      clock.ms += 2 * HOUR;
      const older = await setUp();
      const newer = await setUp({ from: older, sameApp: true });
      const recorder = make();
      await send(recorder, newer, matching(newer));
      for (let n = 0; n < 600; n++) {
        fire(recorder, newer, [{ i: 1, h: b64(older.hashes[1] ?? "") }], `198.${18 + (n % 2)}.${n % 250}.9`);
      }
      await recorder.flush();
      await send(recorder, newer, [{ i: 1, h: foreign("m1-real") }]);
      const incidents = await tampered(newer.admin);
      expect(incidents).toHaveLength(1);
      expect(incidents[0]?.detection_count).toBe(1);
      expect(recorder.dropped()).toMatchObject({ stale: 600, "report-limit": 0, busy: 0 });
    });

    it("M2: 50 Apps of one Organization, each within its own share of lookups, never cost another Organization's freshly registered Build its report", async () => {
      clock.ms += 2 * HOUR;
      const attacker = await setUp();
      const apps = [attacker.appId];
      for (let n = 1; n < 50; n++) apps.push((await createAppFor(api, attacker.admin)).app.id);
      const victim = await setUp();
      const recorder = make();
      const unknown = (appId: string, n: number) =>
        fire(
          recorder,
          { appId, buildId: newId("bld") },
          [{ i: 0, h: foreign("x") }],
          `198.${18 + (n % 2)}.${n % 250}.9`,
        );
      const victims: string[] = [];
      let n = 0;
      for (let second = 0; second < 20; second++) {
        // The first second every App spends the burst of its own share; after that, one lookup a second each.
        for (const appId of apps) for (let k = 0; k < (second === 0 ? 20 : 1); k++) unknown(appId, n++);
        const manifest = manifestFor(victim.appId, "production", 3);
        await register(victim.admin, manifest);
        victims.push(manifest.build_id);
        fire(
          recorder,
          { appId: victim.appId, buildId: manifest.build_id },
          manifest.artifacts.slice(0, 3).map((artifact, i) => ({ i, h: b64(artifact.sha256) })),
        );
        await recorder.flush();
        clock.ms += 1_000;
      }
      for (const buildId of victims) expect(await armedAt(buildId), buildId).not.toBeNull();
      expect(recorder.dropped().busy).toBe(0);
      // The Organization's Apps together are held to the Organization's share.
      expect(recorder.dropped()["org-limit"]).toBeGreaterThan(500);
    }, 60_000);

    it("M2: a registered Build needs no lookup at all, and after a restart one lookup warms an App's recent Builds", async () => {
      clock.ms += 2 * HOUR;
      const first = await setUp();
      const recorder = make();
      const before = seen.lookups;
      const manifest = manifestFor(first.appId, "production", 3);
      await register(first.admin, manifest);
      await send(
        recorder,
        { appId: first.appId, buildId: manifest.build_id },
        manifest.artifacts.slice(0, 3).map((artifact, i) => ({ i, h: b64(artifact.sha256) })),
      );
      expect(await armedAt(manifest.build_id)).not.toBeNull();
      expect(seen.lookups - before).toBe(0);

      const others = [await setUp({ from: first, sameApp: true }), await setUp({ from: first, sameApp: true })];
      const restarted = make();
      const again = seen.lookups;
      for (const [n, s] of [first, ...others].entries()) fire(restarted, s, matching(s), `198.51.${n}.9`);
      await restarted.flush();
      for (const s of [first, ...others]) expect(await armedAt(s.buildId)).not.toBeNull();
      expect(seen.lookups - again).toBe(1);
    });

    it("L1: a hash that is the same path's in a recent Build is stale even when no recent Build's marker lists the path", async () => {
      clock.ms += 2 * HOUR;
      const old = await setUp();
      const recorder = make();
      await send(recorder, old, matching(old));
      clock.ms += 31 * DAY;
      let newest: BuildManifest | undefined;
      for (let n = 0; n < 20; n++) {
        clock.ms += 1_000;
        newest = { ...manifestFor(old.appId, "production", 3), integrity: undefined } as BuildManifest;
        await register(old.admin, newest);
      }
      // A page of the old Build, still served somewhere, loads the newest deploy's file.
      await send(recorder, old, [{ i: 0, h: b64(newest?.artifacts[0]?.sha256 ?? "") }]);
      expect(await tampered(old.admin)).toEqual([]);
      expect(recorder.dropped().stale).toBe(1);
      // Its own tampered file still counts.
      await send(recorder, old, [{ i: 0, h: foreign("l1-real") }]);
      expect(await detectionsOf(old)).toBe(1);
    });

    it("L2: a Build's repeat window and hourly cap survive other Builds crowding the recorder's memory, and a restart", async () => {
      clock.ms += 2 * HOUR;
      const a = await setUp();
      const b = await setUp({ from: a });
      const c = await setUp({ from: a });
      const recorder = make({ maxBuildsPerOrg: 2 });
      for (const s of [a, b, c]) await send(recorder, s, matching(s));
      for (let round = 0; round < 3; round++) {
        await send(recorder, a, [{ i: 0, h: foreign("l2-same") }]);
        await send(recorder, b, [{ i: 0, h: foreign(`l2-b-${round}`) }]);
        await send(recorder, c, [{ i: 0, h: foreign(`l2-c-${round}`) }]);
      }
      expect(await detectionsOf(a)).toBe(1);
      // Distinct hashes of one Build, with the others still pushing: at most 20 in the hour.
      for (let n = 0; n < 30; n++) {
        await send(recorder, a, [{ i: 1, h: foreign(`l2-distinct-${n}`) }]);
        await send(recorder, c, [{ i: 1, h: foreign(`l2-push-${n}`) }]);
      }
      expect(await detectionsOf(a)).toBe(INTEGRITY_LIMITS.newHashesPerHour);
      // The Build that found no room was dropped as busy, never recorded out of turn.
      expect(await detectionsOf(c)).toBe(0);
      expect(recorder.dropped().busy).toBeGreaterThan(0);
      // A restarted process remembers nothing, the database does: the same file and hash is still a repeat.
      const restarted = make();
      await send(restarted, a, [{ i: 0, h: foreign("l2-same") }]);
      expect(await detectionsOf(a)).toBe(INTEGRITY_LIMITS.newHashesPerHour);
      expect(restarted.dropped().repeat).toBe(1);
    });

    /** A database whose statements matching `when` answer `answer()` instead (which may throw). */
    function intercepting(when: (sql: string) => boolean, answer: () => unknown): Db {
      return {
        tx: (scope, fn) =>
          db.tx(scope, (q) =>
            fn({
              query: ((sql: string, params?: unknown[]) =>
                when(sql) ? Promise.resolve().then(answer) : q.query(sql, params)) as typeof q.query,
            }),
          ),
        close: () => db.close(),
      };
    }

    it("L3: a write refused because the Organization was purged meanwhile is one unknown-build drop, and the Build is forgotten", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      await send(make(), s, matching(s));
      const own = captureLogger();
      const recorder = make({
        logger: own,
        db: intercepting(
          (sql) => sql.includes("INSERT INTO incidents"),
          () => {
            throw Object.assign(new Error('insert or update on table "incidents" violates foreign key constraint'), {
              code: "23503",
            });
          },
        ),
      });
      await send(recorder, s, matching(s));
      own.lines.length = 0;
      await send(recorder, s, [{ i: 0, h: foreign("l3-purged") }]);
      expect(own.lines).toEqual(["integrity dropped reason=unknown-build"]);
      expect(recorder.dropped()).toMatchObject({ failed: 0, "unknown-build": 1 });
      expect(recorder.trackedBuilds()).toBe(0);
      // Forgotten: the next report is answered from the unknown-Build memory, without the database.
      await send(recorder, s, [{ i: 0, h: foreign("l3-again") }]);
      expect(own.lines).toEqual(["integrity dropped reason=unknown-build", "integrity dropped reason=unknown-build"]);
    });

    it("L3: any other write failure is one failed count and one log line", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      await send(make(), s, matching(s));
      const own = captureLogger();
      const recorder = make({
        logger: own,
        db: intercepting(
          (sql) => sql.includes("INSERT INTO incidents"),
          () => {
            throw Object.assign(new Error("secret value in a message"), { code: "XX000" });
          },
        ),
      });
      await send(recorder, s, matching(s));
      own.lines.length = 0;
      await send(recorder, s, [{ i: 0, h: foreign("l3-broken") }]);
      expect(own.lines).toEqual([`integrity failed Error build=${s.buildId}`]);
      expect(recorder.dropped().failed).toBe(1);
      // Nothing was recorded, so the same observation is no repeat: with the database back, it is recorded.
      await send(make(), s, [{ i: 0, h: foreign("l3-broken") }]);
      expect(await detectionsOf(s)).toBe(1);
    });

    it("L3: a Build whose row is gone is not armed: no 'armed' line, an unknown-build drop", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const own = captureLogger();
      const recorder = make({
        logger: own,
        db: intercepting(
          (sql) => sql.includes("UPDATE builds SET integrity_first_match_at"),
          () => ({ rows: [{ updated: 0, present: false }] }),
        ),
      });
      await send(recorder, s, matching(s));
      expect(own.lines).toEqual(["integrity dropped reason=unknown-build"]);
      expect(await armedAt(s.buildId)).toBeNull();
      // And a mismatch then is not judged as if the Build were armed.
      await send(recorder, s, [{ i: 0, h: foreign("l3-not-armed") }]);
      expect(await tampered(s.admin)).toEqual([]);
    });

    it("a logger that throws reaches neither the attest handler nor an unhandled rejection", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const unhandled: unknown[] = [];
      const onUnhandled = (reason: unknown) => void unhandled.push(reason);
      process.on("unhandledRejection", onUnhandled);
      try {
        const broken = () => {
          throw new Error("the log pipe is closed");
        };
        const recorder = make({ logger: { info: broken, warn: broken } });
        expect(() => fire(recorder, s, matching(s))).not.toThrow();
        expect(() => fire(recorder, { appId: s.appId, buildId: s.buildId }, [], PEER)).not.toThrow();
        recorder.report({
          appId: s.appId,
          report: { build: s.buildId, files: [], skipped: 0 },
          originHeader: undefined,
          address: PEER,
        });
        await recorder.flush();
        await send(recorder, s, [{ i: 0, h: foreign("logger") }]);
        await new Promise((resolve) => setTimeout(resolve, 20));
        expect(unhandled).toEqual([]);
        // The work itself was done.
        expect(await armedAt(s.buildId)).not.toBeNull();
        expect(await detectionsOf(s)).toBe(1);
      } finally {
        process.off("unhandledRejection", onUnhandled);
      }
    });

    it("charges the reporter's prefix only for a lookup that runs: one refused by the App's share costs the prefix nothing", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const other = await setUp();
      const recorder = make();
      // 70 made-up Builds of one App from one prefix: 20 run, 50 are refused by the App's share.
      for (let n = 0; n < 70; n++)
        fire(recorder, { appId: s.appId, buildId: newId("bld") }, [{ i: 0, h: foreign("x") }]);
      await recorder.flush();
      expect(recorder.dropped()["prefix-limit"]).toBe(0);
      // The same prefix still has 40 lookups left this minute for other Apps.
      await send(recorder, other, matching(other));
      expect(await armedAt(other.buildId)).not.toBeNull();
    });
  });

  describe("the Build says since when it is watched", () => {
    it("answers integrity_first_match_at with a Build that has a marker: null until armed, then the time", async () => {
      const s = await setUp();
      const read = async () =>
        BuildResponseSchema.parse(
          await (await api.app.request(`/v1/apps/${s.appId}/builds/${s.buildId}`, { headers: bearer(s.admin) })).json(),
        ).build;
      expect(await read()).toMatchObject({ integrity_first_match_at: null });
      await send(make(), s, matching(s));
      expect(await read()).toMatchObject({ integrity_first_match_at: new Date(clock.ms).toISOString() });
      // A Build without a marker has no such member at all.
      const manifest = { ...manifestFor(s.appId, "production", 1), integrity: undefined };
      await register(s.admin, manifest as BuildManifest);
      const res = await api.app.request(`/v1/apps/${s.appId}/builds/${manifest.build_id}`, {
        headers: bearer(s.admin),
      });
      expect(BuildResponseSchema.parse(await res.json()).build).not.toHaveProperty("integrity_first_match_at");
    });
  });
});

describe("tamper detection: another visitor is not delayed by forged reports (H1, over the attest route)", () => {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const exported = publicKey.export({ format: "jwk" });
  const JWK = { kty: "EC" as const, crv: "P-256" as const, x: String(exported.x), y: String(exported.y) };
  const JKT = jwkThumbprint(JWK);
  let api: TestApi;
  let recorder: IntegrityRecorder;

  afterAll(async () => {
    await recorder?.flush();
    await api?.close();
  });

  async function challenge(appId: string, address: string): Promise<string> {
    const res = await api.app.request("/v1/attest/challenge", {
      method: "POST",
      headers: { "content-type": "application/json", [PEER_HEADER]: address },
      body: JSON.stringify({ app_id: appId }),
    });
    expect(res.status).toBe(200);
    return ChallengeResponseSchema.parse(await res.json()).nonce;
  }

  async function attest(appId: string, nonce: string, address: string, integrity?: unknown): Promise<number> {
    const res = await api.app.request("/v1/attest", {
      method: "POST",
      headers: { "content-type": "application/json", [PEER_HEADER]: address, origin: ORIGIN },
      body: JSON.stringify({
        app_id: appId,
        nonce,
        device: randomBytes(16).toString("base64url"),
        signals: [],
        cnf: { jkt: JKT, jwk: JWK },
        ...(integrity === undefined ? {} : { integrity }),
      }),
    });
    return res.status;
  }

  it("30 handshakes from one /24, each with 32 forged hashes: a visitor elsewhere waits no more than max(250 ms, 5× baseline)", async () => {
    const db = await openDb();
    recorder = createIntegrityRecorder({ db, notifier: { incidentOpened: () => {} }, logger: captureLogger() });
    api = await makeTestApi({ db, integrity: recorder, clientAddress: (c) => c.req.header(PEER_HEADER) });
    const org = await createOrganization(api);
    const admin = org.admin_key.key;
    const appId = (await createAppFor(api, admin)).app.id;
    const manifests: BuildManifest[] = [];
    for (let n = 0; n < 30; n++) {
      const buildId = newId("bld");
      const paths = Array.from({ length: 200 }, (_, i) => `assets/chunk-${String(i).padStart(3, "0")}.js`);
      const manifest: BuildManifest = {
        ...EXAMPLE_BUILD_MANIFEST,
        build_id: buildId,
        app_id: appId,
        environment: "production",
        version: `30.0.${n}`,
        artifacts: paths.map((path) => ({ path, sha256: sha(`${buildId}:${path}`), bytes: 1024 })),
        integrity: { files: paths.slice(0, 32) },
      };
      manifests.push(manifest);
      expect((await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)))).status).toBe(201);
    }
    const build = manifests.at(-1) as BuildManifest;
    const files = (label: string) => Array.from({ length: 32 }, (_, i) => ({ i, h: foreign(`${label}-${i}`) }));
    const matchingFiles = build.artifacts.slice(0, 32).map((artifact, i) => ({ i, h: b64(artifact.sha256) }));
    // Armed by a genuine visitor.
    expect(
      await attest(appId, await challenge(appId, "192.0.2.1"), "192.0.2.1", {
        build: build.build_id,
        files: matchingFiles,
        skipped: 0,
      }),
    ).toBe(200);
    await recorder.flush();

    const visit = async (address: string) => {
      const started = performance.now();
      expect(await attest(appId, await challenge(appId, address), address)).toBe(200);
      return performance.now() - started;
    };
    const samples: number[] = [];
    for (let n = 0; n < 5; n++) samples.push(await visit(`192.0.3.${n + 1}`));
    const baseline = samples.sort((a, b) => a - b)[2] as number;

    const nonces: string[] = [];
    for (let n = 0; n < 30; n++) nonces.push(await challenge(appId, `198.51.100.${n + 1}`));
    const attack = Promise.all(
      nonces.map((nonce, n) =>
        attest(appId, nonce, `198.51.100.${n + 1}`, { build: build.build_id, files: files(`attack-${n}`), skipped: 0 }),
      ),
    );
    // Every attack request has its answer (a report never delays its own attestation); their reports are still
    // being judged when the visitor arrives.
    expect((await attack).every((status) => status === 200)).toBe(true);
    const waited = await visit("192.0.4.1");
    expect(waited).toBeLessThan(Math.max(250, 5 * baseline));
  }, 60_000);
});
