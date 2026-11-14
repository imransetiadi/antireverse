import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import {
  AttestationClaimsSchema,
  AttestResponseSchema,
  type BuildManifest,
  BuildResponseSchema,
  ChallengeResponseSchema,
  CONTAINMENT_TTLS,
  type Detection,
  type Environment,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_TAMPER_INCIDENT,
  INTEGRITY_LIMITS,
  type Incident,
  IncidentDetailResponseSchema,
  type IntegrityReport,
  ListIncidentsResponseSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { jwkThumbprint, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Db, type OwnedDb, openDb } from "../src/db/db.ts";
import {
  createIntegrityRecorder,
  INTEGRITY_DROP_REASONS,
  type IntegrityRecorder,
  type IntegrityRecorderDeps,
  LOOKUP_APP_BURST,
  LOOKUPS_PER_PREFIX_PER_MINUTE,
} from "../src/detect/integrity.ts";
import { alertMail } from "../src/mail/message.ts";
import { type AlertFetch, createNotifier, type Notifier } from "../src/notify/notifier.ts";
import { classifyRoute } from "../src/slo/middleware.ts";
import {
  bearer,
  type CapturedLogger,
  captureLogger,
  createAppFor,
  createOrganization,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
  withReason,
} from "./helpers.ts";

// Slice 21a, API lane: the integrity report of an attestation, judged after the response by the recorder, and the
// `tampered-build` Incidents it opens.

const T0 = Date.parse("2026-11-14T12:00:00.000Z");
const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ORIGIN = "https://shop.example";
const PEER = "203.0.113.77";
const PEER_PREFIX = "203.0.113.0/24";
const PEER_HEADER = "x-test-peer";
const PATHS = ["vendor.js", "app.js", "chunk-lazy.js"] as const;

const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const b64 = (hex: string) => Buffer.from(hex, "hex").toString("base64url");

interface Setup {
  admin: string;
  organizationId: string;
  organizationName: string;
  appId: string;
  buildId: string;
  environment: Environment;
  /** The registered SHA-256 (hex) of `PATHS[i]`, in the order of `integrity.files`. */
  hashes: string[];
}

interface ReportFile {
  i: number;
  h: string;
}

describe("tamper detection: the integrity recorder", () => {
  let db: OwnedDb;
  let api: TestApi;
  let recorder: IntegrityRecorder;
  let recorderLog: CapturedLogger;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const opened: { incident: Incident; organizationId: string }[] = [];
  /** Bodies the webhook transport was asked to send. */
  const sent: string[] = [];
  let realNotifier: Notifier;
  let lookups = 0;
  let versions = 0;

  /** The recorder's database: the test database, counting the definer lookups. */
  function counting(inner: Db): Db {
    return {
      tx: (scope, fn) =>
        inner.tx(scope, (q) =>
          fn({
            query: (sql, params) => {
              if (typeof sql === "string" && sql.includes("integrity_lookup_build")) lookups++;
              return q.query(sql, params);
            },
          }),
        ),
      close: () => inner.close(),
    };
  }

  /** A Manifest whose three artifacts are all listed by the marker, in an order that is not the artifacts' own. */
  function manifestFor(appId: string, environment: Environment, patch: Partial<BuildManifest> = {}): BuildManifest {
    const buildId = newId("bld");
    versions++;
    return {
      ...EXAMPLE_BUILD_MANIFEST,
      build_id: buildId,
      app_id: appId,
      environment,
      version: `21.0.${versions}`,
      artifacts: [...PATHS].sort().map((path) => ({ path, sha256: sha(`${buildId}:${path}`), bytes: 1024 })),
      integrity: { files: [...PATHS] },
      ...patch,
    };
  }

  async function register(admin: string, manifest: BuildManifest): Promise<void> {
    const res = await api.app.request(`/v1/apps/${manifest.app_id}/builds`, json({ manifest }, bearer(admin)));
    expect(res.status, await res.clone().text()).toBe(201);
  }

  /** An App with one registered Build carrying an integrity marker; a fresh Organization unless one is given. */
  async function setUp(
    options: { from?: Setup; sameApp?: boolean; environment?: Environment; patch?: Partial<BuildManifest> } = {},
  ): Promise<Setup> {
    let { admin, organizationId, organizationName } = options.from ?? {};
    if (admin === undefined || organizationId === undefined || organizationName === undefined) {
      organizationName = `Org ${randomBytes(3).toString("hex")}`;
      const org = await createOrganization(api, organizationName);
      admin = org.admin_key.key;
      organizationId = org.organization.id;
    }
    const appId =
      options.from !== undefined && options.sameApp ? options.from.appId : (await createAppFor(api, admin)).app.id;
    const environment = options.environment ?? "production";
    // A minute passes before every Build: the lookup budgets of the recorder (per prefix and in all) refill.
    clock.ms += MINUTE;
    const manifest = manifestFor(appId, environment, options.patch);
    await register(admin, manifest);
    const digests = new Map(manifest.artifacts.map((artifact) => [artifact.path, artifact.sha256]));
    return {
      admin,
      organizationId,
      organizationName,
      appId,
      buildId: manifest.build_id,
      environment,
      hashes: (manifest.integrity?.files ?? []).map((path) => digests.get(path) ?? ""),
    };
  }

  /** The matching report of the given files of the Build. */
  const matching = (s: Setup, indexes = [0, 1, 2]): ReportFile[] =>
    indexes.map((i) => ({ i, h: b64(s.hashes[i] ?? "") }));
  /** A hash no Build registered, as the wire carries it; `label` makes it distinct. */
  const foreign = (label: string) => b64(sha(`tampered:${label}`));

  /** Hands one report to the recorder as the attest route does, and waits until it has been judged. */
  async function send(
    s: Pick<Setup, "appId" | "buildId">,
    files: ReportFile[],
    options: { origin?: string | undefined; peer?: string; skipped?: number; on?: IntegrityRecorder } = {},
  ): Promise<void> {
    const report: IntegrityReport = { build: s.buildId, files, skipped: options.skipped ?? 0 };
    const target = options.on ?? recorder;
    target.report({
      appId: s.appId,
      report,
      originHeader: "origin" in options ? options.origin : ORIGIN,
      address: options.peer ?? PEER,
    });
    await target.flush();
  }

  const arm = (s: Setup) => send(s, matching(s));

  async function firstMatchAt(s: Pick<Setup, "buildId">): Promise<string | null> {
    return db.owner(async (q) => {
      const { rows } = await q.query<{ at: Date | null }>(
        "SELECT integrity_first_match_at AS at FROM builds WHERE build_id = $1",
        [s.buildId],
      );
      return rows[0]?.at?.toISOString() ?? null;
    });
  }

  async function tampered(admin: string): Promise<Incident[]> {
    const res = await api.app.request("/v1/incidents", { headers: bearer(admin) });
    expect(res.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await res.json()).incidents.filter((i) => i.rule === "tampered-build");
  }

  async function detectionsOf(admin: string, incidentId: string): Promise<Detection[]> {
    const res = await api.app.request(`/v1/incidents/${incidentId}`, { headers: bearer(admin) });
    expect(res.status).toBe(200);
    return IncidentDetailResponseSchema.parse(await res.json()).detections;
  }

  const detectionCount = async (admin: string) =>
    (await tampered(admin)).reduce((total, incident) => total + incident.detection_count, 0);

  function make(overrides: Partial<IntegrityRecorderDeps> = {}): IntegrityRecorder {
    return createIntegrityRecorder({
      db: counting(db),
      notifier: {
        incidentOpened: (incident, organizationId) => {
          opened.push({ incident, organizationId });
          realNotifier.incidentOpened(incident, organizationId);
        },
      },
      now,
      logger: recorderLog,
      ...overrides,
    });
  }

  beforeAll(async () => {
    db = await openDb();
    recorderLog = captureLogger();
    const fetch: AlertFetch = async (_url, init) => {
      sent.push(init.body);
      return { status: 200, body: null };
    };
    realNotifier = createNotifier({
      db,
      now,
      fetch,
      resolve: async () => [{ address: "127.0.0.1", family: 4 }],
      allowPrivate: true,
      consoleUrl: "https://console.example",
      logger: captureLogger(),
    });
    recorder = make();
    api = await makeTestApi({
      db,
      now,
      integrity: recorder,
      allowPrivateAlertUrls: true,
      resolve: async () => [{ address: "127.0.0.1", family: 4 }],
      clientAddress: (c) => c.req.header(PEER_HEADER),
    });
  });
  afterAll(async () => {
    await realNotifier.drain();
    await api.close();
  });

  describe("registering a Build with an integrity marker", () => {
    it("stores the Manifest's integrity.files and returns them with the Build; the Build starts unarmed", async () => {
      const s = await setUp();
      const res = await api.app.request(`/v1/apps/${s.appId}/builds/${s.buildId}`, { headers: bearer(s.admin) });
      expect(BuildResponseSchema.parse(await res.json()).build.integrity).toEqual({ files: [...PATHS] });
      expect(await firstMatchAt(s)).toBeNull();
    });

    it("refuses integrity.files that are not artifacts of the Manifest, twice the same or more than 32 (400)", async () => {
      const org = await createOrganization(api);
      const appId = (await createAppFor(api, org.admin_key.key)).app.id;
      const post = (files: string[]) =>
        api.app.request(
          `/v1/apps/${appId}/builds`,
          json({ manifest: manifestFor(appId, "production", { integrity: { files } }) }, bearer(org.admin_key.key)),
        );
      const problem = await expectProblem(await post(["app.js", "not-an-artifact.js"]), 400);
      expect(problem.errors?.[0]?.path).toBe("manifest.integrity.files.1");
      await expectProblem(await post(["app.js", "app.js"]), 400);
      await expectProblem(await post(Array.from({ length: 33 }, (_, i) => `f${i}.js`)), 400);
      expect((await post([])).status).toBe(201);
    });
  });

  describe("arming: a Build is watched from its first fully matching report (D-100)", () => {
    it("a report whose every file matches arms the Build once and opens nothing", async () => {
      const s = await setUp();
      const before = opened.length;
      await arm(s);
      const armedAt = await firstMatchAt(s);
      expect(armedAt).toBe(new Date(clock.ms).toISOString());
      clock.ms += MINUTE;
      await arm(s);
      expect(await firstMatchAt(s)).toBe(armedAt);
      expect(await tampered(s.admin)).toEqual([]);
      expect(opened).toHaveLength(before);
    });

    it("compares the wire's base64url with the Manifest's hex: a hex-looking or re-encoded hash is no match", async () => {
      const s = await setUp();
      // The same 32 bytes, as the wire spells them, match; nothing else does.
      await send(s, [{ i: 1, h: b64(s.hashes[1] ?? "") }]);
      expect(await firstMatchAt(s)).not.toBeNull();
      const other = await setUp();
      await send(other, [{ i: 1, h: b64(other.hashes[0] ?? "") }]);
      expect(await firstMatchAt(other)).toBeNull();
    });

    it("a partial file list arms, whatever `skipped` says: one verified file shows the origin served this Build", async () => {
      const s = await setUp();
      await send(s, matching(s, [2]), { skipped: 2 });
      expect(await firstMatchAt(s)).not.toBeNull();
    });

    it("a report with no files never arms, nor does one with any mismatching file", async () => {
      const s = await setUp();
      await send(s, [], { skipped: 3 });
      expect(await firstMatchAt(s)).toBeNull();
      await send(s, [...matching(s, [0, 1]), { i: 2, h: foreign("x") }]);
      expect(await firstMatchAt(s)).toBeNull();
      expect(recorder.dropped().empty).toBeGreaterThan(0);
    });

    it("an unarmed Build opens nothing, however many mismatches arrive (it was never seen clean)", async () => {
      const s = await setUp();
      const before = recorder.dropped().unarmed;
      for (let n = 0; n < 5; n++) await send(s, [{ i: 0, h: foreign(`unarmed-${n}`) }]);
      expect(await tampered(s.admin)).toEqual([]);
      expect(await firstMatchAt(s)).toBeNull();
      expect(recorder.dropped().unarmed).toBe(before + 5);
    });
  });

  describe("a mismatch on an armed Build", () => {
    it("opens one High 'Tampered Build' Incident with the file, the observed hash, the origin and the reporter's prefix, and alerts once", async () => {
      const s = await setUp();
      await arm(s);
      const hook = await api.app.request(
        "/v1/alert-channels",
        json({ kind: "webhook", name: "Ops", url: "https://hooks.example/ar" }, withReason(bearer(s.admin))),
      );
      expect(hook.status, await hook.clone().text()).toBe(201);
      const before = opened.length;
      const sentBefore = sent.length;
      clock.ms += MINUTE;
      const observed = sha("one byte changed");
      // The other two files still match: only the changed one is reported on.
      await send(s, [...matching(s, [0, 2]), { i: 1, h: b64(observed) }]);
      const incidents = await tampered(s.admin);
      expect(incidents).toHaveLength(1);
      const [incident] = incidents;
      expect(incident).toMatchObject({
        app_id: s.appId,
        environment: "production",
        rule: "tampered-build",
        title: "Tampered Build",
        severity: "high",
        status: "open",
        build_id: s.buildId,
        ip_prefix: null,
        origin: null,
        canary_id: null,
        advisory_id: null,
        detection_count: 1,
        artifact_path: "app.js",
        observed_sha256: observed,
        first_seen: new Date(clock.ms).toISOString(),
      });
      const detections = await detectionsOf(s.admin, incident?.id ?? "");
      expect(detections).toHaveLength(1);
      expect(detections[0]).toMatchObject({
        rule: "tampered-build",
        count: 1,
        artifact_path: "app.js",
        observed_sha256: observed,
        origin: ORIGIN,
        ip_prefix: PEER_PREFIX,
        canary_id: null,
      });
      // No Events behind it: no evidence, no Actors, and containment does not apply.
      const detail = IncidentDetailResponseSchema.parse(
        await (await api.app.request(`/v1/incidents/${incident?.id}`, { headers: bearer(s.admin) })).json(),
      );
      expect(detail.evidence).toEqual([]);
      expect(detail.actors).toEqual([]);
      const contain = await api.app.request(
        `/v1/incidents/${incident?.id}/containments`,
        json(
          { target: { kind: "prefix" }, ttl_s: CONTAINMENT_TTLS[0], confirm_prefix: PEER_PREFIX },
          withReason(bearer(s.admin)),
        ),
      );
      expect(contain.status).toBe(409);

      // One alert, for the opening only: the opened Incident already names the file and the observed hash.
      expect(opened.slice(before)).toEqual([{ incident: incidents[0], organizationId: s.organizationId }]);
      await realNotifier.drain();
      expect(sent.slice(sentBefore)).toHaveLength(1);
      const payload = WebhookAlertPayloadSchema.parse(JSON.parse(sent.at(-1) ?? ""));
      expect(payload).toEqual({
        type: "incident.opened",
        incident: incidents[0],
        console_url: `https://console.example/incidents/${incident?.id}`,
      });
      expect(Object.keys(JSON.parse(sent.at(-1) ?? "").incident).sort()).toEqual(
        Object.keys(EXAMPLE_TAMPER_INCIDENT).sort(),
      );
    });

    it("groups by Build: another file joins the Incident without a second alert; another Build opens its own", async () => {
      const s = await setUp();
      await arm(s);
      const before = opened.length;
      await send(s, [{ i: 0, h: foreign("vendor") }]);
      clock.ms += MINUTE;
      await send(s, [{ i: 2, h: foreign("chunk") }], { peer: "198.51.100.9", origin: "https://www.shop.example" });
      let incidents = await tampered(s.admin);
      expect(incidents).toHaveLength(1);
      expect(incidents[0]).toMatchObject({ detection_count: 2, build_id: s.buildId, artifact_path: "vendor.js" });
      expect(incidents[0]?.observed_sha256).toBe(sha("tampered:vendor"));
      const detections = await detectionsOf(s.admin, incidents[0]?.id ?? "");
      expect(detections.map((d) => [d.artifact_path, d.origin, d.ip_prefix]).sort()).toEqual([
        ["chunk-lazy.js", "https://www.shop.example", "198.51.100.0/24"],
        ["vendor.js", ORIGIN, PEER_PREFIX],
      ]);
      expect(opened.slice(before)).toHaveLength(1);

      const second = await setUp({ from: s, sameApp: true });
      await arm(second);
      await send(second, [{ i: 0, h: foreign("vendor") }]);
      incidents = await tampered(s.admin);
      expect(incidents.map((i) => i.build_id).sort()).toEqual([s.buildId, second.buildId].sort());
      expect(incidents.every((i) => i.app_id === s.appId && i.environment === "production")).toBe(true);
      expect(opened.slice(before)).toHaveLength(2);
    });

    it("one report with two changed files records two Detections in one Incident", async () => {
      const s = await setUp();
      await arm(s);
      await send(s, [{ i: 0, h: foreign("a") }, { i: 1, h: foreign("b") }, ...matching(s, [2])]);
      const incidents = await tampered(s.admin);
      expect(incidents).toHaveLength(1);
      expect(incidents[0]?.detection_count).toBe(2);
    });

    it("records the same file and hash once per window; after it, the repeat joins the Incident", async () => {
      const s = await setUp();
      await arm(s);
      const before = recorder.dropped().repeat;
      for (let n = 0; n < 4; n++) await send(s, [{ i: 0, h: foreign("same") }], { peer: `198.51.${n}.7` });
      expect(await detectionCount(s.admin)).toBe(1);
      expect(recorder.dropped().repeat).toBe(before + 3);
      clock.ms += HOUR;
      await send(s, [{ i: 0, h: foreign("same") }]);
      expect(await tampered(s.admin)).toHaveLength(1);
      expect(await detectionCount(s.admin)).toBe(2);
    });

    it("a resolved Incident stays resolved: the next mismatch of the Build opens a new one", async () => {
      const s = await setUp();
      await arm(s);
      await send(s, [{ i: 0, h: foreign("first") }]);
      const [first] = await tampered(s.admin);
      const patch = await api.app.request(`/v1/incidents/${first?.id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json", ...withReason(bearer(s.admin)) },
        body: JSON.stringify({ status: "resolved" }),
      });
      expect(patch.status, await patch.clone().text()).toBe(200);
      await send(s, [{ i: 0, h: foreign("second") }]);
      const incidents = await tampered(s.admin);
      expect(incidents.map((i) => i.status).sort()).toEqual(["open", "resolved"]);
    });
  });

  describe("the Origin header", () => {
    it("drops a report with a missing, non-canonical or local Origin: it neither arms nor detects", async () => {
      const s = await setUp();
      const before = recorder.dropped();
      await send(s, matching(s), { origin: undefined });
      await send(s, matching(s), { origin: "HTTPS://Shop.Example:443/" });
      await send(s, matching(s), { origin: "https://shop.example/path" });
      await send(s, matching(s), { origin: "null" });
      await send(s, matching(s), { origin: "http://localhost:5173" });
      await send(s, matching(s), { origin: "http://192.168.1.20" });
      await send(s, matching(s), { origin: "https://dev.internal" });
      expect(await firstMatchAt(s)).toBeNull();
      const after = recorder.dropped();
      expect(after["no-origin"] - before["no-origin"]).toBe(1);
      expect(after["not-canonical"] - before["not-canonical"]).toBe(3);
      expect(after.local - before.local).toBe(3);

      await arm(s);
      await send(s, [{ i: 0, h: foreign("local") }], { origin: "http://127.0.0.1:8080" });
      await send(s, [{ i: 0, h: foreign("missing") }], { origin: undefined });
      expect(await tampered(s.admin)).toEqual([]);
    });

    it("stores a host with one trailing dot as its dotless form", async () => {
      const s = await setUp();
      await arm(s);
      await send(s, [{ i: 0, h: foreign("dot") }], { origin: "https://shop.example." });
      const [incident] = await tampered(s.admin);
      expect((await detectionsOf(s.admin, incident?.id ?? ""))[0]?.origin).toBe(ORIGIN);
    });
  });

  describe("what a report cannot reach", () => {
    it("an unknown Build, a Build of another App, of another Organization, and a Build without a marker open nothing", async () => {
      const s = await setUp();
      await arm(s);
      const sibling = await setUp({ from: s });
      await arm(sibling);
      const stranger = await setUp();
      await arm(stranger);
      const unmarked = await setUp({ patch: { integrity: undefined } });
      const emptyMarker = await setUp({ patch: { integrity: { files: [] } } });
      const before = recorder.dropped();

      await send({ appId: s.appId, buildId: newId("bld") }, [{ i: 0, h: foreign("unknown") }]);
      // The handshake proved `s.appId` only: a Build of any other App is unknown under it.
      await send({ appId: s.appId, buildId: sibling.buildId }, [{ i: 0, h: foreign("sibling") }]);
      await send({ appId: s.appId, buildId: stranger.buildId }, [{ i: 0, h: foreign("stranger") }]);
      await send(unmarked, [{ i: 0, h: foreign("unmarked") }]);
      await send(emptyMarker, [{ i: 0, h: foreign("empty-marker") }]);
      // An index the Build's marker does not have: the whole report is dropped.
      await send(s, [...matching(s, [0]), { i: 3, h: foreign("index") }]);

      for (const setup of [s, sibling, stranger, unmarked, emptyMarker])
        expect(await tampered(setup.admin)).toEqual([]);
      const after = recorder.dropped();
      expect(after["unknown-build"] - before["unknown-build"]).toBe(3);
      expect(after["no-marker"] - before["no-marker"]).toBe(2);
      expect(after["bad-index"] - before["bad-index"]).toBe(1);
      expect(await firstMatchAt(unmarked)).toBeNull();
    });

    it("keeps one Organization's Incident away from another", async () => {
      const s = await setUp();
      await arm(s);
      await send(s, [{ i: 0, h: foreign("mine") }]);
      const [incident] = await tampered(s.admin);
      const other = await createOrganization(api, "Other");
      expect(await tampered(other.admin_key.key)).toEqual([]);
      const res = await api.app.request(`/v1/incidents/${incident?.id}`, { headers: bearer(other.admin_key.key) });
      expect(res.status).toBe(404);
    });
  });

  describe("stale files of a mixed deploy are not tampering", () => {
    it("a hash that is the same path's in another recent Build of the App Environment is dropped", async () => {
      const older = await setUp();
      const newer = await setUp({ from: older, sameApp: true });
      await arm(newer);
      const before = recorder.dropped().stale;
      // The page runs the newer Build but a cache still serves the older Build's app.js and chunk.
      await send(newer, [
        ...matching(newer, [0]),
        { i: 1, h: b64(older.hashes[1] ?? "") },
        { i: 2, h: b64(older.hashes[2] ?? "") },
      ]);
      // And the other way round: an old page, a new file.
      await arm(older);
      await send(older, [{ i: 0, h: b64(newer.hashes[0] ?? "") }]);
      expect(await tampered(older.admin)).toEqual([]);
      expect(recorder.dropped().stale).toBe(before + 3);
    });

    it("only the same path counts, and only the same App Environment", async () => {
      const older = await setUp();
      const newer = await setUp({ from: older, sameApp: true });
      const staging = await setUp({ from: older, sameApp: true, environment: "staging" });
      const elsewhere = await setUp({ from: older });
      await arm(newer);
      // Another path's hash of the older Build, a staging Build's, another App's: none explains this file.
      await send(newer, [{ i: 0, h: b64(older.hashes[1] ?? "") }]);
      await send(newer, [{ i: 1, h: b64(staging.hashes[1] ?? "") }]);
      await send(newer, [{ i: 2, h: b64(elsewhere.hashes[2] ?? "") }]);
      const incidents = await tampered(newer.admin);
      expect(incidents).toHaveLength(1);
      expect(incidents[0]).toMatchObject({ build_id: newer.buildId, detection_count: 3 });
    });

    it("judges a stale report and a tampered file of one report apart", async () => {
      const older = await setUp();
      const newer = await setUp({ from: older, sameApp: true });
      await arm(newer);
      await send(newer, [
        { i: 1, h: b64(older.hashes[1] ?? "") },
        { i: 2, h: foreign("really") },
      ]);
      const [incident] = await tampered(newer.admin);
      expect(incident).toMatchObject({ detection_count: 1, artifact_path: "chunk-lazy.js" });
    });

    it("recent is the last 20 Builds or the last 30 days: an older Build beyond both explains nothing", async () => {
      expect(INTEGRITY_LIMITS).toMatchObject({ recentBuilds: 20, recentDays: 30 });
      const old = await setUp();
      // Within 30 days but 25 Builds back: still recent.
      clock.ms += MINUTE;
      for (let n = 0; n < 24; n++) await register(old.admin, manifestFor(old.appId, "production"));
      const current = await setUp({ from: old, sameApp: true });
      await arm(current);
      clock.ms += 29 * DAY;
      await send(current, [{ i: 0, h: b64(old.hashes[0] ?? "") }]);
      expect(await tampered(old.admin)).toEqual([]);
      // 31 days old and 25 Builds back: no longer recent.
      clock.ms += 2 * DAY;
      await send(current, [{ i: 1, h: b64(old.hashes[1] ?? "") }]);
      expect(await detectionCount(old.admin)).toBe(1);
      // 31 days old but among the last 20 Builds: recent.
      const quiet = await setUp();
      const next = await setUp({ from: quiet, sameApp: true });
      await arm(next);
      clock.ms += 31 * DAY;
      await send(next, [{ i: 2, h: b64(quiet.hashes[2] ?? "") }]);
      expect(await tampered(quiet.admin)).toEqual([]);
    });

    it("reads the recent Builds on every report: a Build registered a moment ago already explains its files", async () => {
      const s = await setUp();
      await arm(s);
      const next = manifestFor(s.appId, "production");
      const nextHash = next.artifacts.find((artifact) => artifact.path === "app.js")?.sha256 ?? "";
      await send(s, [{ i: 1, h: b64(nextHash) }], { peer: "198.51.100.1" });
      expect(await detectionCount(s.admin)).toBe(1);
      const other = await setUp({ from: s, sameApp: true });
      await arm(other);
      await register(s.admin, next);
      await send(other, [{ i: 1, h: b64(nextHash) }]);
      expect(await tampered(s.admin)).toHaveLength(1);
    });
  });

  describe("caches and lookups", () => {
    it("needs no lookup for a Build it saw registered; after a restart it looks a Build up once; an unknown Build too", async () => {
      const s = await setUp();
      const before = lookups;
      // The API's own recorder was told of the registration.
      for (let n = 0; n < 5; n++) await arm(s);
      expect(lookups).toBe(before);
      // A recorder that was not (a restarted process) looks it up once, then answers from memory.
      const fresh = make();
      for (let n = 0; n < 5; n++) await send(s, matching(s), { on: fresh });
      expect(lookups).toBe(before + 1);
      const ghost = { appId: s.appId, buildId: newId("bld") };
      for (let n = 0; n < 5; n++) await send(ghost, [{ i: 0, h: foreign("ghost") }], { on: fresh });
      expect(lookups).toBe(before + 2);
      // Ten minutes later both are looked up again.
      clock.ms += 10 * MINUTE;
      await send(s, matching(s), { on: fresh });
      await send(ghost, [{ i: 0, h: foreign("ghost") }], { on: fresh });
      expect(lookups).toBe(before + 4);
    });

    it("forgets an unknown Build the moment it is registered", async () => {
      const org = await createOrganization(api);
      const appId = (await createAppFor(api, org.admin_key.key)).app.id;
      const manifest = manifestFor(appId, "production");
      const s = { appId, buildId: manifest.build_id };
      const h = b64(manifest.artifacts.find((artifact) => artifact.path === PATHS[0])?.sha256 ?? "");
      // A page of the new deploy reports before the CLI's registration reaches the API.
      await send(s, [{ i: 0, h }]);
      expect(await firstMatchAt(s)).toBeNull();
      await register(org.admin_key.key, manifest);
      await send(s, [{ i: 0, h }]);
      expect(await firstMatchAt(s)).not.toBeNull();
    });

    it("caps the lookups of one reporter prefix per minute, whatever Apps it names", async () => {
      clock.ms += MINUTE;
      const s = await setUp();
      const fresh = make();
      const before = lookups;
      for (let n = 0; n <= LOOKUPS_PER_PREFIX_PER_MINUTE; n++) {
        await send({ appId: newId("app"), buildId: newId("bld") }, [{ i: 0, h: foreign("x") }], {
          on: fresh,
          peer: "192.0.2.5",
        });
      }
      expect(lookups).toBe(before + LOOKUPS_PER_PREFIX_PER_MINUTE);
      expect(fresh.dropped()).toMatchObject({ "unknown-build": LOOKUPS_PER_PREFIX_PER_MINUTE, "prefix-limit": 1 });
      // Another prefix is unaffected.
      await send(s, matching(s), { on: fresh, peer: "192.0.9.5" });
      expect(lookups).toBe(before + LOOKUPS_PER_PREFIX_PER_MINUTE + 1);
    });

    it("caps the lookups one App can cause, whatever the prefixes: 20 at once", async () => {
      clock.ms += MINUTE;
      const s = await setUp();
      const fresh = make();
      const before = lookups;
      for (let n = 0; n < LOOKUP_APP_BURST + 5; n++) {
        await send({ appId: s.appId, buildId: newId("bld") }, [{ i: 0, h: foreign("x") }], {
          on: fresh,
          peer: `192.0.${n}.5`,
        });
      }
      expect(lookups).toBe(before + LOOKUP_APP_BURST);
      expect(fresh.dropped()).toMatchObject({ "unknown-build": LOOKUP_APP_BURST, "app-limit": 5 });
    });

    it("forget() drops what it holds of an Organization, so its next report is looked up again", async () => {
      const s = await setUp();
      await arm(s);
      const before = lookups;
      await arm(s);
      expect(lookups).toBe(before);
      recorder.forget(s.organizationId);
      await arm(s);
      expect(lookups).toBe(before + 1);
    });
  });

  describe("caps (the Clone Beacon numbers; the per-Build caps are in integrity-review.test.ts)", () => {
    it("has the documented numbers", () => {
      expect(INTEGRITY_LIMITS).toMatchObject({ reportsPerHour: 600, newHashesPerHour: 20, hashesPerDay: 50 });
    });

    it("holds at most the configured reports of one Organization in flight; more are dropped", async () => {
      clock.ms += 2 * HOUR;
      const s = await setUp();
      const fresh = make({ maxInFlightPerOrg: 1 });
      await send(s, matching(s), { on: fresh });
      for (let n = 0; n < 3; n++) {
        fresh.report({
          appId: s.appId,
          report: { build: s.buildId, files: [{ i: 0, h: foreign(`busy-${n}`) }], skipped: 0 },
          originHeader: ORIGIN,
          address: PEER,
        });
      }
      await fresh.flush();
      expect(await detectionCount(s.admin)).toBe(1);
      expect(fresh.dropped().busy).toBe(2);
    });

    it("judges at most `maxPending` reports at once", async () => {
      const s = await setUp();
      const fresh = make({ maxPending: 2 });
      for (let n = 0; n < 5; n++) {
        fresh.report({
          appId: s.appId,
          report: { build: newId("bld"), files: [{ i: 0, h: foreign("p") }], skipped: 0 },
          originHeader: ORIGIN,
          address: `198.18.${n}.1`,
        });
      }
      await fresh.flush();
      expect(fresh.dropped()).toMatchObject({ "unknown-build": 2, busy: 3 });
    });
  });

  describe("log lines", () => {
    it("carry reasons, counts and ids only: never a hash, a path, an origin, an address or the App id", () => {
      const lines = recorderLog.lines.filter((line) => line.startsWith("integrity "));
      expect(lines.length).toBeGreaterThan(50);
      const shapes = [
        /^integrity dropped reason=[a-z-]+( build=bld_[0-9a-f]{24})?$/,
        /^integrity armed build=bld_[0-9a-f]{24}$/,
        /^integrity report organization=org_[0-9a-f]{24} build=bld_[0-9a-f]{24} recorded=[0-9]+( incident=inc_[0-9a-f]{24})?( dropped=[a-z-]+:[0-9]+(,[a-z-]+:[0-9]+)*)?$/,
      ];
      for (const line of lines)
        expect(
          shapes.some((shape) => shape.test(line)),
          line,
        ).toBe(true);
      expect(recorderLog.lines).toEqual(lines);
      const reasons = new Set(
        lines.flatMap((line) => [...line.matchAll(/(?:reason=|dropped=|,)([a-z-]+)/g)].map((m) => m[1])),
      );
      for (const reason of reasons) expect(INTEGRITY_DROP_REASONS).toContain(reason);
      // An unknown Build's id comes from the report alone: it is not logged.
      for (const line of lines.filter((l) => l.includes("reason=unknown-build"))) expect(line).not.toContain("build=");
      const text = lines.join("\n");
      for (const leak of ["shop.example", "203.0.113", "app_", "localhost", ".js"]) expect(text).not.toContain(leak);
    });
  });

  describe("alert content of the rule", () => {
    it("pins the alert mail", () => {
      const mail = alertMail({
        incident: EXAMPLE_TAMPER_INCIDENT,
        appName: "Storefront",
        consoleUrl: "https://console.example/",
      });
      expect(mail).toEqual({
        subject: "[Airverse] High: Tampered Build",
        body: [
          "Incident: Tampered Build",
          "Severity: High",
          "App: Storefront",
          "Environment: development",
          "Opened at: 2026-11-10 11:00:00 UTC",
          `Open in the Console: https://console.example/incidents/${EXAMPLE_TAMPER_INCIDENT.id}`,
          "",
          "You receive this mail because this address was confirmed for an alert channel of an Airverse Organization.",
          "",
        ].join("\n"),
      });
    });

    it("pins the webhook payload of the example Incident", () => {
      const payload = {
        type: "incident.opened",
        incident: EXAMPLE_TAMPER_INCIDENT,
        console_url: `https://console.example/incidents/${EXAMPLE_TAMPER_INCIDENT.id}`,
      };
      expect(JSON.parse(JSON.stringify(WebhookAlertPayloadSchema.parse(payload)))).toEqual({
        type: "incident.opened",
        incident: {
          id: "inc_0f1e2d3c4b5a69788796a5b4",
          app_id: "app_89abcdef0123456789abcdef",
          environment: "development",
          rule: "tampered-build",
          severity: "high",
          title: "Tampered Build",
          status: "open",
          ip_prefix: null,
          first_seen: "2026-11-10T11:00:00.000Z",
          last_seen: "2026-11-10T11:00:00.000Z",
          detection_count: 1,
          created_at: "2026-11-10T11:00:00.000Z",
          updated_at: "2026-11-10T11:00:00.000Z",
          canary_id: null,
          build_id: "bld_0123456789abcdef01234567",
          origin: null,
          advisory_id: null,
          artifact_path: "dist/index.js",
          observed_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          detections_capped: false,
        },
        console_url: "https://console.example/incidents/inc_0f1e2d3c4b5a69788796a5b4",
      });
    });
  });
});

describe("tamper detection: the attest hand-off", () => {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const exported = publicKey.export({ format: "jwk" });
  const JWK = { kty: "EC" as const, crv: "P-256" as const, x: String(exported.x), y: String(exported.y) };
  const JKT = jwkThumbprint(JWK);
  /** A well-formed thumbprint of some other key. */
  const OTHER_JKT = b64(sha("another key"));
  const DEVICE = "AAECAwQFBgcICQoLDA0ODw";
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let api: TestApi;
  let admin: string;
  let appId: string;
  let buildId: string;
  let hash: string;
  const handed: Parameters<IntegrityRecorder["report"]>[0][] = [];
  let peer = 0;
  const freshPeer = () => `198.${18 + Math.floor(++peer / 250)}.${peer % 250}.9`;

  const spy: IntegrityRecorder = {
    report: (request) => void handed.push(request),
    buildRegistered: () => {},
    flush: async () => {},
    forget: () => {},
    trackedBuilds: () => 0,
    dropped: () => ({}) as ReturnType<IntegrityRecorder["dropped"]>,
  };

  async function challenge(target: TestApi, app: string, address: string): Promise<string> {
    const res = await target.app.request("/v1/attest/challenge", {
      method: "POST",
      headers: { "content-type": "application/json", [PEER_HEADER]: address },
      body: JSON.stringify({ app_id: app }),
    });
    expect(res.status).toBe(200);
    return ChallengeResponseSchema.parse(await res.json()).nonce;
  }

  interface HandshakeOptions {
    origin?: string;
    address?: string;
    app?: string;
    break?: "nonce" | "jkt";
  }

  async function attestWith(
    target: TestApi,
    nonce: string,
    patch: Record<string, unknown>,
    options: HandshakeOptions = {},
  ): Promise<Response> {
    return target.app.request("/v1/attest", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [PEER_HEADER]: options.address ?? freshPeer(),
        ...(options.origin === undefined ? {} : { origin: options.origin }),
      },
      body: JSON.stringify({
        app_id: options.app ?? appId,
        nonce: options.break === "nonce" ? "0".repeat(32) : nonce,
        device: DEVICE,
        signals: [],
        cnf: { jkt: options.break === "jkt" ? OTHER_JKT : JKT, jwk: JWK },
        ...patch,
      }),
    });
  }

  async function handshake(
    target: TestApi,
    patch: Record<string, unknown>,
    options: HandshakeOptions = {},
  ): Promise<Response> {
    const address = options.address ?? freshPeer();
    const nonce = await challenge(target, options.app ?? appId, address);
    return attestWith(target, nonce, patch, { ...options, address });
  }

  const claimsOf = (token: string) => JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());

  beforeAll(async () => {
    api = await makeTestApi({ now, integrity: spy, clientAddress: (c) => c.req.header(PEER_HEADER) });
    const org = await createOrganization(api);
    admin = org.admin_key.key;
    appId = (await createAppFor(api, admin)).app.id;
    buildId = newId("bld");
    hash = sha("app");
    const manifest: BuildManifest = {
      ...EXAMPLE_BUILD_MANIFEST,
      build_id: buildId,
      app_id: appId,
      environment: "production",
      artifacts: [{ path: "app.js", sha256: hash, bytes: 10 }],
      integrity: { files: ["app.js"] },
    };
    expect((await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)))).status).toBe(201);
  });
  afterAll(async () => {
    await api.close();
  });

  const integrity = (h = b64(sha("changed"))) => ({ build: buildId, files: [{ i: 0, h }], skipped: 0 });

  it("hands the report to the recorder with the App of the handshake, the Origin header and the caller's address", async () => {
    handed.length = 0;
    const res = await handshake(api, { integrity: integrity() }, { origin: ORIGIN, address: PEER });
    expect(res.status).toBe(200);
    expect(handed).toEqual([{ appId, report: integrity(), originHeader: ORIGIN, address: PEER }]);
  });

  it("hands nothing over without a report, or with one that does not parse; the attestation succeeds all the same", async () => {
    handed.length = 0;
    expect((await handshake(api, {}, { origin: ORIGIN })).status).toBe(200);
    expect(
      (await handshake(api, { integrity: { build: "nope", files: [], skipped: 0 } }, { origin: ORIGIN })).status,
    ).toBe(200);
    expect(
      (await handshake(api, { integrity: { build: buildId, files: [{ i: 99, h: "x" }], skipped: 0 } })).status,
    ).toBe(200);
    expect(handed).toEqual([]);
  });

  it("only a handshake that passed the nonce, the key binding and the App limiter reaches the recorder", async () => {
    handed.length = 0;
    await expectProblem(await handshake(api, { integrity: integrity() }, { origin: ORIGIN, break: "nonce" }), 400);
    await expectProblem(await handshake(api, { integrity: integrity() }, { origin: ORIGIN, break: "jkt" }), 400);
    expect(handed).toEqual([]);
    // The App's minute is full: 429, and nothing is handed over.
    clock.ms += MINUTE;
    const limited = await makeTestApi({ now, integrity: spy, clientAddress: (c) => c.req.header(PEER_HEADER) });
    try {
      const org = await createOrganization(limited);
      const app = (await createAppFor(limited, org.admin_key.key)).app.id;
      // 600 requests per App and minute: 301 challenges, then 299 attestations pass and the 300th is refused.
      const nonces: string[] = [];
      for (let n = 0; n < 301; n++) nonces.push(await challenge(limited, app, freshPeer()));
      const statuses: number[] = [];
      for (const nonce of nonces.slice(0, 300)) {
        statuses.push((await attestWith(limited, nonce, { integrity: integrity() }, { app, origin: ORIGIN })).status);
      }
      expect(statuses.filter((status) => status === 200)).toHaveLength(299);
      expect(statuses.at(-1)).toBe(429);
      expect(handed).toHaveLength(299);
      handed.length = 0;
    } finally {
      await limited.close();
    }
  });

  it("changes neither the token's claims nor the verdict nor the response: a report is invisible to the client", async () => {
    clock.ms += MINUTE;
    const plain = await handshake(api, {}, { origin: ORIGIN });
    const reported = await handshake(api, { integrity: integrity() }, { origin: ORIGIN });
    const forged = await handshake(
      api,
      { integrity: integrity(), signals: ["tamper.integrity_mismatch"] },
      { origin: ORIGIN },
    );
    const bodies = await Promise.all(
      [plain, reported, forged].map(async (res) => AttestResponseSchema.parse(await res.json())),
    );
    const [a, b, c] = bodies.map((body) => claimsOf(body.token));
    for (const claims of [a, b, c]) {
      AttestationClaimsSchema.parse(claims);
      expect(Object.keys(claims).sort()).toEqual([
        "aud",
        "cnf",
        "exp",
        "iat",
        "iss",
        "jti",
        "pv",
        "risk",
        "sig",
        "sub",
        "verdict",
      ]);
      expect(claims).toMatchObject({ verdict: "trusted", risk: 5, sig: [] });
    }
    expect({ ...b, jti: a.jti }).toEqual(a);
    expect({ ...c, jti: a.jti }).toEqual(a);
    for (const body of bodies) expect(Object.keys(body).sort()).toEqual(["expires_at", "token"]);
    expect([...plain.headers.keys()].sort()).toEqual([...reported.headers.keys()].sort());
  });

  it("meters the device as before: one reference per device and month, report or not", async () => {
    const devices = () =>
      api.db.owner(async (q) => {
        const { rows } = await q.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM usage_devices WHERE app_id = $1",
          [appId],
        );
        return rows[0]?.n;
      });
    const before = await devices();
    expect(before).toBe(1);
    await handshake(api, { integrity: integrity() }, { origin: ORIGIN });
    expect(await devices()).toBe(before);
  });

  it("adds no route and leaves /v1/attest in SLO-01", () => {
    expect(classifyRoute("POST", "/v1/attest")).toEqual({ slo: "SLO-01", variant: "all" });
    const routes = api.app.routes.filter((route) => route.path.includes("integrity") || route.path.includes("tamper"));
    expect(routes).toEqual([]);
  });

  it("answers without waiting for the recorder: a recorder whose database never answers delays nothing", async () => {
    clock.ms += MINUTE;
    const stalled: Db = { tx: () => new Promise<never>(() => {}), close: async () => {} };
    let begun = 0;
    const slow = createIntegrityRecorder({
      db: {
        tx: (scope, fn) => {
          begun++;
          return stalled.tx(scope, fn);
        },
        close: stalled.close,
      },
      notifier: { incidentOpened: () => {} },
      now,
      logger: captureLogger(),
    });
    const other = await makeTestApi({
      db: api.db,
      now,
      integrity: slow,
      clientAddress: (c) => c.req.header(PEER_HEADER),
    });
    const started = performance.now();
    const res = await handshake(other, { integrity: integrity() }, { origin: ORIGIN });
    expect(res.status).toBe(200);
    AttestResponseSchema.parse(await res.json());
    expect(performance.now() - started).toBeLessThan(2_000);
    // The recorder did start on the report, and is still waiting.
    expect(begun).toBe(1);
    expect(slow.dropped().failed).toBe(0);
  });

  it("a real recorder behind POST /v1/attest: registered Build, matching report, then a mismatch opens the Incident", async () => {
    clock.ms += MINUTE;
    const db = await openDb();
    const real = createIntegrityRecorder({ db, notifier: { incidentOpened: () => {} }, now, logger: captureLogger() });
    const full = await makeTestApi({ db, now, integrity: real, clientAddress: (c) => c.req.header(PEER_HEADER) });
    try {
      const org = await createOrganization(full);
      const app = (await createAppFor(full, org.admin_key.key)).app.id;
      const manifest: BuildManifest = {
        ...EXAMPLE_BUILD_MANIFEST,
        build_id: buildId,
        app_id: app,
        environment: "production",
        artifacts: [{ path: "app.js", sha256: hash, bytes: 10 }],
        integrity: { files: ["app.js"] },
      };
      // Registered through the route: the route tells the recorder (the unknown-Build cache is cleared).
      await handshake(full, { integrity: integrity(b64(hash)) }, { origin: ORIGIN, app });
      await real.flush();
      expect(
        (await full.app.request(`/v1/apps/${app}/builds`, json({ manifest }, bearer(org.admin_key.key)))).status,
      ).toBe(201);
      await handshake(full, { integrity: integrity(b64(hash)) }, { origin: ORIGIN, app });
      await real.flush();
      await handshake(full, { integrity: integrity() }, { origin: ORIGIN, app });
      await real.flush();
      const res = await full.app.request("/v1/incidents", { headers: bearer(org.admin_key.key) });
      const incidents = ListIncidentsResponseSchema.parse(await res.json()).incidents;
      expect(incidents).toHaveLength(1);
      expect(incidents[0]).toMatchObject({
        rule: "tampered-build",
        build_id: buildId,
        artifact_path: "app.js",
        observed_sha256: sha("changed"),
      });
    } finally {
      await full.close();
    }
  });
});
