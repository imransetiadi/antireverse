import { randomBytes } from "node:crypto";
import {
  BEACON_LIMITS,
  type BuildManifest,
  BuildResponseSchema,
  CONTAINMENT_TTLS,
  DETECTION_RULES,
  type Environment,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_SHIELD_EVENT,
  type Incident,
  IncidentDetailResponseSchema,
  IncidentSchema,
  ListBuildsResponseSchema,
  ListIncidentsResponseSchema,
} from "@antireverse/protocol";
import { deriveBeaconToken, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Db, openDb } from "../src/db/db.ts";
import {
  type BeaconRecorder,
  type BeaconRecorderDeps,
  createBeaconRecorder,
  dotlessOrigin,
} from "../src/detect/beacon.ts";
import { matchingRules, ruleConditionSql } from "../src/detect/rules.ts";
import { addressPrefix } from "../src/prefix.ts";
import { CONFLICT_DETAILS } from "../src/problem.ts";
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

// Slice 10, API lane: the public Clone Beacon endpoint, its limits, and the `clone-origin` Incidents it opens.

const T0 = Date.parse("2026-11-11T12:00:00.000Z");
const HOUR = 3_600_000;
const ALLOWED = "https://shop.example";
const PEER = "203.0.113.77";
const PEER_PREFIX = "203.0.113.0/24";
const PEER_HEADER = "x-test-peer";
const UNKNOWN_APP = "app_000000000000000000000000";

interface Setup {
  admin: string;
  organizationId: string;
  appId: string;
  buildId: string;
  token: string;
  environment: Environment;
}

describe("Clone Beacon", () => {
  let db: Db;
  let api: TestApi;
  let recorder: BeaconRecorder;
  let recorderLog: CapturedLogger;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const opened: { incident: Incident; organizationId: string }[] = [];
  const bodies: string[] = [];
  const tokens: string[] = [];
  let versions = 0;
  /** The App each registered token was planted for; a report names it as `a`. */
  const appOfToken = new Map<string, string>();
  const appOf = (token: string) => appOfToken.get(token) ?? UNKNOWN_APP;

  async function request(path: string, init: RequestInit = {}): Promise<Response> {
    const res = await api.app.request(path, init);
    bodies.push(await res.clone().text());
    return res;
  }

  /** An App with one registered Build carrying a beacon; a fresh Organization unless `admin` is given. */
  async function setUp(
    options: { admin?: string; organizationId?: string; appId?: string; environment?: Environment } = {},
  ): Promise<Setup> {
    let admin = options.admin;
    let organizationId = options.organizationId;
    if (admin === undefined || organizationId === undefined) {
      const org = await createOrganization(api, `Org ${randomBytes(3).toString("hex")}`);
      admin = org.admin_key.key;
      organizationId = org.organization.id;
    }
    const appId = options.appId ?? (await createAppFor(api, admin)).app.id;
    const environment = options.environment ?? "production";
    versions++;
    const version = `1.0.${versions}`;
    const token = deriveBeaconToken(1, { appId, version });
    tokens.push(token);
    appOfToken.set(token, appId);
    const manifest: BuildManifest = {
      ...EXAMPLE_BUILD_MANIFEST,
      build_id: newId("bld"),
      app_id: appId,
      environment,
      version,
      beacon: { token, origins: [ALLOWED] },
    };
    const res = await request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)));
    expect(res.status).toBe(201);
    return { admin, organizationId, appId, buildId: manifest.build_id, token, environment };
  }

  /** POSTs a raw report and waits until the recorder has finished with it. */
  async function post(
    body: NonNullable<RequestInit["body"]> | null,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    const res = await request("/v1/beacon", { method: "POST", headers, body });
    await recorder.flush();
    return res;
  }

  /** A report as a browser's sendBeacon sends it: text/plain, Origin header equal to `o`. */
  const report = (token: string, origin: string, peer = PEER) =>
    post(JSON.stringify({ a: appOf(token), t: token, o: origin }), {
      "content-type": "text/plain;charset=UTF-8",
      origin,
      [PEER_HEADER]: peer,
    });

  async function incidentsOf(admin: string): Promise<Incident[]> {
    const res = await request("/v1/incidents", { headers: bearer(admin) });
    expect(res.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await res.json()).incidents;
  }

  const clones = async (admin: string) => (await incidentsOf(admin)).filter((i) => i.rule === "clone-origin");

  beforeAll(async () => {
    db = await openDb();
    recorderLog = captureLogger();
    recorder = createBeaconRecorder({
      db,
      notifier: { incidentOpened: (incident, organizationId) => opened.push({ incident, organizationId }) },
      now,
      logger: recorderLog,
    });
    api = await makeTestApi({ db, now, beacon: recorder, clientAddress: (c) => c.req.header(PEER_HEADER) });
  });
  afterAll(async () => {
    await api.close();
  });

  describe("the endpoint reveals nothing (Review Focus 2)", () => {
    it("answers every report 204 with an empty body and the same headers; only the valid one records", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      const before = opened.length;
      const valid = "https://valid.example";
      const unknownToken = `bcn_${randomBytes(12).toString("hex")}`;
      const big = JSON.stringify({ a: appOf(s.token), t: s.token, o: "https://big.example", pad: "x".repeat(2_000) });
      const cases: [string, NonNullable<RequestInit["body"]> | null, Record<string, string>][] = [
        [
          "valid",
          JSON.stringify({ a: appOf(s.token), t: s.token, o: valid }),
          { "content-type": "text/plain;charset=UTF-8", origin: valid },
        ],
        [
          "unknown token",
          JSON.stringify({ a: appOf(unknownToken), t: unknownToken, o: "https://unknown.example" }),
          { "content-type": "text/plain", origin: "https://unknown.example" },
        ],
        ["malformed JSON", "{ not json", { "content-type": "application/json", origin: "https://bad.example" }],
        ["oversize", big, { "content-type": "application/json", origin: "https://big.example" }],
        [
          "wrong Origin header",
          JSON.stringify({ a: appOf(s.token), t: s.token, o: "https://wrong.example" }),
          { "content-type": "text/plain", origin: "https://other.example" },
        ],
        ["missing Origin header", JSON.stringify({ a: appOf(s.token), t: s.token, o: "https://missing.example" }), {}],
        [
          "local origin",
          JSON.stringify({ a: appOf(s.token), t: s.token, o: "http://localhost:8080" }),
          { "content-type": "text/plain", origin: "http://localhost:8080" },
        ],
        [
          "private address origin",
          JSON.stringify({ a: appOf(s.token), t: s.token, o: "http://192.168.1.10" }),
          { "content-type": "text/plain", origin: "http://192.168.1.10" },
        ],
        [
          "allowed origin",
          JSON.stringify({ a: appOf(s.token), t: s.token, o: ALLOWED }),
          { "content-type": "text/plain", origin: ALLOWED },
        ],
        [
          "non-canonical origin",
          JSON.stringify({ a: appOf(s.token), t: s.token, o: "HTTPS://Noncanon.example:443/" }),
          { "content-type": "text/plain", origin: "HTTPS://Noncanon.example:443/" },
        ],
        [
          "form content-type",
          JSON.stringify({ a: appOf(s.token), t: s.token, o: "https://form.example" }),
          { "content-type": "application/x-www-form-urlencoded", origin: "https://other-form.example" },
        ],
        ["no body", null, { origin: "https://empty.example" }],
        ["JSON that is not a report", JSON.stringify([1, 2]), { origin: "https://array.example" }],
      ];
      const seen: { name: string; status: number; headers: [string, string][]; body: string }[] = [];
      for (const [name, body, headers] of cases) {
        const res = await post(body, { ...headers, [PEER_HEADER]: PEER });
        seen.push({ name, status: res.status, headers: [...res.headers], body: await res.text() });
      }
      for (const response of seen) {
        expect(response.status, response.name).toBe(204);
        expect(response.body, response.name).toBe("");
        expect(response.headers, response.name).toEqual(seen[0]?.headers);
      }
      expect(Object.fromEntries(seen[0]?.headers ?? [])).toEqual({ "cache-control": "no-store" });

      const found = await clones(s.admin);
      expect(found.map((incident) => incident.origin)).toEqual([valid]);
      expect(opened.slice(before).map((call) => call.incident.origin)).toEqual([valid]);
    });

    it("counts a valid report sent as application/json or with no content type alike", async () => {
      const s = await setUp();
      await post(JSON.stringify({ a: appOf(s.token), t: s.token, o: "https://json.example" }), {
        "content-type": "application/json",
        origin: "https://json.example",
      });
      await post(JSON.stringify({ a: appOf(s.token), t: s.token, o: "https://none.example" }), {
        origin: "https://none.example",
      });
      expect((await clones(s.admin)).map((incident) => incident.origin).sort()).toEqual([
        "https://json.example",
        "https://none.example",
      ]);
    });

    it("routes POST only: GET /v1/beacon is the usual 404 problem", async () => {
      const res = await request("/v1/beacon");
      await expectProblem(res, 404);
    });
  });

  describe("clone Incidents", () => {
    it("opens one High 'Clone detected' Incident naming the origin and the Build, with no prefix, and alerts once", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      const before = opened.length;
      const res = await report(s.token, "https://clone.example");
      expect(res.status).toBe(204);

      const [incident, ...rest] = await clones(s.admin);
      expect(rest).toEqual([]);
      expect(IncidentSchema.parse(incident)).toMatchObject({
        app_id: s.appId,
        environment: s.environment,
        rule: "clone-origin",
        title: "Clone detected",
        severity: "high",
        status: "open",
        ip_prefix: null,
        canary_id: null,
        build_id: s.buildId,
        origin: "https://clone.example",
        detection_count: 1,
        first_seen: now().toISOString(),
        last_seen: now().toISOString(),
      });
      const alerts = opened.slice(before);
      expect(alerts).toHaveLength(1);
      expect(alerts[0]?.organizationId).toBe(s.organizationId);
      expect(alerts[0]?.incident).toMatchObject({ origin: "https://clone.example", build_id: s.buildId });

      const detail = await request(`/v1/incidents/${incident?.id}`, { headers: bearer(s.admin) });
      expect(detail.status).toBe(200);
      const parsed = IncidentDetailResponseSchema.parse(await detail.json());
      expect(parsed.evidence).toEqual([]);
      expect(parsed.actors).toEqual([]);
      expect(parsed.containments).toEqual([]);
      expect(parsed.detections).toHaveLength(1);
      expect(parsed.detections[0]).toMatchObject({
        rule: "clone-origin",
        app_id: s.appId,
        environment: s.environment,
        origin: "https://clone.example",
        ip_prefix: PEER_PREFIX,
        canary_id: null,
        count: 1,
        detected_at: now().toISOString(),
      });
    });

    it("groups by origin: a second origin opens its own Incident; another Build of the same App joins by origin", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      const second = await setUp({ admin: s.admin, organizationId: s.organizationId, appId: s.appId });
      const before = opened.length;
      await report(s.token, "https://one.example");
      await report(s.token, "https://two.example");
      await report(second.token, "https://one.example");
      const found = await clones(s.admin);
      const byOrigin = Object.fromEntries(found.map((incident) => [incident.origin, incident]));
      expect(Object.keys(byOrigin).sort()).toEqual(["https://one.example", "https://two.example"]);
      expect(byOrigin["https://one.example"]?.detection_count).toBe(2);
      expect(byOrigin["https://one.example"]?.build_id).toBe(s.buildId);
      expect(byOrigin["https://two.example"]?.detection_count).toBe(1);
      expect(opened.slice(before)).toHaveLength(2);
    });

    it("another Environment of the same App is another group", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      const staging = await setUp({
        admin: s.admin,
        organizationId: s.organizationId,
        appId: s.appId,
        environment: "staging",
      });
      await report(s.token, "https://env.example");
      await report(staging.token, "https://env.example");
      const found = await clones(s.admin);
      expect(found.map((incident) => incident.environment).sort()).toEqual(["production", "staging"]);
    });

    it("opens a new Incident after the open one was resolved", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      await report(s.token, "https://again.example");
      const [first] = await clones(s.admin);
      const patch = await request(`/v1/incidents/${first?.id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json", ...bearer(s.admin) },
        body: JSON.stringify({ status: "resolved" }),
      });
      expect(patch.status).toBe(200);
      clock.ms += HOUR;
      await report(s.token, "https://again.example");
      const found = await clones(s.admin);
      expect(found).toHaveLength(2);
      expect(found.filter((incident) => incident.status === "open")).toHaveLength(1);
    });

    it("refuses any containment on a clone Incident with 409", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      await report(s.token, "https://contain.example");
      const [incident] = await clones(s.admin);
      const path = `/v1/incidents/${incident?.id}/containments`;
      const prefix = await request(
        path,
        json(
          { target: { kind: "prefix" }, ttl_s: CONTAINMENT_TTLS[0], confirm_prefix: PEER_PREFIX },
          withReason(bearer(s.admin)),
        ),
      );
      const problem = await expectProblem(prefix, 409);
      expect(problem.reason).toBe("containment-not-applicable");
      expect(problem.detail).toBe(CONFLICT_DETAILS["containment-not-applicable"]);
      const actor = await request(
        path,
        json(
          { target: { kind: "actor", ip_hash: `iph_${"a".repeat(32)}` }, ttl_s: CONTAINMENT_TTLS[0] },
          withReason(bearer(s.admin)),
        ),
      );
      expect((await expectProblem(actor, 409)).reason).toBe("containment-not-applicable");
      const detail = IncidentDetailResponseSchema.parse(
        await (await request(`/v1/incidents/${incident?.id}`, { headers: bearer(s.admin) })).json(),
      );
      expect(detail.containments).toEqual([]);
    });
  });

  describe("limits (Review Focus 2)", () => {
    it("records one Detection per Build and origin per hour; after the hour a new Detection joins the open Incident", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      const before = opened.length;
      await report(s.token, "https://hourly.example");
      clock.ms += HOUR - 1;
      await report(s.token, "https://hourly.example");
      let [incident] = await clones(s.admin);
      expect(incident?.detection_count).toBe(1);
      clock.ms += 1;
      await report(s.token, "https://hourly.example");
      const found = await clones(s.admin);
      expect(found).toHaveLength(1);
      [incident] = found;
      expect(incident?.detection_count).toBe(2);
      expect(opened.slice(before)).toHaveLength(1);
      expect(recorderLog.lines).toContainEqual(`beacon dropped reason=repeat build=${s.buildId}`);
    });

    it(`counts at most ${BEACON_LIMITS.newOriginsPerHour} new origins per Build per hour`, async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      for (let i = 0; i <= BEACON_LIMITS.newOriginsPerHour; i++) await report(s.token, `https://n${i}.example`);
      const found = await clones(s.admin);
      expect(found).toHaveLength(BEACON_LIMITS.newOriginsPerHour);
      expect(found.map((incident) => incident.origin)).not.toContain(
        `https://n${BEACON_LIMITS.newOriginsPerHour}.example`,
      );
      expect(recorderLog.lines).toContainEqual(`beacon dropped reason=origin-limit build=${s.buildId}`);
      clock.ms += HOUR;
      await report(s.token, "https://later.example");
      expect(await clones(s.admin)).toHaveLength(BEACON_LIMITS.newOriginsPerHour + 1);
    });

    it(`counts at most ${BEACON_LIMITS.reportsPerHour} reports per Build per hour`, async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      for (let i = 0; i < BEACON_LIMITS.reportsPerHour; i++) await report(s.token, "https://flood.example");
      await report(s.token, "https://after-flood.example");
      const found = await clones(s.admin);
      expect(found.map((incident) => incident.origin)).toEqual(["https://flood.example"]);
      expect(recorderLog.lines).toContainEqual(`beacon dropped reason=report-limit build=${s.buildId}`);
      clock.ms += HOUR;
      await report(s.token, "https://after-flood.example");
      expect(await clones(s.admin)).toHaveLength(2);
    });

    it("keeps the limits of one Build apart from another's", async () => {
      clock.ms += 10 * HOUR;
      const a = await setUp();
      const b = await setUp();
      for (let i = 0; i < BEACON_LIMITS.newOriginsPerHour; i++) await report(a.token, `https://a${i}.example`);
      await report(b.token, "https://b.example");
      expect(await clones(b.admin)).toHaveLength(1);
    });

    it("bounds its bookkeeping: at most maxBuilds Builds are tracked, the least recently reported evicted", async () => {
      clock.ms += 10 * HOUR;
      const small = createBeaconRecorder({
        db,
        notifier: { incidentOpened: () => {} },
        now,
        logger: captureLogger(),
        maxBuilds: 2,
        maxBuildsPerOrg: 2,
      });
      const smallApi = await makeTestApi({ db, now, beacon: small });
      const builds = [await setUp(), await setUp(), await setUp()];
      for (const s of builds) {
        await smallApi.app.request("/v1/beacon", {
          method: "POST",
          headers: { origin: "https://bounded.example" },
          body: JSON.stringify({ a: appOf(s.token), t: s.token, o: "https://bounded.example" }),
        });
        await small.flush();
        expect(small.trackedBuilds()).toBeLessThanOrEqual(2);
      }
      expect(small.trackedBuilds()).toBe(2);
    });

    it("keeps at most maxBuildsPerOrg Builds of one Organization, never evicting another Organization's", async () => {
      clock.ms += 10 * HOUR;
      const log = captureLogger();
      const small = createBeaconRecorder({
        db,
        notifier: { incidentOpened: () => {} },
        now,
        logger: log,
        maxBuilds: 10,
        maxBuildsPerOrg: 1,
      });
      const smallApi = await makeTestApi({ db, now, beacon: small });
      const other = await setUp();
      const send = async (token: string, origin: string) => {
        await smallApi.app.request("/v1/beacon", {
          method: "POST",
          headers: { origin },
          body: JSON.stringify({ a: appOf(token), t: token, o: origin }),
        });
        await small.flush();
      };
      await send(other.token, "https://kept.example");
      const s = await setUp();
      const sibling = await setUp({ admin: s.admin, organizationId: s.organizationId, appId: s.appId });
      await send(s.token, "https://x.example");
      await send(sibling.token, "https://x.example");
      expect(small.trackedBuilds()).toBe(2);
      // The other Organization's Build kept its state: a repeat within the hour is still a repeat.
      await send(other.token, "https://kept.example");
      expect(log.lines).toContainEqual(`beacon dropped reason=repeat build=${other.buildId}`);
    });
  });

  describe("unknown tokens", () => {
    /** The test database, counting the token lookups made through it. */
    function countingDb() {
      const counter = { lookups: 0 };
      const counted: Db = {
        tx: (scope, fn) =>
          db.tx(scope, (q) =>
            fn({
              query: (sql, params) => {
                if (sql.includes("beacon_lookup_token")) counter.lookups++;
                return q.query(sql, params);
              },
            }),
          ),
        close: () => db.close(),
      };
      return { counter, counted };
    }

    async function recorderWith(options: Partial<BeaconRecorderDeps> = {}) {
      const { counter, counted } = countingDb();
      const log = captureLogger();
      const own = createBeaconRecorder({
        db: counted,
        notifier: { incidentOpened: () => {} },
        now,
        logger: log,
        ...options,
      });
      const ownApi = await makeTestApi({ db, now, beacon: own, clientAddress: (c) => c.req.header(PEER_HEADER) });
      /** Sends one report without waiting for the recorder. */
      const fire = (token: string, origin = "https://bogus.example", peer = PEER) =>
        ownApi.app.request("/v1/beacon", {
          method: "POST",
          headers: { origin, [PEER_HEADER]: peer },
          body: JSON.stringify({ a: appOf(token), t: token, o: origin }),
        });
      const send = async (token: string, origin = "https://bogus.example", peer = PEER) => {
        const res = await fire(token, origin, peer);
        expect(res.status).toBe(204);
        await own.flush();
      };
      return { counter, own, ownApi, send, fire, log };
    }

    const bogus = () => `bcn_${randomBytes(12).toString("hex")}`;

    it("looks a flooded unknown token up once per 10 minutes", async () => {
      const { counter, send } = await recorderWith();
      const token = bogus();
      for (let i = 0; i < 50; i++) await send(token);
      expect(counter.lookups).toBe(1);
      clock.ms += 10 * 60_000 - 1;
      await send(token);
      expect(counter.lookups).toBe(1);
      clock.ms += 1;
      await send(token);
      expect(counter.lookups).toBe(2);
    });

    it("bounds the cache of unknown tokens, evicting the oldest", async () => {
      const { counter, send } = await recorderWith({ maxUnknownTokens: 2 });
      const [a, b, c] = [bogus(), bogus(), bogus()];
      for (const token of [a, b, c]) await send(token);
      expect(counter.lookups).toBe(3);
      await send(c);
      await send(b);
      expect(counter.lookups).toBe(3);
      await send(a);
      expect(counter.lookups).toBe(4);
    });

    it("keeps a genuine report working through a flood of bogus tokens from one prefix (F1)", async () => {
      clock.ms += 10 * HOUR;
      const victim = await setUp();
      const { own, fire } = await recorderWith();
      const flood = Array.from({ length: 1_500 }, () => fire(bogus(), "https://flood.example", "198.51.100.7"));
      const genuine = fire(victim.token, "https://victim.example", "192.0.2.10");
      const answers = await Promise.all([...flood, genuine]);
      expect(answers.every((res) => res.status === 204)).toBe(true);
      await own.flush();
      expect((await clones(victim.admin)).map((incident) => incident.origin)).toEqual(["https://victim.example"]);
    });

    it("caps lookups per reporter prefix per minute and in all, so known tokens are answered from the cache (F1)", async () => {
      clock.ms += 10 * HOUR;
      const victim = await setUp();
      const { own, fire, send, counter, log } = await recorderWith();
      // Warm: the victim's token is now known, and needs no lookup again.
      await send(victim.token, "https://warm.example", "192.0.2.10");
      const warm = counter.lookups;
      expect(warm).toBe(1);
      // One prefix: at most 60 lookups in a minute.
      await Promise.all(Array.from({ length: 100 }, () => fire(bogus(), "https://p.example", "198.51.100.7")));
      await own.flush();
      expect(counter.lookups - warm).toBe(60);
      expect(log.lines).toContainEqual("beacon dropped reason=prefix-limit");
      // Many prefixes, a minute later: the global bucket (burst 200) bounds the lookups.
      clock.ms += 60_000;
      const spread = Array.from({ length: 1_500 }, (_, i) =>
        fire(bogus(), "https://spread.example", `10.${i >> 8}.${i & 255}.1`),
      );
      const genuine = fire(victim.token, "https://victim2.example", "192.0.2.10");
      await Promise.all([...spread, genuine]);
      await own.flush();
      expect(counter.lookups - warm - 60).toBeLessThanOrEqual(200);
      expect(log.lines).toContainEqual("beacon dropped reason=busy");
      expect((await clones(victim.admin)).map((incident) => incident.origin).sort()).toEqual([
        "https://victim2.example",
        "https://warm.example",
      ]);
    });

    it("caps the reports in flight per Organization, not only in all (F1)", async () => {
      clock.ms += 10 * HOUR;
      const x = await setUp();
      const x2 = await setUp({ admin: x.admin, organizationId: x.organizationId, appId: x.appId });
      const y = await setUp();
      const { own, fire, log } = await recorderWith({ maxInFlightPerOrg: 1 });
      await Promise.all([
        fire(x.token, "https://x1.example"),
        fire(x2.token, "https://x2.example"),
        fire(y.token, "https://y.example"),
      ]);
      await own.flush();
      expect(await clones(x.admin)).toHaveLength(1);
      expect(await clones(y.admin)).toHaveLength(1);
      expect(log.lines.some((line) => line.startsWith("beacon dropped reason=busy build="))).toBe(true);
    });

    it("counts a token reported before its Build was registered as soon as the Build is registered", async () => {
      clock.ms += 10 * HOUR;
      const { send, ownApi } = await recorderWith();
      const org = await createOrganization(ownApi, "Early reports");
      const appId = (await createAppFor(ownApi, org.admin_key.key)).app.id;
      const token = deriveBeaconToken(1, { appId, version: "9.9.9" });
      tokens.push(token);
      appOfToken.set(token, appId);
      await send(token, "https://early.example");
      const manifest: BuildManifest = {
        ...EXAMPLE_BUILD_MANIFEST,
        build_id: newId("bld"),
        app_id: appId,
        environment: "production",
        version: "9.9.9",
        beacon: { token, origins: [ALLOWED] },
      };
      const res = await ownApi.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(org.admin_key.key)));
      expect(res.status).toBe(201);
      await send(token, "https://early.example");
      expect((await clones(org.admin_key.key)).map((incident) => incident.origin)).toEqual(["https://early.example"]);
    });
  });

  describe("trailing dots and App Environment limits (F2, F3)", () => {
    it("treats a host with one trailing dot as its dotless form when checking allowed origins (F2)", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      await report(s.token, "https://shop.example.");
      await report(s.token, "http://localhost.:3000");
      await report(s.token, "http://app.test.");
      expect(await clones(s.admin)).toEqual([]);
      // The port still counts: another port is another origin.
      await report(s.token, "https://shop.example.:8443");
      expect((await clones(s.admin)).map((incident) => incident.origin)).toEqual(["https://shop.example:8443"]);
    });

    it("groups both spellings of a host, with and without one trailing dot, as one dotless origin", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      const before = opened.length;
      await report(s.token, "https://dot.example.");
      await report(s.token, "https://dot.example");
      let found = await clones(s.admin);
      expect(found.map((incident) => [incident.origin, incident.detection_count])).toEqual([
        ["https://dot.example", 1],
      ]);
      // One Detection per Build and origin per hour: the second spelling is the same origin, a repeat.
      expect(recorderLog.lines).toContainEqual(`beacon dropped reason=repeat build=${s.buildId}`);
      clock.ms += HOUR;
      await report(s.token, "https://dot.example.");
      found = await clones(s.admin);
      expect(found.map((incident) => [incident.origin, incident.detection_count])).toEqual([
        ["https://dot.example", 2],
      ]);
      const detail = IncidentDetailResponseSchema.parse(
        await (await request(`/v1/incidents/${found[0]?.id}`, { headers: bearer(s.admin) })).json(),
      );
      expect(detail.detections.map((detection) => detection.origin)).toEqual([
        "https://dot.example",
        "https://dot.example",
      ]);
      expect(opened.slice(before)).toHaveLength(1);
    });

    it("removes exactly one trailing host dot and keeps the port", () => {
      expect(dotlessOrigin("https://x.example.")).toBe("https://x.example");
      expect(dotlessOrigin("https://x.example.:8443")).toBe("https://x.example:8443");
      expect(dotlessOrigin("https://x.example")).toBe("https://x.example");
      expect(dotlessOrigin("https://x.example..")).toBe("https://x.example.");
      expect(dotlessOrigin("https://[2001:db8::1]:8443")).toBe("https://[2001:db8::1]:8443");
      expect(dotlessOrigin("https://.")).toBe("https://.");
    });

    it("spends one new-origin slot for both spellings of a host", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      for (let i = 0; i < BEACON_LIMITS.newOriginsPerHour; i++) {
        await report(s.token, `https://slot${i}.example.`);
        await report(s.token, `https://slot${i}.example`);
      }
      expect(await clones(s.admin)).toHaveLength(BEACON_LIMITS.newOriginsPerHour);
      expect(recorderLog.lines).not.toContainEqual(`beacon dropped reason=origin-limit build=${s.buildId}`);
    });

    it(`counts at most ${BEACON_LIMITS.newOriginsPerHour} new origins per App and Environment per hour across its Builds (F3)`, async () => {
      clock.ms += 10 * HOUR;
      const first = await setUp();
      const builds = [first];
      for (let i = 0; i < 4; i++) {
        builds.push(await setUp({ admin: first.admin, organizationId: first.organizationId, appId: first.appId }));
      }
      for (const [b, build] of builds.entries()) {
        for (let i = 0; i < 25; i++) await report(build.token, `https://f${b}-${i}.example`);
      }
      expect(await clones(first.admin)).toHaveLength(BEACON_LIMITS.newOriginsPerHour);
      expect(recorderLog.lines).toContainEqual(`beacon dropped reason=app-origin-limit build=${builds[1]?.buildId}`);
    });
  });

  describe("privacy (Review Focus 3)", () => {
    it("stores and alerts the reporter's /24 or /48 only; no address, token or body in any log line", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      await report(s.token, "https://v4.example", "203.0.113.77");
      await report(s.token, "https://v6.example", "2001:db8:1:2::5");
      await report(s.token, "https://mapped.example", "::ffff:198.51.100.9");
      const stored = await db.tx({ organizationId: s.organizationId }, async (q) => ({
        detections: (await q.query("SELECT * FROM detections WHERE rule = 'clone-origin'")).rows,
        incidents: (await q.query("SELECT * FROM incidents WHERE rule = 'clone-origin'")).rows,
      }));
      const prefixes = Object.fromEntries(
        (stored.detections as { origin: string; ip_prefix: string | null }[]).map((row) => [row.origin, row.ip_prefix]),
      );
      expect(prefixes["https://v4.example"]).toBe("203.0.113.0/24");
      expect(prefixes["https://v6.example"]).toBe("2001:db8:1::/48");
      expect(prefixes["https://mapped.example"]).toBe("198.51.100.0/24");
      const text = JSON.stringify(stored) + JSON.stringify(opened) + bodies.join("\n");
      for (const address of ["203.0.113.77", "2001:db8:1:2::5", "198.51.100.9"]) expect(text).not.toContain(address);
      for (const line of [...recorderLog.lines, ...api.logger.lines]) {
        for (const token of tokens) expect(line).not.toContain(token);
        expect(line).not.toContain("203.0.113.77");
        expect(line).not.toContain("2001:db8:1:2::5");
        expect(line).not.toContain("v4.example");
      }
    });

    it("records a null reporter prefix when the address is unknown", async () => {
      clock.ms += 10 * HOUR;
      const s = await setUp();
      await post(JSON.stringify({ a: appOf(s.token), t: s.token, o: "https://noaddr.example" }), {
        origin: "https://noaddr.example",
      });
      const [incident] = await clones(s.admin);
      const detail = IncidentDetailResponseSchema.parse(
        await (await request(`/v1/incidents/${incident?.id}`, { headers: bearer(s.admin) })).json(),
      );
      expect(detail.detections[0]?.ip_prefix).toBeNull();
    });

    it("reduces addresses to their network prefix", () => {
      expect(addressPrefix("203.0.113.77")).toBe("203.0.113.0/24");
      expect(addressPrefix("2001:0db8:0001:0002::5")).toBe("2001:db8:1::/48");
      expect(addressPrefix("::ffff:198.51.100.9")).toBe("198.51.100.0/24");
      expect(addressPrefix("fe80::1%eth0")).toBe("fe80:0:0::/48");
      expect(addressPrefix(undefined)).toBeNull();
      expect(addressPrefix("not an address")).toBeNull();
    });
  });

  describe("tenancy (Review Focus 4)", () => {
    it("a token only ever opens Incidents in its own Build's Organization, App and Environment", async () => {
      clock.ms += 10 * HOUR;
      const a = await setUp();
      const b = await setUp();
      await report(a.token, "https://tenant.example");
      const ofA = await clones(a.admin);
      expect(ofA).toHaveLength(1);
      expect(ofA[0]).toMatchObject({ app_id: a.appId, environment: a.environment, build_id: a.buildId });
      expect(await clones(b.admin)).toEqual([]);

      // Within one App a token names one Build: a second Build of A's App with A's token is refused whole.
      const again: BuildManifest = {
        ...EXAMPLE_BUILD_MANIFEST,
        build_id: newId("bld"),
        app_id: a.appId,
        beacon: { token: a.token, origins: ["https://tenant.example"] },
      };
      const taken = await expectProblem(
        await request(`/v1/apps/${a.appId}/builds`, json({ manifest: again }, bearer(a.admin))),
        409,
      );
      expect(taken.reason).toBe("beacon-token-taken");
      expect(taken.detail).toBe(CONFLICT_DETAILS["beacon-token-taken"]);
      const listed = ListBuildsResponseSchema.parse(
        await (await request(`/v1/apps/${a.appId}/builds`, { headers: bearer(a.admin) })).json(),
      );
      expect(listed.builds.map((build) => build.build_id)).toEqual([a.buildId]);
      clock.ms += HOUR;
      await report(a.token, "https://tenant.example");
      expect((await clones(a.admin))[0]?.detection_count).toBe(2);
      expect(await clones(b.admin)).toEqual([]);
    });

    it("Org A carrying Org B's token cannot capture B's reports, and B still registers it (F4)", async () => {
      clock.ms += 10 * HOUR;
      const a = await setUp();
      const orgB = await createOrganization(api, "Victim");
      const adminB = orgB.admin_key.key;
      const appB = (await createAppFor(api, adminB)).app.id;
      const tokenB = deriveBeaconToken(7, { appId: appB, version: "2.0.0" });
      tokens.push(tokenB);
      // A registers the token first, in its own App (it cannot register Builds for B's App at all).
      const squat: BuildManifest = {
        ...EXAMPLE_BUILD_MANIFEST,
        build_id: newId("bld"),
        app_id: a.appId,
        environment: "production",
        version: "6.6.6",
        beacon: { token: tokenB, origins: [ALLOWED] },
      };
      expect((await request(`/v1/apps/${a.appId}/builds`, json({ manifest: squat }, bearer(a.admin)))).status).toBe(
        201,
      );
      expect(
        (await request(`/v1/apps/${appB}/builds`, json({ manifest: { ...squat, app_id: appB } }, bearer(a.admin))))
          .status,
      ).toBe(404);
      // B's own registration of its token succeeds.
      const own: BuildManifest = { ...squat, build_id: newId("bld"), app_id: appB, version: "2.0.0" };
      expect((await request(`/v1/apps/${appB}/builds`, json({ manifest: own }, bearer(adminB)))).status).toBe(201);
      appOfToken.set(tokenB, appB);
      await report(tokenB, "https://victim-clone.example");
      expect((await clones(adminB)).map((incident) => [incident.origin, incident.build_id])).toEqual([
        ["https://victim-clone.example", own.build_id],
      ]);
      expect((await clones(a.admin)).map((incident) => incident.origin)).not.toContain("https://victim-clone.example");
    });

    it("drops a report whose App id is not its token's App", async () => {
      clock.ms += 10 * HOUR;
      const a = await setUp();
      const b = await setUp();
      const origin = "https://mismatch.example";
      await post(JSON.stringify({ a: b.appId, t: a.token, o: origin }), { origin, [PEER_HEADER]: PEER });
      expect(await clones(a.admin)).toEqual([]);
      expect(await clones(b.admin)).toEqual([]);
    });

    it("keeps the beacon table of one Organization invisible to another, and to a transaction without a tenant", async () => {
      const a = await setUp();
      const b = await setUp();
      const own = await db.tx({ organizationId: a.organizationId }, (q) =>
        q.query("SELECT build_id FROM build_beacons"),
      );
      expect(own.rows).toEqual([{ build_id: a.buildId }]);
      const other = await db.tx({ organizationId: b.organizationId }, (q) =>
        q.query("SELECT 1 FROM build_beacons WHERE build_id = $1", [a.buildId]),
      );
      expect(other.rows).toEqual([]);
      const none = await db.tx("none", (q) => q.query("SELECT 1 FROM build_beacons"));
      expect(none.rows).toEqual([]);
      const wrongApp = await db.tx("none", (q) =>
        q.query("SELECT * FROM beacon_lookup_token($1, $2)", [b.appId, a.token]),
      );
      expect(wrongApp.rows).toEqual([]);
      const lookup = await db.tx("none", (q) =>
        q.query("SELECT * FROM beacon_lookup_token($1, $2)", [a.appId, a.token]),
      );
      expect(lookup.rows).toEqual([
        {
          organization_id: a.organizationId,
          build_id: a.buildId,
          app_id: a.appId,
          environment: a.environment,
          origins: [ALLOWED],
        },
      ]);
    });
  });

  describe("Builds", () => {
    it("returns the beacon as its origins, never the token, on register, list and get", async () => {
      const s = await setUp();
      const one = await request(`/v1/apps/${s.appId}/builds/${s.buildId}`, { headers: bearer(s.admin) });
      const build = BuildResponseSchema.parse(await one.clone().json()).build;
      expect(build.beacon).toEqual({ origins: [ALLOWED] });
      expect(await one.text()).not.toContain("token");
      const list = await request(`/v1/apps/${s.appId}/builds`, { headers: bearer(s.admin) });
      expect(ListBuildsResponseSchema.parse(await list.clone().json()).builds[0]?.beacon).toEqual({
        origins: [ALLOWED],
      });
      for (const body of bodies) for (const token of tokens) expect(body).not.toContain(token);
    });

    it("registers a Build without a beacon as before: no beacon member", async () => {
      const org = await createOrganization(api, "No beacon");
      const appId = (await createAppFor(api, org.admin_key.key)).app.id;
      const manifest = { ...EXAMPLE_BUILD_MANIFEST, build_id: newId("bld"), app_id: appId };
      const res = await request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(org.admin_key.key)));
      expect(res.status).toBe(201);
      expect(BuildResponseSchema.parse(await res.json()).build.beacon).toBeUndefined();
    });
  });

  describe("the detection tables", () => {
    async function insertIncident(
      organizationId: string,
      appId: string,
      row: { rule: string; ip_prefix: string | null; origin: string | null; build_id: string | null },
    ) {
      const at = now().toISOString();
      return db.tx({ organizationId }, (q) =>
        q.query(
          `INSERT INTO incidents (id, organization_id, app_id, environment, rule, severity, title, status, ip_prefix,
             first_seen, last_seen, detection_count, created_at, updated_at, build_id, origin)
           VALUES ($1, $2, $3, 'production', $4, 'high', 'X', 'open', $5, $6, $6, 1, $6, $6, $7, $8)`,
          [newId("inc"), organizationId, appId, row.rule, row.ip_prefix, at, row.build_id, row.origin],
        ),
      );
    }

    it("ties origin and a null prefix to clone-origin, and a prefix without origin to every other rule", async () => {
      const s = await setUp();
      const bad = [
        { rule: "clone-origin", ip_prefix: PEER_PREFIX, origin: "https://c1.example", build_id: s.buildId },
        { rule: "clone-origin", ip_prefix: null, origin: null, build_id: s.buildId },
        { rule: "clone-origin", ip_prefix: null, origin: "https://c2.example", build_id: null },
        { rule: "blocked-burst", ip_prefix: PEER_PREFIX, origin: "https://c3.example", build_id: null },
        { rule: "blocked-burst", ip_prefix: null, origin: null, build_id: null },
      ];
      for (const row of bad) {
        await expect(insertIncident(s.organizationId, s.appId, row), JSON.stringify(row)).rejects.toThrow();
      }
      await expect(
        insertIncident(s.organizationId, s.appId, {
          rule: "clone-origin",
          ip_prefix: null,
          origin: "https://c4.example",
          build_id: s.buildId,
        }),
      ).resolves.toBeDefined();
    });
  });

  describe("the Event path", () => {
    it("never counts an Event toward clone-origin, and has no Event condition for it", () => {
      const rule = DETECTION_RULES.find((candidate) => candidate.key === "clone-origin");
      expect(rule).toMatchObject({ title: "Clone detected", severity: "high", threshold: 1, window_s: 3600 });
      const event = {
        ...EXAMPLE_SHIELD_EVENT,
        organization_id: newId("org"),
        app_id: newId("app"),
        environment: "production" as const,
        received_at: now().toISOString(),
      };
      expect(matchingRules(event).map((r) => r.key)).not.toContain("clone-origin");
      expect(() => ruleConditionSql("clone-origin")).toThrow(TypeError);
    });
  });
});
