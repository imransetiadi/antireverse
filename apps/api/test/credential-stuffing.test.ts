import { randomBytes } from "node:crypto";
import {
  ContainmentResponseSchema,
  DETECTION_RULES,
  type Environment,
  EXAMPLE_SHIELD_EVENT,
  INCIDENT_LIMITS,
  type Incident,
  IncidentDetailResponseSchema,
  ListIncidentsResponseSchema,
  type PolicyRule,
  type ShieldEvent,
  type StoredEvent,
} from "@antireverse/protocol";
import { actorHash } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Db } from "../src/db/db.ts";
import {
  coverageEntries,
  coverageOf,
  coveragePattern,
  covers,
  limitCoverage,
  namesRule,
} from "../src/detect/coverage.ts";
import {
  COVERAGE_VERSIONS_PER_ORG,
  COVERAGE_WAITING_PER_ORG,
  createDetector,
  type Detector,
  LATEST_VERSION_MS,
  type PolicyPublished,
} from "../src/detect/detector.ts";
import { matchingRules, needsCoverage, ruleConditionSql } from "../src/detect/rules.ts";
import {
  batchOf,
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  publishPolicy,
  put,
  shieldEvent,
  type TestApi,
  tick,
  uuidv7,
} from "./helpers.ts";

// Slice 08: the `credential-stuffing` rule as it judges an Event of a Shield from before plan amendment A7, which does
// not stamp `decision.limit_rule_id`: a 401 or 403 on a route a login protection (a failure-counting limit Rule) of
// the Policy version the Event names covers, or a throttle naming such a Rule (src/detect/coverage.ts). Events a
// Shield of A7 stamps are tested in credential-stuffing-stamped.test.ts; here THROTTLED is one of those.

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const PREFIX = "203.0.113.0/24";
const OTHER_PREFIX = "198.51.100.0/24";
const STUFFING = DETECTION_RULES.find((rule) => rule.key === "credential-stuffing") ?? DETECTION_RULES[0];
const THRESHOLD = STUFFING.threshold;
const RULE_ID = "rul_0123456789abcdef01234567";
const REQUEST_RULE_ID = "rul_aaaaaaaaaaaaaaaaaaaaaaaa";

const loginLimit = {
  name: "Login protection",
  path: "/login",
  methods: ["POST"],
  limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
};

type Decision = ShieldEvent["decision"];
/** An older Shield's decision: no `limit_rule_id` member, so the coverage guess judges it. */
const { limit_rule_id: _stamp, ...LEGACY } = { ...EXAMPLE_SHIELD_EVENT.decision, policy_version: 1 };
const ALLOW = LEGACY as Decision;
const decision = (overrides: Partial<Decision>): Decision => ({ ...ALLOW, ...overrides });
/** A throttle by the login protection RULE_ID, as a Shield of A7 stamps it. */
const THROTTLED = decision({ action: "throttle", mode: "enforce", rule_id: RULE_ID, limit_rule_id: RULE_ID });
const THROTTLE_MONITORED = decision({ action: "throttle", mode: "monitor", rule_id: RULE_ID, limit_rule_id: RULE_ID });
/** A fresh client: a throttle counts once per client per window. */
const someClient = () => `iph_${randomBytes(16).toString("hex")}`;

/** An Event as Shield sends it: `POST /login` answered `status`, allowed under Policy version 1 unless overridden. */
function login(ms: number, status: number, overrides: Partial<ShieldEvent> = {}): ShieldEvent {
  return {
    ...shieldEvent(ms),
    request: { method: "POST", route: "/login", status, latency_ms: 2 },
    decision: ALLOW,
    actor: { ip_prefix: PREFIX, ip_hash: someClient() },
    ...overrides,
  };
}

interface Target {
  organizationId: string;
  appId: string;
  environment: Environment;
}

const stored = (target: Target, event: ShieldEvent): StoredEvent => ({
  ...event,
  organization_id: target.organizationId,
  app_id: target.appId,
  environment: target.environment,
  received_at: event.ts,
});

const keysOf = (event: StoredEvent, covered = false, limitRule = false) =>
  matchingRules(event, { covered, limitRule }).map((rule) => rule.key);

describe("coverage of a route template by a limit Rule", () => {
  const rule = (path: string, methods: string[] = []) => ({ path, methods });

  it.each([
    // A literal template is covered by the same literal pattern, without regard to ASCII case or a final slash.
    ["/login", "POST", "/login", true],
    ["/login", "POST", "/Login", true],
    ["/LOGIN", "POST", "/login", true],
    ["/login", "POST", "/login/", true],
    ["/login", "POST", "/login/now", false],
    ["/login", "POST", "/logins", false],
    ["/login", "POST", "/api/login", false],
    ["/", "GET", "/", true],
    ["/", "GET", "/login", false],
    ["/api/v1.0/login", "POST", "/api/v1.0/login", true],
    // The dot is literal, not "any character".
    ["/api/v1.0/login", "POST", "/api/v1x0/login", false],
    // One star covers exactly one segment of the template, a parameter included.
    ["/api/users/*/export", "GET", "/api/users/:id/export", true],
    ["/api/users/*/export", "GET", "/api/users/me/export", true],
    ["/api/users/*/export", "GET", "/api/users/export", false],
    ["/api/users/*/export", "GET", "/api/users/:org/:id/export", false],
    // A final double star covers everything below, and the prefix itself.
    ["/api/admin/**", "GET", "/api/admin", true],
    ["/api/admin/**", "GET", "/api/admin/", true],
    ["/api/admin/**", "GET", "/api/admin/users/:id", true],
    ["/api/admin/**", "GET", "/api/administrators", false],
    ["/**", "GET", "/anything/:at/all", true],
    ["/**", "GET", "/", true],
    // Undecidable is not covered: a parameter may or may not take the literal's value.
    ["/login", "POST", "/:page", false],
    ["/api/admin/**", "GET", "/api/:section/users", false],
    // A template wildcard spans several segments: one star does not cover it, a double star does.
    ["/files/*", "GET", "/files/*path", false],
    ["/files/**", "GET", "/files/*path", true],
    // An optional group may be absent: one star does not cover it.
    ["/*/*", "GET", "/users{/:id}", false],
    // No template at all, or one whose mount is unknown: never covered, by any pattern.
    ["/**", "GET", "(unmatched)", false],
    ["/*", "GET", "(unmatched)", false],
    ["/**", "GET", "(mount)/login", false],
    ["/login", "POST", "(mount)/login", false],
  ])("pattern %s, %s %s: %s", (path, method, route, expected) => {
    expect(covers(coverageOf([rule(path)]), method, route)).toBe(expected);
  });

  it("honours the Rule's methods: none is every method, and HEAD counts with GET", () => {
    const post = coverageOf([rule("/login", ["POST"])]);
    expect(covers(post, "POST", "/login")).toBe(true);
    expect(covers(post, "GET", "/login")).toBe(false);
    expect(covers(post, "HEAD", "/login")).toBe(false);
    const get = coverageOf([rule("/login", ["GET"])]);
    expect(covers(get, "HEAD", "/login")).toBe(true);
    expect(covers(get, "GET", "/login")).toBe(true);
    expect(covers(coverageOf([rule("/login", ["HEAD"])]), "GET", "/login")).toBe(false);
    expect(covers(coverageOf([rule("/login")]), "DELETE", "/login")).toBe(true);
  });

  it("is covered when any of the Rules covers it, and by none when there is none", () => {
    const both = coverageOf([rule("/login", ["POST"]), rule("/password/reset", ["POST"])]);
    expect(covers(both, "POST", "/password/reset")).toBe(true);
    expect(covers(both, "POST", "/signup")).toBe(false);
    expect(covers(coverageOf([]), "POST", "/login")).toBe(false);
  });

  it("writes a pattern the database reads the same way: anchored, the lowered literal escaped", () => {
    expect(coveragePattern("/login")).toBe("^/login/?$");
    expect(coveragePattern("/")).toBe("^/$");
    expect(coveragePattern("/API/v1.0/*/Export")).toBe("^/api/v1\\.0/[^/{}()*]+/export/?$");
    expect(coveragePattern("/api/admin/**")).toBe("^/api/admin(/.*)?$");
    expect(coveragePattern("/**")).toBe("^(/.*)?$");
  });
});

describe("managed rule credential-stuffing", () => {
  const target: Target = {
    organizationId: "org_0123456789abcdef01234567",
    appId: "app_89abcdef0123456789abcdef",
    environment: "development",
  };
  const event = (status: number, overrides: Partial<ShieldEvent> = {}) => stored(target, login(T0, status, overrides));

  it("counts an older Shield's throttle only when it names a login protection of the Event's version", () => {
    const legacyThrottle = (mode: "enforce" | "monitor") => decision({ action: "throttle", mode, rule_id: RULE_ID });
    expect(keysOf(event(429, { decision: legacyThrottle("enforce") }), false, true)).toEqual(["credential-stuffing"]);
    expect(keysOf(event(401, { decision: legacyThrottle("monitor") }), true, true)).toEqual(["credential-stuffing"]);
    // A plain request limit, or a Rule the version does not have: nothing, and no failed sign-in either.
    expect(keysOf(event(429, { decision: legacyThrottle("enforce") }), true, false)).toEqual([]);
    expect(keysOf(event(401, { decision: legacyThrottle("monitor") }), false, false)).toEqual([]);
    // A throttle that names no Rule is not a limit Rule's decision.
    expect(
      keysOf(event(429, { decision: decision({ action: "throttle", mode: "enforce", rule_id: null }) }), true, true),
    ).toEqual([]);
    // Stamped by a Shield of A7: the stamp decides, whatever the guess would say.
    expect(keysOf(event(429, { decision: THROTTLED }))).toEqual(["credential-stuffing"]);
    expect(keysOf(event(401, { decision: THROTTLE_MONITORED }))).toEqual(["credential-stuffing"]);
  });

  it("counts an older Shield's 401 or 403 only on a covered route, and never the app's own 429", () => {
    expect(keysOf(event(401), false)).toEqual(["failed-signin-burst"]);
    expect(keysOf(event(403), false)).toEqual(["failed-signin-burst"]);
    // On a covered route a failure counts toward credential-stuffing only: one wave, one Incident.
    expect(keysOf(event(401), true)).toEqual(["credential-stuffing"]);
    expect(keysOf(event(403), true)).toEqual(["credential-stuffing"]);
    for (const status of [200, 302, 400, 404, 429, 500]) expect(keysOf(event(status), true)).toEqual([]);
  });

  it("leaves Shield's own enforced blocks to blocked-burst, and a Containment's to no rule", () => {
    const blocked = event(403, { decision: decision({ action: "block", mode: "enforce", rule_id: RULE_ID }) });
    expect(keysOf(blocked, true)).toEqual(["blocked-burst"]);
    const contained = event(403, {
      decision: decision({ action: "block", mode: "enforce", containment_id: "cnt_0123456789abcdef01234567" }),
    });
    expect(keysOf(contained, true)).toEqual([]);
    // A block in Monitor mode did not answer: the 403 is the app's, on a covered route.
    const monitored = event(403, { decision: decision({ action: "block", mode: "monitor", rule_id: RULE_ID }) });
    expect(keysOf(monitored, true)).toEqual(["credential-stuffing"]);
    expect(keysOf(monitored, false)).toEqual(["failed-signin-burst"]);
  });

  it("asks for the Policy only for an older Shield's Event that the guess could count", () => {
    expect(needsCoverage(event(401))).toBe(true);
    expect(needsCoverage(event(403))).toBe(true);
    expect(needsCoverage(event(429, { decision: decision({ action: "throttle", rule_id: RULE_ID }) }))).toBe(true);
    expect(needsCoverage(event(429))).toBe(false);
    expect(needsCoverage(event(200))).toBe(false);
    // Stamped by a Shield of A7, null included: never.
    expect(needsCoverage(event(429, { decision: THROTTLED }))).toBe(false);
    expect(needsCoverage(event(401, { decision: THROTTLE_MONITORED }))).toBe(false);
    expect(needsCoverage(event(401, { decision: { ...ALLOW, limit_rule_id: null } }))).toBe(false);
    expect(needsCoverage(event(403, { decision: decision({ action: "block", mode: "enforce" }) }))).toBe(false);
  });
});

describe("credential-stuffing detection", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let orgA: string;
  let adminA: string;
  let orgB: string;
  let adminB: string;

  beforeAll(async () => {
    api = await makeTestApi({ now });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    orgA = a.organization.id;
    adminA = a.admin_key.key;
    orgB = b.organization.id;
    adminB = b.admin_key.key;
  });
  afterAll(async () => {
    await api.close();
  });

  /** A new App of an Organization; with `rules`, its development Policy is published as version 1. */
  async function app(rules?: unknown[], admin = adminA, organizationId = orgA): Promise<Target> {
    const appId = (await createAppFor(api, admin, { name: "Storefront" })).app.id;
    if (rules !== undefined) await publishPolicy(api, admin, appId, "development", rules);
    return { organizationId, appId, environment: "development" };
  }

  function detector(db: Db = api.db) {
    const opened: Incident[] = [];
    const logger = captureLogger();
    const instance = createDetector({
      db,
      bus: api.bus,
      notifier: { incidentOpened: (incident) => opened.push(incident) },
      now,
      logger,
    });
    return { instance, opened, logger, stop: instance.start() };
  }

  /** A network prefix of its own for Event `i`: nothing crosses a threshold, so no Detection is written. */
  const spread = (i: number) => ({ ip_prefix: `10.${i % 250}.${Math.floor(i / 250)}.0/24`, ip_hash: null });

  /** Publishes `count` Events from `make(i)` at one instant: the clock stands still. */
  function flood(target: Target, count: number, make: (i: number) => ShieldEvent): void {
    for (let i = 0; i < count; i++) api.bus.publish(stored(target, { ...make(i), event_id: uuidv7(clock.ms) }));
  }

  /** Publishes `count` Events from `make(ms)` at one-second steps of the clock. */
  function burst(target: Target, count: number, make: (ms: number) => ShieldEvent): void {
    for (let i = 0; i < count; i++) {
      clock.ms += 1_000;
      api.bus.publish(stored(target, { ...make(clock.ms), event_id: uuidv7(clock.ms) }));
    }
  }

  async function incidentsOf(target: Target) {
    const { rows } = await api.db.tx({ organizationId: target.organizationId }, (q) =>
      q.query<{ rule: string; severity: string; title: string; ip_prefix: string; detection_count: number }>(
        "SELECT rule, severity, title, ip_prefix, detection_count FROM incidents WHERE app_id = $1 ORDER BY rule",
        [target.appId],
      ),
    );
    return rows;
  }

  async function detectionsOf(target: Target) {
    const { rows } = await api.db.tx({ organizationId: target.organizationId }, (q) =>
      q.query<{ rule: string; count: number; ip_prefix: string }>(
        "SELECT rule, count, ip_prefix FROM detections WHERE app_id = $1 ORDER BY detected_at, id",
        [target.appId],
      ),
    );
    return rows;
  }

  it("opens one High Incident on the 50th throttled request from one prefix, and never a Blocked burst", async () => {
    // No Policy is needed for a throttle decision: the Event names the limit Rule.
    const target = await app();
    const { instance, opened, stop } = detector();
    try {
      burst(target, THRESHOLD - 1, (ms) => login(ms, 429, { decision: THROTTLED }));
      await instance.flush();
      expect(await incidentsOf(target)).toEqual([]);

      burst(target, 1, (ms) => login(ms, 429, { decision: THROTTLED }));
      await instance.flush();
      expect(await incidentsOf(target)).toEqual([
        {
          rule: "credential-stuffing",
          severity: "high",
          title: "Credential stuffing",
          ip_prefix: PREFIX,
          detection_count: 1,
        },
      ]);
      expect(await detectionsOf(target)).toEqual([
        { rule: "credential-stuffing", count: THRESHOLD, ip_prefix: PREFIX },
      ]);
      expect(opened.map((incident) => incident.rule)).toEqual(["credential-stuffing"]);

      // The window starts again: the next crossing joins the same Incident and does not alert again.
      burst(target, THRESHOLD, (ms) => login(ms, 429, { decision: THROTTLED }));
      await instance.flush();
      expect(await incidentsOf(target)).toMatchObject([{ rule: "credential-stuffing", detection_count: 2 }]);
      expect(opened).toHaveLength(1);
    } finally {
      stop();
    }
  });

  it("counts a monitored throttle as well: the response was the app's own", async () => {
    const target = await app();
    const { instance, stop } = detector();
    try {
      burst(target, THRESHOLD, (ms) => login(ms, 200, { decision: THROTTLE_MONITORED }));
      await instance.flush();
      expect((await incidentsOf(target)).map((incident) => incident.rule)).toEqual(["credential-stuffing"]);
    } finally {
      stop();
    }
  });

  it("counts failed and refused responses on a route a limit Rule of the Event's Policy version covers", async () => {
    const target = await app([loginLimit]);
    const { instance, stop } = detector();
    try {
      // Under every per-address limit, so no throttle decision: 401 and 403, mixed with throttles.
      burst(target, 25, (ms) => login(ms, 401));
      burst(target, 15, (ms) => login(ms, 403));
      burst(target, 9, (ms) => login(ms, 429, { decision: THROTTLED }));
      // Never counted: the app's own 429, a success, another method, another route, a route without a template, no
      // prefix.
      burst(target, 10, (ms) => login(ms, 429));
      burst(target, 5, (ms) => login(ms, 200));
      burst(target, 5, (ms) =>
        login(ms, 401, { request: { method: "GET", route: "/login", status: 401, latency_ms: 1 } }),
      );
      burst(target, 5, (ms) =>
        login(ms, 401, { request: { method: "POST", route: "/signup", status: 401, latency_ms: 1 } }),
      );
      burst(target, 5, (ms) =>
        login(ms, 401, { request: { method: "POST", route: "(unmatched)", status: 401, latency_ms: 1 } }),
      );
      burst(target, 5, (ms) => login(ms, 401, { actor: { ip_prefix: null, ip_hash: null } }));
      await instance.flush();
      expect((await detectionsOf(target)).filter((d) => d.rule === "credential-stuffing")).toEqual([]);

      burst(target, 1, (ms) => login(ms, 401));
      await instance.flush();
      expect((await detectionsOf(target)).filter((d) => d.rule === "credential-stuffing")).toEqual([
        { rule: "credential-stuffing", count: THRESHOLD, ip_prefix: PREFIX },
      ]);
      // One wave, one Incident: the 31 failures on the covered route are no failed sign-in burst as well, and the
      // 15 on uncovered routes are under that rule's threshold.
      expect((await incidentsOf(target)).map((incident) => [incident.rule, incident.severity])).toEqual([
        ["credential-stuffing", "high"],
      ]);
      // Failures on routes no limit Rule covers still count toward failed-signin-burst, as before.
      burst(target, 14, (ms) =>
        login(ms, 401, { request: { method: "POST", route: "/signup", status: 401, latency_ms: 1 } }),
      );
      await instance.flush();
      expect((await incidentsOf(target)).map((incident) => incident.rule)).toEqual(["credential-stuffing"]);
      burst(target, 1, (ms) =>
        login(ms, 403, { request: { method: "GET", route: "/login", status: 403, latency_ms: 1 } }),
      );
      await instance.flush();
      expect((await incidentsOf(target)).map((incident) => [incident.rule, incident.severity])).toEqual([
        ["credential-stuffing", "high"],
        ["failed-signin-burst", "medium"],
      ]);
      expect((await detectionsOf(target)).filter((d) => d.rule === "failed-signin-burst")).toEqual([
        { rule: "failed-signin-burst", count: 30, ip_prefix: PREFIX },
      ]);
    } finally {
      stop();
    }
  });

  it("judges coverage by the Policy version the Event names, not by the newest", async () => {
    const target = await app([loginLimit]);
    // Version 2 has no limit Rule; version 3 limits another route.
    await publishPolicy(api, adminA, target.appId, "development", [{ name: "Admin", path: "/api/admin/**" }]);
    await publishPolicy(api, adminA, target.appId, "development", [{ ...loginLimit, path: "/signup" }]);
    const { instance, stop } = detector();
    try {
      const under = (version: number) => (ms: number) =>
        login(ms, 401, { decision: decision({ policy_version: version }) });
      // The built-in Policy, a version without a limit Rule, one that covers another route, one never published.
      for (const version of [0, 2, 3, 4, 99]) burst(target, THRESHOLD, under(version));
      await instance.flush();
      expect((await incidentsOf(target)).filter((incident) => incident.rule === "credential-stuffing")).toEqual([]);

      // A Shield still on version 1 after two publishes: its Events are judged by version 1.
      burst(target, THRESHOLD, under(1));
      await instance.flush();
      expect((await incidentsOf(target)).map((incident) => incident.rule)).toContain("credential-stuffing");
    } finally {
      stop();
    }
  });

  it("never counts across Organization, App, Environment or prefix, and reads no other tenant's Policy", async () => {
    // Organization B limits /login; Organization A's App has the same version number without a limit Rule.
    const limitedB = await app([loginLimit], adminB, orgB);
    const plainA = await app([{ name: "Admin", path: "/api/admin/**" }]);
    const limitedA = await app([loginLimit]);
    const { instance, stop } = detector();
    try {
      burst(plainA, THRESHOLD, (ms) => login(ms, 401));
      // The limit is in the development Policy; production and staging of the same App have none.
      burst({ ...limitedA, environment: "production" }, THRESHOLD, (ms) => login(ms, 401));
      burst({ ...limitedA, environment: "staging" }, THRESHOLD, (ms) => login(ms, 401));
      // An Event that claims Organization B's App under Organization A is judged in Organization A: no Policy there.
      burst({ ...limitedB, organizationId: orgA }, THRESHOLD, (ms) => login(ms, 401));
      // 49 each for two prefixes and two Apps: nothing crosses.
      burst(limitedA, THRESHOLD - 1, (ms) => login(ms, 401));
      burst(limitedA, THRESHOLD - 1, (ms) => login(ms, 401, { actor: { ip_prefix: OTHER_PREFIX, ip_hash: null } }));
      burst(limitedB, THRESHOLD - 1, (ms) => login(ms, 401));
      await instance.flush();
      for (const target of [plainA, limitedA, limitedB]) {
        expect((await incidentsOf(target)).filter((incident) => incident.rule === "credential-stuffing")).toEqual([]);
      }

      burst(limitedB, 1, (ms) => login(ms, 401));
      await instance.flush();
      expect((await incidentsOf(limitedB)).map((incident) => incident.rule)).toEqual(["credential-stuffing"]);
      expect((await incidentsOf(limitedA)).filter((i) => i.rule === "credential-stuffing")).toEqual([]);
      expect(
        (await incidentsOf({ ...limitedB, organizationId: orgA })).filter((i) => i.rule === "credential-stuffing"),
      ).toEqual([]);
    } finally {
      stop();
    }
  });

  it("reads a Policy version once, nothing for an Event coverage cannot count, and nothing for a version above the latest", async () => {
    const target = await app([loginLimit]);
    let reads = 0;
    const counting: Db = {
      tx: (scope, fn) => {
        reads++;
        return api.db.tx(scope, fn);
      },
      close: () => Promise.resolve(),
    };
    const { instance, stop } = detector(counting);
    try {
      burst(target, 20, (ms) => login(ms, 200));
      burst(target, 20, (ms) => login(ms, 429, { decision: THROTTLED }));
      // The built-in Policy has no Rules: not read either.
      burst(target, 20, (ms) => login(ms, 429, { decision: decision({ policy_version: 0 }) }));
      await instance.flush();
      expect(reads).toBe(0);

      // One read gives the version's limit Rules and the latest published version of the App Environment.
      flood(target, 20, (i) => login(clock.ms, 401, { actor: { ip_prefix: `198.51.${i}.0/24`, ip_hash: null } }));
      await instance.flush();
      expect(reads).toBe(1);
      // A version above the latest was never published: ignored without a read, however many are named.
      flood(target, 500, (i) =>
        login(clock.ms, 401, { decision: decision({ policy_version: 2 + i }), actor: spread(i) }),
      );
      await instance.flush();
      expect(reads).toBe(1);
      // The latest is asked for again after a while (a version may have been published since), once.
      clock.ms += LATEST_VERSION_MS + 1;
      flood(target, 500, (i) =>
        login(clock.ms, 401, { decision: decision({ policy_version: 2 + i }), actor: spread(i) }),
      );
      flood(target, 5, (i) => login(clock.ms, 401, { actor: spread(600 + i) }));
      await instance.flush();
      expect(reads).toBe(2);
      // A version published meanwhile is read once it is named, after the latest was asked for again.
      await publishPolicy(api, adminA, target.appId, "development", [loginLimit]);
      flood(target, 5, (i) =>
        login(clock.ms, 401, { decision: decision({ policy_version: 2 }), actor: spread(700 + i) }),
      );
      await instance.flush();
      expect(reads).toBe(2);
      clock.ms += LATEST_VERSION_MS + 1;
      flood(target, 5, (i) =>
        login(clock.ms, 401, { decision: decision({ policy_version: 2 }), actor: spread(700 + i) }),
      );
      flood(target, 5, (i) =>
        login(clock.ms, 401, { decision: decision({ policy_version: 2 }), actor: spread(700 + i) }),
      );
      await instance.flush();
      expect(reads).toBe(3);
    } finally {
      stop();
    }
  });

  describe("one Organization cannot affect another (per-Organization bounds)", () => {
    /** A Db that counts the Detector's transactions per Organization and can hold one Organization's back. */
    function watched() {
      const reads = new Map<string, number>();
      let held: string | undefined;
      let release = () => {};
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const db: Db = {
        tx: async (scope, fn) => {
          const organizationId = typeof scope === "string" ? scope : scope.organizationId;
          reads.set(organizationId, (reads.get(organizationId) ?? 0) + 1);
          if (organizationId === held) await gate;
          return api.db.tx(scope, fn);
        },
        close: () => Promise.resolve(),
      };
      return {
        db,
        readsOf: (organizationId: string) => reads.get(organizationId) ?? 0,
        hold: (organizationId: string) => {
          held = organizationId;
        },
        release,
      };
    }

    it("keeps an Organization's Policy versions when another names more versions than are kept, real or made up", async () => {
      const targetA = await app([loginLimit]);
      const targetB = await app([loginLimit], adminB, orgB);
      // Organization B really has more versions than one Organization may keep.
      const versions = COVERAGE_VERSIONS_PER_ORG + 10;
      for (let version = 2; version <= versions; version++) {
        await publishPolicy(api, adminB, targetB.appId, "development", [loginLimit]);
      }
      const { db, readsOf } = watched();
      const { instance, stop } = detector(db);
      try {
        flood(targetA, 20, () => login(clock.ms, 401));
        await instance.flush();
        expect(readsOf(orgA)).toBe(1);

        // B names every real version, then thousands that were never published.
        // Each from its own prefix: nothing crosses, so every transaction is a read.
        flood(targetB, versions, (i) =>
          login(clock.ms, 401, {
            decision: decision({ policy_version: 1 + i }),
            actor: { ip_prefix: `198.51.${i}.0/24`, ip_hash: null },
          }),
        );
        flood(targetB, 3_000, (i) =>
          login(clock.ms, 401, { decision: decision({ policy_version: versions + 1 + i }), actor: spread(i) }),
        );
        await instance.flush();
        // One read per real version, none for a made-up one.
        expect(readsOf(orgB)).toBe(versions);
        // B kept only its newest versions: naming its first again reads it again. B evicted its own, nobody else's.
        flood(targetB, 1, () => login(clock.ms, 401, { actor: spread(9_999) }));
        await instance.flush();
        expect(readsOf(orgB)).toBe(versions + 1);

        // A's version is still kept: no further read, and its wave is detected.
        flood(targetA, THRESHOLD - 20, () => login(clock.ms, 401));
        await instance.flush();
        expect(readsOf(orgA)).toBe(1 + 1); // the Policy version, then the Detection's own transaction
        expect((await incidentsOf(targetA)).map((incident) => incident.rule)).toEqual(["credential-stuffing"]);
      } finally {
        stop();
      }
    });

    it("bounds the Events of one Organization that wait for a Policy, and never makes another Organization wait", async () => {
      const targetA = await app([loginLimit]);
      const targetB = await app([loginLimit], adminB, orgB);
      const { db, hold, release } = watched();
      const { instance, stop } = detector(db);
      try {
        // B's database is slow: its read does not return.
        hold(orgB);
        flood(targetB, COVERAGE_WAITING_PER_ORG + 500, () => login(clock.ms, 401));
        expect(instance.waitingEvents()).toBe(COVERAGE_WAITING_PER_ORG);

        // A's wave is read, counted and recorded meanwhile.
        flood(targetA, THRESHOLD, () => login(clock.ms, 401));
        expect(instance.waitingEvents()).toBe(COVERAGE_WAITING_PER_ORG + THRESHOLD);
        let found: string[] = [];
        for (let i = 0; i < 200 && found.length === 0; i++) {
          await tick(5);
          found = (await incidentsOf(targetA)).map((incident) => incident.rule);
        }
        expect(found).toEqual(["credential-stuffing"]);
        expect(instance.waitingEvents()).toBe(COVERAGE_WAITING_PER_ORG);
        expect(await incidentsOf(targetB)).toEqual([]);

        // B's read returns: the Events that waited are counted, those over the bound were not.
        release();
        await instance.flush();
        expect(instance.waitingEvents()).toBe(0);
        // Those over the bound were judged not covered: failed sign-ins instead.
        const detections = await detectionsOf(targetB);
        expect(detections.filter((d) => d.rule === "credential-stuffing")).toHaveLength(
          COVERAGE_WAITING_PER_ORG / THRESHOLD,
        );
      } finally {
        release();
        stop();
      }
    });
  });

  it("never fails ingest when the Policy cannot be read: logged without data, the Event not counted", async () => {
    const target = await app([loginLimit]);
    const failing: Db = {
      tx: () => Promise.reject(new Error(`policy read failed for ${PREFIX}`)),
      close: () => Promise.resolve(),
    };
    const { instance, opened, logger, stop } = detector(failing);
    try {
      burst(target, THRESHOLD, (ms) => login(ms, 401));
      await instance.flush();
      expect(opened).toEqual([]);
      expect(logger.lines.some((line) => line.startsWith("detector failed"))).toBe(true);
      for (const line of logger.lines) {
        expect(line).not.toContain(PREFIX);
        expect(line).not.toContain(target.appId);
        expect(line).not.toContain("policy read failed");
      }
      expect(await incidentsOf(target)).toEqual([]);
    } finally {
      stop();
    }
  });

  it("drops what waits for a Policy when it is stopped", async () => {
    const target = await app([loginLimit]);
    const { instance, stop } = detector();
    burst(target, THRESHOLD, (ms) => login(ms, 401));
    stop();
    await instance.flush();
    expect(await incidentsOf(target)).toEqual([]);
    expect(instance.trackedKeys()).toBe(0);
  });
});

describe("publish hook: the Detector learns a new Policy version at once", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let detector: Detector;
  let stop: () => void;
  let orgA: string;
  let adminA: string;
  let adminB: string;
  let reads = 0;
  const published: PolicyPublished[] = [];

  beforeAll(async () => {
    // The app tells the Detector, as `startApi` wires it; the Detector's own transactions are counted.
    api = await makeTestApi({
      now,
      onPolicyPublished: (policy) => {
        published.push(policy);
        detector.policyPublished(policy);
      },
    });
    const counting: Db = {
      tx: (scope, fn) => {
        reads++;
        return api.db.tx(scope, fn);
      },
      close: () => Promise.resolve(),
    };
    detector = createDetector({ db: counting, bus: api.bus, notifier: { incidentOpened: () => {} }, now });
    stop = detector.start();
    const a = await createOrganization(api, "Organization A");
    orgA = a.organization.id;
    adminA = a.admin_key.key;
    adminB = (await createOrganization(api, "Organization B")).admin_key.key;
  });
  afterAll(async () => {
    stop();
    await api.close();
  });

  const send = (target: Target, count: number, make: (i: number) => ShieldEvent): void => {
    for (let i = 0; i < count; i++) api.bus.publish(stored(target, { ...make(i), event_id: uuidv7(clock.ms) }));
  };
  const rulesOf = async (appId: string): Promise<string[]> => {
    const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
      q.query<{ rule: string }>("SELECT rule FROM incidents WHERE app_id = $1 ORDER BY rule", [appId]),
    );
    return rows.map((row) => row.rule);
  };
  const under = (version: number, status = 401) =>
    login(clock.ms, status, { decision: decision({ policy_version: version }) });

  it("judges failures naming a just-published version with its limit Rules: Credential stuffing, no Failed sign-in burst, no wait", async () => {
    const appId = (await createAppFor(api, adminA, { name: "Hooked" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    // Version 1 has no limit Rule, and the Detector has just read that it is the latest.
    await publishPolicy(api, adminA, appId, "development", [{ name: "Admin", path: "/api/admin/**" }]);
    send(target, 1, () => under(1, 401));
    await detector.flush();
    expect(reads).toBe(1);

    // Version 2 protects the login route. The clock does not move: the 10 seconds of belief have not passed.
    await publishPolicy(api, adminA, appId, "development", [loginLimit]);
    expect(published.at(-1)).toEqual({ organizationId: orgA, appId, environment: "development", version: 2 });
    send(target, THRESHOLD, () => under(2));
    await detector.flush();
    // One read for version 2's Rules, one transaction for the Detection: the latest version was not asked for.
    expect(reads).toBe(3);
    expect(await rulesOf(appId)).toEqual(["credential-stuffing"]);

    // A rollback tells it as well: version 3 has no limit Rule, version 4 brings version 2 back.
    await publishPolicy(api, adminA, appId, "development", []);
    const rolledBack = await api.app.request(
      `/v1/apps/${appId}/policies/development/rollback`,
      json({ version: 2 }, bearer(adminA)),
    );
    expect(rolledBack.status).toBe(201);
    expect(published.at(-1)).toEqual({ organizationId: orgA, appId, environment: "development", version: 4 });
    send(target, THRESHOLD, (i) => ({
      ...under(4),
      actor: { ip_prefix: OTHER_PREFIX, ip_hash: null },
      ...(i === 0 ? {} : {}),
    }));
    await detector.flush();
    expect(reads).toBe(5);
    const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
      q.query<{ rule: string; ip_prefix: string }>(
        "SELECT rule, ip_prefix FROM incidents WHERE app_id = $1 ORDER BY ip_prefix",
        [appId],
      ),
    );
    expect(rows).toEqual([
      { rule: "credential-stuffing", ip_prefix: OTHER_PREFIX },
      { rule: "credential-stuffing", ip_prefix: PREFIX },
    ]);
    // A version above the one just published is still made up: no read.
    send(target, 100, (i) => ({ ...under(5 + i), actor: { ip_prefix: `10.0.${i}.0/24`, ip_hash: null } }));
    await detector.flush();
    expect(reads).toBe(5);
  });

  it("tells nothing for a publish that stored nothing, and a failing hook never fails the publish", async () => {
    const appId = (await createAppFor(api, adminA, { name: "Refused" })).app.id;
    const before = published.length;
    for (const res of [
      // Refused by validation, by the guardrail, as a conflict, and for another Organization's App.
      await api.app.request(`/v1/apps/${appId}/policies/development`, put({ rules: [{ name: "x" }] }, bearer(adminA))),
      await api.app.request(
        `/v1/apps/${appId}/policies/development`,
        put({ rules: [{ ...loginLimit, path: "/**", mode: "enforce" }] }, bearer(adminA)),
      ),
      await api.app.request(
        `/v1/apps/${appId}/policies/development`,
        put({ rules: [loginLimit], expected_version: 3 }, bearer(adminA)),
      ),
      await api.app.request(`/v1/apps/${appId}/policies/development`, put({ rules: [loginLimit] }, bearer(adminB))),
      await api.app.request(`/v1/apps/${appId}/policies/development/rollback`, json({ version: 9 }, bearer(adminA))),
    ]) {
      expect(res.status).toBeGreaterThanOrEqual(400);
    }
    expect(published).toHaveLength(before);

    const failing = await makeTestApi({
      onPolicyPublished: () => {
        throw new Error("hook failed");
      },
    });
    try {
      const admin = (await createOrganization(failing, "Hook fails")).admin_key.key;
      const failingApp = (await createAppFor(failing, admin, { name: "Storefront" })).app.id;
      const policy = await publishPolicy(failing, admin, failingApp, "development", [loginLimit]);
      expect(policy.version).toBe(1);
      expect(failing.logger.lines.some((line) => line.includes("hook failed"))).toBe(false);
    } finally {
      await failing.close();
    }
  });
});

describe("Credential stuffing Incident", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let stopDetector: () => void;
  let flush: () => Promise<void>;
  let adminA: string;
  let adminB: string;

  beforeAll(async () => {
    api = await makeTestApi({ now });
    const detector = createDetector({
      db: api.db,
      bus: api.bus,
      notifier: { incidentOpened: () => {} },
      now,
      logger: api.logger,
    });
    stopDetector = detector.start();
    flush = () => detector.flush();
    adminA = (await createOrganization(api, "Organization A")).admin_key.key;
    adminB = (await createOrganization(api, "Organization B")).admin_key.key;
  });
  afterAll(async () => {
    stopDetector();
    await api.close();
  });

  async function ingest(shieldKey: string, events: ShieldEvent[]): Promise<void> {
    const res = await api.app.request("/v1/events", json(batchOf(events), bearer(shieldKey)));
    expect(res.status).toBe(202);
    await flush();
  }

  async function incidentsOf(appId: string, admin = adminA): Promise<Incident[]> {
    const res = await api.app.request(`/v1/incidents?app_id=${appId}`, { headers: bearer(admin) });
    expect(res.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await res.json()).incidents;
  }

  async function detail(id: string) {
    const res = await api.app.request(`/v1/incidents/${id}`, { headers: bearer(adminA) });
    expect(res.status).toBe(200);
    return IncidentDetailResponseSchema.parse(await res.json());
  }

  const from = (shieldKey: string, address: string, prefix = PREFIX) => ({
    actor: { ip_prefix: prefix, ip_hash: actorHash(shieldKey, address) },
  });

  it("shows exactly the counted Events as evidence and their addresses as Actors, also after a new Policy version; Containment works", async () => {
    const created = await createAppFor(api, adminA, { name: "Storefront" });
    const appId = created.app.id;
    const key = created.shield_key.key;
    const policy = await publishPolicy(api, adminA, appId, "development", [loginLimit]);
    const ruleId = (policy.rules[0] as PolicyRule).id;
    const throttled = decision({ action: "throttle", mode: "enforce", rule_id: ruleId });
    const base = T0 + 10_000;
    const at = (i: number) => base + i * 1_000;

    clock.ms += 1_000;
    await ingest(key, [
      // Counted: 30 failed logins from one address, 15 clients throttled once each, 5 failed logins from a third.
      ...Array.from({ length: 30 }, (_, i) => login(at(i), 401, from(key, "203.0.113.7"))),
      ...Array.from({ length: 15 }, (_, i) =>
        login(at(30 + i), 429, { decision: throttled, ...from(key, `203.0.113.${100 + i}`) }),
      ),
      ...Array.from({ length: 5 }, (_, i) => login(at(45 + i), 401, from(key, "203.0.113.9"))),
    ]);
    // One wave, one Incident: the 30 failed logins on the covered route open no Failed sign-in burst.
    expect((await incidentsOf(appId)).map((found) => found.rule)).toEqual(["credential-stuffing"]);
    const incident = (await incidentsOf(appId)).find((found) => found.rule === "credential-stuffing");
    if (incident === undefined) throw new Error("No Credential stuffing Incident was opened.");
    expect(incident).toMatchObject({
      rule: "credential-stuffing",
      severity: "high",
      title: "Credential stuffing",
      status: "open",
      ip_prefix: PREFIX,
      detection_count: 1,
      first_seen: new Date(at(0)).toISOString(),
      last_seen: new Date(at(49)).toISOString(),
    });

    // Inside the Incident's span and prefix, none of them counted.
    const inside = base + 20_500;
    await ingest(key, [
      login(inside, 200, from(key, "203.0.113.20")),
      login(inside + 1, 401, {
        ...from(key, "203.0.113.21"),
        request: { method: "GET", route: "/login", status: 401, latency_ms: 1 },
      }),
      login(inside + 2, 401, {
        ...from(key, "203.0.113.22"),
        request: { method: "POST", route: "/signup", status: 401, latency_ms: 1 },
      }),
      // Shield's own enforced block and a Containment's block, both answered 403 on the covered route.
      login(inside + 3, 403, {
        ...from(key, "203.0.113.23"),
        decision: decision({ action: "block", mode: "enforce", rule_id: ruleId }),
      }),
      login(inside + 4, 403, {
        ...from(key, "203.0.113.24"),
        decision: decision({ action: "block", mode: "enforce", containment_id: "cnt_0123456789abcdef01234567" }),
      }),
      // Under a Policy version that has no limit Rule (the built-in one), and one that was never published.
      login(inside + 5, 401, { ...from(key, "203.0.113.25"), decision: decision({ policy_version: 0 }) }),
      login(inside + 6, 401, { ...from(key, "203.0.113.26"), decision: decision({ policy_version: 9 }) }),
      // Another prefix, and outside the span.
      login(inside + 7, 401, from(key, "198.51.100.27", OTHER_PREFIX)),
      login(base + 3_600_000, 401, from(key, "203.0.113.28")),
    ]);

    const expectDetail = async () => {
      const { evidence, actors, incident: current } = await detail(incident.id);
      expect(current.detection_count).toBe(1);
      expect(evidence).toHaveLength(INCIDENT_LIMITS.evidence);
      for (const event of evidence) {
        expect(event.request).toMatchObject({ method: "POST", route: "/login" });
        expect([401, 429]).toContain(event.request.status);
        expect(event.decision.policy_version).toBe(1);
        expect(event.decision.action === "block").toBe(false);
      }
      // Newest first: the last failed logins, then the throttled ones.
      expect(evidence.slice(0, 6).map((event) => event.decision.action)).toEqual([
        "allow",
        "allow",
        "allow",
        "allow",
        "allow",
        "throttle",
      ]);
      expect(actors.slice(0, 2)).toEqual([
        { ip_hash: actorHash(key, "203.0.113.7"), events: 30 },
        { ip_hash: actorHash(key, "203.0.113.9"), events: 5 },
      ]);
      // Then the throttled clients, one counted Event each; ten Actors are listed.
      expect(actors).toHaveLength(10);
      expect(actors.slice(2).every((a) => a.events === 1)).toBe(true);
    };
    await expectDetail();

    // The limit Rule is removed in version 2: what was counted under version 1 stays the evidence.
    await publishPolicy(api, adminA, appId, "development", [{ name: "Admin", path: "/api/admin/**" }]);
    await expectDetail();

    // Containment as for a Blocked burst: an Actor of the evidence, never an address that was not counted.
    const contain = (body: unknown, admin = adminA) =>
      api.app.request(`/v1/incidents/${incident.id}/containments`, json(body, bearer(admin)));
    const actor = (address: string) => ({ target: { kind: "actor", ip_hash: actorHash(key, address) }, ttl_s: 3_600 });
    for (const address of ["203.0.113.20", "203.0.113.23", "203.0.113.25", "203.0.113.28", "203.0.113.99"]) {
      const refused = await expectProblem(await contain(actor(address)), 409);
      expect(refused.reason).toBe("actor-unknown");
    }
    const blockedActor = await contain(actor("203.0.113.100"));
    expect(blockedActor.status).toBe(201);
    expect(ContainmentResponseSchema.parse(await blockedActor.json()).containment.target).toEqual({
      kind: "actor",
      ip_hash: actorHash(key, "203.0.113.100"),
    });
    const blockedPrefix = await contain({ target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: PREFIX });
    expect(blockedPrefix.status).toBe(201);
    expect(ContainmentResponseSchema.parse(await blockedPrefix.json()).containment.target).toEqual({
      kind: "prefix",
      ip_prefix: PREFIX,
    });
    expect((await detail(incident.id)).containments).toHaveLength(2);

    // Another Organization sees neither the Incident nor a way to act on it.
    expect(await incidentsOf(appId, adminB)).toEqual([]);
    await expectProblem(await api.app.request(`/v1/incidents/${incident.id}`, { headers: bearer(adminB) }), 404);
    await expectProblem(await contain(actor("203.0.113.7"), adminB), 404);
  });

  it("opens no Blocked burst beside it for enforced throttles, and keeps them out of a Blocked burst's evidence", async () => {
    const created = await createAppFor(api, adminA, { name: "Both" });
    const key = created.shield_key.key;
    const throttled = THROTTLED;
    const blocked = decision({ action: "block", mode: "enforce", rule_id: RULE_ID });
    const base = T0 + 5_000_000;
    clock.ms += 1_000;
    await ingest(key, [...Array.from({ length: 60 }, (_, i) => login(base + i * 1_000, 429, { decision: throttled }))]);
    expect((await incidentsOf(created.app.id)).map((incident) => incident.rule)).toEqual(["credential-stuffing"]);

    // A real blocked burst in the same span and prefix: its own Incident, with only blocks as evidence.
    clock.ms += 1_000;
    await ingest(
      key,
      Array.from({ length: DETECTION_RULES[0].threshold }, (_, i) =>
        login(base + i * 1_000 + 500, 403, { decision: blocked }),
      ),
    );
    const incidents = await incidentsOf(created.app.id);
    expect(incidents.map((incident) => incident.rule).sort()).toEqual(["blocked-burst", "credential-stuffing"]);
    for (const incident of incidents) {
      const { evidence } = await detail(incident.id);
      expect(evidence.length).toBeGreaterThan(0);
      const expected = incident.rule === "blocked-burst" ? "block" : "throttle";
      expect(evidence.every((event) => event.decision.action === expected)).toBe(true);
    }
  });

  it("judges a stored Event in SQL exactly as the Detector judges it", async () => {
    const organizationId = "org_0123456789abcdef01234567";
    const target: Target = { organizationId, appId: "app_89abcdef0123456789abcdef", environment: "development" };
    const patterns = ["/", "/login", "/LOGIN", "/api/v1.0/login", "/api/users/*/export", "/api/admin/**", "/*", "/**"];
    const routes = [
      "/",
      "/login",
      "/Login",
      "/login/",
      "/login/now",
      "/logins",
      "/LOGİN",
      "/loKin",
      "/api/v1.0/login",
      "/api/v1x0/login",
      "/api/users/:id/export",
      "/api/users/export",
      "/api/users/a/b/export",
      "/api/users/*rest/export",
      "/api/users/x{/:id}/export",
      "/api/admin",
      "/api/admin/",
      "/api/admin/users/:id",
      "/api/administrators",
      "/api/admin/line\nbreak",
      "/line\nbreak",
      "/:page",
      "(unmatched)",
      "(mount)/login",
      "login",
    ];
    const condition = ruleConditionSql("credential-stuffing", "$1");
    const signinCondition = ruleConditionSql("failed-signin-burst", "$1");
    /** What SQL says of a stored Event: [counts toward credential-stuffing, counts toward failed-signin-burst]. */
    const sqlBoth = async (event: StoredEvent, rules: PolicyRule[], version: number): Promise<[boolean, boolean]> => {
      const { rows } = await api.db.tx({ organizationId }, (q) =>
        q.query<{ counted: boolean; signin: boolean }>(
          `SELECT ${condition} AS counted, ${signinCondition} AS signin FROM (SELECT $2::jsonb AS payload) AS stored`,
          [JSON.stringify(coverageEntries(version, rules)), JSON.stringify(event)],
        ),
      );
      return [rows[0]?.counted === true, rows[0]?.signin === true];
    };
    const sqlCounts = async (event: StoredEvent, rules: PolicyRule[], version: number): Promise<boolean> =>
      (await sqlBoth(event, rules, version))[0];
    /** What the guess says in JS: the version must be the Event's own, as in SQL. */
    const guess = (event: StoredEvent, rules: PolicyRule[], version: number) => {
      const coverage = limitCoverage(rules);
      const own = version === event.decision.policy_version;
      return {
        covered: own && covers(coverage, event.request.method, event.request.route),
        limitRule: own && namesRule(coverage, event.decision.rule_id),
      };
    };
    const jsBoth = (event: StoredEvent, legacy: { covered: boolean; limitRule: boolean }): [boolean, boolean] => {
      const keys = matchingRules(event, legacy).map((rule) => rule.key);
      return [keys.includes("credential-stuffing"), keys.includes("failed-signin-burst")];
    };
    const limitRule = (path: string, methods: string[]): PolicyRule => ({
      id: RULE_ID,
      name: "Limit",
      path,
      methods,
      action: "throttle",
      mode: "monitor",
      limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
    });

    let covered = 0;
    for (const path of patterns) {
      for (const [methods, method] of [
        [[], "POST"],
        [["POST"], "POST"],
        [["POST"], "GET"],
        [["GET"], "HEAD"],
        [["HEAD"], "GET"],
      ] as [string[], string][]) {
        const rules = [limitRule(path, methods)];
        for (const route of routes) {
          const event = stored(target, login(T0, 401, { request: { method, route, status: 401, latency_ms: 1 } }));
          const expected = matchingRules(event, guess(event, rules, 1)).some(
            (rule) => rule.key === "credential-stuffing",
          );
          if (expected) covered++;
          // A failed sign-in on a covered route is no failed-signin-burst Event, in SQL as in the Detector.
          expect([path, methods, method, route, ...(await sqlBoth(event, rules, 1))]).toEqual([
            path,
            methods,
            method,
            route,
            ...jsBoth(event, guess(event, rules, 1)),
          ]);
          expect([path, methods, method, route, await sqlCounts(event, rules, 1)]).toEqual([
            path,
            methods,
            method,
            route,
            expected,
          ]);
        }
      }
    }
    expect(covered).toBeGreaterThan(50);

    // The decision and the status, in both places alike; the version must be the Event's own.
    const rules = [limitRule("/login", ["POST"])];
    const cases: [number, Partial<Decision>, number][] = [
      [401, {}, 1],
      [403, {}, 1],
      [429, {}, 1],
      [200, {}, 1],
      [404, {}, 1],
      [401, {}, 2],
      [401, { policy_version: 0 }, 1],
      [403, { action: "block", mode: "enforce", rule_id: RULE_ID }, 1],
      [403, { action: "block", mode: "monitor", rule_id: RULE_ID }, 1],
      [403, { action: "block", mode: "enforce", containment_id: "cnt_0123456789abcdef01234567" }, 1],
      [429, { action: "throttle", mode: "enforce", rule_id: RULE_ID }, 2],
      [200, { action: "throttle", mode: "monitor", rule_id: RULE_ID }, 2],
      [429, { action: "throttle", mode: "enforce", rule_id: null }, 2],
      [401, { action: "throttle", mode: "monitor", rule_id: RULE_ID }, 2],
      [403, { action: "throttle", mode: "monitor", rule_id: RULE_ID }, 1],
      [401, { action: "throttle", mode: "monitor", rule_id: null }, 2],
      [429, { action: "throttle", mode: "enforce", rule_id: RULE_ID }, 1],
      [429, { action: "throttle", mode: "enforce", rule_id: "rul_ffffffffffffffffffffffff" }, 1],
      // Stamped by a Shield of A7: the stamp decides, in both places.
      [401, { limit_rule_id: RULE_ID }, 2],
      [403, { limit_rule_id: null }, 1],
      [200, { limit_rule_id: RULE_ID }, 1],
      [429, { action: "throttle", mode: "enforce", rule_id: RULE_ID, limit_rule_id: RULE_ID }, 2],
      [429, { action: "throttle", mode: "enforce", rule_id: REQUEST_RULE_ID, limit_rule_id: RULE_ID }, 2],
      [401, { action: "throttle", mode: "monitor", rule_id: REQUEST_RULE_ID, limit_rule_id: RULE_ID }, 2],
      [200, { action: "throttle", mode: "monitor", rule_id: REQUEST_RULE_ID, limit_rule_id: null }, 1],
      [403, { action: "block", mode: "enforce", rule_id: REQUEST_RULE_ID, limit_rule_id: RULE_ID }, 1],
    ];
    for (const [status, overrides, version] of cases) {
      const event = stored(target, login(T0, status, { decision: decision(overrides) }));
      const expected = matchingRules(event, guess(event, rules, version)).some(
        (rule) => rule.key === "credential-stuffing",
      );
      expect([status, overrides, version, await sqlCounts(event, rules, version)]).toEqual([
        status,
        overrides,
        version,
        expected,
      ]);
      expect([status, overrides, version, ...(await sqlBoth(event, rules, version))]).toEqual([
        status,
        overrides,
        version,
        ...jsBoth(event, guess(event, rules, version)),
      ]);
    }
    // A Rule without a limit covers nothing, in either place.
    const plain: PolicyRule = {
      id: RULE_ID,
      name: "Plain",
      path: "/login",
      methods: [],
      action: "block",
      mode: "monitor",
    };
    expect(coverageEntries(1, [plain])).toEqual([]);
    expect(await sqlCounts(stored(target, login(T0, 401)), [plain], 1)).toBe(false);
    expect(() => ruleConditionSql("credential-stuffing")).toThrow(TypeError);
    expect(() => ruleConditionSql("failed-signin-burst")).toThrow(TypeError);
  });

  it("shows a Failed sign-in burst only the failures on routes no limit Rule covers, as evidence and as Actors", async () => {
    const created = await createAppFor(api, adminA, { name: "Sign-in beside a limit" });
    const appId = created.app.id;
    const key = created.shield_key.key;
    await publishPolicy(api, adminA, appId, "development", [loginLimit]);
    const base = T0 + 9_000_000;
    const signup = (ms: number, address: string): ShieldEvent =>
      login(ms, 401, {
        ...from(key, address),
        request: { method: "POST", route: "/signup", status: 401, latency_ms: 1 },
      });
    clock.ms += 1_000;
    await ingest(key, [
      ...Array.from({ length: DETECTION_RULES[1].threshold }, (_, i) => signup(base + i * 1_000, "203.0.113.40")),
      // Inside the span: failures on the covered route, and one under a monitored throttle. Not failed sign-ins.
      ...Array.from({ length: 10 }, (_, i) => login(base + i * 1_000 + 500, 401, from(key, "203.0.113.41"))),
      login(base + 20_500, 403, {
        ...from(key, "203.0.113.42"),
        decision: decision({ action: "throttle", mode: "monitor", rule_id: RULE_ID }),
      }),
    ]);
    const incidents = await incidentsOf(appId);
    expect(incidents.map((incident) => incident.rule)).toEqual(["failed-signin-burst"]);
    const incident = incidents[0] as Incident;
    expect(incident.detection_count).toBe(1);
    const { evidence, actors } = await detail(incident.id);
    expect(evidence).toHaveLength(INCIDENT_LIMITS.evidence);
    expect(evidence.every((event) => event.request.route === "/signup")).toBe(true);
    expect(actors).toEqual([{ ip_hash: actorHash(key, "203.0.113.40"), events: DETECTION_RULES[1].threshold }]);
    for (const address of ["203.0.113.41", "203.0.113.42"]) {
      const refused = await expectProblem(
        await api.app.request(
          `/v1/incidents/${incident.id}/containments`,
          json({ target: { kind: "actor", ip_hash: actorHash(key, address) }, ttl_s: 3_600 }, bearer(adminA)),
        ),
        409,
      );
      expect(refused.reason).toBe("actor-unknown");
    }
  });

  it("never logs a key", () => {
    expectNoKeyLogged(api);
  });
});
