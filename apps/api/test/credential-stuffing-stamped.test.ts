import {
  DETECTION_RULES,
  EXAMPLE_SHIELD_EVENT,
  type Incident,
  IncidentDetailResponseSchema,
  ListIncidentsResponseSchema,
  type ShieldEvent,
  type StoredEvent,
} from "@antireverse/protocol";
import { actorHash } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Db } from "../src/db/db.ts";
import { createDetector, type Detector } from "../src/detect/detector.ts";
import { matchingRules } from "../src/detect/rules.ts";
import { listActors } from "../src/stores/incidents.ts";
import {
  batchOf,
  bearer,
  createAppFor,
  createOrganization,
  json,
  makeTestApi,
  publishPolicy,
  type TestApi,
  uuidv7,
} from "./helpers.ts";

// Plan 08 amendment A7, D-064: Credential stuffing counts login protection only. Shield stamps
// `decision.limit_rule_id` with the failure-counting limit Rule that matched the request. Counted: a 401 or 403 the
// app answered on such a request, and a throttle by that Rule — the latter once per client per 5-minute window, so
// that one client retrying against its own limit is not a wave. Plain request limits open no Incident. An Event of
// an older Shield (the member absent, not null) is judged by the coverage guess, narrowed to failure-counting Rules.
// The scenarios are those of the review script a2.ts (cases 1–5 and 7), with Events as a Shield of A7 sends them.

const T0 = Date.parse("2026-11-10T12:00:00.000Z"); // the start of a 5-minute window
const PREFIX = "203.0.113.0/24";
const THRESHOLD = DETECTION_RULES.find((rule) => rule.key === "credential-stuffing")?.threshold ?? 50;
const SIGNIN_THRESHOLD = DETECTION_RULES.find((rule) => rule.key === "failed-signin-burst")?.threshold ?? 30;
const REQUEST_LIMIT_ID = "rul_aaaaaaaaaaaaaaaaaaaaaaaa";

const loginLimit = (path = "/login") => ({
  name: "Login protection",
  path,
  methods: ["POST"],
  mode: "enforce",
  limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
});
const requestLimit = (path: string, mode = "monitor") => ({
  name: "Rate",
  path,
  methods: [],
  mode,
  limit: { requests: 100, window_s: 60, key: "ip", count: "requests" },
});

type Decision = ShieldEvent["decision"];
/** A decision as a Shield of amendment A7 records it: `limit_rule_id` always present. */
const stamped = (overrides: Partial<Decision> = {}): Decision => ({
  ...EXAMPLE_SHIELD_EVENT.decision,
  policy_version: 1,
  limit_rule_id: null,
  ...overrides,
});
/** A decision as a Shield from before A7 records it: no `limit_rule_id` member at all. */
function legacy(overrides: Partial<Decision> = {}): Decision {
  const { limit_rule_id: _absent, ...rest } = stamped(overrides) as Decision & { limit_rule_id?: unknown };
  return rest as Decision;
}

interface App {
  appId: string;
  key: string;
  ruleIds: string[];
}

describe("Credential stuffing from Events Shield stamps (A7, D-064)", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let detector: Detector;
  let stop: () => void;
  let organizationId: string;
  let admin: string;
  let reads = 0;

  beforeAll(async () => {
    api = await makeTestApi({ now, onPolicyPublished: (policy) => detector.policyPublished(policy) });
    const counting: Db = {
      tx: (scope, fn) => {
        reads++;
        return api.db.tx(scope, fn);
      },
      close: () => Promise.resolve(),
    };
    detector = createDetector({ db: counting, bus: api.bus, notifier: { incidentOpened: () => {} }, now });
    stop = detector.start();
    const created = await createOrganization(api, "Organization");
    organizationId = created.organization.id;
    admin = created.admin_key.key;
  });
  afterAll(async () => {
    stop();
    await api.close();
  });

  async function app(rules: unknown[]): Promise<App> {
    offset = 0; // each scenario from the start of one 5-minute window
    const created = await createAppFor(api, admin, { name: "Storefront" });
    const policy = await publishPolicy(api, admin, created.app.id, "development", rules);
    return { appId: created.app.id, key: created.shield_key.key, ruleIds: policy.rules.map((rule) => rule.id) };
  }

  /** An Event from `address` (hashed with the App's Shield key), `step` ms after the previous one. */
  let offset = 0;
  function event(a: App, method: string, route: string, status: number, d: Decision, address = "203.0.113.7") {
    offset += 1_000;
    return {
      ...EXAMPLE_SHIELD_EVENT,
      event_id: uuidv7(T0 + offset),
      ts: new Date(T0 + offset).toISOString(),
      request: { method, route, status, latency_ms: 1 },
      decision: d,
      actor: { ip_prefix: PREFIX, ip_hash: actorHash(a.key, address) },
    } satisfies ShieldEvent;
  }

  async function ingest(a: App, events: ShieldEvent[]): Promise<void> {
    clock.ms += 1_000;
    const res = await api.app.request("/v1/events", json(batchOf(events), bearer(a.key)));
    expect(res.status).toBe(202);
    await detector.flush();
  }

  async function incidentsOf(a: App): Promise<Incident[]> {
    const res = await api.app.request(`/v1/incidents?app_id=${a.appId}`, { headers: bearer(admin) });
    return ListIncidentsResponseSchema.parse(await res.json()).incidents;
  }
  const rulesOf = async (a: App) => (await incidentsOf(a)).map((incident) => incident.rule).sort();

  it("stores an older Shield's decision without limit_rule_id, and a new Shield's null as null", async () => {
    const a = await app([loginLimit()]);
    await ingest(a, [event(a, "POST", "/login", 200, legacy()), event(a, "POST", "/login", 200, stamped())]);
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ has: boolean; value: unknown }>(
        "SELECT payload->'decision' ? 'limit_rule_id' AS has, payload->'decision'->'limit_rule_id' AS value FROM events WHERE app_id = $1 ORDER BY ts",
        [a.appId],
      ),
    );
    expect(rows).toEqual([
      { has: false, value: null },
      { has: true, value: null },
    ]);
  });

  it("a2 case 1: one client failing 10 times, then retrying 40 times against its own limit, is not a wave", async () => {
    const a = await app([loginLimit()]);
    const [login] = a.ruleIds as [string];
    await ingest(a, [
      ...Array.from({ length: 10 }, () => event(a, "POST", "/login", 401, stamped({ limit_rule_id: login }))),
      ...Array.from({ length: 40 }, () =>
        event(
          a,
          "POST",
          "/login",
          429,
          stamped({ action: "throttle", mode: "enforce", rule_id: login, limit_rule_id: login }),
        ),
      ),
    ]);
    expect(await rulesOf(a)).toEqual([]);
  });

  it("a2 case 1 in Monitor mode: the same, though the app answered the retries itself", async () => {
    const a = await app([{ ...loginLimit(), mode: "monitor" }]);
    const [login] = a.ruleIds as [string];
    await ingest(a, [
      ...Array.from({ length: 10 }, () => event(a, "POST", "/login", 401, stamped({ limit_rule_id: login }))),
      ...Array.from({ length: 40 }, () =>
        event(
          a,
          "POST",
          "/login",
          401,
          stamped({ action: "throttle", mode: "monitor", rule_id: login, limit_rule_id: login }),
        ),
      ),
    ]);
    expect(await rulesOf(a)).toEqual([]);
  });

  it("a2 case 2: a plain request limit over its limit opens no Incident", async () => {
    const a = await app([requestLimit("/api/search")]);
    const [search] = a.ruleIds as [string];
    await ingest(
      a,
      Array.from({ length: 60 }, (_, i) =>
        event(
          a,
          "GET",
          "/api/search",
          200,
          stamped({ action: "throttle", mode: "monitor", rule_id: search }),
          `203.0.113.${i}`,
        ),
      ),
    );
    expect(await rulesOf(a)).toEqual([]);
  });

  it("a2 case 3: the app's 403s beside a plain request limit are failed sign-ins, not Credential stuffing", async () => {
    const a = await app([requestLimit("/api/**")]);
    await ingest(
      a,
      Array.from({ length: 50 }, (_, i) => event(a, "GET", "/api/reports/:id", 403, stamped(), `203.0.113.${i}`)),
    );
    expect(await rulesOf(a)).toEqual(["failed-signin-burst"]);
  });

  for (const [label, route] of [
    ["a2 case 4: a route template coverage cannot judge", "/t/:tenant/login"],
    ["a2 case 5: a login handler mounted with app.use", "(unmatched)"],
  ] as const) {
    it(`${label}: the wave opens Credential stuffing only, with every client as an Actor`, async () => {
      const a = await app([loginLimit("/t/acme/login")]);
      const [login] = a.ruleIds as [string];
      const throttle = stamped({ action: "throttle", mode: "enforce", rule_id: login, limit_rule_id: login });
      await ingest(a, [
        // 30 failures from 30 addresses, then 25 clients throttled twice each: 30 + 25 = 55 counted.
        ...Array.from({ length: 30 }, (_, i) =>
          event(a, "POST", route, 401, stamped({ limit_rule_id: login }), `203.0.113.${i}`),
        ),
        ...Array.from({ length: 50 }, (_, i) =>
          event(a, "POST", "/t/acme/login", 429, throttle, `203.0.113.${100 + (i % 25)}`),
        ),
      ]);
      expect(await rulesOf(a)).toEqual(["credential-stuffing"]);
      const incident = (await incidentsOf(a))[0] as Incident;
      const res = await api.app.request(`/v1/incidents/${incident.id}`, { headers: bearer(admin) });
      const detail = IncidentDetailResponseSchema.parse(await res.json());
      // Every counted client is an Actor (all of them, not only the listed ten), a throttled client with one counted
      // Event per window, though it sent two.
      // The Detection holds the first 50 counted (30 failures, then 20 throttled clients): the Incident's span.
      const actors = await api.db.tx({ organizationId }, (q) => listActors(q, incident, 1_000));
      expect(actors).toHaveLength(THRESHOLD);
      expect(actors.every((actor) => actor.events === 1)).toBe(true);
      expect(actors.map((actor) => actor.ip_hash)).toContain(actorHash(a.key, "203.0.113.100"));
      expect(actors.map((actor) => actor.ip_hash)).toContain(actorHash(a.key, "203.0.113.0"));
      expect(detail.actors).toHaveLength(10);
      // Evidence: each throttled client once, never its repeated 429s.
      const throttles = detail.evidence.filter((e) => e.decision.action === "throttle");
      expect(new Set(throttles.map((e) => e.actor.ip_hash)).size).toBe(throttles.length);
    });
  }

  it("a2 case 7: throttles naming a Rule that is not a login protection count toward nothing, stamped or not", async () => {
    const a = await app([{ name: "b", path: "/x", action: "block" }]);
    const unknown = "rul_ffffffffffffffffffffffff";
    await ingest(
      a,
      Array.from({ length: 60 }, (_, i) =>
        event(
          a,
          "GET",
          "/whatever",
          200,
          stamped({ action: "throttle", mode: "monitor", rule_id: unknown }),
          `203.0.113.${i}`,
        ),
      ),
    );
    await ingest(
      a,
      Array.from({ length: 60 }, (_, i) =>
        event(
          a,
          "GET",
          "/whatever",
          429,
          legacy({ action: "throttle", mode: "enforce", rule_id: unknown }),
          `203.0.113.${i}`,
        ),
      ),
    );
    expect(await rulesOf(a)).toEqual([]);
  });

  it("an older Shield's Events: failures on a route a login protection covers, and its throttles once per client", async () => {
    const a = await app([loginLimit(), requestLimit("/api/**", "enforce")]);
    const [login, rate] = a.ruleIds as [string, string];
    await ingest(a, [
      // Not counted: a plain request limit's throttles, and its covered route's failures (failed sign-ins instead).
      ...Array.from({ length: 60 }, (_, i) =>
        event(
          a,
          "GET",
          "/api/x",
          429,
          legacy({ action: "throttle", mode: "enforce", rule_id: rate }),
          `203.0.113.${i}`,
        ),
      ),
      // 40 failures, and one client throttled 30 times: 41.
      ...Array.from({ length: 40 }, (_, i) => event(a, "POST", "/login", 401, legacy(), `203.0.113.${i}`)),
      ...Array.from({ length: 30 }, () =>
        event(
          a,
          "POST",
          "/login",
          429,
          legacy({ action: "throttle", mode: "enforce", rule_id: login }),
          "203.0.113.200",
        ),
      ),
    ]);
    expect(await rulesOf(a)).toEqual([]);
    // Nine more throttled clients: 50.
    await ingest(
      a,
      Array.from({ length: 9 }, (_, i) =>
        event(
          a,
          "POST",
          "/login",
          429,
          legacy({ action: "throttle", mode: "enforce", rule_id: login }),
          `203.0.113.${210 + i}`,
        ),
      ),
    );
    expect(await rulesOf(a)).toEqual(["credential-stuffing"]);
  });

  it("an older Shield's failures beside a plain request limit only are failed sign-ins", async () => {
    const a = await app([requestLimit("/login")]);
    await ingest(
      a,
      Array.from({ length: SIGNIN_THRESHOLD }, (_, i) => event(a, "POST", "/login", 401, legacy(), `203.0.113.${i}`)),
    );
    expect(await rulesOf(a)).toEqual(["failed-signin-burst"]);
  });

  it("judges by the stamp, never the coverage guess, when the member is present (null included)", () => {
    const base = {
      ...EXAMPLE_SHIELD_EVENT,
      request: { method: "POST", route: "/login", status: 401, latency_ms: 1 },
      organization_id: organizationId,
      app_id: "app_89abcdef0123456789abcdef",
      environment: "development",
      received_at: new Date(T0).toISOString(),
    } as const;
    const keys = (d: Decision, covered: boolean) =>
      matchingRules({ ...base, decision: d } as StoredEvent, { covered, limitRule: covered }).map((rule) => rule.key);
    // Stamped null: a failed sign-in, whatever coverage would say.
    expect(keys(stamped(), true)).toEqual(["failed-signin-burst"]);
    // Stamped with the Rule: Credential stuffing only.
    expect(keys(stamped({ limit_rule_id: REQUEST_LIMIT_ID }), false)).toEqual(["credential-stuffing"]);
    // Absent: the guess decides.
    expect(keys(legacy(), true)).toEqual(["credential-stuffing"]);
    expect(keys(legacy(), false)).toEqual(["failed-signin-burst"]);
  });

  it("F9: Events of an older Shield naming 60 versions round-robin read each version once", async () => {
    const a = await app([loginLimit()]);
    for (let v = 2; v <= 60; v++) {
      await publishPolicy(api, admin, a.appId, "development", [
        { ...loginLimit(), limit: { requests: v, window_s: 300, key: "ip", count: "failures" } },
      ]);
    }
    const pass = async () => {
      const before = reads;
      for (let round = 0; round < 5; round++) {
        await ingest(
          a,
          Array.from({ length: 60 }, (_, i) => ({
            ...event(a, "POST", "/other", 401, legacy({ policy_version: 1 + i }), `198.51.100.${i}`),
            actor: { ip_prefix: `10.${round}.${i}.0/24`, ip_hash: null },
          })),
        );
      }
      return reads - before;
    };
    expect(await pass()).toBeLessThanOrEqual(60);
    expect(await pass()).toBe(0);
  });
});
