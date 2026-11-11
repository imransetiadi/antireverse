import {
  type Environment,
  PolicyResponseSchema,
  type ShieldEvent,
  SIMULATION_LIMITS,
  SimulatePolicyResponseSchema,
  type SimulationResult,
} from "@antireverse/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { insertEvents, REPLAY_EVENTS_SQL } from "../src/stores/events.ts";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  policyPath,
  publishPolicy,
  shieldEvent,
  type TestApi,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-11T09:00:00.000Z");
const HOUR = 3_600_000;
const A = "iph_000000000000000000000000000000aa";
const B = "iph_000000000000000000000000000000bb";

const adminRule = { name: "Admin area", path: "/api/admin/**" };
const signedRule = { name: "Signed checkout", path: "/api/checkout", methods: ["POST"], requires: "signature" };
const limitRule = { name: "Login", path: "/login", methods: ["POST"], limit: { requests: 2, window_s: 60, key: "ip" } };

const simulatePath = (appId: string): string => `/v1/apps/${appId}/policy/simulate`;

describe("Policy simulation", () => {
  let api: TestApi;
  const clock = { now: new Date(T0), elapsed: 0, perRead: 0 };
  let organizationA: string;
  let adminA: string;
  let adminB: string;
  let shieldA: string;

  async function freshApp(): Promise<string> {
    return (await createAppFor(api, adminA, { name: "Storefront" })).app.id;
  }

  /** An Event `agoMs` before now. */
  function event(
    agoMs: number,
    method: string,
    route: string,
    more: { status?: number; ip?: string | null; signature?: ShieldEvent["signature"]; prefix?: string } = {},
  ): ShieldEvent {
    return shieldEvent(clock.now.getTime() - agoMs, {
      request: { method, route, status: more.status ?? 200, latency_ms: 1 },
      actor: { ip_prefix: more.prefix ?? "198.51.100.0/24", ip_hash: more.ip === undefined ? A : more.ip },
      signature: more.signature ?? null,
    });
  }

  async function store(appId: string, events: ShieldEvent[], environment: Environment = "production"): Promise<void> {
    await api.db.tx({ organizationId: organizationA }, (q) =>
      insertEvents(q, { organizationId: organizationA, appId, environment, receivedAt: clock.now }, events),
    );
  }

  async function simulate(
    appId: string,
    rules: unknown[],
    environment: Environment = "production",
  ): Promise<SimulationResult> {
    const res = await api.app.request(simulatePath(appId), json({ environment, rules }, bearer(adminA)));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    return SimulatePolicyResponseSchema.parse(await res.json()).simulation;
  }

  /** Every row of every table, as text: what a request that stores nothing leaves unchanged. */
  async function everything(): Promise<string> {
    return api.db.owner(async (q) => {
      const tables = await q.query<{ name: string }>(
        "SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
      );
      const parts: string[] = [];
      for (const { name } of tables.rows) {
        const rows = await q.query<{ row: string }>(`SELECT t::text AS row FROM "${name}" t ORDER BY 1`);
        parts.push(`${name}:${rows.rows.length}`, ...rows.rows.map(({ row }) => row));
      }
      return parts.join("\n");
    });
  }

  beforeAll(async () => {
    api = await makeTestApi({
      now: () => clock.now,
      simulation: {
        eventsMax: 20,
        timeLimitMs: 10_000,
        // A clock the tests move: every read of it costs `perRead` milliseconds.
        elapsedMs: () => {
          clock.elapsed += clock.perRead;
          return clock.elapsed;
        },
      },
    });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    organizationA = a.organization.id;
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    shieldA = (await createAppFor(api, adminA)).shield_key.key;
  });
  afterAll(async () => {
    await api.close();
  });
  beforeEach(() => {
    // A minute and more later: the simulations of one test never use up the budget of the next.
    clock.now = new Date(clock.now.getTime() + 61_000);
    clock.perRead = 0;
  });

  it("replays the Events of the last 24 hours of the App and Environment against the draft, oldest first", async () => {
    const appId = await freshApp();
    await store(appId, [
      // Given newest first: the limit is replayed in the order of `ts`, not of insertion.
      event(1_000, "POST", "/login", { ip: B }),
      event(2_000, "POST", "/login"),
      event(3_000, "POST", "/login"),
      event(4_000, "POST", "/login"),
      event(5_000, "POST", "/api/checkout", { signature: { status: "missing", body: null } }),
      event(6_000, "POST", "/api/checkout", { signature: { status: "valid", body: "none" } }),
      // A signed body: whether Shield's body hook would have accepted it is not recorded.
      event(6_500, "POST", "/api/checkout", { signature: { status: "valid", body: "checked" } }),
      event(7_000, "GET", "/api/admin/users/:id", { ip: B }),
      event(8_000, "GET", "/api/admin/users"),
      // No client hash: what it may have counted on the login limit is on no client's counter.
      event(9_000, "POST", "(unmatched)", { ip: null }),
      event(2 * HOUR, "POST", "/login"), // outside every window of the limit
      event(25 * HOUR, "GET", "/api/admin/users"), // older than 24 hours
    ]);
    // Another Environment and another App: never read.
    await store(appId, [event(1_000, "GET", "/api/admin/users")], "staging");
    await store(await freshApp(), [event(1_000, "GET", "/api/admin/users")]);

    const simulation = await simulate(appId, [adminRule, signedRule, limitRule]);

    expect(simulation).toEqual({
      period: { from: new Date(clock.now.getTime() - 24 * HOUR).toISOString(), to: clock.now.toISOString() },
      ran_at: clock.now.toISOString(),
      events: 11,
      truncated: false,
      undecidable_events: 2,
      not_simulated: ["patches", "containments", "decoded_paths", "device_limits", "body_verification"],
      rules: [
        {
          index: 0,
          name: "Admin area",
          matched: 2,
          would_block: 2,
          would_fail_signature: 0,
          would_throttle: 0,
          already_refused: 0,
          undecidable: 1,
          clients_affected: 2,
          unknown_client_events: 0,
          sample_routes: [
            { route: "/api/admin/users", method: "GET", count: 1 },
            { route: "/api/admin/users/:id", method: "GET", count: 1 },
          ],
          // Every Rule of the draft is in Monitor mode and none hides another's requests: promoting one refuses
          // what the all-enforced view says.
          if_promoted: { would_refuse: 2, clients_affected: 2, unknown_client_events: 0, undecidable: 1 },
        },
        {
          index: 1,
          name: "Signed checkout",
          matched: 3,
          would_block: 0,
          would_fail_signature: 1,
          would_throttle: 0,
          already_refused: 0,
          undecidable: 2,
          clients_affected: 1,
          unknown_client_events: 0,
          sample_routes: [{ route: "/api/checkout", method: "POST", count: 1 }],
          if_promoted: { would_refuse: 1, clients_affected: 1, unknown_client_events: 0, undecidable: 2 },
        },
        {
          index: 2,
          name: "Login",
          matched: 5,
          would_block: 0,
          would_fail_signature: 0,
          would_throttle: 1,
          already_refused: 0,
          undecidable: 1,
          clients_affected: 1,
          unknown_client_events: 0,
          sample_routes: [{ route: "/login", method: "POST", count: 1 }],
          if_promoted: { would_refuse: 1, clients_affected: 1, unknown_client_events: 0, undecidable: 1 },
        },
      ],
      totals: { would_refuse: 4, clients_affected: 2, unknown_client_events: 0 },
    });
    expect(JSON.stringify(simulation)).not.toContain("iph_");
  });

  it("answers for an App without Events, and for a draft without Rules", async () => {
    const appId = await freshApp();
    expect(await simulate(appId, [adminRule], "staging")).toMatchObject({
      events: 0,
      truncated: false,
      rules: [{ index: 0, name: "Admin area", matched: 0 }],
      totals: { would_refuse: 0, clients_affected: 0, unknown_client_events: 0 },
    });
    expect(await simulate(appId, [])).toMatchObject({ events: 0, rules: [] });
  });

  it("echoes the id of a Rule that has one and invents none", async () => {
    const appId = await freshApp();
    const [published] = (await publishPolicy(api, adminA, appId, "production", [adminRule])).rules;
    const simulation = await simulate(appId, [published, signedRule]);
    expect(simulation.rules[0]?.id).toBe(published?.id);
    expect(simulation.rules[1]).not.toHaveProperty("id");
  });

  it("stores nothing and publishes nothing", async () => {
    const appId = await freshApp();
    await publishPolicy(api, adminA, appId, "production", [adminRule]);
    await store(appId, [event(1_000, "GET", "/api/admin/users"), event(2_000, "POST", "/login")]);
    const before = await everything();
    expect(before).toContain("policy_versions:");

    const simulation = await simulate(appId, [adminRule, limitRule, signedRule]);
    expect(simulation.totals.would_refuse).toBe(1);

    expect(await everything()).toBe(before);
    const res = await api.app.request(policyPath(appId, "production"), { headers: bearer(adminA) });
    const policy = PolicyResponseSchema.parse(await res.json()).policy;
    expect(policy.version).toBe(1);
    expect(policy.rules).toHaveLength(1);
  });

  it("replays the newest Events when there are more than the cap, and says the period was cut short", async () => {
    const appId = await freshApp();
    // 25 Events, one a minute; the cap of this test API is 20.
    await store(
      appId,
      Array.from({ length: 25 }, (_, n) => event((n + 1) * 60_000, "GET", "/api/admin/users")),
    );
    const simulation = await simulate(appId, [adminRule]);
    expect(simulation).toMatchObject({
      events: 20,
      truncated: true,
      // The oldest Event replayed: 20 minutes ago.
      period: { from: new Date(clock.now.getTime() - 20 * 60_000).toISOString(), to: clock.now.toISOString() },
      totals: { would_refuse: 20 },
    });

    // Exactly the cap: nothing was cut.
    const exact = await freshApp();
    await store(
      exact,
      Array.from({ length: 20 }, (_, n) => event((n + 1) * 60_000, "GET", "/api/admin/users")),
    );
    expect(await simulate(exact, [adminRule])).toMatchObject({
      events: 20,
      truncated: false,
      period: { from: new Date(clock.now.getTime() - 24 * HOUR).toISOString() },
    });
  });

  it("is cut off after the time limit with what it has, rather than failing", async () => {
    const appId = await freshApp();
    await store(
      appId,
      Array.from({ length: 10 }, (_, n) => event((n + 1) * 60_000, "GET", "/api/admin/users")),
    );
    clock.perRead = 20_000; // the second look at the clock is already past the limit
    const simulation = await simulate(appId, [adminRule]);
    expect(simulation).toMatchObject({ truncated: true, events: 0, totals: { would_refuse: 0 } });
    expect(simulation.period.from).toBe(new Date(clock.now.getTime() - 24 * HOUR).toISOString());
  });

  it("says what promoting each monitor Rule would refuse, beside the all-enforced view (review F5)", async () => {
    const appId = await freshApp();
    await store(
      appId,
      Array.from({ length: 5 }, (_, n) => event((n + 1) * 1_000, "GET", "/api/data")),
    );
    const simulation = await simulate(appId, [
      { name: "Api", path: "/api/**" },
      { name: "Data", path: "/api/data" },
      { name: "Enforced", path: "/api/other", mode: "enforce" },
    ]);
    // Every Rule enforced, the first takes the five requests; promoted alone, the second refuses them.
    expect(simulation.rules.map((row) => row.would_block)).toEqual([5, 0, 0]);
    expect(simulation.rules.map((row) => row.if_promoted)).toEqual([
      { would_refuse: 5, clients_affected: 1, unknown_client_events: 0, undecidable: 0 },
      { would_refuse: 5, clients_affected: 1, unknown_client_events: 0, undecidable: 0 },
      undefined,
    ]);
    expect(simulation.rules[2]).not.toHaveProperty("if_promoted");
  });

  it("leaves if_promoted out when the time runs out after the main replay", async () => {
    const appId = await freshApp();
    await store(appId, [event(1_000, "GET", "/api/data")]);
    // Reads of the clock: the start, the main replay's check, then the first promotion's check — past the limit.
    clock.perRead = 6_000;
    const simulation = await simulate(appId, [
      { name: "Api", path: "/api/**" },
      { name: "Data", path: "/api/data" },
    ]);
    expect(simulation).toMatchObject({ events: 1, truncated: false, totals: { would_refuse: 1 } });
    expect(simulation.rules.map((row) => row.if_promoted)).toEqual([undefined, undefined]);
  });

  it("counts refused Events without a client hash apart from the clients (review F6)", async () => {
    const appId = await freshApp();
    await store(appId, [
      event(3_000, "GET", "/api/admin/a", { ip: null }),
      event(2_000, "GET", "/api/admin/a", { ip: null }),
      event(1_000, "GET", "/api/admin/a", { ip: B }),
    ]);
    const simulation = await simulate(appId, [adminRule]);
    expect(simulation.rules[0]).toMatchObject({ would_block: 3, clients_affected: 1, unknown_client_events: 2 });
    expect(simulation.totals).toEqual({ would_refuse: 3, clients_affected: 1, unknown_client_events: 2 });
  });

  it("does not judge a limit for a network on the Organization's never-block list (review F3)", async () => {
    const appId = await freshApp();
    const listed = await api.app.request(
      "/v1/allowlist",
      json({ cidr: "203.0.113.0/24", note: "Office" }, bearer(adminA)),
    );
    expect(listed.status).toBe(201);
    await store(appId, [
      ...[6, 5, 4].map((s) => event(s * 1_000, "POST", "/login", { prefix: "203.0.113.0/24" })),
      ...[3, 2, 1].map((s) => event(s * 1_000, "POST", "/login", { ip: B, prefix: "198.51.100.0/24" })),
      event(500, "GET", "/api/admin/a", { prefix: "203.0.113.0/24" }),
    ]);
    const simulation = await simulate(appId, [limitRule, adminRule]);
    expect(simulation.rules[0]).toMatchObject({ matched: 6, would_throttle: 1, undecidable: 3 });
    expect(simulation.rules[1]).toMatchObject({ matched: 1, would_block: 1 });
  });

  it("includes Events stamped up to 5 minutes ahead of the API's clock (review F11)", async () => {
    const appId = await freshApp();
    await store(appId, [
      event(-2_000, "GET", "/api/admin/a"),
      event(-5 * 60_000, "GET", "/api/admin/b"),
      event(-5 * 60_000 - 1, "GET", "/api/admin/c"),
      event(-HOUR, "GET", "/api/admin/d"),
      event(0, "GET", "/api/admin/e"),
      event(24 * HOUR, "GET", "/api/admin/f"),
      event(24 * HOUR + 1, "GET", "/api/admin/g"),
    ]);
    const simulation = await simulate(appId, [adminRule]);
    expect(simulation.events).toBe(4);
    expect(simulation.rules[0]?.sample_routes.map((sample) => sample.route)).toEqual([
      "/api/admin/a",
      "/api/admin/b",
      "/api/admin/e",
      "/api/admin/f",
    ]);
    // The period ends with the newest Event replayed when that is ahead of the clock; the run is dated by the clock.
    expect(simulation.period).toEqual({
      from: new Date(clock.now.getTime() - 24 * HOUR).toISOString(),
      to: new Date(clock.now.getTime() + 5 * 60_000).toISOString(),
    });
    expect(simulation.ran_at).toBe(clock.now.toISOString());
  });

  it("reads its Events through the index made for it", async () => {
    const appId = await freshApp();
    await store(
      appId,
      Array.from({ length: 200 }, (_, n) => event((n + 1) * 1_000, "GET", "/api/admin/users")),
    );
    const plan = await api.db.owner(async (q) => {
      await q.query("ANALYZE events");
      await q.query("SET LOCAL enable_seqscan = off");
      const { rows } = await q.query<Record<string, string>>(
        `EXPLAIN ${REPLAY_EVENTS_SQL.replace("$1", `'${organizationA}'`)
          .replace("$2", `'${appId}'`)
          .replace("$3", "'production'")
          .replace("$4", "'2026-11-10T00:00:00Z'")
          .replace("$5", "'2026-11-12T00:00:00Z'")
          .replace("$6", "21")}`,
      );
      return rows.map((row) => Object.values(row)[0]).join("\n");
    });
    expect(plan).toContain("events_replay");
    // The index gives the order: nothing is sorted.
    expect(plan).not.toContain("Sort");
  });

  it("replays a device limit with the recorded attestation", async () => {
    const appId = await freshApp();
    const attested = { status: "valid", verdict: "trusted", risk: 0 } as const;
    await store(appId, [
      ...[5, 4, 3].map((s) => ({ ...event(s * 1_000, "GET", "/api/search"), attestation: attested })),
      event(2_000, "GET", "/api/search", { ip: B }),
      event(1_000, "GET", "/api/search", { ip: B }),
      event(500, "GET", "/api/search", { ip: null }),
    ]);
    const simulation = await simulate(appId, [
      { name: "Search", path: "/api/search", limit: { requests: 1, window_s: 60, key: "device" } },
    ]);
    // A: attested — its device is unknown, not judged. B: no token, the 2nd is over. No hash: not judged.
    expect(simulation.rules[0]).toMatchObject({ matched: 6, would_throttle: 1, undecidable: 4, clients_affected: 1 });
  });

  it("uses the protocol's limits unless told otherwise", () => {
    expect(SIMULATION_LIMITS).toMatchObject({ eventsMax: 50_000, timeLimitMs: 10_000, perMinute: 6, windowHours: 24 });
  });

  describe("refusals", () => {
    it("requires an admin key", async () => {
      const appId = await freshApp();
      const body = { environment: "production", rules: [adminRule] };
      await expectProblem(await api.app.request(simulatePath(appId), json(body)), 401);
      await expectProblem(await api.app.request(simulatePath(appId), json(body, bearer(shieldA))), 403);
    });

    it("answers 404 for another Organization's App, an unknown App and a malformed id", async () => {
      const appId = await freshApp();
      await store(appId, [event(1_000, "GET", "/api/admin/users")]);
      const body = { environment: "production", rules: [adminRule] };
      await expectProblem(await api.app.request(simulatePath(appId), json(body, bearer(adminB))), 404);
      await expectProblem(
        await api.app.request(simulatePath(`app_${"0".repeat(24)}`), json(body, bearer(adminA))),
        404,
      );
      await expectProblem(await api.app.request(simulatePath("nope"), json(body, bearer(adminA))), 404);
    });

    it.each([
      ["no environment", { rules: [] }, "environment"],
      ["an unknown environment", { environment: "test", rules: [] }, "environment"],
      ["no Rules member", { environment: "production" }, "rules"],
      ["a bad pattern", { environment: "production", rules: [{ name: "X", path: "api" }] }, "rules.0.path"],
      [
        "a limit beside a requirement",
        { environment: "production", rules: [{ ...limitRule, requires: "signature" }] },
        "rules.0.requires",
      ],
      [
        "more than 50 Rules",
        { environment: "production", rules: Array.from({ length: 51 }, () => adminRule) },
        "rules",
      ],
      [
        "an enforced Rule for every path",
        { environment: "production", rules: [{ name: "All", path: "/**", mode: "enforce" }] },
        "rules.0.mode",
      ],
    ])("refuses %s as a publish does", async (_name, body, path) => {
      const appId = await freshApp();
      const problem = await expectProblem(await api.app.request(simulatePath(appId), json(body, bearer(adminA))), 400);
      expect(problem.errors?.map((error) => error.path)).toContain(path);
    });

    it("refuses two Rules with one id", async () => {
      const appId = await freshApp();
      const [published] = (await publishPolicy(api, adminA, appId, "production", [adminRule])).rules;
      const body = { environment: "production", rules: [published, published] };
      const problem = await expectProblem(await api.app.request(simulatePath(appId), json(body, bearer(adminA))), 400);
      expect(problem.errors?.map((error) => error.path)).toEqual(["rules.1.id"]);
    });

    it("allows 6 simulations in any 60 seconds per Organization, then answers 429 with Retry-After", async () => {
      const appId = await freshApp();
      const body = { environment: "production", rules: [adminRule] };
      const run = async (key = adminA, id = appId) =>
        (await api.app.request(simulatePath(id), json(body, bearer(key)))).status;
      // Nothing that is not replayed uses the budget (review F10): a refused draft, an App that does not exist.
      for (let n = 0; n < 8; n++) {
        await expectProblem(
          await api.app.request(simulatePath(appId), json({ environment: "production" }, bearer(adminA))),
          400,
        );
        expect(await run(adminA, `app_${"0".repeat(24)}`)).toBe(404);
        expect(await run(adminB)).toBe(404);
      }
      for (let n = 0; n < 6; n++) {
        clock.now = new Date(clock.now.getTime() + 1_000);
        expect(await run()).toBe(200);
      }
      const refused = await api.app.request(simulatePath(appId), json(body, bearer(adminA)));
      const problem = await expectProblem(refused, 429);
      expect(problem.type).toBe("https://antireverse.dev/problems/too-many-requests");
      // The oldest of the six ran 5 seconds ago: it leaves the 60 seconds in 55.
      expect(refused.headers.get("retry-after")).toBe("55");

      // Another Organization has its own budget.
      const other = (await createAppFor(api, adminB)).app.id;
      expect(await run(adminB, other)).toBe(200);
      // 55 seconds later one has left the window, not all six: one more runs, the next is refused.
      clock.now = new Date(clock.now.getTime() + 55_000);
      expect(await run()).toBe(200);
      expect(await run()).toBe(429);
    });

    it("counts over a sliding window: no 12 simulations around the turn of a minute", async () => {
      const appId = await freshApp();
      const body = { environment: "production", rules: [adminRule] };
      const run = async () => (await api.app.request(simulatePath(appId), json(body, bearer(adminA)))).status;
      const statuses = [await run()];
      clock.now = new Date(clock.now.getTime() + 59_900);
      for (let n = 0; n < 5; n++) statuses.push(await run());
      clock.now = new Date(clock.now.getTime() + 100);
      for (let n = 0; n < 6; n++) statuses.push(await run());
      expect(statuses).toEqual([200, 200, 200, 200, 200, 200, 200, 429, 429, 429, 429, 429]);
    });
  });

  it("logs no key", () => {
    expectNoKeyLogged(api);
  });
});
