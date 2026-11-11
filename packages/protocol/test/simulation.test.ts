import { describe, expect, it } from "vitest";
import {
  ENVIRONMENTS,
  EXAMPLE_LIMIT_RULE,
  EXAMPLE_POLICY,
  EXAMPLE_POLICY_RULE,
  EXAMPLE_SIMULATION_RESULT,
  LIMITS,
  POLICY_LIMITS,
  PublishPolicyRequestSchema,
  SIMULATION_LIMITS,
  SIMULATION_NOT_SIMULATED,
  type SimulatePolicyRequest,
  type SimulatePolicyRequestInput,
  SimulatePolicyRequestSchema,
  type SimulatePolicyResponse,
  SimulatePolicyResponseSchema,
  type SimulationResult,
  SimulationResultSchema,
  type SimulationRuleResult,
  type SimulationSampleRoute,
} from "../src/index.ts";

const rules = (count: number) => Array.from({ length: count }, () => EXAMPLE_POLICY_RULE);
const request = (patch: Record<string, unknown> = {}) => ({ environment: "production", rules: [], ...patch });

const FIRST = EXAMPLE_SIMULATION_RESULT.rules[0] as SimulationRuleResult;
/** Totals of a simulation that would refuse nothing. */
const TOTALS = { would_refuse: 0, clients_affected: 0, unknown_client_events: 0 };
const result = (patch: Record<string, unknown> = {}) => ({ ...EXAMPLE_SIMULATION_RESULT, ...patch });
/** The example with its first Rule row patched. */
const withRule = (patch: Record<string, unknown>) =>
  result({ rules: [{ ...FIRST, ...patch }, ...EXAMPLE_SIMULATION_RESULT.rules.slice(1)] });
const accepts = (value: unknown): boolean => SimulationResultSchema.safeParse(value).success;
const issuePaths = (value: unknown): string[] =>
  SimulationResultSchema.safeParse(value).error?.issues.map((issue) => issue.path.join(".")) ?? [];

describe("SIMULATION_LIMITS (slice 11)", () => {
  it("has the values of the plan", () => {
    expect(SIMULATION_LIMITS).toEqual({
      windowHours: 24,
      eventsMax: 50_000,
      sampleRoutesMax: 5,
      perMinute: 6,
      timeLimitMs: 10_000,
    });
    expect(Object.isFrozen(SIMULATION_LIMITS)).toBe(true);
  });
});

describe("SimulatePolicyRequestSchema", () => {
  it("parses an Environment and draft Rules in order, with the defaults of a publish", () => {
    const input: SimulatePolicyRequestInput = {
      environment: "staging",
      rules: [
        { name: "Login", path: "/login" },
        EXAMPLE_POLICY_RULE,
        { name: "Sign in limit", path: "/login", limit: { requests: 5, window_s: 60, key: "ip" } },
        { name: "Signed", path: "/api/**", requires: "signature" },
      ],
    };
    const parsed: SimulatePolicyRequest = SimulatePolicyRequestSchema.parse(input);
    expect(parsed).toEqual({
      environment: "staging",
      rules: [
        { name: "Login", path: "/login", methods: [], action: "block", mode: "monitor" },
        EXAMPLE_POLICY_RULE,
        {
          name: "Sign in limit",
          path: "/login",
          methods: [],
          action: "throttle",
          mode: "monitor",
          limit: { requests: 5, window_s: 60, key: "ip", count: "requests" },
        },
        { name: "Signed", path: "/api/**", methods: [], action: "block", mode: "monitor", requires: "signature" },
      ],
    });
  });

  it("parses the Rules exactly as a publish does", () => {
    const drafts = [{ name: "Login", path: "/login" }, EXAMPLE_LIMIT_RULE, ...EXAMPLE_POLICY.rules];
    expect(SimulatePolicyRequestSchema.parse(request({ rules: drafts })).rules).toEqual(
      PublishPolicyRequestSchema.parse({ rules: drafts }).rules,
    );
  });

  it("requires one of the Environments", () => {
    for (const environment of ENVIRONMENTS) {
      expect(SimulatePolicyRequestSchema.parse(request({ environment })).environment).toBe(environment);
    }
    expect(SimulatePolicyRequestSchema.safeParse({ rules: [] }).success).toBe(false);
    for (const bad of ["prod", "", "Production", null, 1]) {
      expect(SimulatePolicyRequestSchema.safeParse(request({ environment: bad })).success).toBe(false);
    }
  });

  it("accepts 0 to 50 Rules and rejects 51", () => {
    expect(SimulatePolicyRequestSchema.safeParse(request({ rules: [] })).success).toBe(true);
    expect(SimulatePolicyRequestSchema.safeParse(request({ rules: rules(POLICY_LIMITS.rulesMax) })).success).toBe(true);
    expect(SimulatePolicyRequestSchema.safeParse(request({ rules: rules(POLICY_LIMITS.rulesMax + 1) })).success).toBe(
      false,
    );
  });

  it("requires rules to be a list", () => {
    expect(SimulatePolicyRequestSchema.safeParse({ environment: "production" }).success).toBe(false);
    expect(SimulatePolicyRequestSchema.safeParse(request({ rules: null })).success).toBe(false);
    expect(SimulatePolicyRequestSchema.safeParse(request({ rules: EXAMPLE_POLICY_RULE })).success).toBe(false);
    expect(SimulatePolicyRequestSchema.safeParse(undefined).success).toBe(false);
  });

  it("refuses an invalid draft as a publish does, naming the Rule and the field", () => {
    const malformed = SimulatePolicyRequestSchema.safeParse(
      request({ rules: [EXAMPLE_POLICY_RULE, { name: "Broken", path: "/a//b", methods: ["get"] }] }),
    );
    expect(malformed.error?.issues.map((issue) => issue.path.join("."))).toEqual(["rules.1.path", "rules.1.methods.0"]);

    // The checks that span members (slice 08): a limit needs throttle, throttle needs a limit, never both a
    // requirement and a limit.
    const limit = { requests: 5, window_s: 60, key: "ip" };
    for (const bad of [
      { name: "A", path: "/a", action: "block", limit },
      { name: "A", path: "/a", action: "throttle" },
      { name: "A", path: "/a", requires: "signature", limit },
      { name: "A", path: "/a", limit: { ...limit, requests: 0 } },
      { name: "A", path: "/a", requires: "attestation" },
    ]) {
      expect(SimulatePolicyRequestSchema.safeParse(request({ rules: [bad] })).success).toBe(false);
    }
  });

  it("strips unknown keys, the publish-only members included: a simulation publishes nothing", () => {
    const parsed = SimulatePolicyRequestSchema.parse({
      environment: "production",
      expected_version: 3,
      allow_broad: true,
      app_id: "app_ffffffffffffffffffffffff",
      rules: [{ ...EXAMPLE_POLICY_RULE, published_by: "synthetic" }],
    });
    expect(parsed).toEqual({ environment: "production", rules: [EXAMPLE_POLICY_RULE] });
  });
});

describe("SimulationResultSchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: SimulationResult = SimulationResultSchema.parse(EXAMPLE_SIMULATION_RESULT);
    expect(parsed).toEqual(EXAMPLE_SIMULATION_RESULT);
  });

  it("has exactly the members of the plan's Result line", () => {
    expect(Object.keys(EXAMPLE_SIMULATION_RESULT).sort()).toEqual([
      "events",
      "not_simulated",
      "period",
      "ran_at",
      "rules",
      "totals",
      "truncated",
      "undecidable_events",
    ]);
    expect(Object.keys(EXAMPLE_SIMULATION_RESULT.period).sort()).toEqual(["from", "to"]);
    expect(Object.keys(EXAMPLE_SIMULATION_RESULT.totals).sort()).toEqual([
      "clients_affected",
      "unknown_client_events",
      "would_refuse",
    ]);
    expect(Object.keys(FIRST).sort()).toEqual([
      "already_refused",
      "clients_affected",
      "id",
      "index",
      "matched",
      "name",
      "sample_routes",
      "undecidable",
      "unknown_client_events",
      "would_block",
      "would_fail_signature",
      "would_throttle",
    ]);
    const sample: SimulationSampleRoute | undefined = FIRST.sample_routes[0];
    expect(Object.keys(sample ?? {}).sort()).toEqual(["count", "method", "route"]);
  });

  it("requires every member", () => {
    for (const key of Object.keys(EXAMPLE_SIMULATION_RESULT)) {
      const { [key]: _omitted, ...rest } = EXAMPLE_SIMULATION_RESULT as Record<string, unknown>;
      expect(accepts(rest), key).toBe(false);
    }
    for (const key of Object.keys(FIRST).filter((name) => name !== "id" && name !== "if_promoted")) {
      const { [key]: _omitted, ...rest } = FIRST as Record<string, unknown>;
      expect(accepts(result({ rules: [rest] })), key).toBe(false);
    }
    for (const key of Object.keys(TOTALS)) {
      const { [key]: _omitted, ...rest } = TOTALS as Record<string, unknown>;
      expect(accepts(result({ totals: rest })), key).toBe(false);
    }
    expect(accepts(result({ period: { from: EXAMPLE_SIMULATION_RESULT.period.from } }))).toBe(false);
  });

  it("strips unknown keys at every level, so a client hash or address can never ride along", () => {
    const parsed = SimulationResultSchema.parse({
      ...EXAMPLE_SIMULATION_RESULT,
      ip_hashes: ["iph_0123456789abcdef0123456789abcdef"],
      period: { ...EXAMPLE_SIMULATION_RESULT.period, hours: 24 },
      totals: { ...EXAMPLE_SIMULATION_RESULT.totals, clients: ["iph_0123456789abcdef0123456789abcdef"] },
      rules: EXAMPLE_SIMULATION_RESULT.rules.map((entry) => ({
        ...entry,
        path: "/api/admin/**",
        clients: ["203.0.113.7"],
        sample_routes: entry.sample_routes.map((sample) => ({ ...sample, ip_prefix: "203.0.113.0/24" })),
      })),
    });
    expect(parsed).toEqual(EXAMPLE_SIMULATION_RESULT);
  });

  describe("period", () => {
    it("holds two ISO datetimes, from not after to", () => {
      expect(accepts(result({ period: { from: "2026-11-10T09:00:00.000Z", to: "2026-11-10T09:00:00.000Z" } }))).toBe(
        true,
      );
      for (const bad of [
        { from: "2026-11-10", to: "2026-11-11T09:00:00.000Z" },
        { from: "2026-11-10T09:00:00.000Z", to: 1_794_000_000_000 },
        { from: null, to: "2026-11-11T09:00:00.000Z" },
        { from: "yesterday", to: "now" },
      ]) {
        expect(accepts(result({ period: bad }))).toBe(false);
      }
      expect(
        issuePaths(result({ period: { from: "2026-11-11T09:00:00.001Z", to: "2026-11-11T09:00:00.000Z" } })),
      ).toEqual(["period.from"]);
    });
  });

  describe("counts", () => {
    it("are non-negative integers", () => {
      for (const bad of [-1, 1.5, "3", null]) {
        expect(accepts(result({ events: bad })), `events ${bad}`).toBe(false);
        expect(accepts(result({ undecidable_events: bad })), `undecidable_events ${bad}`).toBe(false);
        for (const key of Object.keys(TOTALS)) {
          expect(accepts(result({ totals: { ...TOTALS, [key]: bad } })), `totals.${key} ${bad}`).toBe(false);
        }
        for (const key of [
          "index",
          "matched",
          "would_block",
          "would_fail_signature",
          "would_throttle",
          "already_refused",
          "undecidable",
          "clients_affected",
          "unknown_client_events",
        ]) {
          expect(accepts(withRule({ [key]: bad })), `${key} ${bad}`).toBe(false);
        }
        expect(accepts(withRule({ sample_routes: [{ route: "/a", method: "GET", count: bad }] }))).toBe(false);
      }
    });

    it("accepts a simulation over no Events and no Rules", () => {
      const empty = result({
        events: 0,
        undecidable_events: 0,
        rules: [],
        totals: TOTALS,
      });
      expect(SimulationResultSchema.parse(empty)).toEqual(empty);
    });

    it("holds at most eventsMax Events", () => {
      expect(accepts(result({ events: SIMULATION_LIMITS.eventsMax }))).toBe(true);
      expect(accepts(result({ events: SIMULATION_LIMITS.eventsMax + 1 }))).toBe(false);
    });

    it("never counts more undecidable or refused Events than Events replayed", () => {
      const { events } = EXAMPLE_SIMULATION_RESULT;
      expect(accepts(result({ undecidable_events: events }))).toBe(true);
      expect(issuePaths(result({ undecidable_events: events + 1 }))).toEqual(["undecidable_events"]);
      expect(issuePaths(result({ totals: { ...TOTALS, would_refuse: events + 1 } }))).toEqual(["totals.would_refuse"]);
    });

    it("never counts more clients than refused requests", () => {
      const { would_refuse } = EXAMPLE_SIMULATION_RESULT.totals;
      const totals = { would_refuse, clients_affected: would_refuse, unknown_client_events: 0 };
      expect(accepts(result({ totals }))).toBe(true);
      expect(issuePaths(result({ totals: { ...totals, clients_affected: would_refuse + 1 } }))).toEqual([
        "totals.clients_affected",
      ]);
    });

    it("counts refused Events without a client hash apart: every other client has at least one refused Event", () => {
      const { would_refuse } = EXAMPLE_SIMULATION_RESULT.totals;
      expect(
        accepts(result({ totals: { would_refuse, clients_affected: 0, unknown_client_events: would_refuse } })),
      ).toBe(true);
      expect(
        accepts(result({ totals: { would_refuse, clients_affected: 3, unknown_client_events: would_refuse - 3 } })),
      ).toBe(true);
      expect(
        issuePaths(result({ totals: { would_refuse, clients_affected: 3, unknown_client_events: would_refuse - 2 } })),
      ).toEqual(["totals.clients_affected"]);
      const base = { matched: 10, would_block: 3, would_fail_signature: 0, would_throttle: 0, already_refused: 0 };
      expect(accepts(withRule({ ...base, clients_affected: 1, unknown_client_events: 2 }))).toBe(true);
      expect(issuePaths(withRule({ ...base, clients_affected: 2, unknown_client_events: 2 }))).toEqual([
        "rules.0.clients_affected",
      ]);
      expect(issuePaths(withRule({ ...base, clients_affected: 0, unknown_client_events: 4 }))).toEqual([
        "rules.0.unknown_client_events",
      ]);
    });
  });

  it("truncated is a boolean", () => {
    expect(accepts(result({ truncated: true }))).toBe(true);
    for (const bad of ["true", 1, null]) expect(accepts(result({ truncated: bad }))).toBe(false);
  });

  it("ran_at is the ISO datetime of the run", () => {
    expect(accepts(result({ ran_at: "2026-11-11T09:00:00.000Z" }))).toBe(true);
    for (const bad of ["2026-11-11", 1_794_000_000_000, null, "now"]) {
      expect(accepts(result({ ran_at: bad })), String(bad)).toBe(false);
    }
  });

  it("not_simulated lists what was left out, and a value added later still parses", () => {
    expect(SIMULATION_NOT_SIMULATED).toEqual([
      "patches",
      "containments",
      "decoded_paths",
      "device_limits",
      "body_verification",
    ]);
    expect(Object.isFrozen(SIMULATION_NOT_SIMULATED)).toBe(true);
    expect(EXAMPLE_SIMULATION_RESULT.not_simulated).toEqual(SIMULATION_NOT_SIMULATED);
    for (const good of [["patches"], ["patches", "canaries"], [], Array.from({ length: 8 }, (_, n) => `kind${n}`)]) {
      expect(accepts(result({ not_simulated: good })), JSON.stringify(good)).toBe(true);
    }
    for (const bad of [[""], ["patches", 1], Array.from({ length: 9 }, (_, n) => `kind${n}`), "patches", null]) {
      expect(accepts(result({ not_simulated: bad })), JSON.stringify(bad)).toBe(false);
    }
  });

  describe("rules", () => {
    const row = (index: number) => ({ ...FIRST, index });

    it("holds at most 50 rows", () => {
      const rows = (count: number) => Array.from({ length: count }, (_, index) => row(index));
      const fits = (count: number) =>
        accepts(
          result({
            events: SIMULATION_LIMITS.eventsMax,
            rules: rows(count),
            totals: TOTALS,
          }),
        );
      expect(fits(POLICY_LIMITS.rulesMax)).toBe(true);
      expect(fits(POLICY_LIMITS.rulesMax + 1)).toBe(false);
    });

    it("every draft Rule has a row: index equals the row's position (0, 1, 2 …)", () => {
      expect(accepts(result({ rules: [row(0), row(1), row(2), row(3)] }))).toBe(true);
      expect(issuePaths(result({ rules: [row(1)] }))).toEqual(["rules.0.index"]);
      expect(issuePaths(result({ rules: [row(0), row(0)] }))).toEqual(["rules.1.index"]);
      expect(issuePaths(result({ rules: [row(0), row(2)] }))).toEqual(["rules.1.index"]);
      expect(issuePaths(result({ rules: [row(1), row(0)] }))).toEqual(["rules.0.index", "rules.1.index"]);
    });

    it("id is optional (a draft Rule that was never published has none) and a Rule id when present", () => {
      const { id: _id, ...withoutId } = FIRST;
      const parsed = SimulationResultSchema.parse(result({ rules: [withoutId] }));
      expect(parsed.rules[0]).toEqual(withoutId);
      expect("id" in (parsed.rules[0] ?? {})).toBe(false);
      for (const bad of ["rul_1", "app_0123456789abcdef01234567", "", null, 7]) {
        expect(accepts(withRule({ id: bad })), String(bad)).toBe(false);
      }
    });

    it("name is a stored Rule name: 1 to 80 characters without control characters", () => {
      expect(accepts(withRule({ name: "A" }))).toBe(true);
      expect(accepts(withRule({ name: "n".repeat(POLICY_LIMITS.nameMax) }))).toBe(true);
      for (const bad of ["", "n".repeat(POLICY_LIMITS.nameMax + 1), "a\u0000b", null]) {
        expect(accepts(withRule({ name: bad }))).toBe(false);
      }
    });

    it("no outcome exceeds matched", () => {
      const base = {
        matched: 10,
        would_block: 0,
        would_fail_signature: 0,
        would_throttle: 0,
        already_refused: 0,
        clients_affected: 0,
      };
      for (const key of ["would_block", "would_fail_signature", "would_throttle", "already_refused"] as const) {
        expect(
          accepts(withRule({ ...base, [key]: 10, clients_affected: key === "already_refused" ? 0 : 1 })),
          key,
        ).toBe(true);
        expect(issuePaths(withRule({ ...base, [key]: 11 })), key).toEqual([`rules.0.${key}`]);
      }
    });

    describe("if_promoted", () => {
      const promoted = { would_refuse: 12, clients_affected: 3, unknown_client_events: 2, undecidable: 7 };

      it("is optional: absent for a Rule that is enforced already, or when it was not computed", () => {
        const { if_promoted: _omitted, ...without } = { ...FIRST, if_promoted: promoted };
        const parsed = SimulationResultSchema.parse(result({ rules: [without] }));
        expect("if_promoted" in (parsed.rules[0] ?? {})).toBe(false);
      });

      it("holds what the enforced Rules plus this one would refuse, and strips anything else", () => {
        const parsed = SimulationResultSchema.parse(withRule({ if_promoted: { ...promoted, clients: ["iph_x"] } }));
        expect(parsed.rules[0]?.if_promoted).toEqual(promoted);
      });

      it("requires its four counts, as non-negative integers", () => {
        for (const key of Object.keys(promoted)) {
          const { [key]: _omitted, ...rest } = promoted as Record<string, unknown>;
          expect(accepts(withRule({ if_promoted: rest })), key).toBe(false);
          for (const bad of [-1, 1.5, "3", null]) {
            expect(accepts(withRule({ if_promoted: { ...promoted, [key]: bad } })), `${key} ${bad}`).toBe(false);
          }
        }
        expect(accepts(withRule({ if_promoted: null }))).toBe(false);
      });

      it("is not bounded by the Rule's own row: an earlier monitor Rule no longer hides its requests", () => {
        expect(
          accepts(
            withRule({
              matched: 5,
              would_block: 0,
              clients_affected: 0,
              unknown_client_events: 0,
              if_promoted: promoted,
            }),
          ),
        ).toBe(true);
      });

      it("never counts more clients than refused requests, nor more refused than Events", () => {
        expect(issuePaths(withRule({ if_promoted: { ...promoted, clients_affected: 11 } }))).toEqual([
          "rules.0.if_promoted.clients_affected",
        ]);
        const { events } = EXAMPLE_SIMULATION_RESULT;
        expect(
          issuePaths(withRule({ if_promoted: { ...promoted, would_refuse: events + 1, unknown_client_events: 0 } })),
        ).toEqual(["rules.0.if_promoted.would_refuse"]);
      });
    });

    it("sample_routes counts are at least 1: a route without a refused Event is no sample", () => {
      expect(accepts(withRule({ sample_routes: [{ route: "/a", method: "GET", count: 1 }] }))).toBe(true);
      expect(accepts(withRule({ sample_routes: [{ route: "/a", method: "GET", count: 0 }] }))).toBe(false);
    });

    it("undecidable is not bounded by matched: it also counts Events whose route could not be judged", () => {
      expect(
        accepts(withRule({ matched: 0, would_block: 0, already_refused: 0, clients_affected: 0, undecidable: 500 })),
      ).toBe(true);
    });

    it("never counts more clients than requests the Rule would refuse", () => {
      const base = {
        matched: 10,
        would_block: 3,
        would_fail_signature: 0,
        would_throttle: 0,
        already_refused: 0,
        unknown_client_events: 0,
      };
      expect(accepts(withRule({ ...base, clients_affected: 3 }))).toBe(true);
      expect(issuePaths(withRule({ ...base, clients_affected: 4 }))).toEqual(["rules.0.clients_affected"]);
    });

    it("sample_routes holds at most 5 entries of route template, method and count", () => {
      const sample = { route: "/api/admin/users/:id", method: "DELETE", count: 2 };
      const samples = (count: number) => Array.from({ length: count }, () => sample);
      expect(accepts(withRule({ sample_routes: [] }))).toBe(true);
      expect(accepts(withRule({ sample_routes: samples(SIMULATION_LIMITS.sampleRoutesMax) }))).toBe(true);
      expect(accepts(withRule({ sample_routes: samples(SIMULATION_LIMITS.sampleRoutesMax + 1) }))).toBe(false);
      expect(accepts(withRule({ sample_routes: [{ ...sample, route: "r".repeat(LIMITS.routeMax) }] }))).toBe(true);
      for (const bad of [
        { ...sample, route: "" },
        { ...sample, route: "r".repeat(LIMITS.routeMax + 1) },
        { ...sample, route: "/a\u0007" },
        { ...sample, method: "get" },
        { ...sample, method: "" },
        { route: sample.route, method: sample.method },
        { route: sample.route, count: 1 },
        { method: sample.method, count: 1 },
      ]) {
        expect(accepts(withRule({ sample_routes: [bad] })), JSON.stringify(bad)).toBe(false);
      }
    });
  });
});

describe("EXAMPLE_SIMULATION_RESULT", () => {
  it("is deeply frozen", () => {
    expect(Object.isFrozen(EXAMPLE_SIMULATION_RESULT)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_SIMULATION_RESULT.period)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_SIMULATION_RESULT.not_simulated)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_SIMULATION_RESULT.totals)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_SIMULATION_RESULT.rules)).toBe(true);
    expect(
      EXAMPLE_SIMULATION_RESULT.rules.every(
        (entry) =>
          Object.isFrozen(entry) && Object.isFrozen(entry.sample_routes) && entry.sample_routes.every(Object.isFrozen),
      ),
    ).toBe(true);
  });

  it("shows a block Rule, a signature Rule and a limit Rule over a full, untruncated 24 hours", () => {
    const { period, rules: rows, truncated } = EXAMPLE_SIMULATION_RESULT;
    expect(truncated).toBe(false);
    expect(Date.parse(period.to) - Date.parse(period.from)).toBe(SIMULATION_LIMITS.windowHours * 3_600_000);
    expect(rows.map((entry) => entry.index)).toEqual([0, 1, 2]);
    expect(rows[0]?.id).toBe(EXAMPLE_POLICY_RULE.id);
    expect(rows[0]?.name).toBe(EXAMPLE_POLICY_RULE.name);
    expect(rows[0]?.would_block).toBeGreaterThan(0);
    // The second Rule is a draft that was never published: it has no id yet.
    expect(rows[1] && "id" in rows[1]).toBe(false);
    expect(rows[1]?.would_fail_signature).toBeGreaterThan(0);
    expect(rows[1]?.undecidable).toBeGreaterThan(0);
    expect(rows[2]?.id).toBe(EXAMPLE_LIMIT_RULE.id);
    expect(rows[2]?.name).toBe(EXAMPLE_LIMIT_RULE.name);
    expect(rows[2]?.would_throttle).toBeGreaterThan(0);
    expect(rows[2]?.already_refused).toBeGreaterThan(0);
  });

  it("adds up: the totals are the sum of what each Rule would refuse, and no hash or address appears", () => {
    const { rules: rows, totals } = EXAMPLE_SIMULATION_RESULT;
    const refused = rows.reduce(
      (sum, entry) => sum + entry.would_block + entry.would_fail_signature + entry.would_throttle,
      0,
    );
    expect(totals.would_refuse).toBe(refused);
    expect(totals.clients_affected).toBeLessThanOrEqual(rows.reduce((sum, entry) => sum + entry.clients_affected, 0));
    expect(totals.clients_affected).toBeGreaterThanOrEqual(Math.max(...rows.map((entry) => entry.clients_affected)));
    for (const entry of rows) {
      for (const sample of entry.sample_routes) expect(sample.count).toBeLessThanOrEqual(entry.matched);
    }
    expect(JSON.stringify(EXAMPLE_SIMULATION_RESULT)).not.toMatch(/iph_|\d+\.\d+\.\d+\.\d+/);
  });
});

describe("SimulatePolicyResponseSchema", () => {
  it("wraps the result in `simulation`, as the other endpoints wrap theirs", () => {
    const parsed: SimulatePolicyResponse = SimulatePolicyResponseSchema.parse({
      simulation: EXAMPLE_SIMULATION_RESULT,
      policy: EXAMPLE_POLICY,
    });
    expect(parsed).toEqual({ simulation: EXAMPLE_SIMULATION_RESULT });
  });

  it("refuses a bare or invalid result", () => {
    expect(SimulatePolicyResponseSchema.safeParse(EXAMPLE_SIMULATION_RESULT).success).toBe(false);
    expect(SimulatePolicyResponseSchema.safeParse({ simulation: null }).success).toBe(false);
    expect(SimulatePolicyResponseSchema.safeParse({ simulation: result({ events: -1 }) }).success).toBe(false);
  });
});
