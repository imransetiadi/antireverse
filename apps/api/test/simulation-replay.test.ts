import { type ParsedPolicyRuleInput, SIMULATION_NOT_SIMULATED, SimulationResultSchema } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  judgeRoute,
  promotions,
  type ReplayEvent,
  replay,
  replayAsync,
  simulationResult,
} from "../src/simulate/replay.ts";

const T0 = Date.parse("2026-11-11T08:00:00.000Z");
const A = "iph_000000000000000000000000000000aa";
const B = "iph_000000000000000000000000000000bb";

function rule(overrides: Partial<ParsedPolicyRuleInput> & { name: string; path: string }): ParsedPolicyRuleInput {
  return { methods: [], action: overrides.limit === undefined ? "block" : "throttle", mode: "monitor", ...overrides };
}

function event(
  atS: number,
  method: string,
  route: string,
  more: {
    status?: number;
    ip?: string | null;
    signature?: ReplayEvent["signature"];
    refused?: "block" | "throttle";
    attested?: boolean;
    prefix?: string | null;
  } = {},
): ReplayEvent {
  return {
    ts: new Date(T0 + atS * 1_000).toISOString(),
    request: { method, route, status: more.status ?? (more.refused === "throttle" ? 429 : more.refused ? 403 : 200) },
    decision: { action: more.refused ?? "allow", mode: more.refused ? "enforce" : "monitor" },
    actor: { ip_hash: more.ip === undefined ? A : more.ip, ip_prefix: more.prefix ?? "198.51.100.0/24" },
    signature: more.signature === undefined ? null : more.signature,
    attestation: more.attested === true ? { status: "valid" } : { status: "missing" },
  };
}

/** A valid signature of a request without a body: the one signature a signature Rule passes with certainty. */
const VALID = { status: "valid", body: "none" } as const;

describe("judgeRoute", () => {
  it.each([
    ["/login", "/login", "covered"],
    ["/login", "/LOGIN/", "covered"],
    ["/api/admin/**", "/api/admin", "covered"],
    ["/api/admin/**", "/api/admin/users/:id", "covered"],
    ["/api/users/*/export", "/api/users/:id/export", "covered"],
    ["/login", "/logout", "not_covered"],
    ["/api/admin/**", "/api/products/:id", "not_covered"],
    ["/api/users/*", "/api/users/:id/export", "not_covered"],
    ["/api/users/*/export", "/api/users/:id", "not_covered"],
    // A parameter may or may not take the literal value.
    ["/api/users/me", "/api/users/:id", "undecidable"],
    ["/api/users/me/**", "/api/users/:id/export", "undecidable"],
    // A template wildcard, an optional group: any number of segments.
    ["/files/a/b", "/files/*path", "undecidable"],
    ["/files/*", "/files/*path", "undecidable"],
    ["/api/users", "/api/users{/:id}", "undecidable"],
    // A template that is not all plain literals and parameters is judged for no Rule (review F1).
    ["/other", "/files/*path", "undecidable"],
    ["/files/**", "/files/*path", "undecidable"],
    ["/*/*", "/^\\/health$/", "undecidable"],
    ["/*/admin", "/^\\/admin/", "undecidable"],
    ["/*/*/users", "/\\/api\\/users/", "undecidable"],
    ["/api/**", "/api[/arr1|/arr2]", "undecidable"],
    ["/*/*/*", "/api[/arr1|/arr2]", "undecidable"],
    ["/api/*", "/api/:name.:ext", "undecidable"],
    ["/api/*", "/api/file-:id", "undecidable"],
    ["/api/*", "/api/a%20b", "undecidable"],
    ["/api/*", "/api/a+", "undecidable"],
    ["/api/*", "/api/x?", "undecidable"],
    ["/a/*", "/a//b", "undecidable"],
    ["/a/*", "/a/..", "undecidable"],
    ["/a/*", '/a/:"quoted name"', "undecidable"],
    ["/strict/s", "/strict/s/", "covered"],
    ["/", "/", "covered"],
    // Not a template: the path is unknown, so every pattern could apply.
    ["/login", "(unmatched)", "undecidable"],
    ["/api/admin/**", "(mount)/users/:id", "undecidable"],
    // A Rule pattern is no template.
    ["/api/admin/**", "/api/admin/**", "undecidable"],
    ["/api/*", "/api/*", "undecidable"],
  ] as const)("%s against %s is %s", (path, route, expected) => {
    expect(judgeRoute(path, route)).toBe(expected);
  });

  // The route of a request Shield refused is the pattern of the Rule that refused it.
  it.each([
    ["/api/admin/**", "/api/admin/**", "covered"],
    ["/api/**", "/api/admin/*/x", "covered"],
    ["/api/admin/users", "/api/admin/**", "undecidable"],
    ["/api/*", "/api/*", "undecidable"],
    ["/login", "/api/admin/**", "not_covered"],
    ["/*/*", "/^\\/health$/", "undecidable"],
    ["/files/**", "/files/*path", "undecidable"],
  ] as const)("%s against the route %s of a refused request is %s", (path, route, expected) => {
    expect(judgeRoute(path, route, { refused: true })).toBe(expected);
  });
});

describe("replay", () => {
  it("gives every draft Rule a row at its position, zero rows included", () => {
    const result = replay(
      [rule({ name: "One", path: "/a" }), rule({ id: `rul_${"0".repeat(24)}`, name: "Two", path: "/b" })],
      [],
    );
    expect(result.rules).toEqual([
      {
        index: 0,
        name: "One",
        matched: 0,
        would_block: 0,
        would_fail_signature: 0,
        would_throttle: 0,
        already_refused: 0,
        undecidable: 0,
        clients_affected: 0,
        unknown_client_events: 0,
        sample_routes: [],
      },
      expect.objectContaining({ index: 1, id: `rul_${"0".repeat(24)}`, name: "Two", matched: 0 }),
    ]);
    expect(result.totals).toEqual({ would_refuse: 0, clients_affected: 0, unknown_client_events: 0 });
    expect(result.undecidable_events).toBe(0);
    expect(result.replayed).toBe(0);
  });

  it("counts what a block Rule would block, with methods as Shield reads them, whatever its mode", () => {
    const result = replay(
      [rule({ name: "Admin", path: "/api/admin/**", methods: ["GET"], mode: "monitor" })],
      [
        event(0, "GET", "/api/admin/users"),
        event(1, "HEAD", "/api/admin/users", { ip: B }),
        event(2, "POST", "/api/admin/users"),
        event(3, "GET", "/api/products/:id"),
        event(4, "GET", "/api/admin/users/:id", { ip: null }),
        event(5, "GET", "/api/admin/users/:id", { ip: null }),
      ],
    );
    expect(result.rules[0]).toMatchObject({
      matched: 4,
      would_block: 4,
      undecidable: 0,
      clients_affected: 2, // A and B; the two Events without a hash are no client (review F6)
      unknown_client_events: 2,
      sample_routes: [
        { route: "/api/admin/users", method: "GET", count: 1 },
        { route: "/api/admin/users", method: "HEAD", count: 1 },
        { route: "/api/admin/users/:id", method: "GET", count: 2 },
      ].sort((x, y) => y.count - x.count),
    });
    expect(result.totals).toEqual({ would_refuse: 4, clients_affected: 2, unknown_client_events: 2 });
  });

  it("never counts a route it cannot judge as a match", () => {
    const result = replay(
      [rule({ name: "Me", path: "/api/users/me" }), rule({ name: "Login", path: "/login" })],
      [event(0, "GET", "/api/users/:id"), event(1, "GET", "(unmatched)"), event(2, "GET", "/login")],
    );
    expect(result.rules[0]).toMatchObject({ matched: 0, would_block: 0, undecidable: 2 });
    expect(result.rules[1]).toMatchObject({ matched: 1, would_block: 1, undecidable: 1 });
    // Undecidable for at least one Rule and refused by none: the first two. The third is refused.
    expect(result.undecidable_events).toBe(2);
    expect(result.totals.would_refuse).toBe(1);
  });

  it("keeps at most 5 sample routes, most refused first", () => {
    const events: ReplayEvent[] = [];
    for (let route = 0; route < 7; route++) {
      for (let n = 0; n <= route; n++) events.push(event(events.length, "GET", `/api/admin/r${route}`));
    }
    const result = replay([rule({ name: "Admin", path: "/api/admin/**" })], events);
    expect(result.rules[0]?.sample_routes).toEqual(
      [6, 5, 4, 3, 2].map((route) => ({ route: `/api/admin/r${route}`, method: "GET", count: route + 1 })),
    );
  });

  it("fails a signature Rule for every signature that is not valid, and judges a signed body for none", () => {
    const result = replay(
      [rule({ name: "Signed", path: "/api/checkout", methods: ["POST"], requires: "signature" })],
      [
        // Valid with a body (review t3 B, t2 seed 26): an enforcing Shield refuses it at once unless `bodyVerified`
        // lists its type, and the Event does not say whether it did — not judged, checked or not.
        event(0, "POST", "/api/checkout", { signature: { status: "valid", body: "checked" } }),
        event(1, "POST", "/api/checkout", { signature: VALID }),
        event(2, "POST", "/api/checkout", { signature: { status: "valid", body: "unchecked" } }),
        event(3, "POST", "/api/checkout", { signature: { status: "missing", body: null }, ip: B }),
        event(4, "POST", "/api/checkout", { signature: { status: "invalid", body: "mismatch" }, ip: B }),
        event(5, "POST", "/api/checkout", { signature: { status: "replayed", body: "checked" }, ip: B }),
        event(6, "POST", "/api/checkout", { signature: null }), // an older Shield: cannot be judged
        event(7, "GET", "/api/checkout", { signature: null }),
      ],
    );
    expect(result.rules[0]).toMatchObject({
      matched: 7,
      would_fail_signature: 3,
      would_block: 0,
      undecidable: 3,
      clients_affected: 1,
    });
    expect(result.undecidable_events).toBe(3);
  });

  it("counts a signed request with a body on no limit: the signature Rule may have refused it (review t2 seed 26)", () => {
    const checked = { status: "valid", body: "checked" } as const;
    const result = replay(
      [
        rule({ name: "Wide", path: "/**", limit: { requests: 1, window_s: 5, key: "ip", count: "requests" } }),
        rule({ name: "Signed", path: "/api/orders", methods: ["POST"], requires: "signature" }),
      ],
      [
        // Shield refuses this one for the signature Rule, and counts it on no limit ...
        event(0, "POST", "/api/orders", { signature: checked }),
        // ... or admits and counts it, and then throttles these.
        event(1, "POST", "/api/orders", { signature: VALID }),
        event(2, "GET", "/api/items/:id", { signature: VALID }),
      ],
    );
    expect(result.rules[1]).toMatchObject({ matched: 2, would_fail_signature: 0, undecidable: 1 });
    // If Shield admitted the signed body, it counted it, and throttles the next two: none of the three is judged.
    expect(result.rules[0]).toMatchObject({ matched: 3, would_throttle: 0, undecidable: 3 });
    expect(result.totals.would_refuse).toBe(0);
  });

  it("lets the first terminal outcome win in Shield's order: block Rules, then signature Rules, then limits", () => {
    const result = replay(
      [
        rule({ name: "Limit", path: "/api/**", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
        rule({ name: "Signed", path: "/api/**", requires: "signature" }),
        rule({ name: "Block", path: "/api/admin/**" }),
        rule({ name: "Block all api", path: "/api/**" }),
      ],
      [event(0, "GET", "/api/admin/x"), event(1, "GET", "/api/admin/x")],
    );
    expect(
      result.rules.map((row) => [row.matched, row.would_block, row.would_fail_signature, row.would_throttle]),
    ).toEqual([
      [2, 0, 0, 0],
      [2, 0, 0, 0],
      [2, 2, 0, 0],
      [2, 0, 0, 0],
    ]);
    expect(result.totals.would_refuse).toBe(2);

    // Without the block Rules the signature Rule decides, and the limit never counts the refused requests.
    const signed = replay(
      [
        rule({ name: "Limit", path: "/api/**", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
        rule({ name: "Signed", path: "/api/**", requires: "signature" }),
      ],
      [
        event(0, "GET", "/api/x", { signature: { status: "missing", body: null } }),
        event(1, "GET", "/api/x", { signature: { status: "missing", body: null } }),
        event(2, "GET", "/api/x", { signature: VALID }),
        event(3, "GET", "/api/x", { signature: VALID }),
      ],
    );
    expect(signed.rules[1]).toMatchObject({ matched: 4, would_fail_signature: 2 });
    expect(signed.rules[0]).toMatchObject({ matched: 4, would_throttle: 1 });
  });

  it("replays a request limit as an exact sliding window per client, in time order", () => {
    const limit = rule({
      name: "Search",
      path: "/api/search",
      limit: { requests: 3, window_s: 10, key: "ip", count: "requests" },
    });
    const result = replay(
      [limit],
      [
        event(0, "GET", "/api/search"),
        event(1, "GET", "/api/search"),
        event(2, "GET", "/api/search"),
        event(3, "GET", "/api/search"), // 4th in 10 s: throttled, not counted
        event(3, "GET", "/api/search", { ip: B }), // another client
        event(9.9, "GET", "/api/search"), // still 3 in the window: throttled
        // The first left the window (by more than 5 ms: in any reading of the clock): admitted.
        event(10.01, "GET", "/api/search"),
        event(10.5, "GET", "/api/search"), // 1 s, 2 s and 10.01 s are in the window: throttled
        event(11.01, "GET", "/api/search"), // 2 s, 10.01 s in the window: admitted
      ],
    );
    expect(result.rules[0]).toMatchObject({ matched: 9, would_throttle: 3, clients_affected: 1 });
  });

  it("never throttles an Event without a client hash: it cannot be judged for a limit Rule", () => {
    const result = replay(
      [
        rule({ name: "Search", path: "/s", limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } }),
        rule({ name: "Block", path: "/b" }),
      ],
      [...[0, 1, 2, 3].map((at) => event(at, "GET", "/s", { ip: null })), event(4, "GET", "/b", { ip: null })],
    );
    expect(result.rules[0]).toMatchObject({ matched: 4, would_throttle: 0, undecidable: 4, clients_affected: 0 });
    // A block Rule needs no client: it refuses the Event, of a client nobody can count.
    expect(result.rules[1]).toMatchObject({
      matched: 1,
      would_block: 1,
      clients_affected: 0,
      unknown_client_events: 1,
    });
    expect(result.undecidable_events).toBe(4);
    expect(result.totals).toEqual({ would_refuse: 1, clients_affected: 0, unknown_client_events: 1 });
  });

  it("holds an Event without a valid attestation to a device limit by its address", () => {
    const result = replay(
      [rule({ name: "Device", path: "/s", limit: { requests: 1, window_s: 60, key: "device", count: "requests" } })],
      [event(0, "GET", "/s"), event(1, "GET", "/s"), event(2, "GET", "/s", { ip: B })],
    );
    expect(result.rules[0]).toMatchObject({ matched: 3, would_throttle: 1, undecidable: 0 });
  });

  it("never judges an attested Event under a device limit: its device is unknown", () => {
    const device = rule({
      name: "Device",
      path: "/s",
      limit: { requests: 2, window_s: 60, key: "device", count: "requests" },
    });
    const attested = Array.from({ length: 12 }, (_, at) => event(at, "GET", "/s", { attested: true }));
    const result = replay([device], attested);
    // Even the first: the same device may have spent the limit from another address.
    expect(result.rules[0]).toMatchObject({ matched: 12, would_throttle: 0, undecidable: 12, clients_affected: 0 });
    expect(result.undecidable_events).toBe(12);
    expect(result.totals.would_refuse).toBe(0);

    // Shield counts an attested request on the address too, so a request without a token after it is not judged
    // until it has left the window; then the address counter is the replay's again.
    const mixed = replay(
      [device],
      [
        event(0, "GET", "/s", { attested: true }),
        event(30, "GET", "/s"),
        event(91, "GET", "/s"),
        event(92, "GET", "/s"),
        event(93, "GET", "/s"), // over the two before: certain
      ],
    );
    expect(mixed.rules[0]).toMatchObject({ matched: 5, would_throttle: 1, undecidable: 2 });

    // An `ip` limit never looks at the attestation.
    const ip = replay([{ ...device, limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } }], attested);
    expect(ip.rules[0]).toMatchObject({ would_throttle: 10, undecidable: 0 });
  });

  it("does not count on another limit an attested Event a device limit may have throttled", () => {
    const result = replay(
      [
        rule({ name: "Device", path: "/s", limit: { requests: 1, window_s: 60, key: "device", count: "requests" } }),
        rule({ name: "Wide", path: "/**", limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } }),
      ],
      [
        event(0, "GET", "/s", { attested: true }),
        event(1, "GET", "/s", { attested: true }), // Device cannot judge either: counted on Wide by neither
        event(2, "GET", "/x"),
        event(3, "GET", "/x"), // and Shield's count of Wide may be 3 or 2 here: not judged
      ],
    );
    expect(result.rules[0]).toMatchObject({ matched: 2, would_throttle: 0, undecidable: 2 });
    expect(result.rules[1]).toMatchObject({ matched: 4, would_throttle: 0, undecidable: 4 });
  });

  it("replays a failure limit: 401 and 403 count, and requests are throttled once the limit is reached", () => {
    const result = replay(
      [
        rule({
          name: "Login",
          path: "/login",
          methods: ["POST"],
          limit: { requests: 2, window_s: 60, key: "ip", count: "failures" },
        }),
      ],
      [
        event(0, "POST", "/login", { status: 200 }),
        event(1, "POST", "/login", { status: 401 }),
        event(2, "POST", "/login", { status: 500 }),
        event(3, "POST", "/login", { status: 403 }),
        event(4, "POST", "/login", { status: 200 }), // 2 failures in the window: throttled
        event(5, "POST", "/login", { status: 401 }), // throttled, and not counted
        event(61.01, "POST", "/login", { status: 401 }), // the first failure left: 1 in the window, admitted, counts
        event(62, "POST", "/login", { status: 200 }), // failures at 3 s and 61.01 s: throttled
        event(64, "POST", "/login", { status: 200 }), // only 61.01 s left: admitted
      ],
    );
    expect(result.rules[0]).toMatchObject({ matched: 9, would_throttle: 3 });
  });

  it("throttles by the first limit over and counts a refused request on no limit", () => {
    const result = replay(
      [
        rule({ name: "Wide", path: "/api/**", limit: { requests: 3, window_s: 60, key: "ip", count: "requests" } }),
        rule({ name: "Narrow", path: "/api/x", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
      ],
      [
        event(0, "GET", "/api/x"),
        event(1, "GET", "/api/x"), // Narrow is over: not counted on Wide
        event(2, "GET", "/api/x"), // the same
        event(3, "GET", "/api/y"),
        event(4, "GET", "/api/y"), // Wide holds 0 s, 3 s, 4 s
        event(5, "GET", "/api/y"), // Wide is over
        event(6, "GET", "/api/x"), // both are over: the first in order names it
      ],
    );
    expect(result.rules[0]).toMatchObject({ matched: 7, would_throttle: 2 });
    expect(result.rules[1]).toMatchObject({ matched: 4, would_throttle: 2 });
    expect(result.totals.would_refuse).toBe(4);
  });

  it("reports Events Shield already refused as such: matched, no outcome, and of unknown weight on limits", () => {
    const result = replay(
      [
        rule({ name: "Admin", path: "/api/admin/**" }),
        rule({ name: "Login", path: "/login", limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } }),
      ],
      [
        event(0, "GET", "/api/admin/**", { refused: "block" }),
        event(1, "POST", "/login", { refused: "throttle" }),
        event(2, "POST", "/login", { refused: "throttle" }),
        event(3, "POST", "/login"),
        event(4, "POST", "/login"),
        event(5, "GET", "(unmatched)", { refused: "block" }), // a Containment
      ],
    );
    expect(result.rules[0]).toMatchObject({ matched: 1, would_block: 0, already_refused: 1, undecidable: 1 });
    // Under the draft the two refused logins might have been admitted and counted: the two after them are not
    // judged.
    expect(result.rules[1]).toMatchObject({ matched: 4, would_throttle: 0, already_refused: 2, undecidable: 3 });
    expect(result.totals.would_refuse).toBe(0);
    expect(result.undecidable_events).toBe(3);
  });

  it("does not treat a monitor decision as a refusal: the request reached the application", () => {
    const monitored: ReplayEvent = {
      ...event(0, "GET", "/api/admin/x"),
      decision: { action: "block", mode: "monitor" },
    };
    const result = replay([rule({ name: "Admin", path: "/api/admin/**" })], [monitored]);
    expect(result.rules[0]).toMatchObject({ matched: 1, would_block: 1, already_refused: 0 });
  });

  it("cannot judge a signature or a limit Rule for OPTIONS: an Event does not say whether it was a preflight", () => {
    const result = replay(
      [
        rule({ name: "Signed", path: "/api/a", requires: "signature" }),
        rule({ name: "Limit", path: "/api/b", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
        rule({ name: "Block", path: "/api/c" }),
      ],
      [
        event(0, "OPTIONS", "/api/a", { signature: { status: "missing", body: null } }),
        event(1, "OPTIONS", "/api/b"),
        event(2, "OPTIONS", "/api/b"),
        event(3, "GET", "/api/b"), // the OPTIONS requests were not counted
        event(4, "OPTIONS", "/api/c"), // a block Rule blocks a preflight too
      ],
    );
    expect(result.rules[0]).toMatchObject({ matched: 1, would_fail_signature: 0, undecidable: 1 });
    // The GET is not judged either: Shield counted the OPTIONS requests if they were no preflights.
    expect(result.rules[1]).toMatchObject({ matched: 3, would_throttle: 0, undecidable: 3 });
    expect(result.rules[2]).toMatchObject({ matched: 1, would_block: 1 });
    expect(result.undecidable_events).toBe(4);
  });

  it("does not count on a limit an Event an earlier Rule may have refused", () => {
    const result = replay(
      [
        rule({ name: "Me", path: "/api/users/me" }),
        rule({ name: "Limit", path: "/api/**", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
      ],
      [
        event(0, "GET", "/api/users/:id"),
        event(1, "GET", "/api/users/:id"),
        event(2, "GET", "/api/x"),
        event(3, "GET", "/api/x"),
      ],
    );
    expect(result.rules[0]).toMatchObject({ matched: 0, undecidable: 2 });
    // Shield counted the first two if Me did not block them: the next two are not judged either.
    expect(result.rules[1]).toMatchObject({ matched: 4, undecidable: 4, would_throttle: 0 });
  });

  it("does not count on a limit an Event another limit may have throttled", () => {
    const result = replay(
      [
        rule({ name: "Wide", path: "/api/**", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
        rule({ name: "Me", path: "/api/users/me", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
      ],
      [event(0, "GET", "/api/users/:id"), event(1, "GET", "/api/users/:id"), event(2, "GET", "/api/x")],
    );
    expect(result.rules[0]).toMatchObject({ matched: 3, undecidable: 3, would_throttle: 0 });
    expect(result.rules[1]).toMatchObject({ matched: 0, undecidable: 2, would_throttle: 0 });
    expect(result.undecidable_events).toBe(3);
  });

  it("stops when told to and says how many Events it replayed", () => {
    let asked = 0;
    const events = Array.from({ length: 5_000 }, (_, n) => event(n, "GET", "/api/admin/x"));
    const result = replay([rule({ name: "Admin", path: "/api/admin/**" })], events, { shouldStop: () => ++asked > 2 });
    expect(result.stopped).toBe(true);
    expect(result.replayed).toBeGreaterThan(0);
    expect(result.replayed).toBeLessThan(5_000);
    expect(result.rules[0]?.would_block).toBe(result.replayed);
  });

  it("does not judge a request past a limit above 1,000: Shield counts those with weighted windows (review F2)", () => {
    const events = Array.from({ length: 1_010 }, (_, n) => event(n * 0.01, "GET", "/s"));
    const big = replay(
      [rule({ name: "Big", path: "/s", limit: { requests: 1_001, window_s: 60, key: "ip", count: "requests" } })],
      events,
    );
    expect(big.rules[0]).toMatchObject({ matched: 1_010, would_throttle: 0, undecidable: 9 });
    const exact = replay(
      [rule({ name: "Exact", path: "/s", limit: { requests: 1_000, window_s: 60, key: "ip", count: "requests" } })],
      events,
    );
    expect(exact.rules[0]).toMatchObject({ matched: 1_010, would_throttle: 10, undecidable: 0 });
  });

  it("does not judge a limit for an Event of a network on the never-block list (review F3)", () => {
    const rules = [
      rule({ name: "Limit", path: "/s", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
      rule({ name: "Block", path: "/b" }),
    ];
    const events = [
      event(0, "GET", "/s", { prefix: "203.0.113.0/24" }),
      event(1, "GET", "/s", { prefix: "203.0.113.0/24" }),
      event(2, "GET", "/s", { prefix: "203.0.113.0/24" }),
      event(3, "GET", "/s", { ip: B, prefix: "198.51.100.0/24" }),
      event(4, "GET", "/s", { ip: B, prefix: "198.51.100.0/24" }),
      event(5, "GET", "/b", { prefix: "203.0.113.0/24" }),
      event(6, "GET", "/s", { ip: B, prefix: "2001:db8:1::/48" }),
    ];
    const listed = replay(rules, events, { neverBlock: ["203.0.113.7/32", "2001:db8::/32"] });
    expect(listed.rules[0]).toMatchObject({ matched: 6, would_throttle: 1, undecidable: 4 });
    // The never-block list exempts a client from limits, not from a block Rule.
    expect(listed.rules[1]).toMatchObject({ matched: 1, would_block: 1 });
    const unlisted = replay(rules, events);
    expect(unlisted.rules[0]).toMatchObject({ matched: 6, would_throttle: 4, undecidable: 0 });
  });

  it("does not claim a throttle that 5 ms at the edge of the window would undo (review F8)", () => {
    const limit = rule({ name: "L", path: "/a", limit: { requests: 1, window_s: 1, key: "ip", count: "requests" } });
    // Shield's limiter read the clock a moment before the Event was stamped: 999 ms apart here may be 1,000 there.
    expect(replay([limit], [event(0.001, "GET", "/a"), event(1, "GET", "/a")]).rules[0]).toMatchObject({
      would_throttle: 0,
      undecidable: 1,
    });
    expect(replay([limit], [event(0, "GET", "/a"), event(0.995, "GET", "/a")]).rules[0]).toMatchObject({
      would_throttle: 0,
      undecidable: 1,
    });
    expect(replay([limit], [event(0, "GET", "/a"), event(0.994, "GET", "/a")]).rules[0]).toMatchObject({
      would_throttle: 1,
      undecidable: 0,
    });
    // Exactly one window apart: Shield may still hold the first — not a certain pass either.
    expect(replay([limit], [event(0, "GET", "/a"), event(1, "GET", "/a")]).rules[0]).toMatchObject({
      would_throttle: 0,
      undecidable: 1,
    });
    // Limit 2: the claim needs both earlier hits in the window, and one of them is at its edge.
    const two = rule({ name: "L", path: "/a", limit: { requests: 2, window_s: 1, key: "ip", count: "requests" } });
    expect(
      replay([two], [event(0, "GET", "/a"), event(0.5, "GET", "/a"), event(0.998, "GET", "/a")]).rules[0],
    ).toMatchObject({ would_throttle: 0, undecidable: 1 });
  });

  describe("tainted counters: the replay's count never exceeds Shield's", () => {
    it("does not pass, and so does not count, a request while an unjudged one may sit on its counter", () => {
      const rules = [
        rule({ name: "Me", path: "/api/users/me" }),
        rule({ name: "Wide", path: "/**", limit: { requests: 1, window_s: 5, key: "ip", count: "requests" } }),
      ];
      const result = replay(rules, [
        // Blocked by Me if it was /api/users/me, else admitted and counted by Shield: not judged, counted nowhere.
        event(0, "GET", "/api/users/:id"),
        // Shield throttles this one if it counted the first; the replay cannot pass it with certainty.
        event(1, "GET", "/x"),
        // Had the replay counted the request at 1 s, it would claim this one; Shield may admit it.
        event(5.5, "GET", "/x"),
        // Every request not judged has left any window: judged again, and passes.
        event(11, "GET", "/x"),
        event(12, "GET", "/x"), // over the request at 11 s: certain
      ]);
      expect(result.rules[1]).toMatchObject({ matched: 5, would_throttle: 1, undecidable: 3 });
      expect(result.undecidable_events).toBe(3);
    });

    it("keeps an attested request a device limit cannot judge on the address counter's conscience (t2 seed 26)", () => {
      const rules = [
        rule({
          name: "Device",
          path: "/api/**",
          limit: { requests: 1, window_s: 60, key: "device", count: "requests" },
        }),
        rule({ name: "Wide", path: "/**", limit: { requests: 1, window_s: 5, key: "ip", count: "requests" } }),
      ];
      const result = replay(rules, [
        event(0, "GET", "/api/x", { attested: true }),
        event(5.1, "GET", "/api/x", { attested: true }), // another device may have passed: Shield counted it on Wide
        event(6, "GET", "/x"), // then Shield throttles this one: not a certain pass
        event(10.5, "GET", "/x"), // and admits this one: no claim
      ]);
      expect(result.rules[0]).toMatchObject({ matched: 2, would_throttle: 0, undecidable: 2 });
      expect(result.rules[1]).toMatchObject({ matched: 4, would_throttle: 0, undecidable: 4 });
      expect(result.totals.would_refuse).toBe(0);
    });

    it("never passes an attested request under a device limit: its device may have spent the limit elsewhere", () => {
      const device = rule({
        name: "Device",
        path: "/s",
        limit: { requests: 1, window_s: 60, key: "device", count: "requests" },
      });
      // One device from two addresses (t2 limits mode, seed 16): Shield throttles the second on the device's
      // counter, which no Event names.
      const result = replay(
        [device],
        [event(0, "GET", "/s", { attested: true }), event(1, "GET", "/s", { ip: B, attested: true })],
      );
      expect(result.rules[0]).toMatchObject({ matched: 2, would_throttle: 0, undecidable: 2 });
      // Without a token the address is the counter: judged.
      const plain = replay([device], [event(0, "GET", "/s"), event(1, "GET", "/s", { ip: B })]);
      expect(plain.rules[0]).toMatchObject({ matched: 2, would_throttle: 0, undecidable: 0 });
    });

    it("does not pass a request that a hit 5 ms short of leaving the window could throttle", () => {
      const limit = rule({ name: "L", path: "/a", limit: { requests: 1, window_s: 1, key: "ip", count: "requests" } });
      const at = (second: number) =>
        replay([limit], [event(0, "GET", "/a"), event(second, "GET", "/a"), event(second + 0.1, "GET", "/a")]).rules[0];
      // 1,002 ms after the first: Shield may still hold it — not judged, so the third is not judged either.
      expect(at(1.002)).toMatchObject({ would_throttle: 0, undecidable: 2 });
      // 1,005 ms after: gone in any reading — passes, and the third is over it.
      expect(at(1.005)).toMatchObject({ would_throttle: 1, undecidable: 0 });
    });

    it("passes a request past 1,000 only if Shield's weighted count could not refuse it", () => {
      const big = rule({
        name: "Big",
        path: "/s",
        limit: { requests: 1_001, window_s: 60, key: "ip", count: "requests" },
      });
      const burst = Array.from({ length: 1_001 }, (_, n) => event(n * 0.01, "GET", "/s"));
      // 70 s later the exact window is empty, but the sub-window before still weighs on Shield's count.
      expect(replay([big], [...burst, event(70, "GET", "/s")]).rules[0]).toMatchObject({ undecidable: 1 });
      // Two windows later nothing of the burst can count.
      expect(replay([big], [...burst, event(121, "GET", "/s")]).rules[0]).toMatchObject({ undecidable: 0 });
    });
  });

  it("stops judging limits once it holds as many timestamps as it may, and says so (review F9)", () => {
    const limit = rule({
      name: "L",
      path: "/a",
      limit: { requests: 5, window_s: 3_600, key: "ip", count: "requests" },
    });
    const events = Array.from({ length: 10 }, (_, n) =>
      event(n, "GET", "/a", { ip: `iph_${String(n).padStart(32, "0")}` }),
    );
    const capped = replay([limit, rule({ name: "B", path: "/a", methods: ["POST"] })], events, { timestampsMax: 4 });
    expect(capped.capped).toBe(true);
    expect(capped.rules[0]).toMatchObject({ matched: 10, would_throttle: 0, undecidable: 6 });
    expect(replay([limit], events).capped).toBe(false);
    // Timestamps that left their window make room again.
    const short = rule({ name: "L", path: "/a", limit: { requests: 5, window_s: 1, key: "ip", count: "requests" } });
    const same = Array.from({ length: 10 }, (_, n) => event(n * 2, "GET", "/a"));
    expect(replay([short], same, { timestampsMax: 2 })).toMatchObject({ capped: false });
  });

  it("replays the same asynchronously, letting other work run in between (review F9)", async () => {
    const rules = [
      rule({ name: "Admin", path: "/api/admin/**" }),
      rule({ name: "L", path: "/a", limit: { requests: 3, window_s: 10, key: "ip", count: "requests" } }),
    ];
    const events = Array.from({ length: 3_000 }, (_, n) => event(n * 1.5, "GET", n % 3 ? "/a" : "/api/admin/x"));
    let ran = false;
    let ranBeforeTheEnd = false;
    setImmediate(() => {
      ran = true;
    });
    // Asked at the 1,024th Event: by then the replay has given way at least once.
    const result = await replayAsync(rules, events, {
      yieldEvery: 50,
      shouldStop: () => {
        ranBeforeTheEnd ||= ran;
        return false;
      },
    });
    expect(ranBeforeTheEnd).toBe(true);
    expect(result).toEqual(replay(rules, events));
  });

  describe("promotions (review F5)", () => {
    const five = Array.from({ length: 5 }, (_, n) => event(n, "GET", "/api/data"));

    it("says what promoting one monitor Rule refuses while the other monitor Rules stay as they are", async () => {
      const rules = [rule({ name: "Api", path: "/api/**" }), rule({ name: "Data", path: "/api/data" })];
      // Every Rule enforced, the first takes all five.
      expect(replay(rules, five).rules.map((row) => row.would_block)).toEqual([5, 0]);
      expect(await promotions(rules, five)).toEqual([
        { would_refuse: 5, clients_affected: 1, unknown_client_events: 0, undecidable: 0 },
        { would_refuse: 5, clients_affected: 1, unknown_client_events: 0, undecidable: 0 },
      ]);
    });

    it("keeps the enforced Rules of the draft in force, and gives an enforced Rule no figure", async () => {
      const rules = [
        rule({ name: "Api", path: "/api/**", mode: "enforce" }),
        rule({ name: "Data", path: "/api/data" }),
        rule({ name: "Other", path: "/other" }),
      ];
      expect(
        await promotions(rules, [...five, event(9, "GET", "/other", { ip: null }), event(10, "GET", "(unmatched)")]),
      ).toEqual([
        undefined,
        { would_refuse: 0, clients_affected: 0, unknown_client_events: 0, undecidable: 1 },
        { would_refuse: 1, clients_affected: 0, unknown_client_events: 1, undecidable: 1 },
      ]);
    });

    it("lets a monitor limit count nothing that changes another Rule", async () => {
      const limit = { requests: 2, window_s: 60, key: "ip", count: "requests" } as const;
      const rules = [
        rule({ name: "Narrow", path: "/api/data", limit: { ...limit, requests: 1 } }),
        rule({ name: "Wide", path: "/api/**", limit }),
      ];
      // Every Rule enforced: Narrow throttles 4 of 5, and Wide never counts those. Wide alone throttles 3.
      expect(replay(rules, five).rules.map((row) => row.would_throttle)).toEqual([4, 0]);
      expect((await promotions(rules, five)).map((promoted) => promoted?.would_refuse)).toEqual([4, 3]);
    });

    it("leaves out the Rules it has no time left for", async () => {
      const rules = [
        rule({ name: "A", path: "/api/data" }),
        rule({ name: "B", path: "/api/data" }),
        rule({ name: "C", path: "/api/data" }),
      ];
      let asked = 0;
      const promoted = await promotions(rules, five, { shouldStop: () => ++asked > 1 });
      expect(promoted).toEqual([expect.objectContaining({ would_refuse: 5 }), undefined, undefined]);
    });
  });

  it("builds a result the protocol accepts, without a hash in it", () => {
    const replayed = replay(
      [rule({ name: "Admin", path: "/api/admin/**" })],
      [event(0, "GET", "/api/admin/x"), event(1, "GET", "(unmatched)")],
    );
    const result = simulationResult(replayed, {
      from: new Date(T0 - 86_400_000),
      to: new Date(T0 + 60_000),
      ranAt: new Date(T0 + 60_000),
      truncated: false,
      promoted: [{ would_refuse: 1, clients_affected: 1, unknown_client_events: 0, undecidable: 1 }],
    });
    expect(SimulationResultSchema.parse(result)).toEqual(result);
    expect(result).toMatchObject({
      period: { from: new Date(T0 - 86_400_000).toISOString(), to: new Date(T0 + 60_000).toISOString() },
      ran_at: new Date(T0 + 60_000).toISOString(),
      events: 2,
      truncated: false,
      undecidable_events: 1,
      not_simulated: [...SIMULATION_NOT_SIMULATED],
      totals: { would_refuse: 1, clients_affected: 1, unknown_client_events: 0 },
    });
    expect(result.rules[0]?.if_promoted).toEqual({
      would_refuse: 1,
      clients_affected: 1,
      unknown_client_events: 0,
      undecidable: 1,
    });
    // Capped timestamps cut the result short as the Event cap does; a Rule without a figure has no member.
    const capped = simulationResult(
      { ...replayed, capped: true },
      { from: new Date(T0), to: new Date(T0), ranAt: new Date(T0), truncated: false },
    );
    expect(capped.truncated).toBe(true);
    expect(capped.rules[0]).not.toHaveProperty("if_promoted");
    expect(JSON.stringify(result)).not.toContain("iph_");
  });
});
