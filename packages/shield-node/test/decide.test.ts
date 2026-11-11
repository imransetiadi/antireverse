import { describe, expect, it } from "vitest";
import { decide } from "../src/decide.ts";
import { compilePattern, type PathPattern } from "../src/policy/match.ts";
import { type AppliedPolicy, BUILT_IN_POLICY, buildPolicy, routeOfDecision } from "../src/policy/store.ts";
import type { Decision } from "../src/types.ts";
import { DAY_MS, NOW } from "./policy-helpers.ts";

interface RuleSpec {
  id: string;
  path: string;
  mode: "monitor" | "enforce";
  methods?: string[];
}

function policy(version: number, rules: RuleSpec[]): AppliedPolicy {
  return buildPolicy({
    version,
    issuedAt: NOW,
    notAfter: NOW + 7 * DAY_MS,
    rules: rules.map((rule) => ({
      id: rule.id,
      path: rule.path,
      mode: rule.mode,
      methods: rule.methods ?? [],
      pattern: compilePattern(rule.path) as PathPattern,
    })),
  });
}

const ADMIN = "rul_0000000000000000000000a1";
const EXPORT = "rul_0000000000000000000000b2";
const PRODUCTS = "rul_0000000000000000000000c3";

describe("decide: the built-in Policy (version 0, no Rules)", () => {
  it("allows every request in Monitor mode", () => {
    for (const input of [
      { method: "GET", path: "/api/products/42" },
      { method: "POST", path: "/api/admin/reports?x=1" },
      { method: "DELETE", path: "/" },
    ]) {
      expect(decide(BUILT_IN_POLICY, input)).toEqual({
        action: "allow",
        mode: "monitor",
        ruleId: null,
        policyVersion: 0,
      });
    }
  });
});

describe("decide: a published Policy", () => {
  const published = policy(7, [
    { id: PRODUCTS, path: "/api/products/**", mode: "monitor" },
    { id: ADMIN, path: "/api/admin/**", mode: "enforce" },
    { id: EXPORT, path: "/api/users/*/export", mode: "enforce", methods: ["GET", "POST"] },
  ]);

  it("allows a request no Rule matches, in Enforce mode, and reports the Policy version", () => {
    expect(decide(published, { method: "GET", path: "/api/login" })).toEqual({
      action: "allow",
      mode: "enforce",
      ruleId: null,
      policyVersion: 7,
    });
  });

  it("an empty published Policy allows in Enforce mode: only version 0 is Monitor mode", () => {
    expect(decide(policy(4, []), { method: "GET", path: "/anything" })).toEqual({
      action: "allow",
      mode: "enforce",
      ruleId: null,
      policyVersion: 4,
    });
  });

  it("blocks a request an Enforce Rule matches", () => {
    expect(decide(published, { method: "GET", path: "/api/admin/reports" })).toEqual({
      action: "block",
      mode: "enforce",
      ruleId: ADMIN,
      policyVersion: 7,
    });
  });

  it("marks a request only a Monitor Rule matches: block in Monitor mode", () => {
    expect(decide(published, { method: "GET", path: "/api/products/42" })).toEqual({
      action: "block",
      mode: "monitor",
      ruleId: PRODUCTS,
      policyVersion: 7,
    });
  });

  it("matches the path without its query string, whatever the letter case, with one trailing slash", () => {
    for (const path of ["/api/admin?x=1", "/API/Admin/", "/api/admin", "/api/admin/x/y?next=/api/login"]) {
      expect(decide(published, { method: "GET", path }), path).toMatchObject({ action: "block", ruleId: ADMIN });
    }
    expect(decide(published, { method: "GET", path: "/api/administrator" })).toMatchObject({ action: "allow" });
  });

  it("a Rule with methods applies to those methods only", () => {
    expect(decide(published, { method: "GET", path: "/api/users/9/export" })).toMatchObject({ ruleId: EXPORT });
    expect(decide(published, { method: "POST", path: "/api/users/9/export" })).toMatchObject({ ruleId: EXPORT });
    expect(decide(published, { method: "DELETE", path: "/api/users/9/export" })).toMatchObject({
      action: "allow",
      ruleId: null,
    });
  });

  it("reads the method in upper case: a caller's lower-case spelling does not get past a Rule", () => {
    expect(decide(published, { method: "post", path: "/api/users/9/export" })).toMatchObject({
      action: "block",
      ruleId: EXPORT,
    });
  });
});

describe("decide: the order of Rules", () => {
  const first = "rul_000000000000000000000001";
  const second = "rul_000000000000000000000002";
  const third = "rul_000000000000000000000003";

  it("an Enforce match wins over an earlier Monitor match", () => {
    const published = policy(2, [
      { id: first, path: "/api/**", mode: "monitor" },
      { id: second, path: "/api/admin/**", mode: "enforce" },
    ]);
    expect(decide(published, { method: "GET", path: "/api/admin/x" })).toEqual({
      action: "block",
      mode: "enforce",
      ruleId: second,
      policyVersion: 2,
    });
    expect(decide(published, { method: "GET", path: "/api/other" })).toMatchObject({ mode: "monitor", ruleId: first });
  });

  it("of two Enforce matches the first decides; of two Monitor matches the first marks", () => {
    const enforce = policy(2, [
      { id: first, path: "/api/**", mode: "enforce" },
      { id: second, path: "/api/admin/**", mode: "enforce" },
    ]);
    expect(decide(enforce, { method: "GET", path: "/api/admin/x" })).toMatchObject({ mode: "enforce", ruleId: first });
    const monitor = policy(2, [
      { id: first, path: "/api/admin/**", mode: "monitor" },
      { id: second, path: "/api/**", mode: "monitor" },
      { id: third, path: "/other", mode: "enforce" },
    ]);
    expect(decide(monitor, { method: "GET", path: "/api/admin/x" })).toMatchObject({ mode: "monitor", ruleId: first });
  });

  it("a Rule whose method does not match is passed over, and a later one decides", () => {
    const published = policy(2, [
      { id: first, path: "/api/admin/**", mode: "enforce", methods: ["DELETE"] },
      { id: second, path: "/api/admin/**", mode: "monitor" },
    ]);
    expect(decide(published, { method: "GET", path: "/api/admin/x" })).toMatchObject({
      mode: "monitor",
      ruleId: second,
    });
    expect(decide(published, { method: "DELETE", path: "/api/admin/x" })).toMatchObject({
      mode: "enforce",
      ruleId: first,
    });
  });
});

describe("decide: the contract of the function", () => {
  const published = policy(3, [{ id: ADMIN, path: "/api/admin/**", mode: "enforce" }]);

  it("is synchronous: the return value is not a Promise", () => {
    const decision: unknown = decide(published, { method: "GET", path: "/" });
    expect(decision).not.toBeInstanceOf(Promise);
    expect(typeof (decision as { then?: unknown }).then).toBe("undefined");
  });

  it("cannot be altered by a caller that mutates the returned Decision", () => {
    for (const path of ["/", "/api/admin/x"]) {
      const before = { ...decide(published, { method: "GET", path }) };
      const returned = decide(published, { method: "GET", path }) as { action: string; ruleId: string | null };
      try {
        returned.action = "allow";
        returned.ruleId = "rul_forged";
      } catch {
        // a frozen object throws in strict mode: also fine
      }
      expect(decide(published, { method: "GET", path })).toEqual(before);
    }
    const builtIn = decide(BUILT_IN_POLICY, { method: "GET", path: "/" }) as { action: string };
    try {
      builtIn.action = "block";
    } catch {
      // frozen
    }
    expect(decide(BUILT_IN_POLICY, { method: "GET", path: "/" }).action).toBe("allow");
  });

  it("never throws, whatever it is given: what cannot be read matches no path", () => {
    const inputs: unknown[] = [
      undefined,
      null,
      {},
      { method: 7, path: 7 },
      { method: "GET" },
      { path: "/api/admin/x" },
      { method: "GET", path: null },
      "text",
    ];
    for (const input of inputs) {
      let decision: Decision | undefined;
      expect(() => {
        decision = decide(published, input as never);
      }).not.toThrow();
      expect(decision?.policyVersion).toBe(3);
    }
    // A method that cannot be read still meets a Rule for every method.
    expect(decide(published, { path: "/api/admin/x" } as never)).toMatchObject({ action: "block", ruleId: ADMIN });
    expect(decide(published, { method: "GET", path: null } as never)).toMatchObject({ action: "allow" });
  });

  it("remembers the path pattern of the Rule behind a block Decision, for the Event of a blocked request", () => {
    const blocked = decide(published, { method: "GET", path: "/api/admin/secret-report" });
    expect(routeOfDecision(blocked)).toBe("/api/admin/**");
    expect(routeOfDecision(decide(published, { method: "GET", path: "/" }))).toBeUndefined();
    expect(routeOfDecision({ ...blocked })).toBeUndefined(); // only Shield's own Decisions are known
  });
});

describe("decide: the text of the path and its canonical forms (review 02, F1)", () => {
  const FILES = "rul_0000000000000000000000f1";
  const published = policy(4, [
    { id: FILES, path: "/files/private/**", mode: "enforce" },
    { id: EXPORT, path: "/api/users/*/export", mode: "enforce" },
    { id: PRODUCTS, path: "/api/products/**", mode: "monitor" },
  ]);
  const at = (path: string): Decision => decide(published, { method: "GET", path });

  it.each([
    "/files/private/secret.txt", // the text itself
    "/files/PRIVATE/secret.txt",
    "/files/%70rivate/secret.txt",
    "/files/%2570rivate/secret.txt", // double encoding
    "/files/private%2fsecret.txt",
    "/files/private%5csecret.txt", // an encoded backslash
    "/files/private\\secret.txt",
    "/files/public/../private/secret.txt",
    "/files/public/%2e%2e/private/secret.txt",
    "/files/public/%2E%2E/private/secret.txt", // mixed case of the hex digits
    "/files/public/%252e%252e/private/secret.txt",
    "/files/./private/secret.txt",
    "/files//private/secret.txt",
    "/files/private",
    "/../files/private/x", // `..` past the root stays at the root
    "/../../../files/./private",
    "/files/public/a%252f..%2f..%2f..%2fprivate/secret.txt", // into private/ after one decoding only
    "/files/public/a%5c..%2f..%2f..%2fprivate/secret.txt", // into private/ with `\\` read as text only
    "/files/private/x?next=/public", // the query string is gone before anything is decoded
  ])("an Enforce Rule blocks %s", (path) => {
    expect(at(path)).toEqual({ action: "block", mode: "enforce", ruleId: FILES, policyVersion: 4 });
    expect(routeOfDecision(at(path))).toBe("/files/private/**"); // the Rule's pattern, never the spelling
  });

  it.each([
    "/files/public/a.txt",
    "/files/public/a%20b.txt",
    "/files/privateer/x",
    "/files/private.txt",
    "/files/%zzprivate/x", // malformed: kept as text, and that text is not `private`
    "/files/public/%2525252e%2525252e/private/x", // a fourth encoding is not decoded: a file of that name
    "/files/public/..%2fx/private",
    "/files/a/../../private/x", // that is /private/x, not below /files
  ])("allows %s", (path) => {
    expect(at(path)).toEqual(published.allow);
  });

  it("only adds matches: a path whose text matches still matches when its canonical form does not", () => {
    expect(at("/api/users/../export")).toMatchObject({ action: "block", ruleId: EXPORT }); // canonical: /api/export
    expect(at("/files/private/../public/a.txt")).toMatchObject({ action: "block", ruleId: FILES });
  });

  it("a Monitor Rule marks a canonical form too", () => {
    expect(at("/api/%70roducts/42")).toEqual({ action: "block", mode: "monitor", ruleId: PRODUCTS, policyVersion: 4 });
    expect(at("/api/x/../products/42")).toMatchObject({ mode: "monitor", ruleId: PRODUCTS });
  });

  it("an Enforce match in a canonical form wins over a Monitor match in the text", () => {
    const ordered = policy(5, [
      { id: PRODUCTS, path: "/api/products/**", mode: "monitor" },
      { id: ADMIN, path: "/api/admin/**", mode: "enforce" },
    ]);
    expect(decide(ordered, { method: "GET", path: "/api/products/%2e%2e/admin/x" })).toMatchObject({
      action: "block",
      mode: "enforce",
      ruleId: ADMIN,
    });
  });
});

describe("decide: cost on long paths (review 02, F3)", () => {
  it("50 Rules that start with * against a 16 KB path of one segment: p99 of 200 calls well under 0.5 ms", () => {
    const rules = Array.from({ length: 50 }, (_, i) => ({
      id: `rul_${i.toString(16).padStart(24, "0")}`,
      path: `/*/r${i}/**`,
      mode: i % 2 === 0 ? ("enforce" as const) : ("monitor" as const),
    }));
    const fifty = policy(6, rules);
    for (const [label, path] of [
      ["16 KB, one segment", `/${"a".repeat(16_000)}`],
      ["16 KB, one segment, then a slash", `/${"a".repeat(16_000)}/`],
      ["16 KB of encoded characters", `/${"%61".repeat(5_333)}`],
    ] as const) {
      for (let i = 0; i < 50; i++) decide(fifty, { method: "GET", path }); // warm-up
      // Each of the 200 samples is the fastest of 5 calls in a row: a busy machine (the suite runs files in
      // parallel) preempts single calls, while a cost that grows with Rules × path length — 2.5 ms and more before
      // the fix — is paid by every one of the 5.
      const times: number[] = [];
      for (let i = 0; i < 200; i++) {
        let fastest = Number.POSITIVE_INFINITY;
        for (let repeat = 0; repeat < 5; repeat++) {
          const started = performance.now();
          const decision = decide(fifty, { method: "GET", path });
          fastest = Math.min(fastest, performance.now() - started);
          expect(decision.action).toBe("allow");
        }
        times.push(fastest);
      }
      times.sort((a, b) => a - b);
      const best = times[Math.floor(times.length * 0.99)] as number;
      expect(best, label).toBeLessThan(0.5);
    }
  });
});
