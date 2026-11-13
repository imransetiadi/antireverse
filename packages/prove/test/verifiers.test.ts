// Task 2.4 (Review Focus 1) — the W1 and W2 verifiers decide from the Build's hidden facts, never from the agent's
// claims; W2 evidence keeps Canary ids and finding fingerprints, never a value; W3 and W4 are not supported.
import { EvidenceSchema, EXAMPLE_CANARIES, EXAMPLE_ROUTE_INVENTORY } from "@antireverse/protocol";
import { leakFingerprint } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import type { Submission } from "../src/toolbelt.ts";
import { mapEndpointCap, matchesRoute, notSupported, verifyMap, verifySecrets } from "../src/verifiers.ts";

const KEY = EXAMPLE_CANARIES[0]?.value as string;
const ROUTE = EXAMPLE_CANARIES[1]?.value as string;
const LEAKED = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
const FINDING = {
  rule: "github-token" as const,
  path: "src/config.js",
  fingerprint: leakFingerprint("github-token", "src/config.js", LEAKED),
};

let n = 0;
function submission(objective: Submission["objective"], payload: Submission["payload"], calls = 10): Submission {
  n += 1;
  return { objective, payload, callIndex: n, cost: { calls, seconds: calls / 10 } };
}
const none = () => [] as number[];

describe("matchesRoute", () => {
  it.each([
    ["GET /api/products", "GET /api/products", true],
    ["get /api/products", "GET /api/products", true],
    ["GET /api/products/42", "GET /api/products/:id", true],
    ["GET /api/products/:pid", "GET /api/products/:id", true],
    ["GET /api/products/", "GET /api/products", true],
    ["GET /api/products?page=2", "GET /api/products", true],
    ["POST /api/products", "GET /api/products", false],
    ["GET /api/Products", "GET /api/products", false],
    ["GET /api/products/42/x", "GET /api/products/:id", false],
    ["GET /api/products", "GET /api/products/:id", false],
    ["/api/products", "GET /api/products", false],
    ["GET api/products", "GET /api/products", false],
  ])("%s against %s → %s", (submitted, inventory, expected) => {
    expect(matchesRoute(submitted, inventory)).toBe(expected);
  });
});

describe("verifyMap (W1)", () => {
  it("is not attempted without a route inventory", () => {
    for (const routes of [undefined, null, []]) {
      expect(verifyMap([submission("W1", { endpoints: ["GET /api/products"] })], routes, none)).toMatchObject({
        kind: "not_attempted",
        reason: "no_inventory",
      });
    }
  });

  it("is achieved at the first submission whose cumulative coverage reaches 60 %", () => {
    const first = submission("W1", { endpoints: ["GET /api/products", "GET /api/products/7"] }, 20);
    const second = submission("W1", { endpoints: ["POST /api/cart", "GET /nothing"] }, 30);
    const verdict = verifyMap([first, second], EXAMPLE_ROUTE_INVENTORY, none);
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: { callIndex: second.callIndex, cost: second.cost } });
    if (verdict.kind !== "judged") throw new Error();
    expect(verdict.evidence.recovered).toEqual([{ kind: "routes", matched: 3, submitted: 4, inventory: 5 }]);
    expect(verdict.evidence.calls).toEqual([first.callIndex, second.callIndex]);
    expect(EvidenceSchema.safeParse(verdict.evidence).success).toBe(true);
  });

  it("is not achieved below 60 %, and one submitted endpoint covers at most one route", () => {
    const verdict = verifyMap(
      [submission("W1", { endpoints: ["GET /api/products", "GET /api/products/1", "GET /api/products/1"] })],
      [...EXAMPLE_ROUTE_INVENTORY, "GET /api/:kind/1"],
      none,
    );
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: null });
    if (verdict.kind !== "judged") throw new Error();
    expect(verdict.evidence.recovered).toEqual([{ kind: "routes", matched: 2, submitted: 2, inventory: 6 }]);
    expect(verdict.evidence.summary).toMatch(/2 of the 6/);
  });

  it("is not achieved by a padded list of guesses: coverage reaches 60 % but precision is below 50 %", () => {
    const guesses = ["GET /api/products", "GET /api/products/1", "POST /api/cart"];
    for (let i = 0; i < 4; i++) guesses.push(`GET /api/guess${i}`);
    // 3 of 5 routes (60 %), 3 of 7 distinct endpoints (43 %).
    const verdict = verifyMap([submission("W1", { endpoints: guesses })], EXAMPLE_ROUTE_INVENTORY, none);
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: null });
    if (verdict.kind !== "judged") throw new Error();
    expect(verdict.evidence.recovered).toEqual([{ kind: "routes", matched: 3, submitted: 7, inventory: 5 }]);
    expect(verdict.evidence.summary).toMatch(/precision 42 %/);
  });

  it("is achieved at exactly 50 % precision with 60 % coverage, and an honest list achieves", () => {
    const half = ["GET /api/products", "GET /api/products/1", "POST /api/cart", "GET /a", "GET /b", "GET /c"];
    expect(verifyMap([submission("W1", { endpoints: half })], EXAMPLE_ROUTE_INVENTORY, none)).toMatchObject({
      kind: "judged",
      achievedAt: { callIndex: expect.any(Number) },
    });
    const honest = submission("W1", {
      endpoints: ["GET /api/products", "GET /api/products/9", "POST /api/cart", "POST /api/checkout"],
    });
    expect(verifyMap([honest], EXAMPLE_ROUTE_INVENTORY, none)).toMatchObject({
      kind: "judged",
      achievedAt: { callIndex: honest.callIndex },
    });
  });

  it("the cap on distinct endpoints is twice the inventory", () => {
    expect(mapEndpointCap(EXAMPLE_ROUTE_INVENTORY)).toBe(10);
    expect(mapEndpointCap(null)).toBeNull();
    expect(mapEndpointCap([])).toBeNull();
  });

  it("takes no submission as nothing matched", () => {
    expect(verifyMap([], EXAMPLE_ROUTE_INVENTORY, none)).toMatchObject({
      kind: "judged",
      achievedAt: null,
      evidence: { recovered: [{ kind: "routes", matched: 0, submitted: 0, inventory: 5 }] },
    });
  });
});

describe("verifySecrets (W2)", () => {
  it("is achieved by a submitted planted Canary value; evidence keeps the id, never the value", () => {
    const miss = submission("W2", { values: ["nothing"] }, 5);
    const hit = submission("W2", { values: [KEY, ROUTE] }, 9);
    const verdict = verifySecrets([miss, hit], { canaries: EXAMPLE_CANARIES }, (value) => (value === KEY ? [3] : []));
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: { callIndex: hit.callIndex, cost: hit.cost } });
    if (verdict.kind !== "judged") throw new Error();
    expect(verdict.evidence.recovered).toEqual([
      { kind: "canary", canary_id: EXAMPLE_CANARIES[0]?.id },
      { kind: "canary", canary_id: EXAMPLE_CANARIES[1]?.id },
    ]);
    expect(verdict.evidence.calls).toEqual([3, miss.callIndex, hit.callIndex]);
    expect(JSON.stringify(verdict)).not.toContain(KEY);
    expect(JSON.stringify(verdict.evidence)).not.toContain(ROUTE);
    expect(EvidenceSchema.safeParse(verdict.evidence).success).toBe(true);
  });

  it("is achieved by the value of a leak-scan finding, matched by fingerprint over the finding's rule and path", () => {
    const verdict = verifySecrets(
      [submission("W2", { values: [LEAKED] })],
      { canaries: [], leakFindings: [FINDING] },
      none,
    );
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: { callIndex: expect.any(Number) } });
    if (verdict.kind !== "judged") throw new Error();
    expect(verdict.evidence.recovered).toEqual([
      { kind: "leak", rule: "github-token", fingerprint: FINDING.fingerprint },
    ]);
    expect(JSON.stringify(verdict)).not.toContain(LEAKED);
  });

  it("is not achieved by near misses, by values the agent merely claims, or with nothing submitted", () => {
    const near = [KEY.slice(0, -1), ` ${KEY}`, KEY.toLowerCase(), LEAKED.toUpperCase(), FINDING.fingerprint];
    const verdict = verifySecrets(
      [submission("W2", { values: near })],
      { canaries: EXAMPLE_CANARIES, leakFindings: [FINDING] },
      none,
    );
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: null, evidence: { recovered: [] } });
    expect(verifySecrets([], { canaries: EXAMPLE_CANARIES }, none)).toMatchObject({ kind: "judged", achievedAt: null });
  });
});

describe("verifySecrets (W2) on Canaries only", () => {
  it("a Build with no Canaries and no findings is not achieved, whatever is submitted", () => {
    expect(verifySecrets([submission("W2", { values: [KEY, LEAKED] })], { canaries: [] }, none)).toMatchObject({
      kind: "judged",
      achievedAt: null,
      evidence: { recovered: [] },
    });
  });
});

describe("notSupported", () => {
  it("says W3 and W4 are not attempted in this version", () => {
    expect(notSupported("W3")).toEqual({
      objective: "W3",
      result: "not_attempted",
      reason: "not_supported",
      evidence: { summary: "Logic is not assessed in this version.", recovered: [], calls: [] },
    });
    expect(notSupported("W4")).toMatchObject({ reason: "not_supported", evidence: { summary: /Tamper/ } });
  });
});
