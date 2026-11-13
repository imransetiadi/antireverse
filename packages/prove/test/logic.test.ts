// Slice 12b — W3 Logic: the submitted function body runs against every hidden vector in a sandbox worker (args as
// a0..aN and `args`, 1 s per vector, 20 s per batch), outputs compared by canonical JSON; achieved when every vector
// of that function passes. Evidence names the function and the pass count, never a vector.
import { EvidenceSchema, EXAMPLE_LOGIC } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { runLogicVectors, verifyLogic } from "../src/logic.ts";
import type { Submission } from "../src/toolbelt.ts";

const PRICE = EXAMPLE_LOGIC.functions[0] as (typeof EXAMPLE_LOGIC.functions)[number];
const CORRECT = "return Math.round((a0 * (100 + a1)) / 100);";
const LOOKUP = `const t = ${JSON.stringify(Object.fromEntries(PRICE.examples.map((e) => [JSON.stringify(e.input), e.output])))}; const k = JSON.stringify(args); return Object.prototype.hasOwnProperty.call(t, k) ? t[k] : null;`;
const FAST = { vectorTimeoutMs: 150, batchTimeoutMs: 5_000 };

let n = 0;
function submission(body: string, functionId = PRICE.id, calls = 4): Submission {
  n += 1;
  return { objective: "W3", payload: { function_id: functionId, body }, callIndex: n, cost: { calls, seconds: 1 } };
}

describe("runLogicVectors", () => {
  it("passes the input as a0..aN and as args, and returns each output as JSON", async () => {
    const results = await runLogicVectors(
      "return [a0, a1, a2, args.length];",
      [
        [1, "x"],
        [2, "y", true],
      ],
      FAST,
    );
    expect(results).toEqual([
      { ok: true, output: JSON.stringify([1, "x", null, 2]) },
      { ok: true, output: JSON.stringify([2, "y", true, 3]) },
    ]);
  });

  it("times out an infinite loop; vectors before it keep their results", async () => {
    const started = Date.now();
    const results = await runLogicVectors("if (a0 === 2) { for (;;) {} } return a0;", [[1], [2], [3]], FAST);
    expect(results[0]).toEqual({ ok: true, output: "1" });
    expect(results[1]).toMatchObject({ ok: false, kind: "timeout" });
    expect(results[2]).toMatchObject({ ok: false, kind: "timeout" });
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it("ends the batch when a vector blocks past what the script timeout can interrupt", async () => {
    const results = await runLogicVectors(
      "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0); return 1;",
      [[1], [2], [3]],
      FAST,
    );
    expect(results).toHaveLength(3);
    for (const result of results) expect(result.ok).toBe(false);
  });

  it("has no require, process or code generation", async () => {
    const results = await runLogicVectors(
      "return [typeof require, typeof process, typeof fetch, (() => { try { return eval('1'); } catch (e) { return e.name; } })()];",
      [[]],
      FAST,
    );
    expect(results).toEqual([
      { ok: true, output: JSON.stringify(["undefined", "undefined", "undefined", "EvalError"]) },
    ]);
  });

  it("a body that does not parse fails every vector without running anything", async () => {
    const results = await runLogicVectors("}); return 1; ({", [[1], [2]], FAST);
    expect(results).toEqual([
      expect.objectContaining({ ok: false, kind: "error" }),
      expect.objectContaining({ ok: false, kind: "error" }),
    ]);
  });
});

describe("verifyLogic (W3)", () => {
  it("is not attempted without a designated function", async () => {
    for (const logic of [undefined, null]) {
      expect(await verifyLogic([submission(CORRECT)], logic)).toMatchObject({
        kind: "not_attempted",
        reason: "not_designated",
      });
    }
  });

  it("is achieved by a correct reimplementation: every hidden vector passes", async () => {
    const wrong = submission(LOOKUP);
    const right = submission(CORRECT);
    const verdict = await verifyLogic([wrong, right], EXAMPLE_LOGIC, FAST);
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: { callIndex: right.callIndex, cost: right.cost } });
    if (verdict?.kind !== "judged") throw new Error();
    expect(verdict.evidence.summary).toMatch(/price-with-tax/);
    expect(verdict.evidence.summary).toMatch(/10 of 10/);
    expect(verdict.evidence.calls).toEqual([wrong.callIndex, right.callIndex]);
    expect(EvidenceSchema.safeParse(verdict.evidence).success).toBe(true);
  });

  it("is not achieved by a lookup over the public examples", async () => {
    const verdict = await verifyLogic([submission(LOOKUP)], EXAMPLE_LOGIC, FAST);
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: null });
    if (verdict?.kind !== "judged") throw new Error();
    expect(verdict.evidence.summary).toMatch(/of 10/);
  });

  it("is not achieved by a body that loops forever (each vector times out)", async () => {
    const verdict = await verifyLogic([submission("for (;;) {}")], EXAMPLE_LOGIC, FAST);
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: null });
    if (verdict?.kind !== "judged") throw new Error();
    expect(verdict.evidence.summary).toMatch(/0 of 10/);
  });

  it("is not achieved for a function id that was not designated", async () => {
    const verdict = await verifyLogic([submission(CORRECT, "unknown-fn")], EXAMPLE_LOGIC, FAST);
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: null });
  });

  it("never puts a vector into the evidence", async () => {
    const verdict = await verifyLogic([submission(LOOKUP), submission(CORRECT)], EXAMPLE_LOGIC, FAST);
    const text = JSON.stringify(verdict);
    for (const vector of PRICE.vectors) {
      expect(text).not.toContain(JSON.stringify(vector.input));
      if (typeof vector.output === "number" && vector.output > 100) expect(text).not.toContain(String(vector.output));
    }
  });

  it("returns null when nothing was submitted (the orchestrator decides)", async () => {
    expect(await verifyLogic([], EXAMPLE_LOGIC, FAST)).toBeNull();
  });
});

describe("runLogicVectors: the import() escape and time (review 12b F1, F4)", () => {
  it("a body cannot see process or read a file through the import() promise", async () => {
    const repoFile = new URL("../package.json", import.meta.url).pathname;
    const body = `const p = import("x"); p.catch(() => {}); try { return String(p.constructor.constructor(${JSON.stringify(`return process.getBuiltinModule("node:fs").readFileSync(${JSON.stringify(repoFile)}, "utf8")`)})()); } catch (e) { return "blocked " + e.name; }`;
    // Since review N1 the body is refused before it compiles.
    expect(await runLogicVectors(body, [[1]], FAST)).toEqual([
      { ok: false, kind: "error", error: expect.stringMatching(/import\(\) and import\.meta are not available/) },
    ]);
  });

  it("stops after the first vector that times out; the rest count as timed out without running", async () => {
    const started = Date.now();
    const results = await runLogicVectors(
      "for (;;) {}",
      Array.from({ length: 50 }, (_, i) => [i]),
      {
        vectorTimeoutMs: 200,
        batchTimeoutMs: 20_000,
      },
    );
    expect(results).toHaveLength(50);
    for (const result of results) expect(result).toMatchObject({ ok: false, kind: "timeout" });
    expect(Date.now() - started).toBeLessThan(3_000);
  });
});

describe("runLogicVectors: import() is unreachable (review N1)", () => {
  it("refuses a body with import() before it compiles; a toJSON forge cannot forge outputs", async () => {
    const forge =
      'const p = import("y"); p.catch(() => {}); const HostObject = Object.getPrototypeOf(Object.getPrototypeOf(p));' +
      'HostObject.toJSON = function () { return { index: 0, ok: true, output: "2", token: this.token }; };' +
      "return a0 * 2;";
    const results = await runLogicVectors(forge, [[1], [2]], FAST);
    for (const result of results) {
      expect(result).toMatchObject({ ok: false, kind: "error" });
      expect((result as { error: string }).error).toMatch(/import\(\) and import\.meta are not available/);
    }
  });
});
