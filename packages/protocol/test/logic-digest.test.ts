import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalJson, EXAMPLE_LOGIC, type LogicFile } from "../src/index.ts";
import { logicDigest } from "../src/server.ts";

const sha256 = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

describe("logicDigest", () => {
  it("is the SHA-256 hex of the canonical JSON of the full function list", () => {
    expect(logicDigest(EXAMPLE_LOGIC)).toBe(sha256(canonicalJson(EXAMPLE_LOGIC.functions)));
    expect(logicDigest(EXAMPLE_LOGIC)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("sorts the functions by id first, so file order does not change it", () => {
    const [first] = EXAMPLE_LOGIC.functions;
    if (first === undefined) throw new Error("example has a function");
    const b = { ...first, id: "b-fn" };
    const a = { ...first, id: "a-fn", description: "Other." };
    const forward: LogicFile = { functions: [a, b] };
    const backward: LogicFile = { functions: [b, a] };
    expect(logicDigest(backward)).toBe(logicDigest(forward));
    expect(logicDigest(backward)).toBe(sha256(canonicalJson([a, b])));
    expect(backward.functions[0]?.id).toBe("b-fn");
  });

  it("does not depend on key order or unknown keys, and does not change its input", () => {
    const [first] = EXAMPLE_LOGIC.functions;
    if (first === undefined) throw new Error("example has a function");
    const reordered = {
      functions: [{ vectors: first.vectors, examples: first.examples, description: first.description, id: first.id }],
    } as LogicFile;
    expect(logicDigest(reordered)).toBe(logicDigest(EXAMPLE_LOGIC));
    expect(logicDigest({ ...EXAMPLE_LOGIC, comment: "x" } as LogicFile)).toBe(logicDigest(EXAMPLE_LOGIC));
    const copy = structuredClone(reordered);
    logicDigest(copy);
    expect(copy).toEqual(reordered);
    expect(Object.keys(copy.functions[0] ?? {})).toEqual(["vectors", "examples", "description", "id"]);
  });

  it("changes with any vector, example or description", () => {
    const [first] = EXAMPLE_LOGIC.functions;
    if (first === undefined) throw new Error("example has a function");
    const variant = (change: object): LogicFile => ({ functions: [{ ...first, ...change }] });
    const base = logicDigest(EXAMPLE_LOGIC);
    expect(logicDigest(variant({ description: "Other." }))).not.toBe(base);
    expect(logicDigest(variant({ examples: [] }))).not.toBe(base);
    const vectors = first.vectors.map((vector, index) => (index === 0 ? { ...vector, output: "changed" } : vector));
    expect(logicDigest(variant({ vectors }))).not.toBe(base);
  });

  it("throws a TypeError for a file that is not a valid logic file", () => {
    expect(() => logicDigest({ functions: [] })).toThrow(TypeError);
    expect(() => logicDigest({} as LogicFile)).toThrow(TypeError);
  });
});
