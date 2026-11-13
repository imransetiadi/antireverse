import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  EXAMPLE_LOGIC,
  LOGIC_LIMITS,
  type LogicFile,
  LogicFileSchema,
  type LogicFunction,
  LogicFunctionSchema,
  LogicHiddenSchema,
  LogicPublicSchema,
} from "../src/index.ts";

const vectors = (count: number) => Array.from({ length: count }, (_, index) => ({ input: [index], output: index * 2 }));
const fn = (overrides: Partial<LogicFunction> = {}): LogicFunction => ({
  id: "double",
  description: "Doubles a number.",
  examples: [{ input: [1], output: 2 }],
  vectors: vectors(10),
  ...overrides,
});
const accepts = (value: unknown) => LogicFunctionSchema.safeParse(value).success;

describe("LOGIC_LIMITS", () => {
  it("bounds the logic file, its functions and the W3 run (plan 12b)", () => {
    expect(LOGIC_LIMITS).toEqual({
      functionsMin: 1,
      functionsMax: 5,
      idMax: 32,
      descriptionMax: 500,
      examplesMax: 2,
      vectorsMin: 10,
      vectorsMax: 200,
      fileBytesMax: 1_048_576,
      bodyBytesMax: 65_536,
      submissionsMax: 3,
      vectorTimeoutMs: 1000,
      batchTimeoutMs: 20_000,
    });
    expect(Object.isFrozen(LOGIC_LIMITS)).toBe(true);
  });
});

describe("LogicFunctionSchema", () => {
  it("parses an id, a description, up to 2 examples and 10–200 vectors", () => {
    expect(LogicFunctionSchema.parse(fn())).toEqual(fn());
    expect(accepts(fn({ examples: [] }))).toBe(true);
    expect(accepts(fn({ examples: vectors(2) }))).toBe(true);
    expect(accepts(fn({ examples: vectors(3) }))).toBe(false);
    expect(accepts(fn({ vectors: vectors(9) }))).toBe(false);
    expect(accepts(fn({ vectors: vectors(200) }))).toBe(true);
    expect(accepts(fn({ vectors: vectors(201) }))).toBe(false);
  });

  it("takes an id /^[a-z][a-z0-9-]{0,31}$/", () => {
    for (const id of ["a", "price-with-tax", "x9", `a${"b".repeat(31)}`]) expect(accepts(fn({ id })), id).toBe(true);
    for (const id of ["", "9a", "-a", "A", "a_b", "a b", `a${"b".repeat(32)}`]) {
      expect(accepts(fn({ id })), id).toBe(false);
    }
  });

  it("takes a description of 1–500 characters without control characters", () => {
    expect(accepts(fn({ description: "" }))).toBe(false);
    expect(accepts(fn({ description: "d".repeat(500) }))).toBe(true);
    expect(accepts(fn({ description: "d".repeat(501) }))).toBe(false);
    expect(accepts(fn({ description: "a\u0000b" }))).toBe(false);
  });

  it("takes an input that is a JSON array of arguments and an output that is any JSON value", () => {
    const one = (input: unknown, output: unknown) => accepts(fn({ examples: [{ input, output }] as never }));
    expect(one([], null)).toBe(true);
    expect(one([1, "a", true, null, [2], { k: { n: 1 } }], { total: 3, items: [1, 2] })).toBe(true);
    expect(one([1], "x")).toBe(true);
    expect(one(1, 2)).toBe(false);
    expect(one({ a: 1 }, 2)).toBe(false);
    expect(one([Number.POSITIVE_INFINITY], 2)).toBe(false);
    expect(one([1], Number.NaN)).toBe(false);
    expect(one([1], undefined)).toBe(false);
    expect(one([new Date(0)], 1)).toBe(false);
  });

  it("strips unknown keys", () => {
    expect(LogicFunctionSchema.parse({ ...fn(), extra: 1 })).not.toHaveProperty("extra");
  });
});

describe("LogicFileSchema", () => {
  const file = (functions: LogicFunction[]): LogicFile => ({ functions });

  it("holds 1–5 functions, each id once", () => {
    expect(LogicFileSchema.safeParse(file([])).success).toBe(false);
    expect(LogicFileSchema.safeParse(file([fn()])).success).toBe(true);
    const five = ["a", "b", "c", "d", "e"].map((id) => fn({ id }));
    expect(LogicFileSchema.safeParse(file(five)).success).toBe(true);
    expect(LogicFileSchema.safeParse(file([...five, fn({ id: "f" })])).success).toBe(false);
    const twice = LogicFileSchema.safeParse(file([fn({ id: "a" }), fn({ id: "a" })]));
    expect(twice.success).toBe(false);
    expect(twice.error?.issues.map((issue) => issue.path)).toEqual([["functions"]]);
  });

  it("is at most 1 MB as UTF-8 JSON", () => {
    const big = (id: string, size: number) =>
      fn({ id, vectors: Array.from({ length: 200 }, (_, index) => ({ input: [index], output: "é".repeat(size) })) });
    // 2 bytes per "é": 200 × 2 × 1,000 = 400 KB per function; two fit, three do not.
    expect(LogicFileSchema.safeParse(file([big("a", 1000), big("b", 1000)])).success).toBe(true);
    const over = LogicFileSchema.safeParse(file([big("a", 1000), big("b", 1000), big("c", 1000)]));
    expect(over.success).toBe(false);
    expect(over.error?.issues.some((issue) => issue.message.includes("1 MB"))).toBe(true);
  });

  it("parses the example, which is deeply frozen", () => {
    expect(LogicFileSchema.parse(EXAMPLE_LOGIC)).toEqual(EXAMPLE_LOGIC);
    expect(Object.isFrozen(EXAMPLE_LOGIC)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_LOGIC.functions[0]?.vectors)).toBe(true);
  });
});

describe("the public and the hidden part of a function", () => {
  it("shows the agent the id, description and examples only", () => {
    const view = LogicPublicSchema.parse(fn());
    expect(view).toEqual({ id: "double", description: "Doubles a number.", examples: [{ input: [1], output: 2 }] });
    expect(view).not.toHaveProperty("vectors");
  });

  it("keeps the hidden part as the id and the vectors", () => {
    const hidden = LogicHiddenSchema.parse(fn());
    expect(hidden).toEqual({ id: "double", vectors: vectors(10) });
    expect(hidden).not.toHaveProperty("description");
    expect(LogicHiddenSchema.safeParse({ id: "double", vectors: vectors(9) }).success).toBe(false);
  });
});

describe("canonicalJson (for the W3 verifier's output comparison)", () => {
  it("sorts keys at every depth and has no whitespace, so equal JSON values compare equal", () => {
    expect(canonicalJson({ b: [1, { d: 1, c: 2 }], a: "x" })).toBe('{"a":"x","b":[1,{"c":2,"d":1}]}');
    expect(canonicalJson({ x: 1, y: { p: null, q: true } })).toBe(canonicalJson({ y: { q: true, p: null }, x: 1 }));
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });
});
