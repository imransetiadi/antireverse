import { gzipSync } from "node:zlib";
import { afterAll, describe, expect, it } from "vitest";
import { harden } from "../src/engine.ts";
import { cleanupModules, importModule } from "./helpers.ts";

afterAll(cleanupModules);

const SAMPLE = `
  const SECRET = "the quick brown fox";
  export function shout(name) {
    return SECRET + " :: " + name.toUpperCase();
  }
`;

// A budget high enough that string encryption is never cut, for tests that exercise the strings pass itself.
const NO_BUDGET = { sizePct: 1_000_000, runPct: 1_000_000 };

function fileNamed(name: string, code: string): Record<string, string> {
  return { [name]: code };
}

describe("harden engine", () => {
  it("light profile mangles only (no string table)", () => {
    const result = harden(fileNamed("a.mjs", SAMPLE), { profile: "light", seed: 1 });
    const out = result.files[0];
    expect(out?.skipped).toBe(false);
    expect(out?.renamed).toBeGreaterThan(0);
    expect(out?.stringsEncrypted).toBe(0);
    expect(out?.code).not.toContain("__ar_d");
    expect(result.transform.strings_encrypted).toBe(0);
    expect(result.transform.integrity).toBe(false);
  });

  it("balanced profile mangles and encrypts strings, preserving behaviour", async () => {
    const result = harden(fileNamed("a.mjs", SAMPLE), { profile: "balanced", seed: 1, budget: NO_BUDGET });
    const out = result.files[0];
    expect(out?.renamed).toBeGreaterThan(0);
    expect(out?.stringsEncrypted).toBeGreaterThan(0);
    expect(out?.code).not.toContain("the quick brown fox");
    const mod = await importModule(out?.code ?? "");
    expect((mod.shout as (n: string) => string)("ada")).toBe("the quick brown fox :: ADA");
  });

  it("maximum profile equals balanced in this slice", () => {
    const bal = harden(fileNamed("a.mjs", SAMPLE), { profile: "balanced", seed: 3 });
    const max = harden(fileNamed("a.mjs", SAMPLE), { profile: "maximum", seed: 3 });
    expect(max.files[0]?.code).toBe(bal.files[0]?.code);
  });

  it("is deterministic: same seed byte-identical, two seeds differ, behaviour identical", async () => {
    const one = harden(fileNamed("a.mjs", SAMPLE), { profile: "balanced", seed: 10 });
    const two = harden(fileNamed("a.mjs", SAMPLE), { profile: "balanced", seed: 10 });
    expect(one.files[0]?.code).toBe(two.files[0]?.code);

    const other = harden(fileNamed("a.mjs", SAMPLE), { profile: "balanced", seed: 11 });
    expect(other.files[0]?.code).not.toBe(one.files[0]?.code);

    const a = await importModule(one.files[0]?.code ?? "");
    const b = await importModule(other.files[0]?.code ?? "");
    expect((a.shout as (n: string) => string)("x")).toBe((b.shout as (n: string) => string)("x"));
  });

  it("budget guard: a string-heavy small file falls back to mangle-only with a reason", () => {
    // Many distinct long strings in a tiny file: the string table blows the gzip size budget.
    const parts = Array.from({ length: 40 }, (_, i) => `"literal-string-number-${i}-padding-xyz"`);
    const heavy = `export const list = [${parts.join(",")}];`;
    const result = harden(fileNamed("heavy.mjs", heavy), { profile: "balanced", seed: 1 });
    const out = result.files[0];
    expect(out?.mangleOnly).toBeTypeOf("string");
    expect(out?.stringsEncrypted).toBe(0);
    expect(out?.code).not.toContain("__ar_d");
    expect(result.transform.files_mangle_only).toBe(1);
  });

  it("never ships a file over the size budget", () => {
    const parts = Array.from({ length: 40 }, (_, i) => `"literal-string-number-${i}-padding-xyz"`);
    const heavy = `export const list = [${parts.join(",")}];`;
    const sizePct = 35;
    const result = harden(fileNamed("heavy.mjs", heavy), {
      profile: "balanced",
      seed: 1,
      budget: { sizePct, runPct: 15 },
    });
    // The chosen output's gzip overhead is at or under budget (mangle-only here).
    const out = result.files[0];
    expect(out).toBeDefined();
    expect(out?.mangleOnly).toMatch(/budget/i);
    // The guarantee that matters: whatever actually shipped is within the budget.
    const shipped = out as NonNullable<typeof out>;
    const before = gzipSync(Buffer.from(heavy, "utf8")).length;
    const after = gzipSync(Buffer.from(shipped.code, "utf8")).length;
    expect(((after - before) / before) * 100).toBeLessThanOrEqual(sizePct);
  });

  it("protection map 'skip' emits the file byte-identical", () => {
    const result = harden(fileNamed("a.mjs", SAMPLE), {
      profile: "balanced",
      seed: 1,
      protectionMap: { "a.mjs": "skip" },
    });
    const out = result.files[0];
    expect(out?.skipped).toBe(true);
    expect(out?.code).toBe(SAMPLE);
    expect(out?.renamed).toBe(0);
    expect(out?.stringsEncrypted).toBe(0);
  });

  it("reports a parse error per file and does not throw", () => {
    const result = harden(fileNamed("bad.mjs", "export function ( {{{ bad syntax"), { profile: "balanced", seed: 1 });
    const out = result.files[0];
    expect(out?.skipped).toBe(true);
    expect(out?.error ?? "").toMatch(/parse|error|syntax/i);
    // The original code is passed through unchanged when it cannot be parsed.
    expect(out?.code).toBe("export function ( {{{ bad syntax");
  });

  it("aggregates the transform summary across files", () => {
    const result = harden(
      { "a.mjs": SAMPLE, "b.mjs": `export const x = "y";` },
      {
        profile: "balanced",
        seed: 1,
        budget: NO_BUDGET,
      },
    );
    expect(result.files.length).toBe(2);
    expect(result.transform.mangled).toBeGreaterThan(0);
    expect(result.transform.strings_encrypted).toBeGreaterThan(0);
  });
});
