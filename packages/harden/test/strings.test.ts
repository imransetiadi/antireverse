import { afterAll, describe, expect, it } from "vitest";
import { generateCode, parseSource } from "../src/babel.ts";
import { createStringsPass } from "../src/passes/strings.ts";
import { mulberry32 } from "../src/rng.ts";
import { cleanupModules, importModule } from "./helpers.ts";

afterAll(cleanupModules);

/** Runs the strings pass alone over `code`. Names stay stable because mangle does not run. */
function strings(code: string, seed = 1, path = "s.mjs"): { code: string; count: number } {
  const ast = parseSource(code, path);
  const pass = createStringsPass();
  const { count } = pass.run(ast, { rng: mulberry32(seed), seed, types: undefined as never });
  return { code: generateCode(ast), count };
}

describe("strings pass", () => {
  it("encrypts plain string literals and preserves behaviour", async () => {
    const src = `export const greeting = "hello world"; export const other = "second value";`;
    const { code, count } = strings(src);
    expect(count).toBe(2);
    expect(code).not.toContain('"hello world"');
    expect(code).not.toContain('"second value"');
    const mod = await importModule(code);
    expect(mod.greeting).toBe("hello world");
    expect(mod.other).toBe("second value");
  });

  it("binds the decoded value to a local — no per-access decode call", () => {
    const src = `
      export function hot(parts) {
        let acc = parts;
        for (let i = 0; i < 3; i++) acc = acc + "TOKEN";
        return acc;
      }
    `;
    const { code } = strings(src);
    // "TOKEN" is one unique string: it is decoded exactly once, not on every loop iteration.
    const decodeCalls = code.match(/__ar_d\(/g) ?? [];
    expect(decodeCalls.length).toBe(1);
    // The use site inside the loop is a bare identifier reference (declaration + use = 2+ occurrences).
    const refs = code.match(/__ar_s0/g) ?? [];
    expect(refs.length).toBeGreaterThanOrEqual(2);
    expect(code).toMatch(/acc \+ __ar_s0/);
  });

  it("leaves template literals, import/export sources and plain keys untouched", async () => {
    const src = `
      import { readFileSync } from "node:fs";
      export const t = (name) => \`hi \${name}\`;
      export const obj = { plainKey: "encrypted value", "quoted-key": 1 };
      export const readIt = readFileSync;
    `;
    const { code } = strings(src);
    expect(code).toContain('"node:fs"'); // import source untouched
    expect(code).toContain("`hi ${"); // template literal untouched
    expect(code).toContain("plainKey"); // identifier key untouched
    expect(code).toContain("quoted-key"); // quoted non-computed key untouched
    expect(code).not.toContain('"encrypted value"'); // the value IS encrypted
    const mod = await importModule(code);
    expect((mod.t as (n: string) => string)("x")).toBe("hi x");
    expect((mod.obj as Record<string, unknown>).plainKey).toBe("encrypted value");
    expect((mod.obj as Record<string, unknown>)["quoted-key"]).toBe(1);
  });

  it("preserves non-ASCII strings and escapes", async () => {
    const src = `export const euro = "€19.00"; export const tab = "a\\tb\\n\\"c\\""; export const emoji = "🚀 go";`;
    const { code } = strings(src);
    const mod = await importModule(code);
    expect(mod.euro).toBe("€19.00");
    expect(mod.tab).toBe('a\tb\n"c"');
    expect(mod.emoji).toBe("🚀 go");
  });

  it("encrypts computed member keys and string values but not the access pattern", async () => {
    const src = `export function get(o) { return o["enterprise-eu"]; }`;
    const { code } = strings(src);
    expect(code).not.toContain('"enterprise-eu"');
    const mod = await importModule(code);
    expect((mod.get as (o: Record<string, number>) => number)({ "enterprise-eu": 9900 })).toBe(9900);
  });

  it("is deterministic for one seed and differs between seeds (same behaviour)", async () => {
    const src = `export const a = "alpha"; export const b = "beta";`;
    expect(strings(src, 4).code).toBe(strings(src, 4).code);
    expect(strings(src, 4).code).not.toBe(strings(src, 5).code);
    const m4 = await importModule(strings(src, 4).code);
    const m5 = await importModule(strings(src, 5).code);
    expect(m4.a).toBe(m5.a);
    expect(m4.b).toBe(m5.b);
  });
});
