import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { generateCode, parseSource } from "../src/babel.ts";
import { createManglePass } from "../src/passes/mangle.ts";
import { mulberry32 } from "../src/rng.ts";
import { cleanupModules, importModule } from "./helpers.ts";

afterAll(cleanupModules);

/** Runs the mangle pass alone over `code` and returns the generated output plus the rename count. */
function mangle(code: string, seed = 1, path = "m.mjs"): { code: string; count: number } {
  const ast = parseSource(code, path);
  const pass = createManglePass();
  const { count } = pass.run(ast, { rng: mulberry32(seed), seed, types: undefined as never });
  return { code: generateCode(ast), count };
}

describe("mangle pass", () => {
  it("renames local bindings but preserves behaviour", async () => {
    const src = `
      export function add(first, second) {
        const sum = first + second;
        return sum;
      }
    `;
    const { code, count } = mangle(src);
    expect(count).toBeGreaterThan(0);
    expect(code).not.toContain("first");
    expect(code).not.toContain("second");
    expect(code).not.toContain("sum");
    // The public export name survives.
    expect(code).toContain("add");
    const mod = await importModule(code);
    expect((mod.add as (a: number, b: number) => number)(2, 3)).toBe(5);
  });

  it("never renames imports, exports, globals, or property keys", () => {
    const src = `
      import { readFileSync } from "node:fs";
      const box = { free: 1, "enterprise-eu": 2 };
      export function sizeOf(path) {
        const data = readFileSync(path);
        return Math.max(data.length, box.free);
      }
    `;
    const { code } = mangle(src);
    // import binding and its source untouched
    expect(code).toContain("readFileSync");
    expect(code).toContain('"node:fs"');
    // global untouched
    expect(code).toContain("Math.max");
    // property keys untouched
    expect(code).toContain("free");
    expect(code).toContain("enterprise-eu");
    // exported name untouched
    expect(code).toContain("sizeOf");
  });

  it("is deterministic for one seed and differs between seeds", () => {
    const src = `function outer(a){ const b = a*2; function inner(c){ return b + c; } return inner; }`;
    expect(mangle(src, 7).code).toBe(mangle(src, 7).code);
    expect(mangle(src, 7).code).not.toBe(mangle(src, 8).code);
  });

  it("preserves this, getters/setters and string-keyed objects", async () => {
    const src = `
      export function makeCounter(start) {
        const state = { _n: start };
        return {
          get value() { return state._n; },
          set value(v) { state._n = v; },
          inc() { this.value = this.value + 1; return this.value; },
        };
      }
    `;
    const { code } = mangle(src);
    const mod = await importModule(code);
    const c = (mod.makeCounter as (n: number) => { value: number; inc: () => number })(10);
    expect(c.value).toBe(10);
    expect(c.inc()).toBe(11);
    c.value = 20;
    expect(c.value).toBe(20);
  });

  it("handles the reference bundle module (TypeScript, imports, exports, global)", () => {
    const here = fileURLToPath(new URL("../../../apps/range/web/src/pricing.ts", import.meta.url));
    const src = readFileSync(here, "utf8");
    const { code, count } = mangle(src, 1, "pricing.ts");
    expect(count).toBeGreaterThan(0);
    // exported names preserved
    expect(code).toContain("priceOf");
    expect(code).toContain("format");
    expect(code).toContain("discounted");
    // global preserved
    expect(code).toContain("Math.round");
    // object keys preserved
    expect(code).toContain("enterprise-eu");
    // the private binding TIERS is renamed away
    expect(code).not.toContain("TIERS");
  });
});
