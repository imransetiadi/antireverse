// Slice 21a — the integrity marker: one planted statement that pushes `{ b: <Build id>, f: [<artifact paths>] }`
// under `globalThis[Symbol.for("ar.build")]`. Identifiers only, never a hash. It is planted in the Canary planting
// step, never fails a build, and degrades (fewer files, then none) when it does not fit the size budget.
import { createHash } from "node:crypto";
import { runInNewContext } from "node:vm";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { plantCanaries } from "../src/canaries.ts";
import { hardenBundle } from "../src/engine.ts";
import { MARKER_KEY, markerFiles, markerStatement } from "../src/marker.ts";
import { beaconHostModule } from "./helpers.ts";

const BUILD = "bld_0123456789abcdef01234567";
const MODULE = beaconHostModule();

/**
 * Runs planted text in a fresh context with no globals of its own and returns what then sits under the marker key.
 * Read from inside the context: node:vm does not mirror a symbol-keyed global onto the sandbox object. `before`
 * runs first, in the same context.
 */
function pushed(code: string, before = ""): unknown {
  return runInNewContext(`${before}\n${code}\n;globalThis[Symbol.for(${JSON.stringify(MARKER_KEY)})]`, {});
}

/** Incompressible module text of roughly `bytes` bytes. */
function filler(name: string, bytes: number): string {
  let text = "";
  for (let i = 0; text.length < bytes; i++) text += createHash("sha256").update(`${name}-${i}`).digest("hex");
  return `export const ${name} = ${JSON.stringify(text)};\n`;
}

describe("markerStatement", () => {
  it("pushes exactly { b, f } under globalThis[Symbol.for('ar.build')] in a context with no globals", () => {
    expect(MARKER_KEY).toBe("ar.build");
    const statement = markerStatement(BUILD, ["src/a.js", "src/b.js"]);
    const value = pushed(statement) as unknown[];
    expect(JSON.parse(JSON.stringify(value))).toEqual([{ b: BUILD, f: ["src/a.js", "src/b.js"] }]);
    expect(Object.keys(value[0] as object)).toEqual(["b", "f"]);
  });

  it("is one line: a statement in try/catch that binds no global and carries no hash", () => {
    const statement = markerStatement(BUILD, ["src/a.js"]);
    expect(statement).toMatch(/^;\(function\(\)\{try\{.*\}catch\(e\)\{\}\}\)\(\);$/);
    expect(statement).not.toContain("\n");
    expect(statement).not.toMatch(/[0-9a-f]{64}/);
    const sandbox: Record<string, unknown> = {};
    runInNewContext(statement, sandbox);
    expect(Object.keys(sandbox)).toEqual([]);
  });

  it("appends to an array another Build's marker left; two bundles on one page both show", () => {
    const first = markerStatement(BUILD, ["a.js"]);
    const second = markerStatement("bld_89abcdef0123456789abcdef", ["b.js"]);
    const value = pushed(`${first}\n${second}`);
    expect(JSON.parse(JSON.stringify(value))).toEqual([
      { b: BUILD, f: ["a.js"] },
      { b: "bld_89abcdef0123456789abcdef", f: ["b.js"] },
    ]);
  });

  it("never throws: a hostile value under the key, or no Symbol at all, is swallowed", () => {
    const statement = markerStatement(BUILD, ["a.js"]);
    expect(pushed(statement, 'globalThis[Symbol.for("ar.build")] = 7;')).toBe(7);
    expect(pushed(statement, 'globalThis[Symbol.for("ar.build")] = Object.freeze([]);')).toEqual([]);
    expect(() => runInNewContext(`var Symbol=undefined;${statement}`, {})).not.toThrow();
    expect(() => runInNewContext(`"use strict";${statement}`, {})).not.toThrow();
  });

  it("embeds every path as an HTML-safe literal that round-trips", () => {
    const paths = ["a</script><b>&.js", "ü/ñ – 日本.js", 'q"uo\\te.js', "line\u2028sep\u2029.js", "<!--.js"];
    const statement = markerStatement(BUILD, paths);
    expect(statement).not.toMatch(/[<>&\u2028\u2029]/);
    expect((pushed(statement) as { f: string[] }[])[0]?.f).toEqual(paths);
  });

  it("refuses a Build id that is not one, more than 32 files, a duplicate and an empty path", () => {
    expect(() => markerStatement("bld_nope", ["a.js"])).toThrow(/Build id/);
    expect(() => markerStatement(BUILD, [])).toThrow(/1 to 32/);
    expect(() =>
      markerStatement(
        BUILD,
        Array.from({ length: 33 }, (_, i) => `f${i}.js`),
      ),
    ).toThrow(/1 to 32/);
    expect(() => markerStatement(BUILD, ["a.js", "a.js"])).toThrow(/twice/);
    expect(() => markerStatement(BUILD, [""])).toThrow(/path/);
  });
});

describe("markerFiles", () => {
  it("lists the planted file first, then the largest files, ties by path", () => {
    const files = [
      { path: "z.js", bytes: 10 },
      { path: "planted.js", bytes: 1 },
      { path: "b.js", bytes: 500 },
      { path: "a.js", bytes: 500 },
      { path: "c.js", bytes: 9000 },
    ];
    expect(markerFiles("planted.js", files)).toEqual(["planted.js", "c.js", "a.js", "b.js", "z.js"]);
  });

  it("lists at most 32", () => {
    const files = Array.from({ length: 50 }, (_, i) => ({ path: `f${String(i).padStart(2, "0")}.js`, bytes: i }));
    const listed = markerFiles("f00.js", files);
    expect(listed).toHaveLength(32);
    expect(listed[0]).toBe("f00.js");
    expect(listed[1]).toBe("f49.js");
    expect(listed[31]).toBe("f19.js");
  });
});

describe("planting the marker (hardenBundle)", () => {
  const options = { profile: "light", seed: 7 } as const;

  it("plants no marker unless asked", () => {
    const result = hardenBundle({ sources: { "a.mjs": MODULE } }, options);
    expect(result.integrity).toBeNull();
    expect(result.files[0]?.code).not.toContain("ar.build");
  });

  it("plants it in the Canaries' file, after them, listing that file first and then the largest protected files", () => {
    const sources = {
      "a.mjs": MODULE,
      "big.mjs": filler("big", 6000),
      "mid.mjs": filler("mid", 3000),
      "types.d.ts": "export declare const x: number;\n",
      "skip.mjs": filler("skipped", 9000),
    };
    const result = hardenBundle(
      { sources },
      { ...options, protectionMap: { "skip.mjs": "skip" }, integrityMarker: { buildId: BUILD } },
    );
    expect(result.plantError).toBeUndefined();
    expect(result.plantedIn).toBe("a.mjs");
    // Protected JavaScript only: neither the skipped file nor the declaration file.
    expect(result.integrity).toEqual({ files: ["a.mjs", "big.mjs", "mid.mjs"], eligible: 3 });
    const planted = result.files.find((f) => f.path === "a.mjs")?.code ?? "";
    const lines = planted.trimEnd().split("\n");
    expect(lines.at(-1)).toBe(markerStatement(BUILD, ["a.mjs", "big.mjs", "mid.mjs"]));
    expect(lines.at(-2)).toMatch(/^void \{apiKey:/);
    for (const other of result.files.filter((f) => f.path !== "a.mjs")) expect(other.code).not.toContain("ar.build");
    expect((pushed(lines.at(-1) ?? "") as unknown[])[0]).toEqual({ b: BUILD, f: ["a.mjs", "big.mjs", "mid.mjs"] });
  });

  it("is deterministic and leaves every other byte as without the marker", () => {
    const sources = { "a.mjs": MODULE, "b.mjs": filler("b", 2000) };
    const plain = hardenBundle({ sources }, options);
    const marked = hardenBundle({ sources }, { ...options, integrityMarker: { buildId: BUILD } });
    const again = hardenBundle({ sources }, { ...options, integrityMarker: { buildId: BUILD } });
    expect(marked.files).toEqual(again.files);
    expect(marked.plantedIn).toBe(plain.plantedIn);
    const a = marked.files.find((f) => f.path === "a.mjs")?.code ?? "";
    const base = plain.files.find((f) => f.path === "a.mjs")?.code ?? "";
    expect(a.startsWith(base)).toBe(true);
    expect(a.slice(base.length)).toBe(`${markerStatement(BUILD, ["a.mjs", "b.mjs"])}\n`);
    expect(marked.files.find((f) => f.path === "b.mjs")).toEqual(plain.files.find((f) => f.path === "b.mjs"));
    expect(marked.transform).toEqual(plain.transform);
    expect(marked.transform.integrity).toBe(false);
  });

  it("lists at most 32 files of a larger bundle", () => {
    const sources: Record<string, string> = { "a.mjs": MODULE + filler("pad", 40_000) };
    for (let i = 0; i < 40; i++) sources[`m${String(i).padStart(2, "0")}.mjs`] = filler(`m${i}`, 200 + i * 64);
    const result = hardenBundle({ sources }, { ...options, integrityMarker: { buildId: BUILD } });
    expect(result.integrity?.eligible).toBe(41);
    expect(result.integrity?.files).toHaveLength(32);
    expect(result.integrity?.files[0]).toBe("a.mjs");
    expect(result.integrity?.files[1]).toBe("m39.mjs");
  });

  it("degrades to fewer files when the full marker does not fit the size budget, and still plants", () => {
    // Long incompressible paths make each listed file cost gzip bytes; the host has room for only some.
    const sources: Record<string, string> = { "a.mjs": MODULE };
    for (let i = 0; i < 31; i++) {
      const name = createHash("sha256").update(`p${i}`).digest("hex");
      sources[`${name}/${name.split("").reverse().join("")}.mjs`] = filler(`f${i}`, 300 + i);
    }
    const plain = hardenBundle({ sources }, options);
    const result = hardenBundle({ sources }, { ...options, integrityMarker: { buildId: BUILD } });
    expect(result.plantError).toBeUndefined();
    expect(result.plantedIn).toBe(plain.plantedIn);
    const listed = result.integrity?.files ?? [];
    expect(result.integrity?.eligible).toBe(32);
    expect(listed.length).toBeGreaterThan(0);
    expect(listed.length).toBeLessThan(32);
    expect(listed[0]).toBe("a.mjs");
    // What was planted is exactly what is reported, and it is within the budget; one more file would not be.
    const code = result.files.find((f) => f.path === "a.mjs")?.code ?? "";
    expect(code.trimEnd().split("\n").at(-1)).toBe(markerStatement(BUILD, listed));
    const before = gzipSync(Buffer.from(MODULE)).length;
    expect(((gzipSync(Buffer.from(code)).length - before) / before) * 100).toBeLessThanOrEqual(35);
  });

  it("plants no marker at all when even one file does not fit: the build still succeeds and says so", () => {
    // A host that holds the Canaries with almost nothing to spare.
    const sources = { "a.mjs": MODULE };
    const budget = { sizePct: 9, runPct: 15 };
    const plain = hardenBundle({ sources }, { ...options, budget });
    expect(plain.plantError).toBeUndefined();
    const result = hardenBundle({ sources }, { ...options, budget, integrityMarker: { buildId: BUILD } });
    expect(result.plantError).toBeUndefined();
    expect(result.integrity).toEqual({ files: [], eligible: 1 });
    expect(result.files).toEqual(plain.files);
  });

  it("an invalid Build id is refused loudly, before anything is planted: it never costs the Canaries", () => {
    for (const buildId of ["bld_nope", "", "app_0123456789abcdef01234567"]) {
      expect(() =>
        hardenBundle({ sources: { "a.mjs": MODULE } }, { ...options, integrityMarker: { buildId } }),
      ).toThrow(/integrityMarker\.buildId must be a Build id/);
    }
    const files = [{ path: "a.mjs", code: MODULE, skipped: false }];
    const canaries = hardenBundle({ sources: { "a.mjs": MODULE } }, options).canaries;
    expect(() => plantCanaries(files, canaries, undefined, undefined, { buildId: "bld_nope" })).toThrow(
      /integrityMarker\.buildId must be a Build id/,
    );
  });

  it("a build whose Canaries fit no file fails as before, marker or not", () => {
    const result = hardenBundle(
      { sources: { "a.mjs": "export const a = 1;\n" } },
      { ...options, integrityMarker: { buildId: BUILD } },
    );
    expect(result.plantError).toMatch(/cannot plant Canaries/);
    expect(result.integrity).toBeNull();
  });
});
