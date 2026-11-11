// Slice 07 — Canary planting and the bundle pipeline (leak scan → transforms → plant → budget gate).
// Review focus 2 (the scan catches what string encryption hides; a planted Canary is never reported) and 3
// (determinism, behaviour, no global, budget never silently exceeded).
import { runInNewContext } from "node:vm";
import { gzipSync } from "node:zlib";
import { CANARY_VALUE_PATTERNS, EXAMPLE_CANARIES } from "@antireverse/protocol";
import { deriveCanaries } from "@antireverse/protocol/server";
import { afterAll, describe, expect, it, vi } from "vitest";

// Spy on the scanner so a test can prove it only ever sees the INPUT (amendment A3).
vi.mock("../src/leaks/scan.ts", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/leaks/scan.ts")>();
  return { ...original, scanLeaks: vi.fn(original.scanLeaks) };
});

import { canaryStatement, plantCanaries } from "../src/canaries.ts";
import { DEFAULT_BUDGET, harden, hardenBundle } from "../src/engine.ts";
import { scanLeaks } from "../src/leaks/scan.ts";
import { cleanupModules, importModule } from "./helpers.ts";

afterAll(cleanupModules);

const AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE";
const NO_BUDGET = { sizePct: 1_000_000, runPct: 1_000_000 };

// A module big enough that the planted statement fits in the default size budget.
const MODULE = `
const TIERS = { free: 0, pro: 1900, business: 4900, "enterprise-eu": 9900, team: 2900, startup: 1500 };
export function priceOf(tier) {
  const cents = TIERS[tier];
  if (cents === undefined) throw new Error("unknown tier: " + tier);
  return cents;
}
export function label(tier) {
  return "the " + tier + " plan costs " + priceOf(tier) + " cents per seat each month, billed yearly";
}
export function discounted(cents, pct) {
  const factor = 1 - pct / 100;
  return Math.round(cents * factor);
}
export function format(cents) {
  const euros = (cents / 100).toFixed(2);
  return "€" + euros;
}
export function quote(tier, pct = 0) {
  return format(discounted(priceOf(tier), pct)) + " / " + label(tier);
}
export function table() {
  return Object.keys(TIERS).map((tier) => [tier, quote(tier, 10)]);
}
`;

const SEEDS = [0, 1, 2, 3, 7, 13, 42, 99, 1263, 1091];

function gzipLen(s: string): number {
  return gzipSync(Buffer.from(s, "utf8")).length;
}

describe("canaryStatement / plantCanaries", () => {
  it("is one behaviour-neutral expression statement carrying the key and both routes", () => {
    const stmt = canaryStatement(EXAMPLE_CANARIES);
    const [key, r1, r2] = EXAMPLE_CANARIES;
    expect(stmt).toBe(`void {apiKey:"${key?.value}",internalApi:"${r1?.value}",exportUrl:"${r2?.value}"};`);
  });

  it("plants into the first protected file in sorted path order, never a skipped one", () => {
    const files = [
      { path: "z.js", code: "z();", skipped: false },
      { path: "a.js", code: "a();", skipped: true },
      { path: "m.js", code: "m();", skipped: false },
    ];
    const { files: out, plantedIn } = plantCanaries(files, EXAMPLE_CANARIES);
    expect(plantedIn).toBe("m.js");
    expect(out.find((f) => f.path === "a.js")?.code).toBe("a();");
    expect(out.find((f) => f.path === "z.js")?.code).toBe("z();");
    expect(out.find((f) => f.path === "m.js")?.code).toBe(`m();\n${canaryStatement(EXAMPLE_CANARIES)}\n`);
  });

  it("tries the next protected file when the first would go over the size budget", () => {
    const big = `export const rows = [${Array.from({ length: 200 }, (_, i) => `{ id: ${i}, name: "row ${i}" }`).join(", ")}];\n`;
    const files = [
      { path: "a.js", code: "a();", skipped: false },
      { path: "b.js", code: big, skipped: false },
    ];
    const { plantedIn } = plantCanaries(files, EXAMPLE_CANARIES, {
      originals: { "a.js": "a();", "b.js": big },
      sizePct: DEFAULT_BUDGET.sizePct,
    });
    expect(plantedIn).toBe("b.js");
  });

  it("fails with a clear message (never drops Canaries silently) when no protected file fits", () => {
    const files = [{ path: "a.js", code: "a();", skipped: false }];
    expect(() =>
      plantCanaries(files, EXAMPLE_CANARIES, { originals: { "a.js": "a();" }, sizePct: DEFAULT_BUDGET.sizePct }),
    ).toThrow(/Canar.*budget|budget.*Canar/i);
    expect(() => plantCanaries([{ path: "a.js", code: "a();", skipped: true }], EXAMPLE_CANARIES)).toThrow(
      /no protected/i,
    );
  });
});

describe("Canaries are never reported by the leak scan (A3)", () => {
  it("decoy values never match a provider rule, across many seeds", () => {
    for (let seed = 0; seed < 500; seed++) {
      const canaries = deriveCanaries(seed);
      const text = canaries.map((c) => `x("${c.value}");`).join("\n");
      const { findings } = scanLeaks([{ path: "c.js", text }], ["c.js"], { version: 1, allow: [] });
      expect(findings, `seed ${seed}`).toEqual([]);
    }
  });

  it("the planted statement itself matches secret-assignment, so the scan must only ever see the input", () => {
    const { findings } = scanLeaks([{ path: "c.js", text: canaryStatement(EXAMPLE_CANARIES) }], ["c.js"], {
      version: 1,
      allow: [],
    });
    expect(findings.map((f) => f.rule)).toEqual(["secret-assignment"]);
  });

  it("hardenBundle scans the input only, never the planted output", () => {
    const spy = vi.mocked(scanLeaks);
    spy.mockClear();
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 5 });
    expect(result.leakScan.status).toBe("clean");
    expect(result.plantedIn).toBe("m.mjs");
    expect(spy).toHaveBeenCalledTimes(1);
    const scanned = spy.mock.calls[0]?.[0] ?? [];
    expect(scanned.map((f) => f.text)).toEqual([MODULE]);
    for (const c of result.canaries) expect(JSON.stringify(spy.mock.calls)).not.toContain(c.value);
  });
});

describe("hardenBundle — leak scan before transforms", () => {
  it("catches a secret inside a string literal that balanced would encrypt", () => {
    const source = `export function client() { return { region: "eu-west-1", id: "${AWS_EXAMPLE}" }; }\n${MODULE}`;
    // Proof that an output-only scan would miss it: balanced encrypts the literal away.
    const plain = harden({ "k.mjs": source }, { profile: "balanced", seed: 1, budget: NO_BUDGET });
    expect(plain.files[0]?.stringsEncrypted).toBeGreaterThan(0);
    expect(plain.files[0]?.code).not.toContain(AWS_EXAMPLE);

    const result = hardenBundle({ sources: { "k.mjs": source } }, { profile: "balanced", seed: 1, budget: NO_BUDGET });
    expect(result.leakScan.status).toBe("failed");
    expect(result.leakScan.findings.map((f) => f.rule)).toEqual(["aws-access-key"]);
    // Nothing is transformed or planted on failure, and the value is nowhere in the result.
    expect(result.files).toEqual([]);
    expect(result.canaries).toEqual([]);
    expect(result.plantedIn).toBeNull();
    expect(JSON.stringify(result)).not.toContain(AWS_EXAMPLE);
  });

  it("scans the extra (non-JS) text files and the file names of the bundle", () => {
    const result = hardenBundle(
      {
        sources: { "m.mjs": MODULE },
        extraFiles: [{ path: "config.json", text: `{ "url": "http://10.0.0.7/admin" }` }],
        fileNames: ["m.mjs", "config.json", "m.mjs.map"],
      },
      { profile: "balanced", seed: 1 },
    );
    expect(result.leakScan.status).toBe("failed");
    expect(result.leakScan.findings.map((f) => `${f.rule}:${f.path}`).sort()).toEqual([
      "internal-url:config.json",
      "source-map:m.mjs.map",
    ]);
  });

  it("an allowlisted finding passes as 'suppressed' and the Build is hardened and planted", async () => {
    const { leakFingerprint } = await import("@antireverse/protocol/server");
    const source = `export const k = "${AWS_EXAMPLE}";\n${MODULE}`;
    const result = hardenBundle(
      { sources: { "k.mjs": source } },
      {
        profile: "balanced",
        seed: 1,
        allow: {
          version: 1,
          allow: [{ fingerprint: leakFingerprint("aws-access-key", "k.mjs", AWS_EXAMPLE), reason: "example" }],
        },
      },
    );
    expect(result.leakScan).toEqual({ status: "suppressed", findings: [], suppressed: 1 });
    expect(result.plantedIn).toBe("k.mjs");
  });
});

describe("review fixes L1/M3", () => {
  const DECL = "export declare function priceOf(tier: string): number;\nexport declare const VERSION: string;\n";

  it("L1: a .d.ts file is never transformed nor planted into", () => {
    const result = hardenBundle(
      { sources: { "a.d.ts": DECL, "b.mjs": MODULE, "types/c.d.mts": DECL, "types/d.d.cts": DECL } },
      { profile: "balanced", seed: 1 },
    );
    expect(result.plantedIn).toBe("b.mjs");
    for (const path of ["a.d.ts", "types/c.d.mts", "types/d.d.cts"]) {
      const file = result.files.find((f) => f.path === path);
      expect(file?.code).toBe(DECL);
      expect(file?.skipped).toBe(true);
    }
  });

  it("L1: plantCanaries refuses a declaration file even when it is not marked skipped", () => {
    expect(() => plantCanaries([{ path: "a.d.ts", code: DECL, skipped: false }], EXAMPLE_CANARIES)).toThrow(
      /no protected/i,
    );
    const { plantedIn } = plantCanaries(
      [
        { path: "a.d.ts", code: DECL, skipped: false },
        { path: "b.ts", code: "export const b = 1;\n", skipped: false },
      ],
      EXAMPLE_CANARIES,
    );
    expect(plantedIn).toBe("b.ts");
  });

  it("M3: canaryScope derives v2 Canaries; same inputs reproduce, another version differs", () => {
    const scope = { appId: "app_0123456789abcdef01234567", version: "1.0.0" };
    const one = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 1, canaryScope: scope });
    const again = hardenBundle(
      { sources: { "m.mjs": MODULE } },
      { profile: "balanced", seed: 1, canaryScope: { ...scope } },
    );
    const next = hardenBundle(
      { sources: { "m.mjs": MODULE } },
      { profile: "balanced", seed: 1, canaryScope: { ...scope, version: "1.0.1" } },
    );
    expect(one.canaries).toEqual(deriveCanaries(1, scope));
    expect(again.files).toEqual(one.files);
    expect(next.canaries.map((c) => c.id)).not.toEqual(one.canaries.map((c) => c.id));
    expect(one.files[0]?.code).toContain(canaryStatement(deriveCanaries(1, scope)));
  });
});

describe("hardenBundle — planting, determinism and behaviour", () => {
  it("plants the seed's Canaries (seed normalised with >>> 0, A1)", () => {
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 1 });
    expect(result.canaries).toEqual(deriveCanaries(1));
    const planted = result.files.find((f) => f.path === "m.mjs")?.code ?? "";
    expect(planted.endsWith(`${canaryStatement(deriveCanaries(1))}\n`)).toBe(true);
    for (const c of result.canaries) expect(c.value).toMatch(CANARY_VALUE_PATTERNS[c.kind]);

    const neg = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: -5 });
    const pos = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 4294967291 });
    expect(neg.canaries).toEqual(deriveCanaries(4294967291));
    expect(neg.files).toEqual(pos.files);
  });

  it("same input and seed give byte-identical output including Canaries; seeds differ", () => {
    const input = { sources: { "a.mjs": MODULE, "b.mjs": MODULE.replace("TIERS", "PLANS") } };
    const one = hardenBundle(input, { profile: "balanced", seed: 77 });
    const two = hardenBundle(input, { profile: "balanced", seed: 77 });
    expect(one.files.map((f) => f.code)).toEqual(two.files.map((f) => f.code));
    expect(one.canaries).toEqual(two.canaries);
    const other = hardenBundle(input, { profile: "balanced", seed: 78 });
    expect(other.canaries).not.toEqual(one.canaries);
  });

  it.each(SEEDS)("behaviour is unchanged with Canaries planted (seed %i)", async (seed) => {
    const original = await importModule(MODULE);
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed });
    expect(result.plantedIn).toBe("m.mjs");
    const code = result.files[0]?.code ?? "";
    expect(code).toContain(result.canaries[0]?.value ?? "missing");
    const mod = await importModule(code);
    expect((mod.table as () => unknown)()).toEqual((original.table as () => unknown)());
    expect((mod.quote as (t: string, p: number) => string)("pro", 25)).toBe(
      (original.quote as (t: string, p: number) => string)("pro", 25),
    );
  });

  it("creates no global: a script runs in a fresh context with the same globals as without Canaries", () => {
    const script = `(function () { var total = 0; for (var i = 0; i < 10; i++) total += i; result.value = total; })();\n${MODULE.replace(/export /g, "")}`;
    const run = (code: string) => {
      const context: Record<string, unknown> = { result: {} };
      const before = Object.getOwnPropertyNames(runInNewContext("globalThis", context)).sort();
      runInNewContext(code, context);
      const after = Object.getOwnPropertyNames(runInNewContext("globalThis", context)).sort();
      return { before, after, result: context.result };
    };
    const unplanted = harden({ "s.js": script }, { profile: "balanced", seed: 3 }).files[0]?.code ?? "";
    const planted = hardenBundle({ sources: { "s.js": script } }, { profile: "balanced", seed: 3 });
    expect(planted.plantedIn).toBe("s.js");
    const a = run(unplanted);
    const b = run(planted.files[0]?.code ?? "");
    expect(b.after).toEqual(a.after);
    expect(b.result).toEqual(a.result);
  });

  it("creates no global for an ES module either", async () => {
    const before = Object.getOwnPropertyNames(globalThis).sort();
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 9 });
    await importModule(result.files[0]?.code ?? "");
    expect(Object.getOwnPropertyNames(globalThis).sort()).toEqual(before);
  });

  it("budget gate counts the planted statement: the planted file stays within budget", () => {
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 1 });
    const planted = result.files.find((f) => f.path === result.plantedIn);
    if (!planted) throw new Error("not planted");
    const overhead = ((gzipLen(planted.code) - gzipLen(MODULE)) / gzipLen(MODULE)) * 100;
    expect(overhead).toBeLessThanOrEqual(DEFAULT_BUDGET.sizePct);
  });

  it("fails clearly when no protected file can hold the Canaries within budget", () => {
    const result = hardenBundle(
      { sources: { "t.mjs": "export const q = (n) => n;\n" } },
      { profile: "light", seed: 1 },
    );
    expect(result.plantedIn).toBeNull();
    expect(result.plantError).toMatch(/Canar/);
  });

  it("never plants into a skipped file", () => {
    const result = hardenBundle(
      { sources: { "a.mjs": MODULE, "b.mjs": MODULE } },
      { profile: "balanced", seed: 1, protectionMap: { "a.mjs": "skip" } },
    );
    expect(result.plantedIn).toBe("b.mjs");
    expect(result.files.find((f) => f.path === "a.mjs")?.code).toBe(MODULE);
  });
});
