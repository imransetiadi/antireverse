// Slice 10 — the Clone Beacon statement and its planting beside the Canaries (plan Task 2, Review Focus 1 and 5).
// The statement is executed in `vm` contexts with stubbed `location` / `navigator`: no traffic on allowed or
// local origins, exactly one report elsewhere, never a throw, inert outside a browser. Its client-side local
// check is pinned against the protocol's `isLocalOrigin` over a corpus of browser-produced origins.
import { createContext, runInNewContext, Script } from "node:vm";
import { gzipSync } from "node:zlib";
import { BEACON_LIMITS, canonicalOrigin, EXAMPLE_CANARIES, isLocalOrigin } from "@antireverse/protocol";
import { deriveBeaconToken, deriveCanaries } from "@antireverse/protocol/server";
import { afterAll, describe, expect, it } from "vitest";
import { beaconEndpointUrl, beaconStatement } from "../src/beacon.ts";
import { canaryStatement, plantCanaries } from "../src/canaries.ts";
import { DEFAULT_BUDGET, harden, hardenBundle } from "../src/engine.ts";
import { beaconHostModule, cleanupModules, importModule } from "./helpers.ts";

afterAll(cleanupModules);

const APP = "app_0123456789abcdef01234567";
const TOKEN = deriveBeaconToken(1, { appId: APP, version: "1.0.0" });
const ORIGINS = ["https://shop.example.com", "https://www.shop.example.com:8443"];
const ENDPOINT = "https://api.antireverse.example";
const URL_ = "https://api.antireverse.example/v1/beacon";
const BEACON = { appId: APP, token: TOKEN, origins: ORIGINS, endpoint: ENDPOINT };

interface Run {
  calls: Array<[unknown, unknown]>;
  threw: unknown;
}

/** Runs `code` in a fresh context with the given globals; sendBeacon (when `send` is true) records its calls. */
function runIn(code: string, origin: unknown, opts: { send?: boolean } = {}): Run {
  const calls: Array<[unknown, unknown]> = [];
  const context: Record<string, unknown> = {
    location: { origin },
    navigator: {
      sendBeacon:
        opts.send === false
          ? undefined
          : (url: unknown, body: unknown) => {
              calls.push([url, body]);
              return true;
            },
    },
  };
  let threw: unknown;
  try {
    runInNewContext(code, context);
  } catch (error) {
    threw = error;
  }
  return { calls, threw };
}

describe("beaconStatement — shape and inputs", () => {
  it("is deterministic and embeds the token, origins and report URL as JSON string literals", () => {
    const one = beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT);
    expect(beaconStatement(APP, TOKEN, [...ORIGINS], ENDPOINT)).toBe(one);
    expect(one.startsWith(";(function(){try{")).toBe(true);
    expect(one.endsWith("}catch(e){}})();")).toBe(true);
    expect(one).toContain(JSON.stringify(TOKEN));
    expect(one).toContain(JSON.stringify(URL_));
    for (const o of ORIGINS) expect(one).toContain(o);
    expect(one).not.toContain("\n");
    // No timers, listeners or other side channel; the only network call is sendBeacon.
    for (const banned of ["setTimeout", "setInterval", "addEventListener", "fetch", "XMLHttpRequest", "document"]) {
      expect(one).not.toContain(banned);
    }
  });

  it("the report URL is the endpoint with any trailing slash removed, plus /v1/beacon", () => {
    expect(beaconEndpointUrl("https://api.example.com")).toBe("https://api.example.com/v1/beacon");
    expect(beaconEndpointUrl("https://api.example.com///")).toBe("https://api.example.com/v1/beacon");
    expect(beaconEndpointUrl("http://127.0.0.1:39991/")).toBe("http://127.0.0.1:39991/v1/beacon");
    expect(beaconEndpointUrl("https://example.com/ar/")).toBe("https://example.com/ar/v1/beacon");
  });

  it.each([
    "ftp://api.example.com",
    "javascript:alert(1)",
    "api.example.com",
    "",
    "https://user:pass@api.example.com",
    "https://api.example.com/?q=1",
    "https://api.example.com/#x",
    "https://api.example.com/a b",
    "https://api.example.com/ ",
  ])("refuses an endpoint that is not a plain http(s) URL: %j", (endpoint) => {
    expect(() => beaconEndpointUrl(endpoint)).toThrow(/endpoint/);
    expect(() => beaconStatement(APP, TOKEN, ORIGINS, endpoint)).toThrow(/endpoint/);
  });

  it("refuses a bad token, a non-canonical, local or duplicate origin, none or too many", () => {
    expect(() => beaconStatement(APP, "bcn_xyz", ORIGINS, ENDPOINT)).toThrow(/token/);
    expect(() => beaconStatement(APP, TOKEN, ["https://Shop.example.com"], ENDPOINT)).toThrow(/origin/);
    expect(() => beaconStatement(APP, TOKEN, ["http://localhost:3000"], ENDPOINT)).toThrow(/origin/);
    expect(() => beaconStatement(APP, TOKEN, ["https://a.example", "https://a.example"], ENDPOINT)).toThrow(/origin/);
    expect(() => beaconStatement(APP, TOKEN, [], ENDPOINT)).toThrow(/origin/);
    const many = Array.from({ length: BEACON_LIMITS.originsMax + 1 }, (_, i) => `https://s${i}.example.com`);
    expect(() => beaconStatement(APP, TOKEN, many, ENDPOINT)).toThrow(/origin/);
  });

  it("embedded strings cannot break out of their literal (JSON quoting)", () => {
    const endpoint = 'https://api.example.com/a"b\\c';
    const stmt = beaconStatement(APP, TOKEN, ORIGINS, endpoint);
    const run = runIn(stmt, "https://clone.example.net");
    expect(run.threw).toBeUndefined();
    expect(run.calls).toEqual([
      [`${endpoint}/v1/beacon`, JSON.stringify({ a: APP, t: TOKEN, o: "https://clone.example.net" })],
    ]);
  });

  it("size: at most 700 bytes before gzip apart from the embedded origins, for 20 typical origins (Jev restore_guards)", () => {
    const twenty = Array.from({ length: 20 }, (_, i) => `https://shop${i}.example.com`);
    const stmt = beaconStatement(APP, TOKEN, twenty, ENDPOINT);
    const originsBytes = twenty.reduce((n, o) => n + o.length + 1, 0);
    const bytes = Buffer.byteLength(stmt, "utf8");
    // Recorded for the report: the whole statement and its gzip size.
    console.info(`beacon statement: ${bytes} bytes (${originsBytes} of them origins), gzip ${gzipSync(stmt).length}`);
    expect(bytes - originsBytes).toBeLessThanOrEqual(700);
  });
});

describe("beaconStatement — behaviour in a fake browser (vm)", () => {
  const stmt = beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT);

  it("an allowed origin sends nothing", () => {
    for (const o of ORIGINS) expect(runIn(stmt, o)).toEqual({ calls: [], threw: undefined });
  });

  it("a foreign origin sends exactly one report with the exact URL and body {t, o}", () => {
    for (const o of ["https://clone.example.net", "http://shop.example.com", "https://shop.example.com:8443"]) {
      const run = runIn(stmt, o);
      expect(run.threw).toBeUndefined();
      expect(run.calls).toEqual([[URL_, JSON.stringify({ a: APP, t: TOKEN, o })]]);
      expect(JSON.parse(String(run.calls[0]?.[1]))).toEqual({ a: APP, t: TOKEN, o });
    }
  });

  it.each([
    "http://localhost",
    "http://localhost:3000",
    "https://app.localhost",
    "http://printer.local",
    "https://shop.test:8443",
    "https://svc.internal",
    "http://127.0.0.1:8080",
    "http://10.1.2.3",
    "http://172.20.0.1",
    "http://192.168.1.10",
    "http://169.254.169.254",
    "http://0.0.0.0:8000",
    "http://[::1]:3000",
    "http://[::]",
    "http://[fd00::1]",
    "http://[fe80::1]",
    "http://[::ffff:7f00:1]",
    "http://[::ffff:c0a8:101]:8080",
    "null",
    "file://",
    "chrome-extension://abcdefghijklmnop",
    "",
  ])("a local or non-http(s) origin sends nothing: %j", (o) => {
    expect(runIn(stmt, o)).toEqual({ calls: [], threw: undefined });
  });

  it("missing location, navigator or sendBeacon: no throw, no call", () => {
    const contexts: Array<Record<string, unknown>> = [
      {},
      { location: { origin: "https://clone.example.net" } },
      { navigator: { sendBeacon: () => true } },
      { location: { origin: "https://clone.example.net" }, navigator: {} },
      { location: { origin: "https://clone.example.net" }, navigator: { sendBeacon: "nope" } },
      { location: {}, navigator: { sendBeacon: () => true } },
      { location: null, navigator: null },
    ];
    for (const context of contexts) {
      expect(() => runInNewContext(stmt, context)).not.toThrow();
    }
    expect(runIn(stmt, "https://clone.example.net", { send: false })).toEqual({ calls: [], threw: undefined });
  });

  it("a throwing sendBeacon or a throwing location.origin is swallowed", () => {
    let attempts = 0;
    const throwing = {
      location: { origin: "https://clone.example.net" },
      navigator: {
        sendBeacon: () => {
          attempts++;
          throw new Error("blocked by CSP");
        },
      },
    };
    expect(() => runInNewContext(stmt, throwing)).not.toThrow();
    expect(attempts).toBe(1);
    const getterThrows = {
      location: {
        get origin(): string {
          throw new Error("SecurityError");
        },
      },
      navigator: { sendBeacon: () => true },
    };
    expect(() => runInNewContext(stmt, getterThrows)).not.toThrow();
  });

  it("creates no global binding (the context's own names are unchanged)", () => {
    const context: Record<string, unknown> = {
      location: { origin: "https://clone.example.net" },
      navigator: { sendBeacon: () => true },
    };
    const before = Object.getOwnPropertyNames(runInNewContext("globalThis", context)).sort();
    runInNewContext(stmt, context);
    expect(Object.getOwnPropertyNames(runInNewContext("globalThis", context)).sort()).toEqual(before);
  });

  it("runs in strict mode too (an ES module body is strict)", () => {
    const run = runIn(`"use strict";${stmt}`, "https://clone.example.net");
    expect(run.threw).toBeUndefined();
    expect(run.calls).toHaveLength(1);
  });
});

/** A small deterministic PRNG for the corpus (not the engine's). */
function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s;
  };
}

/** Browser-produced origins: each input as a browser would serialise `location.origin`. */
function corpus(): string[] {
  const inputs: string[] = [];
  const names = [
    "localhost",
    "LOCALHOST",
    "localhost.",
    "a.localhost",
    "a.b.localhost.",
    "mylocalhost",
    "localhost.com",
    "localhost.example",
    "local",
    "test",
    "internal",
    "printer.local",
    "printer.local.",
    "local.example.com",
    "shop.test",
    "shop.test.",
    "test.example",
    "svc.internal",
    "internal.example.com",
    "xlocal",
    "x-test",
    "shop.example.com",
    "clone.example.net",
    "bücher.example",
    "bücher.test",
    "127.example.com",
    "10.example.com",
    "fc00.example.com",
    "fe80.example.com",
    "0x7f.1",
    "2130706433",
    "127.1",
  ];
  const v4 = [
    "127.0.0.1",
    "127.255.255.255",
    "126.255.255.255",
    "128.0.0.0",
    "10.0.0.0",
    "10.255.255.255",
    "9.255.255.255",
    "11.0.0.0",
    "100.64.0.1",
    "172.15.255.255",
    "172.16.0.0",
    "172.31.255.255",
    "172.32.0.0",
    "192.168.0.0",
    "192.168.255.255",
    "192.167.255.255",
    "192.169.0.0",
    "169.254.0.0",
    "169.254.255.255",
    "169.253.255.255",
    "169.255.0.0",
    "0.0.0.0",
    "0.0.0.1",
    "0.1.0.0",
    "1.0.0.0",
    "8.8.8.8",
    "255.255.255.255",
  ];
  const v6 = [
    "::1",
    "::",
    "::2",
    "::0:1",
    "0:0:0:0:0:0:0:1",
    "1::",
    "fc00::",
    "fc00::1",
    "fcff::1",
    "fd12:3456::1",
    "fdff:ffff::",
    "fbff::1",
    "fe00::1",
    "fe7f::1",
    "fe80::1",
    "fe80::",
    "febf::1",
    "fec0::1",
    "ff02::1",
    "fc::1",
    "fd::1",
    "fe8::1",
    "2001:db8::1",
    "64:ff9b::7f00:1",
    "::127.0.0.1",
    "::ffff:127.0.0.1",
    "::ffff:127.255.0.9",
    "::ffff:126.0.0.1",
    "::ffff:10.1.2.3",
    "::ffff:11.0.0.1",
    "::ffff:172.16.0.1",
    "::ffff:172.31.0.1",
    "::ffff:172.32.0.1",
    "::ffff:172.15.0.1",
    "::ffff:192.168.1.1",
    "::ffff:192.169.1.1",
    "::ffff:169.254.0.1",
    "::ffff:169.255.0.1",
    "::ffff:0.0.0.0",
    "::ffff:0.0.0.1",
    "::ffff:0.10.0.1",
    "::ffff:8.8.8.8",
    "::ffff:0:a00:1",
    "FE80::ABCD",
  ];
  for (const n of names) inputs.push(`https://${n}`, `http://${n}:8080`);
  for (const a of v4) inputs.push(`http://${a}`, `https://${a}:8443`);
  for (const a of v6) inputs.push(`http://[${a}]`, `https://[${a}]:8443`);
  // Random IPv4 and IPv6 (plain and IPv4-mapped), deterministic.
  const next = lcg(20261111);
  for (let i = 0; i < 3000; i++) {
    const r = next();
    // Bias towards the interesting first octets.
    const pick = [0, 10, 127, 169, 172, 192, r >>> 24][i % 7] as number;
    const a = `${pick}.${(r >>> 16) & 255}.${(r >>> 8) & 255}.${r & 255}`;
    inputs.push(`http://${a}`, `http://[::ffff:${a}]`);
  }
  for (let i = 0; i < 3000; i++) {
    const r = next();
    const firsts = [0xfc00, 0xfd00, 0xfe80, 0xfec0, 0xfbff, 0xfe7f, 0xfebf, 0x2001, 0, r >>> 16];
    const first = ((firsts[i % firsts.length] as number) | (i % 3 === 0 ? r & 0xff : 0)) & 0xffff;
    const words = [first, (r >>> 8) & 0xffff, 0, 0, 0, 0, i % 5 === 0 ? 0 : r & 0xffff, i % 2];
    inputs.push(`https://[${words.map((w) => w.toString(16)).join(":")}]`);
  }
  // What a browser hands a script on a non-http(s) page, and odd values.
  const raw = ["null", "file://", "chrome-extension://abcdefghijklmnop", "ftp://shop.example.com", "", "about:blank"];
  const origins = inputs.map((x) => canonicalOrigin(x)).filter((o): o is string => o !== null);
  return [...new Set([...origins, ...raw])];
}

describe("the client-side local check mirrors isLocalOrigin (corpus)", () => {
  const allowed = ["https://shop.example.com"];
  const stmt = beaconStatement(APP, TOKEN, allowed, ENDPOINT);

  it("over a corpus of browser-produced origins, a report is sent exactly when the protocol says it is foreign", () => {
    const origins = corpus();
    expect(origins.length).toBeGreaterThan(5000);
    const local = origins.filter((o) => isLocalOrigin(o)).length;
    // The corpus exercises both sides in quantity.
    expect(local).toBeGreaterThan(1000);
    expect(origins.length - local).toBeGreaterThan(1000);
    // One context and one compiled script for the whole corpus: a fresh `vm` context per origin (as `runIn` makes)
    // costs about half a millisecond, so 5,000+ of them took ~3 s alone and passed the 5 s timeout under the load
    // of the full run. Each run still executes the whole statement, with its own `location` and its own record of
    // `sendBeacon` calls. The statement is one IIFE whose variables are local to it, so a run leaves nothing behind
    // for the next one — checked below: the context ends with exactly the globals it was given.
    const script = new Script(stmt);
    let calls: unknown[][] = [];
    const location = { origin: "" as unknown };
    const context = createContext({
      location,
      navigator: { sendBeacon: (url: unknown, body: unknown) => calls.push([url, body]) > 0 },
    });
    const mismatches: string[] = [];
    for (const o of origins) {
      const expected = isLocalOrigin(o) || allowed.includes(o) ? 0 : 1;
      calls = [];
      location.origin = o;
      let threw: unknown;
      try {
        script.runInContext(context);
      } catch (error) {
        threw = error;
      }
      if (threw !== undefined || calls.length !== expected) mismatches.push(`${o} → ${calls.length}`);
    }
    expect(mismatches).toEqual([]);
    expect(Object.keys(context).sort()).toEqual(["location", "navigator"]);
    // The shared context changes nothing: a sample of the corpus gives the same answers in fresh contexts.
    for (let i = 0; i < origins.length; i += 97) {
      const o = origins[i] as string;
      expect(runIn(stmt, o).calls.length, o).toBe(isLocalOrigin(o) || allowed.includes(o) ? 0 : 1);
    }
  });
});

// A module big enough for the Canaries and the beacon within the default size budget.
const MODULE = beaconHostModule();

const SEEDS = [0, 1, 2, 3, 7, 13, 42, 99, 1263, 1091];

function gzipLen(s: string): number {
  return gzipSync(Buffer.from(s, "utf8")).length;
}

describe("plantCanaries with the beacon — one combined planting step", () => {
  const files = [
    { path: "z.js", code: "z();", skipped: false },
    { path: "a.js", code: "a();", skipped: true },
    { path: "m.js", code: "m();", skipped: false },
  ];

  it("appends the Canary statement then the beacon statement, each on its own line, into the same file", () => {
    const beacon = beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT);
    const { files: out, plantedIn } = plantCanaries(files, EXAMPLE_CANARIES, undefined, beacon);
    expect(plantedIn).toBe("m.js");
    expect(out.find((f) => f.path === "m.js")?.code).toBe(`m();\n${canaryStatement(EXAMPLE_CANARIES)}\n${beacon}\n`);
    expect(out.find((f) => f.path === "a.js")?.code).toBe("a();");
    expect(out.find((f) => f.path === "z.js")?.code).toBe("z();");
  });

  it("the budget counts both: a file that holds the Canaries alone but not with the beacon is passed over", () => {
    const beacon = beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT);
    const canary = canaryStatement(EXAMPLE_CANARIES);
    // Find a file size where the Canaries alone fit the budget and Canaries + beacon do not.
    let small = "";
    for (let n = 1; n < 400; n++) {
      const code = `export const rows = [${Array.from({ length: n }, (_, i) => `{ id: ${i}, name: "row ${i}" }`).join(", ")}];\n`;
      const pct = (planted: string) => ((gzipLen(planted) - gzipLen(code)) / gzipLen(code)) * 100;
      if (pct(`${code}${canary}\n`) <= 35 && pct(`${code}${canary}\n${beacon}\n`) > 35) {
        small = code;
        break;
      }
    }
    expect(small).not.toBe("");
    const budget = { originals: { "a.js": small, "b.js": MODULE }, sizePct: 35 };
    const two = [
      { path: "a.js", code: small, skipped: false },
      { path: "b.js", code: MODULE, skipped: false },
    ];
    expect(plantCanaries(two, EXAMPLE_CANARIES, budget).plantedIn).toBe("a.js");
    expect(plantCanaries(two, EXAMPLE_CANARIES, budget, beacon).plantedIn).toBe("b.js");
    expect(() => plantCanaries([two[0] as (typeof two)[0]], EXAMPLE_CANARIES, budget, beacon)).toThrow(
      /Canaries and the Clone Beacon/,
    );
  });

  it("never plants into a declaration file or a skipped file", () => {
    const beacon = beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT);
    expect(() =>
      plantCanaries(
        [
          { path: "a.d.ts", code: "export declare const a: number;\n", skipped: false },
          { path: "b.js", code: "b();", skipped: true },
        ],
        EXAMPLE_CANARIES,
        undefined,
        beacon,
      ),
    ).toThrow(/no protected/i);
  });
});

describe("hardenBundle with a beacon", () => {
  it("plants Canaries and the beacon together; the result records the beacon (token and origins)", () => {
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 1, beacon: BEACON });
    expect(result.plantError).toBeUndefined();
    expect(result.plantedIn).toBe("m.mjs");
    expect(result.beacon).toEqual({ token: TOKEN, origins: ORIGINS });
    const code = result.files[0]?.code ?? "";
    expect(
      code.endsWith(`${canaryStatement(result.canaries)}\n${beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT)}\n`),
    ).toBe(true);
  });

  it("without a beacon nothing changes: the beacon is null and the output is the slice-07 output", () => {
    const off = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 1 });
    expect(off.beacon).toBeNull();
    expect(off.files[0]?.code).not.toContain("sendBeacon");
    expect(off.files[0]?.code.endsWith(`${canaryStatement(off.canaries)}\n`)).toBe(true);
  });

  it("determinism: the same inputs give byte-identical output; another token changes only the beacon", () => {
    const input = { sources: { "a.mjs": MODULE, "b.mjs": MODULE.replace("TIERS", "PLANS2") } };
    const one = hardenBundle(input, { profile: "balanced", seed: 77, beacon: BEACON });
    const two = hardenBundle(input, { profile: "balanced", seed: 77, beacon: { ...BEACON, origins: [...ORIGINS] } });
    expect(two.files.map((f) => f.code)).toEqual(one.files.map((f) => f.code));
    const otherToken = deriveBeaconToken(77, { appId: "app_0123456789abcdef01234567", version: "1.0.1" });
    expect(otherToken).not.toBe(TOKEN);
    const three = hardenBundle(input, { profile: "balanced", seed: 77, beacon: { ...BEACON, token: otherToken } });
    expect(three.files.find((f) => f.path === "a.mjs")?.code).toContain(otherToken);
    expect(three.files.find((f) => f.path === "a.mjs")?.code).not.toContain(TOKEN);
  });

  it("the budget gate counts Canaries + beacon: the planted file stays within budget", () => {
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 1, beacon: BEACON });
    const planted = result.files.find((f) => f.path === result.plantedIn);
    if (!planted) throw new Error("not planted");
    const overhead = ((gzipLen(planted.code) - gzipLen(MODULE)) / gzipLen(MODULE)) * 100;
    expect(overhead).toBeLessThanOrEqual(DEFAULT_BUDGET.sizePct);
  });

  it("fails cleanly (plantError, nothing planted) when no file holds both", () => {
    const result = hardenBundle(
      { sources: { "t.mjs": "export const q = (n) => n;\n" } },
      { profile: "light", seed: 1, beacon: BEACON },
    );
    expect(result.plantedIn).toBeNull();
    expect(result.plantError).toMatch(/Canaries and the Clone Beacon/);
  });

  it("a bad beacon configuration is reported as a plant error, never thrown", () => {
    const result = hardenBundle(
      { sources: { "m.mjs": MODULE } },
      { profile: "balanced", seed: 1, beacon: { ...BEACON, endpoint: "ftp://x" } },
    );
    expect(result.plantedIn).toBeNull();
    expect(result.plantError).toMatch(/endpoint/);
  });

  it("never plants into a .d.ts or a skipped file", () => {
    const DECL = "export declare const a: number;\n";
    const result = hardenBundle(
      { sources: { "a.d.ts": DECL, "b.mjs": MODULE, "c.mjs": MODULE } },
      { profile: "balanced", seed: 1, protectionMap: { "b.mjs": "skip" }, beacon: BEACON },
    );
    expect(result.plantedIn).toBe("c.mjs");
    expect(result.files.find((f) => f.path === "a.d.ts")?.code).toBe(DECL);
    expect(result.files.find((f) => f.path === "b.mjs")?.code).toBe(MODULE);
  });

  it.each(SEEDS)("equivalence: behaviour is unchanged with Canaries + beacon planted (seed %i)", async (seed) => {
    const original = await importModule(MODULE);
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed, beacon: BEACON });
    expect(result.plantedIn).toBe("m.mjs");
    const code = result.files[0]?.code ?? "";
    expect(code).toContain(TOKEN);
    const mod = await importModule(code);
    expect((mod.table as () => unknown)()).toEqual((original.table as () => unknown)());
    expect((mod.quote as (t: string, p: number) => string)("pro", 25)).toBe(
      (original.quote as (t: string, p: number) => string)("pro", 25),
    );
    expect(mod.SKUS).toEqual(original.SKUS);
  });

  it("outside a browser (plain Node import of the protected output): a no-op and no new global", async () => {
    const before = Object.getOwnPropertyNames(globalThis).sort();
    const result = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 9, beacon: BEACON });
    await importModule(result.files[0]?.code ?? "");
    expect(Object.getOwnPropertyNames(globalThis).sort()).toEqual(before);
  });

  it("a protected script in a fake browser: one report on a clone origin, none on an allowed one, same globals", () => {
    const script = MODULE.replace(/export /g, "");
    const result = hardenBundle({ sources: { "s.js": script } }, { profile: "balanced", seed: 3, beacon: BEACON });
    const code = result.files[0]?.code ?? "";
    const unplanted = harden({ "s.js": script }, { profile: "balanced", seed: 3 }).files[0]?.code ?? "";
    const names = (c: string, origin: string) => {
      const context: Record<string, unknown> = { location: { origin }, navigator: { sendBeacon: () => true } };
      runInNewContext(c, context);
      return Object.getOwnPropertyNames(runInNewContext("globalThis", context)).sort();
    };
    expect(names(code, "https://clone.example.net")).toEqual(names(unplanted, "https://clone.example.net"));
    expect(runIn(code, "https://clone.example.net").calls).toEqual([
      [URL_, JSON.stringify({ a: APP, t: TOKEN, o: "https://clone.example.net" })],
    ]);
    expect(runIn(code, ORIGINS[0]).calls).toEqual([]);
    expect(runIn(code, "http://localhost:5173").calls).toEqual([]);
  });

  it("Canaries are unchanged by the beacon (same derivation)", () => {
    const on = hardenBundle({ sources: { "m.mjs": MODULE } }, { profile: "balanced", seed: 1, beacon: BEACON });
    expect(on.canaries).toEqual(deriveCanaries(1));
  });
});

describe("review fixes F2/F4/F6", () => {
  it("F4: the report body is {a, t, o} with the App id; a bad App id is refused", () => {
    const stmt = beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT);
    expect(stmt).toContain(JSON.stringify(APP));
    const run = runIn(stmt, "https://clone.example.net");
    expect(run.calls).toHaveLength(1);
    expect(JSON.parse(String(run.calls[0]?.[1]))).toEqual({ a: APP, t: TOKEN, o: "https://clone.example.net" });
    expect(Object.keys(JSON.parse(String(run.calls[0]?.[1])))).toEqual(["a", "t", "o"]);
    for (const bad of ["my-app", "app_XYZ", 'app_0123456789abcdef0123456"', ""]) {
      expect(() => beaconStatement(bad, TOKEN, ORIGINS, ENDPOINT)).toThrow(/App id/);
    }
    const result = hardenBundle(
      { sources: { "m.mjs": MODULE } },
      { profile: "balanced", seed: 1, beacon: { ...BEACON, appId: "nope" } },
    );
    expect(result.plantError).toMatch(/App id/);
  });

  it("F2: a page origin whose host ends in one dot matches the allowed origin without it (no report)", () => {
    const stmt = beaconStatement(APP, TOKEN, ["http://shop.example:39961", "https://shop.example.com"], ENDPOINT);
    for (const o of ["http://shop.example.:39961", "https://shop.example.com.", "http://shop.example:39961"]) {
      expect(runIn(stmt, o)).toEqual({ calls: [], threw: undefined });
    }
    // Only one dot is removed, and only at the end of the host.
    for (const o of ["http://shop.example..:39961", "http://shop.example.:39962", "https://shop.example.com.evil"]) {
      expect(runIn(stmt, o).calls, o).toHaveLength(1);
    }
    // The report carries the page's origin exactly as the browser gave it (the API compares it with Origin).
    expect(runIn(stmt, "https://clone.example.net.").calls[0]?.[1]).toBe(
      JSON.stringify({ a: APP, t: TOKEN, o: "https://clone.example.net." }),
    );
  });

  it("F2: an allowed origin given with a trailing dot also allows the page origin without it", () => {
    const stmt = beaconStatement(APP, TOKEN, ["https://shop.example.com."], ENDPOINT);
    for (const o of ["https://shop.example.com", "https://shop.example.com."]) {
      expect(runIn(stmt, o).calls, o).toEqual([]);
    }
  });

  it("F2: trailing-dot local names are local (vm), as isLocalOrigin says", () => {
    const stmt = beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT);
    for (const o of [
      "http://localhost.",
      "http://localhost.:3000",
      "http://app.localhost.:5173",
      "http://printer.local.",
      "https://shop.test.:8443",
      "https://svc.internal.",
    ]) {
      expect(isLocalOrigin(o), o).toBe(true);
      expect(runIn(stmt, o).calls, o).toEqual([]);
    }
    for (const o of ["https://localhost.com.", "https://local.", "https://example.com."]) {
      expect(isLocalOrigin(o), o).toBe(false);
      expect(runIn(stmt, o).calls, o).toHaveLength(1);
    }
  });

  it("F6: an endpoint with < or > is refused", () => {
    for (const endpoint of [
      "https://api.example.com/</script>",
      "https://api.example.com/a>b",
      "https://api.example.com/<x",
    ]) {
      expect(() => beaconEndpointUrl(endpoint), endpoint).toThrow(/endpoint/);
      expect(() => beaconStatement(APP, TOKEN, ORIGINS, endpoint)).toThrow(/endpoint/);
    }
  });

  it("F6: no literal '<' in the statement, and & in an embedded string is escaped (still exact at run time)", () => {
    const twenty = Array.from({ length: 20 }, (_, i) => `https://shop${i}.example.com`);
    for (const stmt of [
      beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT),
      beaconStatement(APP, TOKEN, twenty, ENDPOINT),
      beaconStatement(APP, TOKEN, ["http://[2001:db8::1]:8080"], "http://[2001:db8::2]:9/x&y"),
    ]) {
      expect(stmt).not.toContain("<");
      expect(stmt).not.toContain("</");
    }
    const amp = beaconStatement(APP, TOKEN, ORIGINS, "https://api.example.com/x&y");
    expect(amp).not.toContain("x&y");
    expect(amp).toContain("x\\u0026y");
    expect(runIn(amp, "https://clone.example.net").calls[0]?.[0]).toBe("https://api.example.com/x&y/v1/beacon");
  });
});

describe("Jev decision: typeof guards return before anything is touched (no exception, even inside the try)", () => {
  const stmt = beaconStatement(APP, TOKEN, ORIGINS, ENDPOINT);

  /** A location whose `origin` read is counted, and a navigator whose `sendBeacon` read is counted. */
  function spies() {
    const reads = { origin: 0, sendBeacon: 0 };
    const location = {
      get origin(): string {
        reads.origin++;
        return "https://clone.example.net";
      },
    };
    const navigator = {
      get sendBeacon(): () => boolean {
        reads.sendBeacon++;
        return () => true;
      },
    };
    return { reads, location, navigator };
  }

  it("no navigator: location.origin is never read", () => {
    const { reads, location } = spies();
    expect(() => runInNewContext(stmt, { location })).not.toThrow();
    expect(reads).toEqual({ origin: 0, sendBeacon: 0 });
  });

  it("no location: navigator.sendBeacon is never read", () => {
    const { reads, navigator } = spies();
    expect(() => runInNewContext(stmt, { navigator })).not.toThrow();
    expect(reads).toEqual({ origin: 0, sendBeacon: 0 });
  });

  it("neither: nothing is touched; with both, each is read once", () => {
    expect(() => runInNewContext(stmt, {})).not.toThrow();
    const { reads, location, navigator } = spies();
    runInNewContext(stmt, { location, navigator });
    expect(reads.origin).toBe(1);
    expect(reads.sendBeacon).toBeGreaterThanOrEqual(1);
  });

  it("with the try/catch removed, a context without location or navigator still does not throw", () => {
    const bare = stmt.replace(";(function(){try{", ";(function(){{").replace("}catch(e){}})();", "}})();");
    expect(bare).not.toContain("catch");
    for (const context of [{}, { location: { origin: "https://clone.example.net" } }, { navigator: {} }]) {
      expect(() => runInNewContext(bare, context)).not.toThrow();
    }
  });
});
