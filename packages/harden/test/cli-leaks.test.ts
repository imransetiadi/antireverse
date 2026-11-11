// Slice 07 — the CLI around the leak scan and Canaries: exit code 3, nothing written or registered, no finding
// value in any output channel, allowlist loading, the report/--json/Manifest additions, seed normalisation and
// the integrity wrapper over planted code.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BuildManifestSchema, EXAMPLE_BUILD } from "@antireverse/protocol";
import { deriveCanaries, leakFingerprint } from "@antireverse/protocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canaryStatement } from "../src/canaries.ts";
import { main } from "../src/cli.ts";

const AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE";
const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

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
  return "EUR " + euros;
}
export function table() {
  return Object.keys(TIERS).map((tier) => [tier, format(discounted(priceOf(tier), 10)), label(tier)]);
}
`;

const temps: string[] = [];
afterEach(() => {
  vi.unstubAllGlobals();
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  temps.push(d);
  return d;
}

/** A bundle directory with the given files (relative path → content). */
function bundle(files: Record<string, string | Buffer>): string {
  const d = tempDir("harden-cli7-");
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(join(d, rel, ".."), { recursive: true });
    writeFileSync(join(d, rel), content);
  }
  return d;
}

async function run(argv: string[], opts: { cwd: string; env?: Record<string, string> }) {
  let out = "";
  let err = "";
  const code = await main(argv, {
    env: opts.env ?? {},
    cwd: opts.cwd,
    stdout: (s) => {
      out += s;
    },
    stderr: (s) => {
      err += s;
    },
  });
  return { code, out, err };
}

function stubRegister(): Array<{ url: string; body: string }> {
  const calls: Array<{ url: string; body: string }> = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    calls.push({ url, body: String(init.body) });
    return new Response(JSON.stringify({ build: EXAMPLE_BUILD }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  });
  return calls;
}

const REGISTER = [
  "--register",
  "--endpoint",
  "https://api.example.test",
  "--key-env",
  "AR_ADMIN_KEY",
  "--app",
  EXAMPLE_BUILD.app_id,
  "--environment",
  "development",
  "--build-version",
  "1.0.0",
];

const LEAKY = `export const client = { id: "${AWS_EXAMPLE}" };\n${MODULE}`;

describe("leak scan in the CLI", () => {
  it("exits 3 on an unsuppressed finding: masked report, nothing written, nothing registered", async () => {
    const d = bundle({ "src/k.mjs": LEAKY });
    const out = join(tempDir("harden-out-"), "out");
    const calls = stubRegister();
    for (const json of [false, true]) {
      const r = await run(["harden", d, "--seed", "1", "--out", out, ...REGISTER, ...(json ? ["--json"] : [])], {
        cwd: d,
        env: { AR_ADMIN_KEY: KEY },
      });
      expect(r.code).toBe(3);
      expect(existsSync(out)).toBe(false);
      expect(calls).toEqual([]);
      expect(r.out + r.err).not.toContain(AWS_EXAMPLE);
      const fp = leakFingerprint("aws-access-key", "src/k.mjs", AWS_EXAMPLE);
      if (json) {
        const report = JSON.parse(r.out);
        expect(report.leak_scan).toEqual({
          status: "failed",
          findings: [{ rule: "aws-access-key", path: "src/k.mjs", line: 1, masked: "AKIA…", fingerprint: fp }],
          suppressed: 0,
          not_scanned: [],
          decoded_as_latin1: [],
        });
      } else {
        expect(r.out).toContain("✗ leak scan: 1 finding");
        expect(r.out).toContain(`aws-access-key  src/k.mjs:1  AKIA…  ${fp}`);
        expect(r.err).toMatch(/nothing written or registered/);
      }
    }
  });

  it("scans non-JS text files and .map files of the bundle, and says which binary files it skipped", async () => {
    const d = bundle({
      "app.mjs": MODULE,
      "app.mjs.map": `{"version":3}`,
      "config.json": `{ "endpoint": "http://192.168.0.10/api" }`,
      "logo.png": Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe, 0x00, 0xc3]),
    });
    const r = await run(["harden", d, "--seed", "1", "--json"], { cwd: d });
    expect(r.code).toBe(3);
    const report = JSON.parse(r.out);
    expect(report.leak_scan.findings.map((f: { rule: string; path: string }) => `${f.rule}:${f.path}`).sort()).toEqual([
      "internal-url:config.json",
      "source-map:app.mjs.map",
    ]);
    expect(report.leak_scan.not_scanned).toEqual(["logo.png"]);
  });

  it("an allowlisted finding passes (default file in the working directory), is counted, and the Manifest carries no value", async () => {
    const d = bundle({ "src/k.mjs": LEAKY });
    const cwd = tempDir("harden-cwd-");
    mkdirSync(join(cwd, ".antireverse"));
    writeFileSync(
      join(cwd, ".antireverse", "leak-allow.json"),
      JSON.stringify({
        version: 1,
        allow: [{ fingerprint: leakFingerprint("aws-access-key", "src/k.mjs", AWS_EXAMPLE), reason: "AWS example" }],
      }),
    );
    const calls = stubRegister();
    const out = join(cwd, "out");
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...REGISTER, "--json"], {
      cwd,
      env: { AR_ADMIN_KEY: KEY },
    });
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.leak_scan).toEqual({
      status: "suppressed",
      findings: [],
      suppressed: 1,
      not_scanned: [],
      decoded_as_latin1: [],
    });
    expect(calls).toHaveLength(1);
    const manifest = BuildManifestSchema.parse(JSON.parse(calls[0]?.body ?? "").manifest);
    expect(manifest.leak_scan).toEqual({ status: "suppressed", suppressed: 1 });
    // Registered: the Canaries are scoped to the App and version (derivation v2), so a pinned seed can
    // register more than one Build per Organization.
    const scoped = deriveCanaries(1, { appId: EXAMPLE_BUILD.app_id, version: "1.0.0" });
    expect(manifest.canaries).toEqual(scoped);
    for (const channel of [r.out, r.err, calls[0]?.body ?? ""]) expect(channel).not.toContain(AWS_EXAMPLE);
    // The output (written) is hardened: the literal was encrypted by balanced, and Canaries are planted.
    expect(readFileSync(join(out, "src/k.mjs"), "utf8")).toContain(canaryStatement(scoped));
  });

  it("--leak-allow <file> is resolved against the working directory", async () => {
    const d = bundle({ "src/k.mjs": LEAKY });
    const cwd = tempDir("harden-cwd-");
    writeFileSync(
      join(cwd, "allow.json"),
      JSON.stringify({
        version: 1,
        allow: [{ fingerprint: leakFingerprint("aws-access-key", "src/k.mjs", AWS_EXAMPLE), reason: "AWS example" }],
      }),
    );
    const r = await run(["harden", d, "--seed", "1", "--leak-allow", "allow.json"], { cwd });
    expect(r.code).toBe(0);
    expect(r.out).toContain("✓ leak scan clean (1 suppressed)");
  });

  it("a malformed allowlist or a given-but-missing one fails before anything else", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const cwd = tempDir("harden-cwd-");
    writeFileSync(join(cwd, "bad.json"), "{ nope");
    const bad = await run(["harden", d, "--leak-allow", "bad.json"], { cwd });
    expect(bad.code).toBe(2);
    expect(bad.err).toMatch(/leak-allow|allowlist/i);
    const missing = await run(["harden", d, "--leak-allow", "missing.json"], { cwd });
    expect(missing.code).toBe(2);
    mkdirSync(join(cwd, ".antireverse"));
    writeFileSync(
      join(cwd, ".antireverse", "leak-allow.json"),
      JSON.stringify({ version: 1, allow: [{ fingerprint: "x" }] }),
    );
    const malformedDefault = await run(["harden", d], { cwd });
    expect(malformedDefault.code).toBe(2);
  });
});

describe("review fixes M3/M4", () => {
  it("M4: a non-UTF-8 text file is scanned as latin1 (the repro exits 3) and listed", async () => {
    const config = Buffer.concat([
      Buffer.from(`{ "name": "caf`),
      Buffer.from([0xe9]),
      Buffer.from(`", "key": "${AWS_EXAMPLE}" }`),
    ]);
    const d = bundle({ "a.mjs": MODULE, "config.json": config });
    const r = await run(["harden", d, "--seed", "1", "--json"], { cwd: d });
    expect(r.code).toBe(3);
    const report = JSON.parse(r.out);
    expect(report.leak_scan.findings.map((f: { rule: string; path: string }) => `${f.rule}:${f.path}`)).toEqual([
      "aws-access-key:config.json",
    ]);
    expect(report.leak_scan.decoded_as_latin1).toEqual(["config.json"]);
    expect(report.leak_scan.not_scanned).toEqual([]);
    expect(r.out + r.err).not.toContain(AWS_EXAMPLE);
    const human = await run(["harden", d, "--seed", "1"], { cwd: d });
    expect(human.out).toContain("decoded as latin1 (not UTF-8): config.json");
  });

  it("M4: a file with a NUL byte is still skipped, but only then, and listed", async () => {
    const withNul = Buffer.concat([Buffer.from(`k = "${AWS_EXAMPLE}"`), Buffer.from([0x00, 0xff])]);
    const d = bundle({ "a.mjs": MODULE, "blob.bin": withNul });
    const r = await run(["harden", d, "--seed", "1", "--json"], { cwd: d });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).leak_scan.not_scanned).toEqual(["blob.bin"]);
  });

  it("M3: two registers with the same seed but versions 1.0.0 and 1.0.1 get different Canaries", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const calls = stubRegister();
    const register = (version: string) => [...REGISTER.slice(0, -1), version];
    const one = await run(["harden", d, "--seed", "1", ...register("1.0.0"), "--json"], {
      cwd: d,
      env: { AR_ADMIN_KEY: KEY },
    });
    const two = await run(["harden", d, "--seed", "1", ...register("1.0.1"), "--json"], {
      cwd: d,
      env: { AR_ADMIN_KEY: KEY },
    });
    expect(one.code).toBe(0);
    expect(two.code).toBe(0);
    const [m1, m2] = calls.map((c) => BuildManifestSchema.parse(JSON.parse(c.body).manifest));
    expect(m1?.canaries).toEqual(deriveCanaries(1, { appId: EXAMPLE_BUILD.app_id, version: "1.0.0" }));
    expect(m2?.canaries).toEqual(deriveCanaries(1, { appId: EXAMPLE_BUILD.app_id, version: "1.0.1" }));
    const ids1 = new Set(m1?.canaries?.map((c) => c.id));
    const vals1 = new Set(m1?.canaries?.map((c) => c.value));
    for (const c of m2?.canaries ?? []) {
      expect(ids1.has(c.id)).toBe(false);
      expect(vals1.has(c.value)).toBe(false);
    }
    // The same inputs still reproduce byte for byte.
    const again = await run(["harden", d, "--seed", "1", ...register("1.0.0"), "--json"], {
      cwd: d,
      env: { AR_ADMIN_KEY: KEY },
    });
    expect(JSON.parse(again.out).canaries).toEqual(JSON.parse(one.out).canaries);
  });

  it("M3: an --app that is not an App id is a usage error before any work", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const args = [...REGISTER];
    args[args.indexOf("--app") + 1] = "my-app";
    const r = await run(["harden", d, "--seed", "1", ...args], { cwd: d, env: { AR_ADMIN_KEY: KEY } });
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/--app/);
  });
});

describe("Canaries in the CLI report", () => {
  it("human report: clean scan, Canaries planted, and 'not watched' without --register", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const r = await run(["harden", d, "--seed", "1"], { cwd: d });
    expect(r.code).toBe(0);
    expect(r.out).toContain("✓ leak scan clean");
    expect(r.out).toContain("✓ 3 Canaries planted in a.mjs (not watched: pass --register)");
    for (const c of deriveCanaries(1)) {
      expect(r.out).toContain(`${c.kind} ${c.id}`);
      expect(r.out).not.toContain(c.value); // values only in --json and the Manifest
    }
  });

  it("human report does not say 'not watched' when registering", async () => {
    const d = bundle({ "a.mjs": MODULE });
    stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...REGISTER], { cwd: d, env: { AR_ADMIN_KEY: KEY } });
    expect(r.code).toBe(0);
    expect(r.out).toContain("✓ 3 Canaries planted in a.mjs");
    expect(r.out).not.toContain("not watched");
  });

  it("--json carries leak_scan and the Canaries with their decoy values", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const r = await run(["harden", d, "--seed", "1", "--json"], { cwd: d });
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.leak_scan).toEqual({
      status: "clean",
      findings: [],
      suppressed: 0,
      not_scanned: [],
      decoded_as_latin1: [],
    });
    expect(report.canaries).toEqual(deriveCanaries(1));
    expect(report.canaries_planted_in).toBe("a.mjs");
  });

  it("--seed -5 equals --seed 4294967291 byte for byte, including Canaries (A1)", async () => {
    const d = bundle({ "a.mjs": MODULE, "b.mjs": MODULE });
    const base = tempDir("harden-seed-");
    const a = await run(["harden", d, "--seed", "-5", "--out", join(base, "a"), "--json"], { cwd: d });
    const b = await run(["harden", d, "--seed", "4294967291", "--out", join(base, "b"), "--json"], { cwd: d });
    expect(a.code).toBe(0);
    expect(b.code).toBe(0);
    expect(JSON.parse(a.out)).toEqual(JSON.parse(b.out));
    for (const f of readdirSync(join(base, "a"))) {
      expect(readFileSync(join(base, "a", f), "utf8")).toBe(readFileSync(join(base, "b", f), "utf8"));
    }
    expect(JSON.parse(a.out).canaries).toEqual(deriveCanaries(4294967291));
  });

  it("fails with a clear message when no file can hold the Canaries within budget", async () => {
    const d = bundle({ "a.mjs": "export const q = (n) => n;\n" });
    const r = await run(["harden", d, "--seed", "1"], { cwd: d });
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/Canar/);
  });

  it("--integrity wraps the planted code so the self-check still passes", async () => {
    const script = `(function () { globalThis.__ar_probe = 6 * 7; })();\n${MODULE.replace(/export /g, "")}`;
    const d = bundle({ "bundle.js": script });
    const out = join(tempDir("harden-int-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--integrity", "--out", out], { cwd: d });
    expect(r.code).toBe(0);
    const wrapped = readFileSync(join(out, "bundle.js"), "utf8");
    expect(wrapped).toContain(deriveCanaries(1)[0]?.value);
    delete (globalThis as Record<string, unknown>).__ar_probe;
    // biome-ignore lint/security/noGlobalEval: the integrity wrapper is designed to be eval'd at load.
    const indirectEval = eval;
    expect(() => indirectEval(wrapped)).not.toThrow();
    expect((globalThis as Record<string, unknown>).__ar_probe).toBe(42);
    delete (globalThis as Record<string, unknown>).__ar_probe;
  });
});
