// Slice 19 — the CLI around the component inventory: `--lockfile` (default ./package-lock.json in the cwd),
// components sent beside the Manifest with --register (count and digest in the Manifest), `--fail-on` (needs
// --register, validated before any work; exit 4 on open findings at or above the level), report lines and
// --json. Package names never reach the output beyond the findings summary's items.
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EXAMPLE_BUILD,
  EXAMPLE_FINDINGS_SUMMARY,
  type FindingsSummary,
  RegisterBuildRequestSchema,
} from "@antireverse/protocol";
import { componentsDigest } from "@antireverse/protocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EXIT_FINDINGS, main } from "../src/cli.ts";
import { beaconHostModule } from "./helpers.ts";

const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const ENDPOINT = "https://api.example.test";
const MODULE = beaconHostModule();

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

/** A bundle dir with one module; returns the dir (used as cwd too). */
function bundle(): string {
  const d = tempDir("harden-cli19-");
  writeFileSync(join(d, "a.mjs"), MODULE);
  return d;
}

// Distinctive names: none of them may appear in the output unless a findings item names it.
const LOCK = {
  name: "private-app-zq",
  lockfileVersion: 3,
  packages: {
    "": { name: "private-app-zq", version: "1.0.0" },
    "node_modules/example-parser": { version: "1.2.3" },
    "node_modules/@zq-internal/secret-sdk": { version: "3.1.0" },
    "node_modules/zq-dev-tool": { version: "0.4.0", dev: true },
    "node_modules/zq-from-git": { version: "git+https://example.test/zq.git" },
    "node_modules/.zq-bad": { version: "1.0.0" },
  },
};

function writeLock(dir: string, content: unknown = LOCK, name = "package-lock.json"): string {
  const file = join(dir, name);
  writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content));
  return file;
}

async function run(argv: string[], cwd: string, env: Record<string, string> = { AR_ADMIN_KEY: KEY }) {
  let out = "";
  let err = "";
  const code = await main(argv, {
    env,
    cwd,
    stdout: (s) => {
      out += s;
    },
    stderr: (s) => {
      err += s;
    },
  });
  return { code, out, err };
}

function stubRegister(findings?: FindingsSummary): Array<{ url: string; body: string }> {
  const calls: Array<{ url: string; body: string }> = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    calls.push({ url, body: String(init.body) });
    return new Response(JSON.stringify({ build: EXAMPLE_BUILD, ...(findings ? { findings } : {}) }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  });
  return calls;
}

const register = [
  "--register",
  "--endpoint",
  ENDPOINT,
  "--key-env",
  "AR_ADMIN_KEY",
  "--app",
  EXAMPLE_BUILD.app_id,
  "--environment",
  "development",
  "--build-version",
  "1.0.0",
];

const EXPECTED = [
  { name: "@zq-internal/secret-sdk", version: "3.1.0", dev: false },
  { name: "example-parser", version: "1.2.3", dev: false },
  { name: "zq-dev-tool", version: "0.4.0", dev: true },
];

function noPackageNames(text: string): void {
  for (const name of ["secret-sdk", "zq-internal", "zq-dev-tool", "zq-from-git", "zq-bad", "private-app-zq"]) {
    expect(text).not.toContain(name);
  }
}

const SUMMARY_3_HIGH_UP: FindingsSummary = {
  open: { critical: 1, high: 2, medium: 4, low: 0, unknown: 1 },
  items: [
    {
      advisory: "GHSA-aaaa-bbbb-cccc",
      package: "example-parser",
      version: "1.2.3",
      severity: "critical",
      fixed: ["1.2.4"],
    },
    {
      advisory: "GHSA-2c3m-4p5q-6r7v",
      package: "example-parser",
      version: "1.2.3",
      severity: "high",
      fixed: ["1.2.4", "2.1.1"],
    },
    { advisory: "GHSA-dddd-eeee-ffff", package: "example-parser", version: "1.2.3", severity: "high", fixed: [] },
    {
      advisory: "GHSA-gggg-hhhh-jjjj",
      package: "example-parser",
      version: "1.2.3",
      severity: "medium",
      fixed: ["1.3.0"],
    },
    { advisory: "GHSA-kkkk-mmmm-pppp", package: "example-parser", version: "1.2.3", severity: "unknown", fixed: [] },
  ],
};

describe("--lockfile and the inventory without --register", () => {
  it("reads ./package-lock.json from the cwd by default and reports counts only (not sent)", async () => {
    const d = bundle();
    writeLock(d);
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const r = await run(["harden", d, "--seed", "1"], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain("✓ 3 components in inventory (2 skipped)");
    expect(r.out).toContain("3 components read (not sent: pass --register)");
    expect(fetchSpy).not.toHaveBeenCalled();
    noPackageNames(r.out + r.err);
  });

  it("without a default lockfile, inventory is off with a report line and exit 0", async () => {
    const d = bundle();
    const r = await run(["harden", d, "--seed", "1"], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain("no lockfile: component inventory skipped");
  });

  it("--lockfile <path> reads that file, relative to the cwd", async () => {
    const d = bundle();
    mkdirSync(join(d, "sub"));
    writeLock(join(d, "sub"));
    const r = await run(["harden", d, "--seed", "1", "--lockfile", "sub/package-lock.json"], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain("✓ 3 components in inventory (2 skipped)");
  });

  it("a given-but-missing --lockfile exits 2 before any work", async () => {
    const d = bundle();
    const out = join(tempDir("harden-out-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--out", out, "--lockfile", "nope.json"], d);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/lockfile/);
    expect(r.out).toBe("");
    expect(existsSync(out)).toBe(false);
  });

  it("--lockfile with no value exits 2", async () => {
    const d = bundle();
    const r = await run(["harden", d, "--seed", "1", "--lockfile"], d);
    expect(r.code).toBe(2);
  });

  it("an unparseable lockfile (given or default) exits 2 without echoing its content", async () => {
    const d = bundle();
    writeLock(d, '{"zq-internal": broken');
    for (const argv of [
      ["harden", d, "--seed", "1"],
      ["harden", d, "--seed", "1", "--lockfile", "package-lock.json"],
    ]) {
      const r = await run(argv, d);
      expect(r.code).toBe(2);
      expect(r.err).toMatch(/lockfile/);
      noPackageNames(r.out + r.err);
    }
  });

  it("over 5,000 components exits 2 with a clear message, before any register", async () => {
    const d = bundle();
    const packages: Record<string, unknown> = { "": {} };
    for (let i = 0; i < 5001; i++) packages[`node_modules/p${i}`] = { version: "1.0.0" };
    writeLock(d, { lockfileVersion: 3, packages });
    const calls = stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register], d);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/5,000/);
    expect(calls).toEqual([]);
  });

  it("--json carries components {count, skipped} and findings null", async () => {
    const d = bundle();
    writeLock(d);
    const r = await run(["harden", d, "--seed", "1", "--json"], d);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.components).toEqual({ count: 3, skipped: 2 });
    expect(report.findings).toBeNull();
    noPackageNames(r.out + r.err);
  });

  it("--json without a lockfile carries components null", async () => {
    const d = bundle();
    const r = await run(["harden", d, "--seed", "1", "--json"], d);
    expect(JSON.parse(r.out).components).toBeNull();
  });
});

describe("--register sends the components beside the Manifest", () => {
  it("body is { manifest (component_count, components_digest), components }", async () => {
    const d = bundle();
    writeLock(d);
    const calls = stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register], d);
    expect(r.code).toBe(0);
    expect(calls.length).toBe(1);
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(Object.keys(body).sort()).toEqual(["components", "manifest"]);
    expect(body.components).toEqual(EXPECTED);
    expect(body.manifest.component_count).toBe(3);
    expect(body.manifest.components_digest).toBe(componentsDigest(EXPECTED));
    expect(RegisterBuildRequestSchema.safeParse(body).success).toBe(true);
    expect(r.out).toContain("✓ 3 components in inventory (2 skipped)");
    expect(r.out).not.toContain("not sent");
    noPackageNames(r.out + r.err);
  });

  it("without a lockfile the body is { manifest } with no component fields", async () => {
    const d = bundle();
    const calls = stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register], d);
    expect(r.code).toBe(0);
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(Object.keys(body)).toEqual(["manifest"]);
    expect(body.manifest.component_count).toBeUndefined();
    expect(body.manifest.components_digest).toBeUndefined();
  });

  it("an empty inventory still sends count 0 and the digest of []", async () => {
    const d = bundle();
    writeLock(d, { lockfileVersion: 3, packages: { "": { name: "x" } } });
    const calls = stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register], d);
    expect(r.code).toBe(0);
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(body.components).toEqual([]);
    expect(body.manifest.component_count).toBe(0);
    expect(body.manifest.components_digest).toBe(componentsDigest([]));
  });

  it("sends no components when the lockfile lists dependencies but every one was skipped, and says why", async () => {
    const d = bundle();
    writeLock(d, {
      lockfileVersion: 3,
      packages: {
        "": { name: "x" },
        "node_modules/zq-from-git": { version: "git+https://example.test/zq.git" },
        "node_modules/zq-local": { version: "file:../zq" },
      },
    });
    const calls = stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register], d);
    expect(r.code).toBe(0);
    const body = JSON.parse(calls[0]?.body ?? "{}");
    // An empty list would tell the API the Build ships nothing, and fix every older Finding.
    expect(Object.keys(body)).toEqual(["manifest"]);
    expect(body.manifest.component_count).toBeUndefined();
    expect(r.out).toContain(
      "lockfile lists 2 dependencies but none could be read (all skipped): component inventory off for this Build",
    );
    noPackageNames(r.out + r.err);

    const json = await run(["harden", d, "--seed", "1", "--json", ...register], d);
    expect(JSON.parse(json.out).components).toEqual({ count: 0, skipped: 2, sent: false });
  });

  it("prints open findings counts after register when the response has a summary", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(EXAMPLE_FINDINGS_SUMMARY);
    const r = await run(["harden", d, "--seed", "1", ...register], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain("open findings: critical 0, high 1, medium 0, low 0, unknown 0");
  });

  it("--json carries the findings summary after register", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(EXAMPLE_FINDINGS_SUMMARY);
    const r = await run(["harden", d, "--seed", "1", "--json", ...register], d);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.findings).toEqual(EXAMPLE_FINDINGS_SUMMARY);
    expect(report.components).toEqual({ count: 3, skipped: 2 });
  });
});

describe("--fail-on", () => {
  it("needs --register: exit 2 before any work", async () => {
    const d = bundle();
    writeLock(d);
    const out = join(tempDir("harden-out-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--out", out, "--fail-on", "high"], d);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/--fail-on needs --register/);
    expect(r.out).toBe("");
    expect(existsSync(out)).toBe(false);
  });

  it("rejects an unknown level (and a missing value) with exit 2 before register", async () => {
    const d = bundle();
    writeLock(d);
    const calls = stubRegister();
    for (const level of ["severe", "unknown", "HIGH", ""]) {
      const r = await run(["harden", d, "--seed", "1", ...register, "--fail-on", level], d);
      expect(r.code).toBe(2);
      expect(r.err).toMatch(/--fail-on/);
    }
    const missing = await run(["harden", d, "--seed", "1", ...register, "--fail-on"], d);
    expect(missing.code).toBe(2);
    expect(calls).toEqual([]);
  });

  it("exits 4 when open findings are at or above the level, listing each item", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(SUMMARY_3_HIGH_UP);
    const r = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "high"], d);
    expect(EXIT_FINDINGS).toBe(4);
    expect(r.code).toBe(4);
    expect(r.out).toContain("✗ 3 open findings at or above high");
    expect(r.out).toContain("GHSA-aaaa-bbbb-cccc  example-parser@1.2.3  critical  fixed in 1.2.4");
    expect(r.out).toContain("GHSA-2c3m-4p5q-6r7v  example-parser@1.2.3  high  fixed in 1.2.4, 2.1.1");
    expect(r.out).toContain("GHSA-dddd-eeee-ffff  example-parser@1.2.3  high  no fixed version");
    // Below the level: not listed.
    expect(r.out).not.toContain("GHSA-gggg-hhhh-jjjj");
    expect(r.out).not.toContain("GHSA-kkkk-mmmm-pppp");
    expect(r.err).toMatch(/3 open findings at or above high/);
    noPackageNames(r.out + r.err);
  });

  it("counts every level at or above: medium includes critical and high (unknown never counts)", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(SUMMARY_3_HIGH_UP);
    const r = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "medium"], d);
    expect(r.code).toBe(4);
    expect(r.out).toContain("✗ 7 open findings at or above medium");
    expect(r.out).toContain("GHSA-gggg-hhhh-jjjj  example-parser@1.2.3  medium  fixed in 1.3.0");
    expect(r.out).not.toContain("GHSA-kkkk-mmmm-pppp");
  });

  it("passes (exit 0) when nothing is at or above the level", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister({ ...SUMMARY_3_HIGH_UP, open: { critical: 0, high: 0, medium: 4, low: 2, unknown: 1 } });
    const r = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "high"], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain("✓ no open findings at or above high");
  });

  it("a single finding uses the singular", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(EXAMPLE_FINDINGS_SUMMARY);
    const r = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "critical"], d);
    expect(r.code).toBe(0);
    const low = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "low"], d);
    expect(low.code).toBe(4);
    expect(low.out).toContain("✗ 1 open finding at or above low");
  });

  it("writes --out (the Build is registered) and still exits 4", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(SUMMARY_3_HIGH_UP);
    const out = join(tempDir("harden-out-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...register, "--fail-on", "critical"], d);
    expect(r.code).toBe(4);
    expect(existsSync(join(out, "a.mjs"))).toBe(true);
  });

  it("--json on a failed gate prints the report with the findings and exits 4", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(SUMMARY_3_HIGH_UP);
    const r = await run(["harden", d, "--seed", "1", "--json", ...register, "--fail-on", "high"], d);
    expect(r.code).toBe(4);
    expect(JSON.parse(r.out).findings).toEqual(SUMMARY_3_HIGH_UP);
    expect(JSON.parse(r.out).gate).toEqual({
      level: "high",
      evaluated: true,
      passed: false,
      count: 3,
      unknown_not_counted: 1,
    });
    expect(r.err).toMatch(/3 open findings at or above high/);
  });

  it("without a findings summary in the response, the gate fails closed (exit 4)", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "high"], d);
    expect(r.code).toBe(4);
    expect(r.err).toContain("harden: findings gate could not be evaluated: the API returned no findings summary");
    expect(r.out).toContain("✗ findings gate could not be evaluated: the API returned no findings summary");
    const json = await run(["harden", d, "--seed", "1", "--json", ...register, "--fail-on", "high"], d);
    expect(json.code).toBe(4);
    expect(JSON.parse(json.out).gate).toEqual({
      level: "high",
      evaluated: false,
      passed: false,
      count: 0,
      unknown_not_counted: 0,
    });
  });

  it("reports open unknown-severity findings as not counted (human and --json)", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(SUMMARY_3_HIGH_UP);
    const r = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "high"], d);
    expect(r.out).toContain("+ 1 open finding with unknown severity, not counted");
    stubRegister({ ...SUMMARY_3_HIGH_UP, open: { critical: 0, high: 0, medium: 0, low: 0, unknown: 2 } });
    const pass = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "low"], d);
    expect(pass.code).toBe(0);
    expect(pass.out).toContain("✓ no open findings at or above low");
    expect(pass.out).toContain("+ 2 open findings with unknown severity, not counted");
    const json = await run(["harden", d, "--seed", "1", "--json", ...register, "--fail-on", "low"], d);
    expect(json.code).toBe(0);
    expect(JSON.parse(json.out).gate).toEqual({
      level: "low",
      evaluated: true,
      passed: true,
      count: 0,
      unknown_not_counted: 2,
    });
  });

  it("without --fail-on, --json has gate null", async () => {
    const d = bundle();
    writeLock(d);
    stubRegister(EXAMPLE_FINDINGS_SUMMARY);
    const r = await run(["harden", d, "--seed", "1", "--json", ...register], d);
    expect(JSON.parse(r.out).gate).toBeNull();
  });

  it("a failed register is exit 1, not 4", async () => {
    const d = bundle();
    writeLock(d);
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED");
    });
    const r = await run(["harden", d, "--seed", "1", ...register, "--fail-on", "high"], d);
    expect(r.code).toBe(1);
  });
});
