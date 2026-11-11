// Slice 10 — the CLI around the Clone Beacon: `--origin` validation (exit 2, before any scan or transform), the
// token derived from the normalised seed, App and version, the report / --json / Manifest additions, the
// integrity wrapper over the planted beacon, and the equivalence gate with the beacon planted.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { BuildManifestSchema, EXAMPLE_BUILD } from "@antireverse/protocol";
import { deriveBeaconToken } from "@antireverse/protocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { beaconStatement } from "../src/beacon.ts";
import { main } from "../src/cli.ts";
import { beaconHostModule } from "./helpers.ts";

const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE";
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

function bundle(files: Record<string, string>): string {
  const d = tempDir("harden-cli10-");
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
    env: opts.env ?? { AR_ADMIN_KEY: KEY },
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

const register = (version = "1.0.0", endpoint = ENDPOINT) => [
  "--register",
  "--endpoint",
  endpoint,
  "--key-env",
  "AR_ADMIN_KEY",
  "--app",
  EXAMPLE_BUILD.app_id,
  "--environment",
  "development",
  "--build-version",
  version,
];

const SHOP = "https://shop.example.com";
const WWW = "https://www.shop.example.com:8443";

describe("--origin validation: exit 2 before any scan or transform", () => {
  // A leaky bundle: if the scan ran, the exit code would be 3, not 2.
  const leaky = () => bundle({ "a.mjs": `export const k = "${AWS_EXAMPLE}";\n${MODULE}` });

  const cases: Array<[string, string[], RegExp]> = [
    ["--origin without --register", ["--origin", SHOP], /--origin needs --register/],
    ["--origin without a value", [...register(), "--origin"], /--origin needs a value/],
    [
      "more than 20 origins",
      [...register(), ...Array.from({ length: 21 }, (_, i) => ["--origin", `https://s${i}.example.com`]).flat()],
      /at most 20/,
    ],
    ["a duplicate origin", [...register(), "--origin", SHOP, "--origin", SHOP], /twice/],
    [
      "a non-canonical origin (shows the canonical form)",
      [...register(), "--origin", "HTTPS://Shop.Example.com:443/"],
      /not canonical.*"https:\/\/shop\.example\.com"/,
    ],
    ["a non-canonical IPv6 origin", [...register(), "--origin", "http://[0:0:0:0:0:0:0:2]:80"], /"http:\/\/\[::2\]"/],
    ["not an origin at all", [...register(), "--origin", "shop.example.com"], /not an http\(s\) origin/],
    ["an origin with a path", [...register(), "--origin", "https://shop.example.com/app"], /not an http\(s\) origin/],
    ["a local origin", [...register(), "--origin", "http://localhost:3000"], /local/],
    ["a private-address origin", [...register(), "--origin", "http://192.168.1.10"], /local/],
    [
      "a non-http(s) endpoint with --origin",
      [...register("1.0.0", "ftp://api.example.test"), "--origin", SHOP],
      /--endpoint/,
    ],
    [
      "an endpoint with credentials with --origin",
      [...register("1.0.0", "https://u:p@api.example.test"), "--origin", SHOP],
      /--endpoint/,
    ],
  ];

  it.each(cases)("%s → exit 2, nothing scanned, written or registered", async (_name, args, message) => {
    const d = leaky();
    const out = join(tempDir("harden-out-"), "out");
    const calls = stubRegister();
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...args], { cwd: d });
    expect(r.code).toBe(2);
    expect(r.err).toMatch(message);
    expect(r.out).toBe("");
    expect(existsSync(out)).toBe(false);
    expect(calls).toEqual([]);
  });

  it("the canonical form of the origin is accepted (exit 0)", async () => {
    const d = bundle({ "a.mjs": MODULE });
    stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register(), "--origin", SHOP], { cwd: d });
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
  });

  it("20 origins are accepted", async () => {
    const d = bundle({ "a.mjs": MODULE });
    stubRegister();
    const origins = Array.from({ length: 20 }, (_, i) => ["--origin", `https://s${i}.example.com`]).flat();
    const r = await run(["harden", d, "--seed", "1", ...register(), ...origins, "--json"], { cwd: d });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).beacon.origins).toHaveLength(20);
  });
});

describe("review fixes F4/F5/F6 in the CLI", () => {
  it("F4: the planted report body carries the --app id", async () => {
    const d = bundle({ "a.mjs": MODULE });
    stubRegister();
    const out = join(tempDir("harden-out-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...register(), "--origin", SHOP, "--json"], {
      cwd: d,
    });
    expect(r.code).toBe(0);
    const line = readFileSync(join(out, "a.mjs"), "utf8")
      .split("\n")
      .find((l) => l.startsWith(";(function"));
    const calls: unknown[][] = [];
    runInNewContext(line ?? "", {
      location: { origin: "https://clone.example.net" },
      navigator: { sendBeacon: (...args: unknown[]) => calls.push(args) },
    });
    expect(JSON.parse(String(calls[0]?.[1]))).toEqual({
      a: EXAMPLE_BUILD.app_id,
      t: JSON.parse(r.out).beacon.token,
      o: "https://clone.example.net",
    });
  });

  it("F5: registration happens before --out is written; a failed register writes nothing (exit 1)", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const out = join(tempDir("harden-out-"), "out");
    // An unreachable endpoint (nothing listens on port 9 of 127.0.0.1).
    const r = await run(
      ["harden", d, "--seed", "1", "--out", out, ...register("1.0.0", "http://127.0.0.1:9"), "--origin", SHOP],
      {
        cwd: d,
      },
    );
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/register failed/);
    expect(existsSync(out)).toBe(false);
    // Also without a beacon.
    const plain = await run(["harden", d, "--seed", "1", "--out", out, ...register("1.0.0", "http://127.0.0.1:9")], {
      cwd: d,
    });
    expect(plain.code).toBe(1);
    expect(existsSync(out)).toBe(false);
  });

  it("F5: on success the files are written after the register call", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const out = join(tempDir("harden-out-"), "out");
    let existedAtRegister: boolean | undefined;
    vi.stubGlobal("fetch", async () => {
      existedAtRegister = existsSync(join(out, "a.mjs"));
      return new Response(JSON.stringify({ build: EXAMPLE_BUILD }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    });
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...register(), "--origin", SHOP], { cwd: d });
    expect(r.code).toBe(0);
    expect(existedAtRegister).toBe(false);
    expect(existsSync(join(out, "a.mjs"))).toBe(true);
  });

  it("F6: an --endpoint containing </script> is refused with --origin (exit 2, before any work)", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const calls = stubRegister();
    for (const endpoint of ["https://api.example.test/</script>", "https://api.example.test/a>b"]) {
      const r = await run(["harden", d, "--seed", "1", ...register("1.0.0", endpoint), "--origin", SHOP], { cwd: d });
      expect(r.code).toBe(2);
      expect(r.err).toMatch(/--endpoint/);
      expect(r.out).toBe("");
    }
    expect(calls).toEqual([]);
  });
});

describe("--origin with --register: planting, report, --json and Manifest", () => {
  it("plants the beacon with the derived token; the Manifest records {token, origins}", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const calls = stubRegister();
    const out = join(tempDir("harden-out-"), "out");
    const r = await run(
      ["harden", d, "--seed", "1", "--out", out, ...register(), "--origin", SHOP, "--origin", WWW, "--json"],
      { cwd: d },
    );
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    const token = deriveBeaconToken(1, { appId: EXAMPLE_BUILD.app_id, version: "1.0.0" });
    const written = readFileSync(join(out, "a.mjs"), "utf8");
    expect(written.endsWith(`${beaconStatement(EXAMPLE_BUILD.app_id, token, [SHOP, WWW], ENDPOINT)}\n`)).toBe(true);

    expect(calls).toHaveLength(1);
    const manifest = BuildManifestSchema.parse(JSON.parse(calls[0]?.body ?? "").manifest);
    expect(manifest.beacon).toEqual({ token, origins: [SHOP, WWW] });

    const report = JSON.parse(r.out);
    expect(report.beacon).toEqual({ token, origins: [SHOP, WWW], planted_in: "a.mjs" });
    expect(report.canaries_planted_in).toBe("a.mjs");
  });

  it("the token uses the normalised seed (A1): --seed -5 equals --seed 4294967291", async () => {
    const d = bundle({ "a.mjs": MODULE });
    stubRegister();
    const a = await run(["harden", d, "--seed", "-5", ...register(), "--origin", SHOP, "--json"], { cwd: d });
    const b = await run(["harden", d, "--seed", "4294967291", ...register(), "--origin", SHOP, "--json"], { cwd: d });
    expect(JSON.parse(a.out).beacon.token).toBe(
      deriveBeaconToken(4294967291, { appId: EXAMPLE_BUILD.app_id, version: "1.0.0" }),
    );
    expect(JSON.parse(a.out).beacon).toEqual(JSON.parse(b.out).beacon);
  });

  it("determinism: same inputs give identical bytes; another version gives another token", async () => {
    const d = bundle({ "a.mjs": MODULE });
    stubRegister();
    const base = tempDir("harden-det-");
    const once = async (name: string, version: string) => {
      const r = await run(
        ["harden", d, "--seed", "7", "--out", join(base, name), ...register(version), "--origin", SHOP, "--json"],
        { cwd: d },
      );
      expect(r.code).toBe(0);
      return { token: JSON.parse(r.out).beacon.token as string, code: readFileSync(join(base, name, "a.mjs"), "utf8") };
    };
    const one = await once("one", "1.0.0");
    const again = await once("again", "1.0.0");
    const next = await once("next", "1.0.1");
    expect(again.code).toBe(one.code);
    expect(next.token).not.toBe(one.token);
    expect(next.code).toContain(next.token);
    expect(next.code).not.toContain(one.token);
  });

  it("human report: '✓ Clone Beacon: on (N origins) in <path>'", async () => {
    const d = bundle({ "a.mjs": MODULE });
    stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register(), "--origin", SHOP, "--origin", WWW], { cwd: d });
    expect(r.code).toBe(0);
    expect(r.out).toContain("✓ Clone Beacon: on (2 origins) in a.mjs");
    const one = await run(["harden", d, "--seed", "1", ...register(), "--origin", SHOP], { cwd: d });
    expect(one.out).toContain("✓ Clone Beacon: on (1 origin) in a.mjs");
  });

  it("without --origin: no beacon planted, no report line, no --json key, no Manifest field", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const calls = stubRegister();
    const out = join(tempDir("harden-out-"), "out");
    const human = await run(["harden", d, "--seed", "1", "--out", out, ...register()], { cwd: d });
    expect(human.code).toBe(0);
    expect(human.out).not.toContain("Clone Beacon");
    expect(readFileSync(join(out, "a.mjs"), "utf8")).not.toContain("sendBeacon");
    const json = await run(["harden", d, "--seed", "1", ...register(), "--json"], { cwd: d });
    expect(JSON.parse(json.out)).not.toHaveProperty("beacon");
    for (const c of calls) expect(JSON.parse(c.body).manifest).not.toHaveProperty("beacon");
  });

  it("fails (exit 1) when no file can hold the Canaries and the beacon within budget", async () => {
    const d = bundle({ "a.mjs": "export const q = (n) => n;\n" });
    const calls = stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register(), "--origin", SHOP], { cwd: d });
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/Canaries and the Clone Beacon/);
    expect(calls).toEqual([]);
  });

  it("--integrity wraps the planted beacon: the self-check passes and the beacon fires in a fake browser", async () => {
    const script = `(function () { globalThis.__ar_probe = 6 * 7; })();\n${MODULE.replace(/export /g, "")}`;
    const d = bundle({ "bundle.js": script });
    stubRegister();
    const out = join(tempDir("harden-int-"), "out");
    const r = await run(
      ["harden", d, "--seed", "1", "--integrity", "--out", out, ...register(), "--origin", SHOP, "--json"],
      { cwd: d },
    );
    expect(r.code).toBe(0);
    const token = JSON.parse(r.out).beacon.token as string;
    const wrapped = readFileSync(join(out, "bundle.js"), "utf8");
    expect(wrapped).toContain(token);
    const browser = (origin: string) => {
      const calls: unknown[][] = [];
      const context: Record<string, unknown> = {
        location: { origin },
        navigator: { sendBeacon: (...args: unknown[]) => calls.push(args) },
      };
      runInNewContext(wrapped, context);
      return { calls, probe: runInNewContext("globalThis.__ar_probe", context) };
    };
    expect(browser("https://clone.example.net")).toEqual({
      calls: [
        [
          `${ENDPOINT}/v1/beacon`,
          JSON.stringify({ a: EXAMPLE_BUILD.app_id, t: token, o: "https://clone.example.net" }),
        ],
      ],
      probe: 42,
    });
    expect(browser(SHOP)).toEqual({ calls: [], probe: 42 });
    // Tampering with the beacon inside the payload trips the integrity check.
    const tampered = wrapped.replace(token, `bcn_${"0".repeat(24)}`);
    expect(() => runInNewContext(tampered, { location: { origin: SHOP }, navigator: {} })).toThrow(/integrity/);
  });

  it("the equivalence gate passes with the beacon planted (--test)", async () => {
    const d = bundle({
      "src/a.mjs": MODULE,
      "check.mjs": `import { table, SKUS } from "./src/a.mjs";\nif (table().length !== 6 || SKUS.length !== 200) process.exit(1);\nconsole.log("ok");\n`,
    });
    stubRegister();
    const r = await run(
      ["harden", d, "--seed", "3", ...register(), "--origin", SHOP, "--test", "node check.mjs", "--json"],
      { cwd: d },
    );
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.equivalence).toBe("passed");
    expect(report.beacon.planted_in).toBe(report.canaries_planted_in);
  });
});
