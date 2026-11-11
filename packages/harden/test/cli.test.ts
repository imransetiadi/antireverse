import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { EXAMPLE_BUILD } from "@antireverse/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.ts";
import { hardenBundle } from "../src/engine.ts";

let dir = "";
afterEach(() => {
  vi.unstubAllGlobals();
  if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  dir = "";
});

// Slice 07: every Build gets Canaries planted within the size budget, so the default bundle is a realistic
// module rather than a one-liner (a one-line file cannot hold the planted statement within 35%). It is sized
// to hold them comfortably for every seed (pinned by a test below), since runs without --seed use a random one.
const DEFAULT_MODULE = `
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
export function invoice(lines, tier) {
  const subtotal = lines.reduce((sum, line) => sum + line.quantity * priceOf(tier), 0);
  const tax = Math.round(subtotal * 0.21);
  return { subtotal, tax, total: subtotal + tax, currency: "EUR", note: "VAT reverse-charged for EU businesses" };
}
export function summary(lines, tier) {
  const { total, currency } = invoice(lines, tier);
  return lines.length + " line(s) on the " + tier + " plan, total " + format(total) + " (" + currency + ")";
}
export function compareTiers(firstTier, secondTier) {
  const firstPrice = priceOf(firstTier);
  const secondPrice = priceOf(secondTier);
  const difference = Math.abs(firstPrice - secondPrice);
  const cheaperTier = firstPrice <= secondPrice ? firstTier : secondTier;
  return { cheaperTier, difference, formattedDifference: format(difference) };
}
export function recommend(expectedSeats, budgetCents) {
  const affordableTiers = Object.keys(TIERS).filter((tier) => priceOf(tier) * expectedSeats <= budgetCents);
  affordableTiers.sort((left, right) => priceOf(right) - priceOf(left));
  return affordableTiers.length > 0 ? affordableTiers[0] : "free";
}
export const q = (n) => "v" + n;
`;

function bundle(code = DEFAULT_MODULE): string {
  dir = mkdtempSync(join(tmpdir(), "harden-cli-"));
  writeFileSync(join(dir, "index.mjs"), code, "utf8");
  return dir;
}

/** Captures stdout/stderr and returns the exit code plus the captured text. */
async function run(
  argv: string[],
  env: Record<string, string> = {},
): Promise<{ code: number; out: string; err: string }> {
  let out = "";
  let err = "";
  const code = await main(argv, {
    env,
    cwd: dir || tmpdir(),
    stdout: (s) => {
      out += s;
    },
    stderr: (s) => {
      err += s;
    },
  });
  return { code, out, err };
}

describe("antireverse CLI", () => {
  it("prints a JSON report with --json and exits zero", async () => {
    const d = bundle();
    const { code, out } = await run(["harden", d, "--profile", "balanced", "--seed", "1", "--json"]);
    expect(code).toBe(0);
    const report = JSON.parse(out);
    expect(report.profile).toBe("balanced");
    expect(report.transform).toBeDefined();
    expect(Array.isArray(report.files)).toBe(true);
    expect(report.files[0].path).toBe("index.mjs");
  });

  it("prints a short human report by default", async () => {
    const d = bundle();
    const { code, out } = await run(["harden", d, "--profile", "light", "--seed", "1"]);
    expect(code).toBe(0);
    expect(out).toMatch(/profile/i);
    expect(out).toMatch(/light/);
  });

  it("exits non-zero when a file cannot be parsed", async () => {
    const d = bundle("export function ( {{{ broken");
    const { code } = await run(["harden", d, "--profile", "balanced", "--seed", "1", "--json"]);
    expect(code).not.toBe(0);
  });

  it("reads the admin key only from the named env var and never prints it", async () => {
    const d = bundle();
    const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    let seenAuth = "";
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      seenAuth = new Headers(init.headers).get("authorization") ?? "";
      return new Response(JSON.stringify({ build: EXAMPLE_BUILD }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    });
    const { code, out, err } = await run(
      [
        "harden",
        d,
        "--profile",
        "balanced",
        "--seed",
        "1",
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
        "--json",
      ],
      { AR_ADMIN_KEY: KEY },
    );
    expect(code).toBe(0);
    expect(seenAuth).toBe(`Bearer ${KEY}`);
    expect(out).not.toContain(KEY);
    expect(err).not.toContain(KEY);
  });

  it("fails clearly when --register is asked but the key env var is unset", async () => {
    const d = bundle();
    const { code, err } = await run([
      "harden",
      d,
      "--profile",
      "balanced",
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
    ]);
    expect(code).not.toBe(0);
    expect(err).toMatch(/AR_ADMIN_KEY|key/i);
  });

  it("states responsible use in --help", async () => {
    const { code, out } = await run(["--help"]);
    expect(code).toBe(0);
    expect(out).toMatch(/own/i);
    expect(out).toMatch(/behaviou?r/i);
  });

  it("the default test bundle holds the Canaries for every seed (no CLI test depends on the random seed)", () => {
    for (const profile of ["light", "balanced"] as const) {
      for (let i = 0; i < 50; i++) {
        const seed = (Math.imul(i + 1, 0x9e3779b1) ^ i) >>> 0;
        const result = hardenBundle({ sources: { "index.mjs": DEFAULT_MODULE } }, { profile, seed });
        expect(result.plantError, `${profile} seed ${seed}`).toBeUndefined();
        expect(result.plantedIn).toBe("index.mjs");
        // Comfortably inside the 35% budget, not borderline: at most 30% with the Canaries planted.
        const gz = (code: string) => gzipSync(Buffer.from(code, "utf8")).length;
        const overhead = ((gz(result.files[0]?.code ?? "") - gz(DEFAULT_MODULE)) / gz(DEFAULT_MODULE)) * 100;
        expect(overhead, `${profile} seed ${seed}`).toBeLessThanOrEqual(30);
      }
    }
  });

  it("validates --register arguments before any scan or transform (a missing key wins over an unplantable bundle)", async () => {
    const d = bundle("export const q = (n) => n;\n"); // too small to hold the Canaries
    const base = ["harden", d, "--profile", "balanced", "--seed", "1"];
    const unset = await run([
      ...base,
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
    ]);
    expect(unset.code).toBe(2);
    expect(unset.err).toMatch(/AR_ADMIN_KEY/);
    expect(unset.err).not.toMatch(/Canar/);

    const missingFlags = await run([...base, "--register", "--endpoint", "https://api.example.test"]);
    expect(missingFlags.code).toBe(2);
    expect(missingFlags.err).toMatch(/--register needs/);

    const badEnv = await run(
      [
        ...base,
        "--register",
        "--endpoint",
        "https://api.example.test",
        "--key-env",
        "AR_ADMIN_KEY",
        "--app",
        EXAMPLE_BUILD.app_id,
        "--environment",
        "moon",
        "--build-version",
        "1.0.0",
      ],
      { AR_ADMIN_KEY: "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ" },
    );
    expect(badEnv.code).toBe(2);
    expect(badEnv.err).toMatch(/environment/);
  });

  it.each(["dist", "build", "node_modules"])(
    "finds the sources of a bundle whose absolute path has a '%s' segment (skip list is relative)",
    async (segment) => {
      dir = mkdtempSync(join(tmpdir(), "harden-cli-"));
      const nested = join(dir, segment, "app");
      mkdirSync(nested, { recursive: true });
      writeFileSync(join(nested, "index.mjs"), DEFAULT_MODULE, "utf8");
      // A skipped directory INSIDE the bundle is still skipped.
      mkdirSync(join(nested, "node_modules", "dep"), { recursive: true });
      writeFileSync(join(nested, "node_modules", "dep", "x.mjs"), "export const x = 1;\n", "utf8");
      const { code, out, err } = await run(["harden", nested, "--seed", "1", "--json"]);
      expect(err).toBe("");
      expect(code).toBe(0);
      expect(JSON.parse(out).files.map((f: { path: string }) => f.path)).toEqual(["index.mjs"]);
    },
  );
});
