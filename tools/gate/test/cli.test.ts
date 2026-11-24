// Slice 18e: the two commands as the user runs them — `gate:verify-report <path>` (exit 0 valid, 1 invalid, 2 usage)
// and `gate:release --help` / a bad option (exit 3, nothing run).
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "../src/paths.ts";
import { loadOrCreateKey, signReport } from "../src/sign.ts";

const dir = mkdtempSync(join(tmpdir(), "gate-cli-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
const tsx = join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs");

function run(script: string, args: string[], env: Record<string, string> = {}) {
  return new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
    execFile(
      process.execPath,
      [tsx, join(REPO_ROOT, "tools/gate/src", script), ...args],
      { cwd: REPO_ROOT, env: { ...process.env, ...env } },
      (error, stdout, stderr) =>
        resolve({ code: error ? (typeof error.code === "number" ? error.code : -1) : 0, stdout, stderr }),
    );
  });
}

describe("gate:verify-report", () => {
  const keyFile = join(dir, "key", "gate-key.json");
  const key = loadOrCreateKey(keyFile);
  const report = { schema: "airverse.release-gate/1", verdict: "blocked", criteria: [] };
  const good = join(dir, "good");
  const bad = join(dir, "bad.json");
  // A report directory (report.json inside) and a tampered file.
  mkdirSync(good);
  writeFileSync(join(good, "report.json"), JSON.stringify(signReport(report, key)));
  writeFileSync(bad, JSON.stringify({ ...signReport(report, key), verdict: "releasable" }));

  it("accepts a report directory, says it verifies and whether the local gate key signed it", async () => {
    const out = await run("verify-cli.ts", [good], { AR_GATE_KEY_FILE: keyFile });
    expect(out.code, out.stderr).toBe(0);
    expect(out.stdout).toContain(`valid: Ed25519 signature by ${key.fingerprint}`);
    expect(out.stdout).toContain("the local gate key: yes");
  });

  it("refuses a tampered report with exit 1", async () => {
    const out = await run("verify-cli.ts", [bad], { AR_GATE_KEY_FILE: keyFile });
    expect(out.code).toBe(1);
    expect(out.stdout + out.stderr).toContain("INVALID: signature does not verify");
  });

  it("exits 2 without a path or for a missing file", async () => {
    expect((await run("verify-cli.ts", [])).code).toBe(2);
    expect((await run("verify-cli.ts", [join(dir, "nope.json")])).code).toBe(2);
  });
});

describe("gate:release", () => {
  it("exits 3 on an unknown option, before running anything", async () => {
    const out = await run("cli.ts", ["--fast"], { AR_GATE_KEY_FILE: join(dir, "k2.json") });
    expect(out.code).toBe(3);
    expect(out.stderr).toContain("unknown option --fast");
  });

  it("prints its usage with --help", async () => {
    const out = await run("cli.ts", ["--help"]);
    expect(out.code).toBe(0);
    expect(out.stdout).toMatch(/--only <ids>/);
    expect(out.stdout).toMatch(/--skip-slow/);
    expect(out.stdout).toMatch(/--online/);
    // Slice 18h: the local upgrade, rollback and kill-switch checks can be run on their own.
    for (const id of ["upgrade-local", "rollback-local", "kill-switch-drill"]) {
      expect(out.stdout).toMatch(new RegExp(`Checks: .*\\b${id}\\b`));
      expect(out.stdout).toMatch(new RegExp(`Criteria: .*\\bgate-${id.replace("-drill", "")}`));
    }
    // Slice 23: so can the five SDK checks.
    for (const id of [
      "sdk-reproducible",
      "sdk-install-smoke",
      "sdk-equivalence",
      "sdk-sbom-allowlist",
      "sdk-signed-manifest",
    ]) {
      expect(out.stdout).toMatch(new RegExp(`Checks: .*\\b${id}\\b`));
    }
    expect(out.stdout).toMatch(/Criteria: .*\bgate-sdk-artifacts-local\b/);
  });
});
