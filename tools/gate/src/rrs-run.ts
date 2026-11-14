// The stand-in regression check's child (slice 18e; D-097): the slice-13 RRS gate on the reference Build with the
// stand-in agent, at the baseline recorded in tools/gate/baselines/rrs-stand-in.json (TC-PRV-006 itself waits for a
// real AI agent). Starts the API on a free loopback port with a temporary data directory and the default (stand-in)
// assessor, builds the reference app (apps/range/web) as one ES module, and runs the real CLI
// `antireverse harden … --register --assess <tier> --min-rrs <baseline> --json` once per profile of the baseline.
// Prints one `GATE-RESULT {"variants":[…]}` line. The admin key is passed to the CLI in the environment only and
// never printed.
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startApi } from "@antireverse/api";
import { EXAMPLE_ROUTE_INVENTORY } from "@antireverse/protocol";
import { buildSync } from "esbuild";
import type { RrsVariant } from "./parsers.ts";
import { REPO_ROOT } from "./paths.ts";
import { loadRrsBaseline } from "./rrs-baseline.ts";

const KEY_ENV = "AR_GATE_ADMIN_KEY";
const ESM_CHECK = `import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
const web = await import(pathToFileURL("bundle.mjs").href);
assert.equal(web.quote("pro", 10), "€17.10");
assert.equal(web.quote("business"), "€49.00");
console.log("ok");
`;

function cli(
  args: string[],
  cwd: string,
  key: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs"), join(REPO_ROOT, "packages/harden/src/cli.ts"), ...args],
      { cwd, env: { ...process.env, [KEY_ENV]: key }, maxBuffer: 16 * 1024 * 1024, timeout: 15 * 60_000 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : null;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
}

async function main(): Promise<void> {
  const baseline = loadRrsBaseline(REPO_ROOT);
  const temp = mkdtempSync(join(tmpdir(), "airverse-gate-rrs-"));
  const api = await startApi({
    host: "127.0.0.1",
    port: 0,
    dataDir: join(temp, "data", "pg"),
    logger: { info() {}, warn() {} },
    smtp: null,
  });
  try {
    if (/:(8787|3000)$/.test(api.url)) throw new Error(`refusing a reserved port: ${api.url}`);
    const post = async (path: string, body: unknown, key?: string) => {
      const res = await fetch(`${api.url}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", ...(key ? { authorization: `Bearer ${key}` } : {}) },
        body: JSON.stringify(body),
      });
      if (res.status !== 201) throw new Error(`POST ${path}: ${res.status}`);
      return res.json() as Promise<Record<string, { key?: string; id?: string }>>;
    };
    const admin = (await post("/v1/organizations", { name: "Gate RRS" })).admin_key?.key as string;
    const appId = (await post("/v1/apps", { name: "ar-range-web" }, admin)).app?.id as string;

    // The reference Build, as in tests/e2e/reverse-assessment-12b.http.test.ts: one ES module, the route inventory and
    // the reference logic file (W3), and an equivalence check the protected copy must pass.
    const work = join(temp, "ci");
    const bundleDir = join(temp, "bundle", "web");
    mkdirSync(work, { recursive: true });
    mkdirSync(bundleDir, { recursive: true });
    buildSync({
      entryPoints: [join(REPO_ROOT, "apps/range/web/src/index.ts")],
      bundle: true,
      format: "esm",
      outfile: join(bundleDir, "bundle.mjs"),
      logLevel: "error",
    });
    writeFileSync(join(work, "routes.json"), JSON.stringify(EXAMPLE_ROUTE_INVENTORY));
    writeFileSync(join(work, "logic.json"), readFileSync(join(REPO_ROOT, "tests/e2e/fixtures/reference-logic.json")));
    writeFileSync(join(work, "check-esm.mjs"), ESM_CHECK);

    const variants: RrsVariant[] = [];
    let n = 0;
    for (const [profile, threshold] of Object.entries(baseline.profiles)) {
      n += 1;
      const run = await cli(
        [
          "harden",
          bundleDir,
          "--profile",
          profile,
          "--seed",
          "1",
          "--test",
          `node ${join(work, "check-esm.mjs")}`,
          "--routes",
          "routes.json",
          "--logic",
          "logic.json",
          "--register",
          "--endpoint",
          api.url,
          "--key-env",
          KEY_ENV,
          "--app",
          appId,
          "--environment",
          "development",
          "--build-version",
          `18.5.${n}`,
          "--assess",
          baseline.tier,
          "--min-rrs",
          String(threshold),
          "--wait",
          "600",
          "--json",
        ],
        work,
        admin,
      );
      let gate: RrsVariant["gate"] = null;
      try {
        const report = JSON.parse(run.stdout) as { rrs_gate?: RrsVariant["gate"] & { weakest?: unknown } };
        gate = report.rrs_gate ?? null;
      } catch {
        process.stderr.write(`${profile}: no JSON report (exit ${run.code}): ${run.stderr.slice(-2_000)}\n`);
      }
      process.stderr.write(`${profile}: exit ${run.code}, gate ${JSON.stringify(gate)}\n`);
      variants.push({ profile, threshold, exitCode: run.code, gate });
    }
    process.stdout.write(
      `GATE-RESULT ${JSON.stringify({ variants, baseline: { recorded: baseline.recorded, decision: baseline.decision } })}\n`,
    );
  } finally {
    await api.close();
    rmSync(temp, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  process.stdout.write(
    `GATE-RESULT ${JSON.stringify({ error: error instanceof Error ? error.message : String(error) })}\n`,
  );
  process.exitCode = 1;
});
