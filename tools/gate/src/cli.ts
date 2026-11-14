// `npm run gate:release [-- --only <ids>] [--skip-slow] [--online]` (slice 18e). Exit 0 releasable, 1 blocked by a
// failed check, 2 blocked only by criteria that cannot be checked, 3 a usage or runner error.
import { join } from "node:path";
import { CHECK_IDS, CRITERIA } from "./catalog.ts";
import { createExecutors } from "./checks.ts";
import { parseArgs, runGate } from "./gate.ts";
import { REPO_ROOT } from "./paths.ts";
import { runCommand } from "./run.ts";
import { defaultKeyFile } from "./sign.ts";
import { EXIT } from "./verdict.ts";

const USAGE = `npm run gate:release -- [options]

Checks the working tree against every line of QASUITE §16 and SECURITY §12 and writes a signed report to
reports/gate/<timestamp>/ (report.json, report.md). Releasable only when every line passes.

Options:
  --only <ids>   Comma-separated check or criterion ids; the others are reported as not checked.
                 Checks: ${CHECK_IDS.join(", ")}
                 Criteria: ${CRITERIA.map((c) => c.id).join(", ")}
  --skip-slow    Skip verify, e2e-browser and bench-shield (reported as not checked, never as passed).
  --online       Also run npm audit (contacts the npm registry).

Key: AR_GATE_KEY_FILE, default $XDG_CONFIG_HOME/airverse/gate-key.json or ~/.config/airverse/gate-key.json
(Ed25519, mode 0600, created on first use, never inside the repository).
Exit: 0 releasable · 1 blocked by a failure · 2 blocked by not-checkable lines only · 3 usage or runner error.
`;

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(USAGE);
    return 0;
  }
  const options = parseArgs(argv);
  const { report, dir, exitCode } = await runGate(options, {
    executors: createExecutors({ root: REPO_ROOT, online: options.online, run: runCommand }),
    outDir: join(REPO_ROOT, "reports", "gate"),
    keyFile: defaultKeyFile(process.env),
    log: (line) => process.stderr.write(`${line}\n`),
  });
  const out: string[] = [];
  out.push(`Verdict: ${report.verdict} (exit ${exitCode})`);
  out.push(`Every checkable criterion passed: ${report.all_checkable_passed ? "yes" : "no"}`);
  for (const c of report.criteria) out.push(`  ${c.state.padEnd(13)} ${c.id}`);
  out.push(`Report: ${join(dir, "report.json")} (signed, key ${report.signature?.fingerprint})`);
  out.push(`        ${join(dir, "report.md")}`);
  process.stdout.write(`${out.join("\n")}\n`);
  return exitCode;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`gate: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = EXIT.error;
  },
);
