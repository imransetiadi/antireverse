// `npm run gate:verify-report -- <report.json | report directory> [--expect <fingerprint>]` (slice 18e): checks the
// report's Ed25519 signature against the public key it embeds, and trusts that key only when it is the local gate key
// or the fingerprint given with --expect (review M4). Exit 0 valid and trusted, 1 invalid or untrusted, 2 usage.
// Never creates a key.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { defaultKeyFile, loadOrCreateKey, verifyReport } from "./sign.ts";

const USAGE = "usage: npm run gate:verify-report -- <report.json | report directory> [--expect <fingerprint>]\n";

function main(): number {
  const args = process.argv.slice(2);
  let expect: string | undefined;
  const paths: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === "--expect") {
      expect = args[++i];
      if (expect === undefined || !/^[0-9a-f]{64}$/.test(expect)) {
        process.stderr.write(`--expect needs a 64-character hex fingerprint\n${USAGE}`);
        return 2;
      }
    } else if (arg === "--help" || arg.startsWith("--")) {
      process.stderr.write(USAGE);
      return 2;
    } else paths.push(arg);
  }
  if (paths.length !== 1) {
    process.stderr.write(USAGE);
    return 2;
  }
  const path = resolve(process.env.INIT_CWD ?? process.cwd(), paths[0] as string);
  const file = existsSync(path) && statSync(path).isDirectory() ? join(path, "report.json") : path;
  if (!existsSync(file)) {
    process.stderr.write(`no report at ${file}\n`);
    return 2;
  }
  let report: unknown;
  try {
    report = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    process.stdout.write(`INVALID: ${file} is not JSON\n`);
    return 1;
  }
  const result = verifyReport(report);
  if (!result.ok) {
    process.stdout.write(`INVALID: ${result.reason} (${file})\n`);
    return 1;
  }
  const keyFile = defaultKeyFile(process.env);
  let local: string | null = null;
  let localNote = "no local gate key";
  if (existsSync(keyFile)) {
    try {
      local = loadOrCreateKey(keyFile).fingerprint;
      localNote = `the local gate key: ${local === result.fingerprint ? "yes" : "no"}`;
    } catch (error) {
      localNote = `the local gate key could not be read (${error instanceof Error ? error.message : String(error)})`;
    }
  }
  const verdict = (report as { verdict?: string }).verdict ?? "?";
  const trusted = result.fingerprint === local || (expect !== undefined && result.fingerprint === expect);
  if (!trusted) {
    process.stdout.write(
      `UNTRUSTED KEY: the signature is valid but by ${result.fingerprint}, which is neither the local gate key nor --expect (${localNote}); ${file}\n`,
    );
    return 1;
  }
  const by = result.fingerprint === local ? localNote : "the fingerprint given with --expect";
  process.stdout.write(`valid: Ed25519 signature by ${result.fingerprint} (${by}); verdict ${verdict}; ${file}\n`);
  return 0;
}

process.exitCode = main();
