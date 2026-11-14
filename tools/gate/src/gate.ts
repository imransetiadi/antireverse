// The release-gate runner (slice 18e): runs the selected checks one after another, decides the tri-state verdict over
// the catalog, and writes the signed JSON report and its Markdown rendering.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CHECK_IDS, CHECKS, type CheckId, CRITERIA, type Criterion, catalogDrift, validateCatalog } from "./catalog.ts";
import type { Executors } from "./checks.ts";
import { checklist, performanceBudgets, requireTargets, sloTargets } from "./docs.ts";
import { loadTargets } from "./load.ts";
import { REPO_ROOT } from "./paths.ts";
import { type Report, renderMarkdown } from "./report.ts";
import { loadRrsBaseline } from "./rrs-baseline.ts";
import { loadOrCreateKey, signReport } from "./sign.ts";
import { type CheckResult, decide } from "./verdict.ts";

export interface GateOptions {
  /** Check ids to run; null: all. */
  only: CheckId[] | null;
  skipSlow: boolean;
  online: boolean;
}

export function parseArgs(argv: readonly string[]): GateOptions {
  const options: GateOptions = { only: null, skipSlow: false, online: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (arg === "--skip-slow") options.skipSlow = true;
    else if (arg === "--online") options.online = true;
    else if (arg === "--only") {
      const value = argv[++i];
      if (value === undefined || value.startsWith("--")) throw new Error("--only needs a comma-separated list of ids");
      const ids: CheckId[] = [];
      for (const id of value
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)) {
        if ((CHECK_IDS as string[]).includes(id)) ids.push(id as CheckId);
        else {
          const criterion = CRITERIA.find((c) => c.id === id);
          if (!criterion) throw new Error(`unknown check or criterion ${id}`);
          ids.push(...(criterion.checks as CheckId[]));
        }
      }
      options.only = [...new Set(ids)];
    } else throw new Error(`unknown option ${arg}`);
  }
  return options;
}

export interface GateEnv {
  executors: Executors;
  /** Reports go to <outDir>/<timestamp>/. */
  outDir: string;
  keyFile: string;
  now?: () => Date;
  root?: string;
  log?: (line: string) => void;
  /** The catalog; default CRITERIA (tests inject broken ones). */
  criteria?: readonly Criterion[];
}

/** The gate's own consistency, shown as a criterion: the catalog against the documents, and every input it reads. */
const INTEGRITY: Criterion = {
  id: "gate-integrity",
  title: "The gate's inputs are consistent",
  source: {
    doc: "gate",
    section: "preflight",
    text: "The catalog matches QASUITE §16 and SECURITY §12; the budgets, SLO targets and stand-in baseline it reads are complete and agree.",
  },
  checks: ["gate-preflight"],
  gaps: [],
  requires: [],
  integrity: true,
};

/** Every problem with the gate's inputs (review M2, M3): drift, unreadable or disagreeing targets, the baseline. */
export function preflight(root: string, criteria: readonly Criterion[]): string[] {
  const problems: string[] = [];
  const read = (doc: string) => {
    try {
      return readFileSync(join(root, doc), "utf8");
    } catch {
      problems.push(`${doc}: cannot be read`);
      return undefined;
    }
  };
  const docs: Record<string, string> = {};
  for (const doc of ["QASUITE.md", "SECURITY.md"]) {
    const text = read(doc);
    if (text !== undefined) docs[doc] = text;
  }
  problems.push(...catalogDrift(docs, criteria));
  const perf = read("PERFORMANCE.md");
  if (perf !== undefined) {
    const attempt = (what: () => unknown) => {
      try {
        what();
      } catch (error) {
        problems.push(error instanceof Error ? error.message : String(error));
      }
    };
    const budgets = performanceBudgets(perf);
    for (const id of ["PB-01", "PB-02"]) attempt(() => requireTargets(budgets, id));
    attempt(() => loadTargets(budgets, sloTargets(perf)));
  }
  try {
    loadRrsBaseline(root);
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
  }
  return problems;
}

function git(root: string, args: string[]): string {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "unknown";
  }
}

function toolVersions(root: string): Record<string, string> {
  const pkg = (name: string) => {
    try {
      return (JSON.parse(readFileSync(join(root, "node_modules", name, "package.json"), "utf8")) as { version: string })
        .version;
    } catch {
      return "missing";
    }
  };
  let npm = "unknown";
  try {
    npm = execFileSync("npm", ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {}
  return {
    node: process.version,
    npm,
    typescript: pkg("typescript"),
    vitest: pkg("vitest"),
    "@playwright/test": pkg("@playwright/test"),
    "@biomejs/biome": pkg("@biomejs/biome"),
    tsx: pkg("tsx"),
  };
}

/** A directory of its own per run: <outDir>/<timestamp>-<6 random characters>. */
function reportDir(outDir: string, at: Date): string {
  const stamp = at
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z")
    .replace(/:/g, "-");
  mkdirSync(outDir, { recursive: true });
  return mkdtempSync(join(outDir, `${stamp}-`));
}

export async function runGate(
  options: GateOptions,
  env: GateEnv,
): Promise<{ report: Report; dir: string; exitCode: number }> {
  const root = env.root ?? REPO_ROOT;
  const catalog = env.criteria ?? CRITERIA;
  // A broken catalog is a runner error (exit 3), before any check runs.
  const catalogErrors = validateCatalog(catalog, CHECKS);
  if (catalogErrors.length > 0) throw new Error(`catalog: ${catalogErrors.join("; ")}`);
  const now = env.now ?? (() => new Date());
  const log = env.log ?? (() => {});
  // The key first: a key the gate cannot use stops it before an hour of checks.
  const key = loadOrCreateKey(env.keyFile);
  if (key.created) log(`created the gate key ${key.file} (fingerprint ${key.fingerprint})`);
  const started = now();
  const t0 = performance.now();

  const problems = preflight(root, catalog);
  const results: CheckResult[] = [
    {
      id: "gate-preflight",
      state: problems.length === 0 ? "pass" : "fail",
      summary: problems.length === 0 ? "catalog, budgets, SLO targets and baseline consistent" : problems.join("; "),
    },
  ];
  if (problems.length > 0) log(`gate inputs inconsistent: ${problems.join("; ")}`);
  for (const id of CHECK_IDS) {
    const spec = CHECKS[id];
    if (options.only !== null && !options.only.includes(id)) {
      results.push({ id, state: "not-checkable", summary: "not selected (--only)" });
      continue;
    }
    if (spec.online && !options.online) {
      results.push({ id, state: "not-checkable", summary: "needs the registry: run with --online" });
      continue;
    }
    if (spec.slow && options.skipSlow) {
      results.push({ id, state: "not-checkable", summary: "skipped (--skip-slow): not checked" });
      continue;
    }
    log(`▶ ${id}: ${spec.title}`);
    let result: CheckResult;
    try {
      result = await env.executors[id]();
    } catch (error) {
      result = { id, state: "fail", summary: `error: ${error instanceof Error ? error.message : String(error)}` };
    }
    log(`  ${result.state}: ${result.summary}`);
    results.push(result);
  }

  const criteria = [INTEGRITY, ...catalog];
  const decision = decide(criteria, results);
  const lines = new Map<string, number>();
  for (const doc of ["QASUITE.md", "SECURITY.md"] as const) {
    const sectionId = doc === "QASUITE.md" ? "16" : "12";
    try {
      for (const l of checklist(readFileSync(join(root, doc), "utf8"), sectionId))
        lines.set(`${doc}\n${l.text}`, l.line);
    } catch {
      // Reported by the preflight.
    }
  }
  const report: Report = {
    schema: "airverse.release-gate/1",
    generated_at: started.toISOString(),
    duration_ms: Math.round(performance.now() - t0),
    git: {
      commit: git(root, ["rev-parse", "HEAD"]),
      branch: git(root, ["rev-parse", "--abbrev-ref", "HEAD"]),
      dirty: git(root, ["status", "--porcelain"]) !== "",
    },
    tools: toolVersions(root),
    options: { only: options.only, skip_slow: options.skipSlow, online: options.online },
    partial: options.only !== null,
    verdict: decision.verdict,
    all_checkable_passed: decision.allCheckablePassed,
    exit_code: decision.exitCode,
    reasons: decision.reasons,
    criteria: criteria.map((c, i) => ({
      id: c.id,
      title: c.title,
      state: decision.criteria[i]?.state ?? "not-checkable",
      source: { ...c.source, line: lines.get(`${c.source.doc}\n${c.source.text}`) ?? null },
      checks: c.checks,
      gaps: c.gaps,
      requires: c.requires,
      notes: c.notes ?? [],
      reasons: decision.criteria[i]?.reasons ?? [],
    })),
    checks: results.map((r) => ({
      id: r.id,
      title: r.id === "gate-preflight" ? "The gate's own inputs" : (CHECKS[r.id as CheckId]?.title ?? r.id),
      state: r.state,
      summary: r.summary,
      command: r.command ?? null,
      duration_ms: r.durationMs ?? null,
      excerpt: r.excerpt ?? null,
      measurements: r.measurements ?? {},
    })),
  };
  const signed = signReport(report, key);
  const dir = reportDir(env.outDir, started);
  writeFileSync(join(dir, "report.json"), `${JSON.stringify(signed, null, 2)}\n`);
  writeFileSync(join(dir, "report.md"), renderMarkdown(signed));
  return { report: signed, dir, exitCode: decision.exitCode };
}
