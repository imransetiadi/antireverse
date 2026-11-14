// Parsers of each check's output: the vitest and Playwright summaries, the Shield bench, a child's GATE-RESULT line,
// the RRS gate reports and npm audit's JSON. Each returns null (or a breach) rather than guessing.
import type { Budget } from "./docs.ts";
import type { State } from "./verdict.ts";

// biome-ignore lint/suspicious/noControlCharactersInRegex: ANSI escape sequences start with ESC
const ANSI = /\u001b\[[0-9;?]*[A-Za-z]/g;
export const stripAnsi = (text: string): string => text.replace(ANSI, "");

export interface VitestSummary {
  files: { passed: number; failed: number; skipped: number; total: number };
  tests: { passed: number; failed: number; skipped: number; todo: number; total: number };
}

function counts(line: string): Record<string, number> & { total: number } {
  const out: Record<string, number> = {};
  for (const m of line.matchAll(/(\d+) (passed|failed|skipped|todo)/g)) out[m[2] as string] = Number(m[1]);
  const total = /\((\d+)\)\s*$/.exec(line);
  return { ...out, total: total ? Number(total[1]) : 0 };
}

/** The last "Test Files … / Tests …" summary of a vitest run. */
export function parseVitestSummary(text: string): VitestSummary | null {
  const lines = stripAnsi(text).split("\n");
  let files: Record<string, number> | null = null;
  let tests: Record<string, number> | null = null;
  for (const line of lines) {
    if (/^\s*Test Files\s/.test(line)) files = counts(line);
    else if (/^\s*Tests\s+\d/.test(line)) tests = counts(line);
  }
  if (!files || !tests) return null;
  return {
    files: {
      passed: files.passed ?? 0,
      failed: files.failed ?? 0,
      skipped: files.skipped ?? 0,
      total: files.total ?? 0,
    },
    tests: {
      passed: tests.passed ?? 0,
      failed: tests.failed ?? 0,
      skipped: tests.skipped ?? 0,
      todo: tests.todo ?? 0,
      total: tests.total ?? 0,
    },
  };
}

export interface PlaywrightSummary {
  passed: number;
  failed: number;
  flaky: number;
  skipped: number;
  didNotRun: number;
  interrupted: number;
  duration: string | null;
}

/** The closing summary of Playwright's list reporter ("  25 passed (3.1m)", "  1 failed", …). */
export function parsePlaywrightSummary(text: string): PlaywrightSummary | null {
  const out: PlaywrightSummary = {
    passed: 0,
    failed: 0,
    flaky: 0,
    skipped: 0,
    didNotRun: 0,
    interrupted: 0,
    duration: null,
  };
  let found = false;
  for (const line of stripAnsi(text).split("\n")) {
    const m = /^\s{2}(\d+) (passed|failed|flaky|skipped|did not run|interrupted)(?: \(([^)]+)\))?\s*$/.exec(line);
    if (!m) continue;
    found = true;
    const n = Number(m[1]);
    const kind = m[2] as string;
    if (kind === "did not run") out.didNotRun = n;
    else out[kind as "passed" | "failed" | "flaky" | "skipped" | "interrupted"] = n;
    if (m[3]) out.duration = m[3];
  }
  return found ? out : null;
}

export interface BenchSample {
  budget: "PB-01" | "PB-02";
  section: string;
  scenario: string;
  p50Us: number;
  p99Us: number;
}

/**
 * The Shield bench's measurements, each with its section and scenario. A section is a line at the margin, or an
 * indented line naming "budget PB-01"; a section naming PB-01 is held to PB-01 (attested routes), any other to PB-02.
 */
export function parseBench(text: string): BenchSample[] {
  const samples: BenchSample[] = [];
  let section = "";
  let budget: BenchSample["budget"] = "PB-02";
  let scenario: string | null = null;
  for (const raw of stripAnsi(text).split("\n")) {
    if (raw.trim() === "") continue;
    const measured = /p50 ([\d.]+) µs\s+p99 ([\d.]+) µs/.exec(raw);
    if (measured) {
      samples.push({
        budget,
        section,
        scenario: scenario ?? section,
        p50Us: Number(measured[1]),
        p99Us: Number(measured[2]),
      });
      continue;
    }
    const header = !/^\s/.test(raw) || /budget PB-01/.test(raw);
    if (header) {
      section = raw.trim();
      budget = /PB-01/.test(raw) ? "PB-01" : "PB-02";
      scenario = null;
    } else if (!/^\s*(Events|Probe):/.test(raw)) {
      scenario = raw.trim();
    }
  }
  return samples;
}

const round = (n: number) => Math.round(n * 1_000) / 1_000;

/**
 * The scenarios the Shield bench measures per budget (packages/shield-node/bench/overhead.bench.ts, 2026-11-14): fewer
 * means a run ended early or a section was not recognised. Raise these when the bench gains scenarios.
 */
export const MIN_BENCH_SAMPLES: Readonly<Record<"PB-01" | "PB-02", number>> = { "PB-01": 14, "PB-02": 17 };

/** Every p50 and p99 against its budget's targets (PERFORMANCE §2, in µs here); anything it cannot judge is a breach. */
export function judgeBench(
  samples: readonly BenchSample[],
  budgets: ReadonlyMap<string, Budget>,
  minSamples: Readonly<Record<"PB-01" | "PB-02", number>> = MIN_BENCH_SAMPLES,
): { breaches: string[]; worst: Record<string, { p50Us: number; p99Us: number }> } {
  const breaches: string[] = [];
  const worst: Record<string, { p50Us: number; p99Us: number }> = {};
  for (const id of ["PB-01", "PB-02"] as const) {
    const own = samples.filter((s) => s.budget === id);
    if (own.length === 0) breaches.push(`no ${id} measurement`);
    else {
      worst[id] = { p50Us: Math.max(...own.map((s) => s.p50Us)), p99Us: Math.max(...own.map((s) => s.p99Us)) };
      if (own.length < minSamples[id])
        breaches.push(`${id}: ${own.length} samples, expected at least ${minSamples[id]}`);
    }
    const budget = budgets.get(id);
    if (!budget || budget.targets.length === 0) breaches.push(`${id}: no target read from PERFORMANCE §2`);
    for (const part of budget?.unparsed ?? []) breaches.push(`${id}: cannot read "${part}" in PERFORMANCE §2`);
    for (const t of budget?.targets ?? []) {
      if (t.percentile !== 50 && t.percentile !== 99) {
        breaches.push(`${id}: cannot evaluate p${t.percentile} (the bench reports p50 and p99)`);
      }
    }
  }
  // In the bench's own order, so the report reads like its output.
  for (const sample of samples) {
    for (const target of budgets.get(sample.budget)?.targets ?? []) {
      const value = target.percentile === 50 ? sample.p50Us : target.percentile === 99 ? sample.p99Us : null;
      const limitUs = round(target.ms * 1_000);
      if (value !== null && value > limitUs) {
        const where = sample.scenario === sample.section ? sample.section : `${sample.section} / ${sample.scenario}`;
        breaches.push(`${sample.budget} p${target.percentile} ${value} µs > ${limitUs} µs: ${where}`);
      }
    }
  }
  return { breaches, worst };
}

/** The last `GATE-RESULT <json>` line a child script printed. */
export function parseResultLine(text: string): unknown {
  const lines = stripAnsi(text)
    .split("\n")
    .filter((l) => l.startsWith("GATE-RESULT "));
  const last = lines.at(-1);
  if (last === undefined) return null;
  try {
    return JSON.parse(last.slice("GATE-RESULT ".length));
  } catch {
    return null;
  }
}

export interface RrsGate {
  result: string;
  rrs: number | null;
  threshold: number;
  status: string | null;
  reason: string | null;
}
export interface RrsVariant {
  profile: string;
  threshold: number;
  exitCode: number | null;
  gate: RrsGate | null;
}
export type RrsRun = { error: string } | { variants: RrsVariant[] };

/** The slice-13 gate's verdict per profile: exit 0 passed, 5 failed (below), 6 no score; anything else fails. */
export function judgeRrs(run: RrsRun): { state: State; lines: string[] } {
  if ("error" in run) return { state: "fail", lines: [`error: ${run.error}`] };
  if (run.variants.length === 0) return { state: "fail", lines: ["no profile was assessed"] };
  const lines: string[] = [];
  let failed = false;
  let unscored = false;
  for (const v of run.variants) {
    const g = v.gate;
    if (g === null) {
      failed = true;
      lines.push(`${v.profile}: no gate report (exit ${v.exitCode})`);
    } else if (g.result === "passed" && v.exitCode === 0 && g.rrs !== null && g.rrs >= v.threshold) {
      lines.push(`${v.profile}: RRS ${g.rrs} ≥ ${v.threshold} (passed)`);
    } else if (g.result === "failed" && v.exitCode === 5) {
      failed = true;
      lines.push(`${v.profile}: RRS ${g.rrs} < ${v.threshold} (failed)`);
    } else if (g.result === "no_score" && v.exitCode === 6) {
      unscored = true;
      lines.push(`${v.profile}: no score from the stand-in (${g.status ?? "unknown"}: ${g.reason ?? "no reason"})`);
    } else {
      failed = true;
      lines.push(`${v.profile}: gate ${g.result} with exit ${v.exitCode}: inconsistent`);
    }
  }
  return { state: failed ? "fail" : unscored ? "not-checkable" : "pass", lines };
}

export interface AuditCounts {
  low: number;
  moderate: number;
  high: number;
  critical: number;
  total: number;
}

/** `npm audit --json`'s vulnerability counts (the JSON object within the output). */
export function parseNpmAudit(text: string): AuditCounts | null {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end < start) return null;
  try {
    const v = (JSON.parse(text.slice(start, end + 1)) as { metadata?: { vulnerabilities?: Record<string, number> } })
      .metadata?.vulnerabilities;
    if (!v) return null;
    return {
      low: v.low ?? 0,
      moderate: v.moderate ?? 0,
      high: v.high ?? 0,
      critical: v.critical ?? 0,
      total: v.total ?? 0,
    };
  } catch {
    return null;
  }
}
