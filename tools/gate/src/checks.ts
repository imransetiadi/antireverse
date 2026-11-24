// The runnable checks (slice 18e). Each starts a child process with a timeout, parses what it printed, and returns
// pass / fail / not-checkable with evidence: the command, the duration, a trimmed excerpt and the measured numbers.
// A test that was skipped, left as todo or did not run is never a pass (review H1); an exit code or signal that does
// not match the parsed result fails the check (M1).
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CheckId } from "./catalog.ts";
import { performanceBudgets, sloTargets } from "./docs.ts";
import { judgeLoad, type LoadRun, loadTargets } from "./load.ts";
import { fixedFileProblems, judgeMatrixJson, MATRICES, selectMatrixFiles } from "./matrix.ts";
import {
  judgeBench,
  judgeRrs,
  parseBench,
  parseNpmAudit,
  parsePlaywrightSummary,
  parseResultLine,
  parseVitestSummary,
  type RrsRun,
} from "./parsers.ts";
import { type RunOptions, type RunResult, trimOutput } from "./run.ts";
import type { CheckResult, State } from "./verdict.ts";

export interface CheckContext {
  root: string;
  /** With --online: npm may contact the registry. Without it every npm child runs offline. */
  online?: boolean;
  run(options: RunOptions): Promise<RunResult>;
}

export type Executors = Record<CheckId, () => Promise<CheckResult>>;

const MINUTE = 60_000;
const EXCERPT = { lines: 40, chars: 4_000 };
/** The ports of the Playwright config's web servers (tests/e2e/playwright.config.ts); never 8787 or 3000. */
export const E2E_PORTS = [18_787, 13_000] as const;

function evidence(
  id: CheckId,
  command: string,
  run: RunResult,
  state: State,
  summary: string,
  measurements?: Record<string, number | string>,
): CheckResult {
  const timedOut = run.timedOut ? `timed out after ${Math.round(run.durationMs / 1_000)} s; ` : "";
  const signalled = run.signal !== null && !run.timedOut ? `ended by ${run.signal}; ` : "";
  return {
    id,
    state: run.timedOut || run.signal !== null ? "fail" : state,
    summary: `${timedOut}${signalled}${summary}`,
    command,
    durationMs: run.durationMs,
    excerpt: trimOutput(run.output, EXCERPT),
    ...(measurements === undefined ? {} : { measurements }),
  };
}

export function createExecutors(ctx: CheckContext): Executors {
  const node = process.execPath;
  const tsx = join(ctx.root, "node_modules/tsx/dist/cli.mjs");
  const vitest = join(ctx.root, "node_modules/vitest/vitest.mjs");
  const perf = () => readFileSync(join(ctx.root, "PERFORMANCE.md"), "utf8");
  /** npm never updates itself or (without --online) reaches the registry from a check. */
  const npmEnv = (online: boolean): Record<string, string> => ({
    npm_config_update_notifier: "false",
    ...(online ? {} : { npm_config_offline: "true" }),
  });

  const vitestCheck = async (id: CheckId, command: string, options: RunOptions, extra = {}) => {
    const run = await ctx.run(options);
    const summary = parseVitestSummary(run.output);
    if (!summary)
      return { run, result: evidence(id, command, run, "fail", `no vitest summary (exit ${run.exitCode})`, extra) };
    const t = summary.tests;
    const m = {
      ...extra,
      files: summary.files.total,
      tests_passed: t.passed,
      tests_failed: t.failed,
      tests_skipped: t.skipped,
      tests_todo: t.todo,
    };
    const ok =
      run.exitCode === 0 &&
      t.failed === 0 &&
      t.skipped === 0 &&
      t.todo === 0 &&
      summary.files.failed === 0 &&
      summary.files.skipped === 0 &&
      t.passed > 0;
    const text = `${t.passed} passed, ${t.failed} failed, ${t.skipped} skipped, ${t.todo} todo in ${summary.files.total} files (exit ${run.exitCode})`;
    return { run, result: evidence(id, command, run, ok ? "pass" : "fail", text, m) };
  };

  const matrix = (id: CheckId) => async () => {
    const spec = MATRICES.find((m) => m.id === id);
    if (!spec) throw new Error(`no matrix ${id}`);
    const files = selectMatrixFiles(spec, ctx.root);
    const projects = [...new Set(files.map((f) => f.project))];
    const command = `vitest run ${projects.map((p) => `--project ${p}`).join(" ")} <${files.length} files>`;
    // A check that names its files needs every one of them, with tests in it (slice 18h review M1): nothing is run
    // on a partial selection.
    const absent = fixedFileProblems(spec, files);
    if (absent.length > 0) {
      const summary = `the check's fixed files are not all there: ${absent.join("; ")}`;
      return { id, state: "fail" as const, summary, command, durationMs: 0 };
    }
    if (files.length === 0) {
      return { id, state: "fail" as const, summary: "no test file matched the matrix", command, durationMs: 0 };
    }
    const dir = mkdtempSync(join(tmpdir(), "airverse-gate-matrix-"));
    const jsonFile = join(dir, "report.json");
    try {
      const args = [
        vitest,
        "run",
        "--reporter=default",
        "--reporter=json",
        `--outputFile.json=${jsonFile}`,
        ...projects.flatMap((p) => ["--project", p]),
        ...files.map((f) => f.file),
      ];
      const names = files.reduce((n, f) => n + f.names.length, 0);
      const { result } = await vitestCheck(
        id,
        command,
        { command: node, args, cwd: ctx.root, timeoutMs: 10 * MINUTE },
        { matching_test_names: names, selected_files: files.map((f) => `${f.file} (${f.names.length})`).join(", ") },
      );
      let json: unknown = {};
      try {
        json = JSON.parse(readFileSync(jsonFile, "utf8"));
      } catch {}
      const problems = judgeMatrixJson(json, files, ctx.root);
      const shown = problems.slice(0, 5).join("; ") + (problems.length > 5 ? `; and ${problems.length - 5} more` : "");
      return {
        ...result,
        state: problems.length > 0 ? ("fail" as const) : result.state,
        summary: `${result.summary}; ${names} matching test names${problems.length > 0 ? `; ${shown}` : ", every one ran and passed"}`,
      };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  return {
    verify: async () =>
      (
        await vitestCheck("verify", "npm run verify", {
          command: "npm",
          args: ["run", "verify"],
          cwd: ctx.root,
          env: npmEnv(false),
          timeoutMs: 40 * MINUTE,
        })
      ).result,

    "e2e-browser": async () => {
      const command = "npm run e2e";
      const run = await ctx.run({
        command: "npm",
        args: ["run", "e2e"],
        cwd: ctx.root,
        env: npmEnv(false),
        timeoutMs: 40 * MINUTE,
        cleanupPorts: [...E2E_PORTS],
      });
      const s = parsePlaywrightSummary(run.output);
      if (!s) return evidence("e2e-browser", command, run, "fail", `no Playwright summary (exit ${run.exitCode})`);
      const bad = s.failed + s.flaky + s.interrupted + s.didNotRun + s.skipped;
      const ok = run.exitCode === 0 && bad === 0 && s.passed > 0;
      const text = `${s.passed} passed, ${s.failed} failed, ${s.flaky} flaky, ${s.skipped} skipped, ${s.didNotRun} did not run, ${s.interrupted} interrupted (${s.duration ?? "?"}; exit ${run.exitCode})`;
      return evidence("e2e-browser", command, run, ok ? "pass" : "fail", text, {
        passed: s.passed,
        failed: s.failed,
        flaky: s.flaky,
        skipped: s.skipped,
        did_not_run: s.didNotRun,
      });
    },

    "matrix-audit": matrix("matrix-audit"),
    "matrix-tenant": matrix("matrix-tenant"),
    "matrix-authz": matrix("matrix-authz"),
    "matrix-privacy": matrix("matrix-privacy"),
    // Slice 15a: fixed files, run and judged like a matrix (every test of every file ran and passed).
    "campaign-safety": matrix("campaign-safety"),
    // Slice 18h: the local upgrade check, the rollback rehearsal and the kill-switch drill, fixed files likewise.
    "upgrade-local": matrix("upgrade-local"),
    "rollback-local": matrix("rollback-local"),
    "kill-switch-drill": matrix("kill-switch-drill"),

    "rrs-stand-in": async () => {
      const command = "tsx tools/gate/src/rrs-run.ts";
      const run = await ctx.run({
        command: node,
        args: [tsx, join(ctx.root, "tools/gate/src/rrs-run.ts")],
        cwd: ctx.root,
        timeoutMs: 20 * MINUTE,
      });
      const result = parseResultLine(run.output) as RrsRun | null;
      if (!result) return evidence("rrs-stand-in", command, run, "fail", `no result line (exit ${run.exitCode})`);
      const judged = judgeRrs(result);
      const m: Record<string, number | string> = {};
      if ("variants" in result) {
        for (const v of result.variants) {
          m[`${v.profile} RRS`] = v.gate?.rrs ?? "none";
          m[`${v.profile} baseline`] = v.threshold;
        }
      }
      const exitOk = run.exitCode === 0;
      const state = exitOk ? judged.state : "fail";
      const text = `${judged.lines.join("; ")}${exitOk ? "" : `; the child exited ${run.exitCode}`}`;
      return evidence("rrs-stand-in", command, run, state, text, m);
    },

    "bench-shield": async () => {
      const command = "npm run bench";
      const run = await ctx.run({
        command: "npm",
        args: ["run", "bench"],
        cwd: ctx.root,
        env: npmEnv(false),
        timeoutMs: 20 * MINUTE,
      });
      const samples = parseBench(run.output);
      const judged = judgeBench(samples, performanceBudgets(perf()));
      const m: Record<string, number | string> = { samples: samples.length };
      for (const [id, w] of Object.entries(judged.worst)) {
        m[`${id} p50 µs`] = w.p50Us;
        m[`${id} p99 µs`] = w.p99Us;
      }
      const ok = run.exitCode === 0 && judged.breaches.length === 0;
      const text =
        judged.breaches.length > 0
          ? judged.breaches.join("; ")
          : `${samples.length} scenarios within PB-01 and PB-02 (worst p99: PB-02 ${m["PB-02 p99 µs"]} µs, PB-01 ${m["PB-01 p99 µs"]} µs; exit ${run.exitCode})`;
      return evidence("bench-shield", command, run, ok ? "pass" : "fail", text, m);
    },

    "load-smoke": async () => {
      const command = "tsx tools/gate/src/load-smoke.ts";
      const targets = loadTargets(performanceBudgets(perf()), sloTargets(perf()));
      const run = await ctx.run({
        command: node,
        args: [tsx, join(ctx.root, "tools/gate/src/load-smoke.ts")],
        cwd: ctx.root,
        timeoutMs: 2 * MINUTE,
      });
      const result = parseResultLine(run.output) as (LoadRun & { error?: string }) | null;
      if (!result || result.error !== undefined || !result.series) {
        return evidence("load-smoke", command, run, "fail", `no result (${result?.error ?? `exit ${run.exitCode}`})`);
      }
      const judged = judgeLoad({ series: result.series, errors: result.errors ?? [] }, targets);
      const m: Record<string, number | string> = {};
      for (const x of judged.measurements) m[`${x.id} ${x.series} p${x.percentile} ms`] = x.ms;
      for (const [series, values] of Object.entries(result.series)) m[`${series} samples`] = values?.length ?? 0;
      const text =
        judged.breaches.length > 0
          ? judged.breaches.join("; ")
          : judged.measurements.map((x) => `${x.id} ${x.series} p${x.percentile} ${x.ms} ≤ ${x.target} ms`).join("; ");
      return evidence("load-smoke", command, run, run.exitCode === 0 ? judged.state : "fail", text, m);
    },

    "npm-audit": async () => {
      const command = "npm audit --json";
      const run = await ctx.run({
        command: "npm",
        args: ["audit", "--json"],
        cwd: ctx.root,
        env: npmEnv(true),
        timeoutMs: 3 * MINUTE,
      });
      const counts = parseNpmAudit(run.output);
      if (!counts) return evidence("npm-audit", command, run, "fail", `no audit result (exit ${run.exitCode})`);
      // npm audit exits 1 when it found anything at all; any other exit is an error of npm itself.
      const exitOk = run.exitCode === 0 || run.exitCode === 1;
      const bad = counts.high + counts.critical;
      const text = `${counts.critical} critical, ${counts.high} high, ${counts.moderate} moderate, ${counts.low} low${exitOk ? "" : `; npm exited ${run.exitCode}`}`;
      return evidence("npm-audit", command, run, bad === 0 && exitOk ? "pass" : "fail", text, { ...counts });
    },
  };
}
