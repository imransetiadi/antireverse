// Slice 18e, independent review (H1, M1–M5, L1, the cheap items) and owner decision D-097. Each case here reproduces a
// finding: it failed against the first version of the gate.
import { execFile, execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SLO_CATALOG } from "@antireverse/protocol";
import { afterAll, describe, expect, it } from "vitest";
import { CHECKS, type CheckId, CRITERIA, type Criterion, catalogDrift } from "../src/catalog.ts";
import { type CheckContext, createExecutors } from "../src/checks.ts";
import { budgetParts, checklist, performanceBudgets, requireTargets, sloTargets } from "../src/docs.ts";
import { parseArgs, runGate } from "../src/gate.ts";
import { loadTargets } from "../src/load.ts";
import { judgeMatrixJson } from "../src/matrix.ts";
import { judgeBench, MIN_BENCH_SAMPLES, parseBench } from "../src/parsers.ts";
import { REPO_ROOT } from "../src/paths.ts";
import { loadRrsBaseline } from "../src/rrs-baseline.ts";
import type { RunOptions, RunResult } from "../src/run.ts";
import { runCommand } from "../src/run.ts";
import { loadOrCreateKey, signReport } from "../src/sign.ts";
import type { CheckResult } from "../src/verdict.ts";

const dirs: string[] = [];
const temp = (prefix = "gate-review-") => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
};
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const PERFORMANCE = readFileSync(join(REPO_ROOT, "PERFORMANCE.md"), "utf8");

function fake(reply: (options: RunOptions) => Partial<RunResult>, online = false) {
  const calls: RunOptions[] = [];
  const ctx: CheckContext = {
    root: REPO_ROOT,
    online,
    async run(options) {
      calls.push(options);
      return { exitCode: 0, signal: null, timedOut: false, durationMs: 10, output: "", ...reply(options) };
    },
  };
  return { ctx, calls };
}

describe("H1: skipped, todo and did-not-run tests never pass", () => {
  const verify = async (output: string) => (await createExecutors(fake(() => ({ output })).ctx).verify()).state;

  it("fails a vitest run with skipped or todo tests, naming the counts", async () => {
    expect(await verify(" Test Files  1 passed (1)\n      Tests  707 skipped | 1 passed (708)\n")).toBe("fail");
    const out = await createExecutors(
      fake(() => ({ output: " Test Files  9 passed (9)\n      Tests  50 skipped | 3 todo | 8113 passed (8166)\n" }))
        .ctx,
    ).verify();
    expect(out.state).toBe("fail");
    expect(out.summary).toMatch(/50 skipped/);
    expect(out.summary).toMatch(/3 todo/);
  });

  it("fails a Playwright run with skipped or did-not-run tests", async () => {
    const e2e = async (output: string) => (await createExecutors(fake(() => ({ output })).ctx)["e2e-browser"]()).state;
    expect(await e2e("  25 skipped\n  1 passed (10s)\n")).toBe("fail");
    expect(await e2e("  2 did not run\n  24 passed (1m)\n")).toBe("fail");
  });

  it("a matrix requires every matching test name to have run and passed (JSON reporter)", () => {
    const selected = [
      { project: "api", file: "apps/api/test/a.test.ts", names: ["answers 404 to another Organization", "tenancy"] },
    ];
    const json = (statuses: Record<string, string>) => ({
      testResults: [
        {
          name: join(REPO_ROOT, "apps/api/test/a.test.ts"),
          assertionResults: Object.entries(statuses).map(([title, status]) => ({
            title,
            ancestorTitles: title.startsWith("in tenancy") ? ["tenancy"] : [],
            status,
          })),
        },
      ],
    });
    expect(
      judgeMatrixJson(
        json({ "answers 404 to another Organization": "passed", "in tenancy: x": "passed" }),
        selected,
        REPO_ROOT,
      ),
    ).toEqual([]);
    expect(
      judgeMatrixJson(
        json({ "answers 404 to another Organization": "skipped", "in tenancy: x": "passed" }),
        selected,
        REPO_ROOT,
      ),
    ).toEqual(['apps/api/test/a.test.ts: "answers 404 to another Organization" did not pass (skipped)']);
    expect(judgeMatrixJson(json({ "in tenancy: x": "passed" }), selected, REPO_ROOT)).toEqual([
      'apps/api/test/a.test.ts: "answers 404 to another Organization" did not run',
    ]);
    expect(judgeMatrixJson({}, selected, REPO_ROOT)).toEqual(["no JSON report"]);
  });

  it("matrix checks run with the JSON reporter and fail when a matching test did not run", async () => {
    const { ctx, calls } = fake((options) => {
      const arg = options.args.find((a) => a.startsWith("--outputFile.json="));
      if (arg) writeFileSync(arg.slice("--outputFile.json=".length), JSON.stringify({ testResults: [] }));
      return { output: " Test Files  1 passed (1)\n      Tests  35 passed (35)\n" };
    });
    const out = await createExecutors(ctx)["matrix-audit"]();
    expect(calls[0]?.args).toContain("--reporter=json");
    expect(out.state).toBe("fail");
    expect(out.summary).toMatch(/did not run/);
  });
});

describe("M1: exit codes and signals", () => {
  const rrs = {
    variants: [
      {
        profile: "balanced",
        threshold: 24,
        exitCode: 0,
        gate: { result: "passed", rrs: 24, threshold: 24, status: "scored", reason: null },
      },
    ],
  };
  it("rrs-stand-in fails when its child exits non-zero or by a signal", async () => {
    const line = `GATE-RESULT ${JSON.stringify(rrs)}\n`;
    const run = async (r: Partial<RunResult>) =>
      (await createExecutors(fake(() => ({ output: line, ...r })).ctx)["rrs-stand-in"]()).state;
    expect(await run({})).toBe("pass");
    expect(await run({ exitCode: 1 })).toBe("fail");
    expect(await run({ exitCode: null, signal: "SIGKILL" })).toBe("fail");
  });

  it("npm-audit accepts exit 0 or 1 without a signal only", async () => {
    const audit = JSON.stringify({
      metadata: { vulnerabilities: { low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
    });
    const run = async (r: Partial<RunResult>) =>
      (await createExecutors(fake(() => ({ output: audit, ...r }), true).ctx)["npm-audit"]()).state;
    expect(await run({ exitCode: 1 })).toBe("pass");
    expect(await run({ exitCode: 2 })).toBe("fail");
    expect(await run({ exitCode: null, signal: "SIGTERM" })).toBe("fail");
  });
});

describe("M2: thresholds are never dropped silently", () => {
  it("reports every part of a budget cell it cannot read, and accepts μs, µs, < and <=", () => {
    expect(budgetParts("p50 ≤ 0.5 ms · p99 about 1.5 ms")).toEqual({
      targets: [{ variant: "all", percentile: 50, ms: 0.5 }],
      unparsed: ["p99 about 1.5 ms"],
    });
    expect(budgetParts("p50 <= 100 μs · p99 < 500 µs").targets).toEqual([
      { variant: "all", percentile: 50, ms: 0.1 },
      { variant: "all", percentile: 99, ms: 0.5 },
    ]);
  });

  it("requires the expected set of targets of PB-01, PB-02 and PB-21", () => {
    const budgets = performanceBudgets(PERFORMANCE);
    expect(requireTargets(budgets, "PB-21").map((t) => `${t.variant} p${t.percentile}`)).toEqual([
      "read p95",
      "write p95",
    ]);
    const broken = performanceBudgets(
      PERFORMANCE.replace("p50 ≤ 0.1 ms · p99 ≤ 0.5 ms", "p50 ≤ 0.1 ms · p99 ≈ 0.5 ms"),
    );
    expect(() => requireTargets(broken, "PB-02")).toThrow(/PB-02: cannot read "p99 ≈ 0.5 ms"/);
    const missing = performanceBudgets(PERFORMANCE.replace("p50 ≤ 0.5 ms · p99 ≤ 1.5 ms", "p99 ≤ 1.5 ms"));
    expect(() => requireTargets(missing, "PB-01")).toThrow(/PB-01: missing all p50/);
  });

  it("the bench judge refuses a percentile it cannot evaluate and too few samples", () => {
    const budgets = performanceBudgets(
      PERFORMANCE.replace("p50 ≤ 0.1 ms · p99 ≤ 0.5 ms", "p95 ≤ 0.1 ms · p99 ≤ 0.5 ms"),
    );
    const bench =
      "Built-in\n  GET /x\n    p50 1.00 µs   p99 2.00 µs\nAttested (budget PB-01)\n  GET /y\n    p50 1.00 µs   p99 2.00 µs\n";
    const out = judgeBench(parseBench(bench), budgets);
    expect(out.breaches).toContain("PB-02: cannot evaluate p95 (the bench reports p50 and p99)");
    expect(out.breaches).toContain(`PB-01: 1 samples, expected at least ${MIN_BENCH_SAMPLES["PB-01"]}`);
    expect(out.breaches).toContain(`PB-02: 1 samples, expected at least ${MIN_BENCH_SAMPLES["PB-02"]}`);
  });

  it("reads SLO-01 and SLO-02 from PERFORMANCE §3 and cross-checks them with the protocol catalog", () => {
    const slo = sloTargets(PERFORMANCE);
    expect(slo.get("SLO-01")).toEqual([
      { percentile: 95, ms: 50 },
      { percentile: 99, ms: 120 },
    ]);
    expect(slo.get("SLO-02")).toEqual([{ percentile: 99, ms: 150 }]);
    for (const id of ["SLO-01", "SLO-02"]) {
      expect(slo.get(id)).toEqual(
        SLO_CATALOG.find((s) => s.id === id)?.latency_targets.map((t) => ({ percentile: t.percentile, ms: t.ms })),
      );
    }
    const changed = PERFORMANCE.replace("acknowledgement p99 ≤ 150 ms", "acknowledgement p99 ≤ 100 ms");
    expect(() => loadTargets(performanceBudgets(changed), sloTargets(changed))).toThrow(
      /SLO-02: PERFORMANCE §3 says p99 ≤ 100 ms, the protocol catalog p99 ≤ 150 ms/,
    );
  });
});

describe("M3: catalog drift", () => {
  it("reads checklist lines with any list marker and extra spaces", () => {
    const doc =
      "## 12. Gate\n*  [ ] Star line.\n+ [x]   Plus line.\n1. [ ] Numbered line.\n2)  [X] Paren line.\n-   [ ] Spaced line.\n";
    expect(checklist(doc, "12").map((l) => l.text)).toEqual([
      "Star line.",
      "Plus line.",
      "Numbered line.",
      "Paren line.",
      "Spaced line.",
    ]);
  });

  it("finds unmapped and stale lines", () => {
    const docs = {
      "QASUITE.md": readFileSync(join(REPO_ROOT, "QASUITE.md"), "utf8").replace(
        "- [ ] Rollback rehearsed.",
        "- [ ] Rollback rehearsed twice.\n* [ ] A new exit criterion.",
      ),
      "SECURITY.md": readFileSync(join(REPO_ROOT, "SECURITY.md"), "utf8"),
    };
    expect(catalogDrift(docs)).toEqual([
      'QASUITE.md §16: unmapped line "Rollback rehearsed twice."',
      'QASUITE.md §16: unmapped line "A new exit criterion."',
      'stale entry qa16-rollback: "Rollback rehearsed." is not a line of QASUITE.md §16',
    ]);
  });

  it("runGate shows drift as a failing gate-integrity criterion in the report", async () => {
    const root = temp();
    for (const doc of ["QASUITE.md", "SECURITY.md", "PERFORMANCE.md"]) cpSync(join(REPO_ROOT, doc), join(root, doc));
    writeFileSync(
      join(root, "SECURITY.md"),
      readFileSync(join(root, "SECURITY.md"), "utf8").replace(
        "- [ ] Prompt-injection evaluations pass.",
        "- [ ] Prompt-injection evaluations pass.\n- [ ] A brand new security line.",
      ),
    );
    const out = await runGate(
      { only: ["load-smoke"], skipSlow: false, online: false },
      { ...gateEnv(), root, executors: passing() },
    );
    const integrity = out.report.criteria.find((c) => c.id === "gate-integrity");
    expect(integrity?.state).toBe("fail");
    expect(integrity?.reasons.join("\n")).toMatch(/unmapped line "A brand new security line\."/);
    expect(out.exitCode).toBe(1);
  });
});

describe("M4: gate:verify-report trusts only the local key or --expect", () => {
  const tsx = join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs");
  const run = (args: string[], env: Record<string, string>) =>
    new Promise<{ code: number; out: string }>((resolve) => {
      execFile(
        process.execPath,
        [tsx, join(REPO_ROOT, "tools/gate/src/verify-cli.ts"), ...args],
        { cwd: REPO_ROOT, env: { ...process.env, ...env } },
        (error, stdout, stderr) =>
          resolve({ code: error ? (typeof error.code === "number" ? error.code : -1) : 0, out: stdout + stderr }),
      );
    });

  it("a validly signed report by another key exits non-zero with UNTRUSTED KEY, unless --expect names it", async () => {
    const dir = temp();
    const signer = loadOrCreateKey(join(dir, "signer", "k.json"));
    const local = join(dir, "local", "k.json");
    loadOrCreateKey(local);
    const file = join(dir, "report.json");
    writeFileSync(file, JSON.stringify(signReport({ verdict: "blocked" }, signer)));
    const untrusted = await run([file], { AR_GATE_KEY_FILE: local });
    expect(untrusted.code).toBe(1);
    expect(untrusted.out).toContain("UNTRUSTED KEY");
    const noLocal = await run([file], { AR_GATE_KEY_FILE: join(dir, "none", "k.json") });
    expect(noLocal.code).toBe(1);
    expect(noLocal.out).toContain("UNTRUSTED KEY");
    const expected = await run([file, "--expect", signer.fingerprint], { AR_GATE_KEY_FILE: local });
    expect(expected.code, expected.out).toBe(0);
    expect(expected.out).toContain("--expect");
  });
});

describe("M5: the key is never inside the repository", () => {
  it("refuses a path under a directory named ..something inside the repository", () => {
    expect(() => loadOrCreateKey(join(REPO_ROOT, "..something", "gate-key.json"))).toThrow(/inside the repository/);
  });

  it("refuses the repository reached through a differently cased path", () => {
    const upper = REPO_ROOT.replace("/Users/", "/USERS/").replace("scratch", "SCRATCH");
    expect(upper).not.toBe(REPO_ROOT);
    let caseInsensitive = false;
    try {
      caseInsensitive = execFileSync("stat", ["-f", "%i", upper], { encoding: "utf8" }).length > 0;
    } catch {}
    if (caseInsensitive) expect(() => loadOrCreateKey(join(upper, "gate-key.json"))).toThrow(/inside the repository/);
  });

  it("still accepts a sibling directory whose name starts with the repository's name", () => {
    const file = join(temp(), "gate-key.json");
    expect(loadOrCreateKey(file).created).toBe(true);
  });
});

describe("L1: a timeout also stops what the run left listening on its ports", () => {
  it("kills a detached grandchild listening on one of the run's ports", async () => {
    const port = await freePort();
    const script = join(temp(), "spawner.cjs");
    writeFileSync(
      script,
      `const { spawn } = require("node:child_process");
const child = spawn(process.execPath, ["-e", "require('node:http').createServer(() => {}).listen(${port}, '127.0.0.1'); setInterval(() => {}, 1000)"], { detached: true, stdio: "ignore" });
child.unref();
setInterval(() => {}, 1000);`,
    );
    const out = await runCommand({ command: process.execPath, args: [script], timeoutMs: 1_500, cleanupPorts: [port] });
    expect(out.timedOut).toBe(true);
    expect(await listening(port)).toBe(false);
  }, 30_000);
});

describe("cheap items", () => {
  it("child processes never see AR_GATE_KEY_FILE", async () => {
    process.env.AR_GATE_KEY_FILE = "/secret/path/gate-key.json";
    try {
      const out = await runCommand({
        command: process.execPath,
        args: ["-e", "console.log('key=' + (process.env.AR_GATE_KEY_FILE ?? 'absent'))"],
        timeoutMs: 10_000,
      });
      expect(out.output).toContain("key=absent");
    } finally {
      delete process.env.AR_GATE_KEY_FILE;
    }
  });

  it("npm runs offline and without the update notifier unless --online", async () => {
    const offline = fake(() => ({ output: "" }));
    await createExecutors(offline.ctx).verify();
    expect(offline.calls[0]?.env).toMatchObject({ npm_config_update_notifier: "false", npm_config_offline: "true" });
    const online = fake(() => ({ output: "" }), true);
    await createExecutors(online.ctx)["npm-audit"]();
    expect(online.calls[0]?.env?.npm_config_offline).toBeUndefined();
    expect(online.calls[0]?.env).toMatchObject({ npm_config_update_notifier: "false" });
  });

  it("each run gets its own report directory, even within the same second", async () => {
    const e = gateEnv();
    const a = await runGate({ only: ["load-smoke"], skipSlow: false, online: false }, { ...e, executors: passing() });
    const b = await runGate({ only: ["load-smoke"], skipSlow: false, online: false }, { ...e, executors: passing() });
    expect(a.dir).toMatch(/2026-11-14T10-00-00Z-[A-Za-z0-9]{6}$/);
    expect(a.dir).not.toBe(b.dir);
  });

  it("a requirement cycle in the catalog is a runner error", async () => {
    const cyclic: Criterion[] = [
      { id: "a", title: "a", source: { doc: "gate", section: "x", text: "a" }, checks: [], gaps: [], requires: ["b"] },
      { id: "b", title: "b", source: { doc: "gate", section: "x", text: "b" }, checks: [], gaps: [], requires: ["a"] },
    ];
    await expect(
      runGate({ only: null, skipSlow: false, online: false }, { ...gateEnv(), executors: passing(), criteria: cyclic }),
    ).rejects.toThrow(/cycle/);
  });

  it("all_checkable_passed is computed over criteria, and --only is marked a partial run", async () => {
    const out = await runGate(
      { only: ["load-smoke"], skipSlow: false, online: false },
      { ...gateEnv(), executors: passing() },
    );
    expect(out.report.partial).toBe(true);
    // load-smoke passed, but no criterion passed: qa16-performance still has gaps and other checks were not run.
    expect(out.report.all_checkable_passed).toBe(false);
    const full = await runGate({ only: null, skipSlow: false, online: false }, { ...gateEnv(), executors: passing() });
    expect(full.report.partial).toBe(false);
    expect(full.report.all_checkable_passed).toBe(true);
    const md = readFileSync(join(out.dir, "report.md"), "utf8");
    expect(md).toMatch(/partial run/);
  });

  it("parseArgs still refuses unknown ids", () => {
    expect(() => parseArgs(["--only", "x"])).toThrow();
  });
});

describe("the gate's own reports do not fail the next verify", () => {
  it("Biome leaves reports/gate alone (it does not read .gitignore)", () => {
    const biome = JSON.parse(readFileSync(join(REPO_ROOT, "biome.json"), "utf8")) as { files: { includes: string[] } };
    expect(biome.files.includes).toContain("!**/reports/gate");
    expect(readFileSync(join(REPO_ROOT, ".gitignore"), "utf8")).toMatch(/^reports\/gate\/$/m);
  });
});

describe("D-097: TC-PRV-006 waits for a real agent; the stand-in is a regression against a recorded baseline", () => {
  it("keeps the baseline in a reviewed file with its date and decision", () => {
    const baseline = loadRrsBaseline(REPO_ROOT);
    expect(baseline).toMatchObject({ decision: "D-097", recorded: "2026-11-14", tier: "T1", agent: "stand-in" });
    expect(baseline.profiles).toEqual({ balanced: 24, maximum: 24 });
    expect(baseline.notes.join(" ")).toMatch(/W4.*integrity.*Harden/s);
  });

  it("TC-PRV-006 and the RRS line of SECURITY §12 are not checkable; a separate criterion runs the stand-in", () => {
    const resistance = CRITERIA.find((c) => c.id === "qa16-resistance");
    expect(resistance?.checks).toEqual([]);
    expect(resistance?.gaps.map((g) => g.reason).join(" ")).toMatch(/real AI agent/);
    expect(CRITERIA.find((c) => c.id === "sec12-rrs-pentest")?.checks).toEqual([]);
    const regression = CRITERIA.find((c) => c.id === "gate-rrs-regression");
    expect(regression).toMatchObject({ checks: ["rrs-stand-in"], gaps: [], source: { doc: "gate" } });
    expect(regression?.notes?.join(" ")).toMatch(/W4/);
    expect(CHECKS["rrs-stand-in"].title).toMatch(/baseline/);
  });
});

// --- helpers -------------------------------------------------------------------------------------------------------

function gateEnv() {
  return {
    outDir: temp(),
    keyFile: join(temp(), "gate-key.json"),
    now: () => new Date("2026-11-14T10:00:00Z"),
  };
}

function passing(): Record<CheckId, () => Promise<CheckResult>> {
  return Object.fromEntries(
    (Object.keys(CHECKS) as CheckId[]).map((id) => [id, async () => ({ id, state: "pass" as const, summary: "ok" })]),
  ) as Record<CheckId, () => Promise<CheckResult>>;
}

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as { port: number };
      server.close(() => resolve(address.port));
    });
  });
}

function listening(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();
    server.once("error", () => resolve(true));
    server.listen(port, "127.0.0.1", () => server.close(() => resolve(false)));
  });
}
