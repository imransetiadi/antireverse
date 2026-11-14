// Slice 18e: the runner with injected check executors — options (--only, --skip-slow, --online), the report (JSON and
// Markdown, git state, tool versions, evidence, signature) and the exit codes. No real check runs here.
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { CHECKS, type CheckId } from "../src/catalog.ts";
import { parseArgs, runGate } from "../src/gate.ts";
import { renderMarkdown } from "../src/report.ts";
import { loadOrCreateKey, verifyReport } from "../src/sign.ts";
import type { CheckResult } from "../src/verdict.ts";

const dirs: string[] = [];
const temp = () => {
  const dir = mkdtempSync(join(tmpdir(), "gate-run-"));
  dirs.push(dir);
  return dir;
};
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const ALL = Object.keys(CHECKS) as CheckId[];
/** Executors that record what ran and pass (or fail the given ids). */
function executors(failing: CheckId[] = []) {
  const ran: CheckId[] = [];
  const make = (id: CheckId) => async (): Promise<CheckResult> => {
    ran.push(id);
    return failing.includes(id)
      ? { id, state: "fail", summary: "broken", command: `fake ${id}`, durationMs: 5, excerpt: "boom" }
      : {
          id,
          state: "pass",
          summary: "ok",
          command: `fake ${id}`,
          durationMs: 5,
          excerpt: "fine",
          measurements: { n: 1 },
        };
  };
  return {
    ran,
    executors: Object.fromEntries(ALL.map((id) => [id, make(id)])) as Record<CheckId, () => Promise<CheckResult>>,
  };
}

const env = () => ({
  outDir: temp(),
  keyFile: join(temp(), "gate-key.json"),
  now: () => new Date("2026-11-14T10:00:00Z"),
});

describe("parseArgs", () => {
  it("reads --only, --skip-slow and --online", () => {
    expect(parseArgs(["--only", "verify,matrix-tenant", "--skip-slow", "--online"])).toEqual({
      only: ["verify", "matrix-tenant"],
      skipSlow: true,
      online: true,
    });
    expect(parseArgs([])).toEqual({ only: null, skipSlow: false, online: false });
  });

  it("refuses unknown flags and unknown ids", () => {
    expect(() => parseArgs(["--fast"])).toThrow(/unknown option --fast/);
    expect(() => parseArgs(["--only", "nope"])).toThrow(/unknown check or criterion nope/);
    expect(() => parseArgs(["--only"])).toThrow(/--only needs/);
  });

  it("accepts a criterion id for --only and expands it to its checks", () => {
    expect(parseArgs(["--only", "sec12-isolation"]).only).toEqual(["matrix-tenant", "matrix-authz", "matrix-privacy"]);
  });
});

describe("runGate", () => {
  it("runs every offline check; npm audit is not checkable without --online; the verdict is blocked", async () => {
    const { ran, executors: ex } = executors();
    const out = await runGate({ only: null, skipSlow: false, online: false }, { ...env(), executors: ex });
    expect(ran.sort()).toEqual(ALL.filter((id) => id !== "npm-audit").sort());
    const audit = out.report.checks.find((c) => c.id === "npm-audit");
    expect(audit).toMatchObject({ state: "not-checkable", summary: expect.stringMatching(/--online/) });
    expect(out.report.verdict).toBe("blocked");
    expect(out.report.all_checkable_passed).toBe(true);
    expect(out.exitCode).toBe(2);
  });

  it("runs npm audit only with --online", async () => {
    const { ran, executors: ex } = executors();
    await runGate({ only: ["npm-audit"], skipSlow: false, online: true }, { ...env(), executors: ex });
    expect(ran).toEqual(["npm-audit"]);
  });

  it("--skip-slow reports the slow checks as not checked, never as passed", async () => {
    const { ran, executors: ex } = executors();
    const out = await runGate({ only: null, skipSlow: true, online: false }, { ...env(), executors: ex });
    for (const id of ["verify", "e2e-browser", "bench-shield"] as const) {
      expect(ran).not.toContain(id);
      expect(out.report.checks.find((c) => c.id === id)).toMatchObject({
        state: "not-checkable",
        summary: "skipped (--skip-slow): not checked",
      });
    }
  });

  it("--only runs the selected checks; the others are not run and not checkable", async () => {
    const { ran, executors: ex } = executors();
    const out = await runGate({ only: ["load-smoke"], skipSlow: false, online: false }, { ...env(), executors: ex });
    expect(ran).toEqual(["load-smoke"]);
    expect(out.report.checks.find((c) => c.id === "verify")).toMatchObject({
      state: "not-checkable",
      summary: "not selected (--only)",
    });
  });

  it("a failing check gives exit 1 and names the reason", async () => {
    const { executors: ex } = executors(["matrix-authz"]);
    const out = await runGate({ only: null, skipSlow: false, online: false }, { ...env(), executors: ex });
    expect(out.exitCode).toBe(1);
    expect(out.report.reasons.join("\n")).toMatch(/sec12-isolation: check matrix-authz failed: broken/);
  });

  it("an executor that throws is a fail with the error, not a crash", async () => {
    const { executors: ex } = executors();
    ex["load-smoke"] = async () => {
      throw new Error("port in use");
    };
    const out = await runGate({ only: ["load-smoke"], skipSlow: false, online: false }, { ...env(), executors: ex });
    expect(out.report.checks.find((c) => c.id === "load-smoke")).toMatchObject({
      state: "fail",
      summary: "error: port in use",
    });
  });

  it("writes report.json (signed, with git state and tool versions) and report.md under <out>/<timestamp>-<suffix>", async () => {
    const { executors: ex } = executors();
    const e = env();
    const out = await runGate({ only: ["load-smoke"], skipSlow: false, online: false }, { ...e, executors: ex });
    expect(out.dir.startsWith(join(e.outDir, "2026-11-14T10-00-00Z-"))).toBe(true);
    const json = JSON.parse(readFileSync(join(out.dir, "report.json"), "utf8"));
    expect(json.git.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(typeof json.git.dirty).toBe("boolean");
    expect(json.tools.node).toBe(process.version);
    expect(json.tools.npm).toMatch(/^\d+\.\d+\.\d+/);
    expect(json.options).toEqual({ only: ["load-smoke"], skip_slow: false, online: false });
    expect(json.criteria.length).toBeGreaterThan(10);
    expect(json.checks.find((c: CheckResult) => c.id === "load-smoke")).toMatchObject({
      command: "fake load-smoke",
      duration_ms: 5,
      excerpt: "fine",
      measurements: { n: 1 },
    });
    const key = loadOrCreateKey(e.keyFile);
    expect(verifyReport(json, { expectedFingerprint: key.fingerprint })).toEqual({
      ok: true,
      fingerprint: key.fingerprint,
    });
    const md = readFileSync(join(out.dir, "report.md"), "utf8");
    expect(md).toContain("**Verdict: blocked**");
    expect(md).toContain(key.fingerprint);
    expect(existsSync(e.keyFile)).toBe(true);
  });
});

describe("renderMarkdown", () => {
  it("states the verdict, the all-checkable line, the reasons and every criterion with its source line", async () => {
    const { executors: ex } = executors(["bench-shield"]);
    const out = await runGate({ only: null, skipSlow: false, online: false }, { ...env(), executors: ex });
    const md = renderMarkdown(out.report);
    expect(md).toMatch(/\*\*Verdict: blocked\*\*/);
    expect(md).toMatch(/Every checkable criterion passed: no/);
    expect(md).toMatch(/qa16-performance.*fail/);
    expect(md).toContain("All performance budgets met; no unaccepted regression.");
    expect(md).toContain("QASUITE.md:");
    expect(md).toMatch(/## Not checkable/);
  });
});
