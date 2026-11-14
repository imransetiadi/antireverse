// Slice 18e: the tri-state verdict. Releasable only when every criterion passes; one fail or one not-checkable
// criterion blocks, with distinct exit codes. Results are injected: no check runs here.
import { describe, expect, it } from "vitest";
import { CRITERIA, type Criterion } from "../src/catalog.ts";
import { type CheckResult, decide, EXIT } from "../src/verdict.ts";

const src = { doc: "QASUITE.md", section: "16", text: "t" } as const;
const crit = (id: string, over: Partial<Criterion> = {}): Criterion => ({
  id,
  title: id,
  source: { ...src, text: id },
  checks: [],
  gaps: [],
  requires: [],
  ...over,
});
const pass = (id: string): CheckResult => ({ id, state: "pass", summary: "ok" });
const fail = (id: string): CheckResult => ({ id, state: "fail", summary: "broken" });
const skipped = (id: string): CheckResult => ({ id, state: "not-checkable", summary: "skipped (--skip-slow)" });

describe("decide", () => {
  const criteria = [
    crit("a", { checks: ["x"] }),
    crit("b", { checks: ["y", "z"] }),
    crit("c", { requires: ["a", "b"] }),
  ];

  it("is releasable, exit 0, only when every criterion passes", () => {
    const out = decide(criteria, [pass("x"), pass("y"), pass("z")]);
    expect(out.verdict).toBe("releasable");
    expect(out.allCheckablePassed).toBe(true);
    expect(out.exitCode).toBe(EXIT.releasable);
    expect(EXIT.releasable).toBe(0);
    expect(out.criteria.map((c) => c.state)).toEqual(["pass", "pass", "pass"]);
    expect(out.reasons).toEqual([]);
  });

  it("one failing check blocks the release, fails its criterion and those that require it", () => {
    const out = decide(criteria, [pass("x"), fail("y"), pass("z")]);
    expect(out.verdict).toBe("blocked");
    expect(out.allCheckablePassed).toBe(false);
    expect(out.exitCode).toBe(EXIT.failed);
    expect(out.criteria.map((c) => c.state)).toEqual(["pass", "fail", "fail"]);
    expect(out.reasons.join("\n")).toMatch(/b: check y failed: broken/);
  });

  it("one not-checkable criterion blocks with its own exit code, while every checkable one passed", () => {
    const out = decide(
      [...criteria, crit("d", { gaps: [{ reason: "needs staging", slice: "18" }] })],
      [pass("x"), pass("y"), pass("z")],
    );
    expect(out.verdict).toBe("blocked");
    expect(out.allCheckablePassed).toBe(true);
    expect(out.exitCode).toBe(EXIT.notCheckable);
    expect(new Set([EXIT.releasable, EXIT.failed, EXIT.notCheckable, EXIT.error]).size).toBe(4);
    expect(out.reasons).toEqual(["d: not checkable: needs staging (slice 18)"]);
  });

  it("a skipped or missing check is not checkable, never a pass", () => {
    const out = decide(criteria, [pass("x"), skipped("y")]);
    expect(out.criteria.map((c) => c.state)).toEqual(["pass", "not-checkable", "not-checkable"]);
    expect(out.reasons.join("\n")).toMatch(/b: check y not checkable: skipped/);
    expect(out.reasons.join("\n")).toMatch(/b: check z not checkable: not run/);
    expect(out.exitCode).toBe(EXIT.notCheckable);
  });

  it("a fail outranks a not-checkable in the same criterion, and in the exit code", () => {
    const out = decide([crit("e", { checks: ["x"], gaps: [{ reason: "and more", slice: "15" }] })], [fail("x")]);
    expect(out.criteria[0]?.state).toBe("fail");
    expect(out.exitCode).toBe(EXIT.failed);
  });

  it("a criterion with a check and a gap is not checkable even when the check passes", () => {
    const out = decide(
      [crit("e", { checks: ["x"], gaps: [{ reason: "real agents", slice: "unplanned" }] })],
      [pass("x")],
    );
    expect(out.criteria[0]?.state).toBe("not-checkable");
  });

  it("with no check run at all, every checkable criterion did not pass", () => {
    const out = decide([crit("a", { gaps: [{ reason: "none yet here", slice: "18" }] })], []);
    expect(out.allCheckablePassed).toBe(false);
  });

  it("on the real catalog, all checks passing still blocks: some lines cannot be checked yet", () => {
    const ids = [...new Set(CRITERIA.flatMap((c) => c.checks))];
    const out = decide(CRITERIA, ids.map(pass));
    expect(out.verdict).toBe("blocked");
    expect(out.exitCode).toBe(EXIT.notCheckable);
    expect(out.allCheckablePassed).toBe(true);
    expect(out.criteria.some((c) => c.state === "not-checkable")).toBe(true);
  });
});
