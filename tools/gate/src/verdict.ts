// The tri-state verdict (slice 18e, D-096): every criterion is pass, fail or not-checkable. The release is releasable
// only when every criterion passes; otherwise it is blocked, with the reasons. A skipped or missing check is never a pass.
import type { Criterion } from "./catalog.ts";

export type State = "pass" | "fail" | "not-checkable";

export interface CheckResult {
  id: string;
  state: State;
  /** One line: what was found, or why it was not checked. */
  summary: string;
  command?: string;
  durationMs?: number;
  /** The trimmed tail of the output. */
  excerpt?: string;
  /** The measured numbers. */
  measurements?: Record<string, number | string>;
}

export interface CriterionResult {
  id: string;
  state: State;
  reasons: string[];
}

/** Exit codes: distinct for a release blocked by a failure and one blocked only by unchecked lines. */
export const EXIT = { releasable: 0, failed: 1, notCheckable: 2, error: 3 } as const;

export interface Decision {
  verdict: "releasable" | "blocked";
  /** True when no criterion failed and at least one criterion with checks passed (gate-integrity aside). */
  allCheckablePassed: boolean;
  criteria: CriterionResult[];
  reasons: string[];
  exitCode: number;
}

export function decide(criteria: readonly Criterion[], checks: readonly CheckResult[]): Decision {
  const byCheck = new Map(checks.map((c) => [c.id, c]));
  const byCriterion = new Map(criteria.map((c) => [c.id, c]));
  const done = new Map<string, CriterionResult>();

  const evaluate = (criterion: Criterion): CriterionResult => {
    const cached = done.get(criterion.id);
    if (cached) return cached;
    const failures: string[] = [];
    const unchecked: string[] = [];
    for (const id of criterion.checks) {
      const result = byCheck.get(id);
      if (!result) unchecked.push(`check ${id} not checkable: not run`);
      else if (result.state === "fail") failures.push(`check ${id} failed: ${result.summary}`);
      else if (result.state === "not-checkable") unchecked.push(`check ${id} not checkable: ${result.summary}`);
    }
    for (const gap of criterion.gaps) unchecked.push(`not checkable: ${gap.reason} (slice ${gap.slice})`);
    for (const id of criterion.requires) {
      const required = byCriterion.get(id);
      const state = required ? evaluate(required).state : "not-checkable";
      if (state === "fail") failures.push(`requires ${id}, which failed`);
      else if (state === "not-checkable") unchecked.push(`requires ${id}, which is not checkable`);
    }
    const state: State = failures.length > 0 ? "fail" : unchecked.length > 0 ? "not-checkable" : "pass";
    const result = { id: criterion.id, state, reasons: [...failures, ...unchecked] };
    done.set(criterion.id, result);
    return result;
  };

  const results = criteria.map(evaluate);
  const reasons = results.flatMap((r) => r.reasons.map((reason) => `${r.id}: ${reason}`));
  const anyFail = results.some((r) => r.state === "fail");
  const releasable = results.every((r) => r.state === "pass");
  const counted = criteria.map((c, i) => ({ c, r: results[i] as CriterionResult })).filter(({ c }) => !c.integrity);
  const allCheckablePassed =
    !anyFail && counted.some(({ c, r }) => r.state === "pass" && (c.checks.length > 0 || c.requires.length > 0));
  return {
    verdict: releasable ? "releasable" : "blocked",
    allCheckablePassed,
    criteria: results,
    reasons,
    exitCode: releasable ? EXIT.releasable : anyFail ? EXIT.failed : EXIT.notCheckable,
  };
}
