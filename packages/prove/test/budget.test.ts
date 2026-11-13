// Task 2.1 — the budget: calls and wall time per tier, overridable for tests; a call over the budget is refused
// before it runs, and the run's cost is what was spent.
import { TIERS } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { Budget, BudgetExhaustedError, resolveTiers } from "../src/budget.ts";

function clock(start = 1_000) {
  let ms = start;
  return {
    now: () => ms,
    advance: (by: number) => {
      ms += by;
    },
  };
}

describe("resolveTiers", () => {
  it("defaults to the protocol's tiers (T1 150 / 15 min, T2 1,500 / 2 h, T3 6,000 / 8 h)", () => {
    expect(resolveTiers()).toEqual(TIERS);
    expect(resolveTiers().T1).toEqual({ calls: 150, seconds: 900 });
  });

  it("takes overrides per tier and keeps the others", () => {
    const tiers = resolveTiers({ T1: { calls: 5, seconds: 2 } });
    expect(tiers.T1).toEqual({ calls: 5, seconds: 2 });
    expect(tiers.T2).toEqual(TIERS.T2);
  });

  it.each([
    ["negative calls", { T1: { calls: -1, seconds: 1 } }],
    ["fractional calls", { T1: { calls: 1.5, seconds: 1 } }],
    ["infinite seconds", { T1: { calls: 1, seconds: Number.POSITIVE_INFINITY } }],
    ["a tier below the previous one", { T2: { calls: 100, seconds: 7200 } }],
    ["a tier above the protocol's (scores would claim a tier they did not fit)", { T1: { calls: 151, seconds: 900 } }],
  ])("refuses %s", (_name, overrides) => {
    expect(() => resolveTiers(overrides)).toThrow(TypeError);
  });
});

describe("Budget", () => {
  it("counts every charged call and reports the cost since it started", () => {
    const time = clock();
    const budget = new Budget({ calls: 3, seconds: 10 }, time.now);
    budget.charge();
    time.advance(1_500);
    budget.charge();
    expect(budget.cost()).toEqual({ calls: 2, seconds: 1.5 });
    expect(budget.calls()).toBe(2);
    expect(budget.callsLeft()).toBe(1);
    expect(budget.secondsLeft()).toBe(8.5);
    expect(budget.exhausted()).toBe(false);
  });

  it("allows exactly the limit of calls and refuses the next one without counting it", () => {
    const budget = new Budget({ calls: 2, seconds: 10 }, clock().now);
    budget.charge();
    budget.charge();
    expect(budget.exhausted()).toBe(true);
    const error = (() => {
      try {
        budget.charge();
      } catch (caught) {
        return caught;
      }
      return null;
    })();
    expect(error).toBeInstanceOf(BudgetExhaustedError);
    expect((error as BudgetExhaustedError).reason).toBe("calls");
    expect(budget.cost().calls).toBe(2);
  });

  it("refuses a call once the wall time is over the limit", () => {
    const time = clock();
    const budget = new Budget({ calls: 100, seconds: 1 }, time.now);
    budget.charge();
    time.advance(1_000);
    budget.charge(); // exactly at the limit: inclusive
    time.advance(1);
    expect(budget.exhausted()).toBe(true);
    expect(() => budget.charge()).toThrow(expect.objectContaining({ reason: "time" }));
    expect(budget.cost()).toEqual({ calls: 2, seconds: 1.001 });
  });

  it("stop() ends the budget: every later call is refused, the cost stays", () => {
    const budget = new Budget({ calls: 100, seconds: 100 }, clock().now);
    budget.charge();
    budget.stop("time");
    expect(budget.exhausted()).toBe(true);
    expect(() => budget.charge()).toThrow(BudgetExhaustedError);
    expect(budget.cost().calls).toBe(1);
    expect(budget.stoppedBy()).toBe("time");
  });

  it("remembers what ended it: the first refused call, stop(), or close(); not merely reaching the limit", () => {
    const budget = new Budget({ calls: 1, seconds: 100 }, clock().now);
    budget.charge();
    expect(budget.endedBy()).toBeNull();
    expect(() => budget.charge()).toThrow(BudgetExhaustedError);
    expect(budget.endedBy()).toBe("calls");
    const closed = new Budget({ calls: 5, seconds: 100 }, clock().now);
    closed.stop("closed");
    expect(() => closed.charge()).toThrow(expect.objectContaining({ reason: "closed" }));
  });

  it("never reports more seconds than the clock gives, and never a negative number", () => {
    let ms = 5_000;
    const budget = new Budget({ calls: 1, seconds: 1 }, () => ms);
    ms = 4_000; // a clock that went back
    expect(budget.seconds()).toBe(0);
  });
});
