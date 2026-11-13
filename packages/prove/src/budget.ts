// The budget of one run (slice 12a): tool calls and wall-clock seconds, both inclusive, from the run's tier
// (overridable for tests). Every Toolbelt call is charged before it runs; a call over the budget is refused and
// not counted, so the cost never exceeds the tier's limits.
import { type AssessmentCost, type AssessmentTier, TIER_IDS, TIERS, type TierLimits } from "@antireverse/protocol";
import type { BudgetView } from "./types.ts";

/** Why a budget ended: its calls or its time were spent, or the run closed it (the Toolbelt is then unusable). */
export type BudgetEnd = "calls" | "time" | "closed";

/** Thrown by every Toolbelt call once the budget is spent. The agent should let it end its run. */
export class BudgetExhaustedError extends Error {
  readonly reason: BudgetEnd;
  constructor(reason: BudgetEnd) {
    super(
      reason === "calls"
        ? "The budget's tool calls are spent."
        : reason === "time"
          ? "The budget's time is spent."
          : "The run is over: the Toolbelt is closed.",
    );
    this.name = "BudgetExhaustedError";
    this.reason = reason;
  }
}

function validLimits(limits: TierLimits | undefined): limits is TierLimits {
  return (
    typeof limits === "object" &&
    limits !== null &&
    Number.isInteger(limits.calls) &&
    limits.calls >= 0 &&
    Number.isFinite(limits.seconds) &&
    limits.seconds >= 0
  );
}

/**
 * The tiers' limits with `overrides` applied. Throws a TypeError for limits that are not whole, non-negative
 * calls and finite, non-negative seconds, for a tier below the previous one (the tier mapping needs them in
 * order), or for a tier above the protocol's (a cost within it must also fit the protocol's tier, which the
 * results schema checks).
 */
export function resolveTiers(
  overrides: Partial<Record<AssessmentTier, TierLimits>> = {},
): Record<AssessmentTier, TierLimits> {
  const tiers = {} as Record<AssessmentTier, TierLimits>;
  let previous: TierLimits | null = null;
  for (const tier of TIER_IDS) {
    const limits = overrides[tier] ?? TIERS[tier];
    if (!validLimits(limits)) throw new TypeError(`The ${tier} limits are whole calls and finite seconds, ≥ 0.`);
    if (limits.calls > TIERS[tier].calls || limits.seconds > TIERS[tier].seconds) {
      throw new TypeError(
        `The ${tier} limits must not exceed the protocol's (${TIERS[tier].calls} calls, ${TIERS[tier].seconds} s).`,
      );
    }
    if (previous !== null && (limits.calls < previous.calls || limits.seconds < previous.seconds)) {
      throw new TypeError(`The ${tier} limits must not be below the previous tier's.`);
    }
    tiers[tier] = { calls: limits.calls, seconds: limits.seconds };
    previous = limits;
  }
  return tiers;
}

/** Seconds with millisecond precision, so costs are stable numbers. */
function toSeconds(ms: number): number {
  return Math.max(0, Math.round(ms)) / 1000;
}

export class Budget implements BudgetView {
  readonly limits: TierLimits;
  readonly #now: () => number;
  readonly #start: number;
  #calls = 0;
  #stopped: BudgetEnd | null = null;

  /** `now` is a clock in milliseconds. The budget starts when it is created. */
  constructor(limits: TierLimits, now: () => number) {
    if (!validLimits(limits)) throw new TypeError("Limits are whole calls and finite seconds, ≥ 0.");
    this.limits = { calls: limits.calls, seconds: limits.seconds };
    this.#now = now;
    this.#start = now();
  }

  calls(): number {
    return this.#calls;
  }

  seconds(): number {
    return toSeconds(this.#now() - this.#start);
  }

  callsLeft(): number {
    return Math.max(0, this.limits.calls - this.#calls);
  }

  secondsLeft(): number {
    return Math.max(0, Math.round((this.limits.seconds - this.seconds()) * 1000) / 1000);
  }

  /** What ended the budget: the first refused call, `stop()`, or null while nothing did. */
  endedBy(): BudgetEnd | null {
    return this.#stopped;
  }

  /** Why the budget is spent (or would refuse the next call), or null while it is not. */
  stoppedBy(): BudgetEnd | null {
    if (this.#stopped !== null) return this.#stopped;
    if (this.seconds() > this.limits.seconds) return "time";
    if (this.#calls >= this.limits.calls) return "calls";
    return null;
  }

  exhausted(): boolean {
    return this.stoppedBy() !== null;
  }

  /** Counts one call, or throws a `BudgetExhaustedError` (and counts nothing) when the budget is spent. */
  charge(): void {
    const end = this.stoppedBy();
    if (end !== null) {
      this.#stopped ??= end;
      throw new BudgetExhaustedError(end);
    }
    this.#calls += 1;
  }

  /** Ends the budget now: `time` when the run's wall time ran out between calls, `closed` when the run is over. */
  stop(reason: BudgetEnd): void {
    this.#stopped ??= reason;
  }

  /** What was spent: calls made and seconds since the start. */
  cost(): AssessmentCost {
    return { calls: this.#calls, seconds: this.seconds() };
  }
}
