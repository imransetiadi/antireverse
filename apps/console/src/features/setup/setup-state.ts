import type { AppSetup } from "@antireverse/protocol";

// The set-up of one App Environment (slice 16) as the Set up page reads it. Pure.

/** The steps, in their fixed order (UIUX.md SCR-01). */
export const SETUP_STEPS = ["shield", "guard", "harden"] as const;
export type SetupStepId = (typeof SETUP_STEPS)[number];

/** How many of the three steps are done. */
export function doneCount(setup: AppSetup): number {
  return SETUP_STEPS.filter((step) => setup[step].done_at !== null).length;
}

/** The first step not done, or null when all three are. */
export function currentStep(setup: AppSetup): SetupStepId | null {
  return SETUP_STEPS.find((step) => setup[step].done_at === null) ?? null;
}

const earliest = (a: string | null, b: string | null): string | null => {
  if (a === null) return b;
  if (b === null) return a;
  return Date.parse(b) < Date.parse(a) ? b : a;
};

/** `next` merged into `current`: each step keeps its earliest time, so a step once done stays done. */
export function mergeSetup(current: AppSetup, next: AppSetup): AppSetup {
  const merged = { ...current };
  let changed = false;
  for (const step of SETUP_STEPS) {
    const at = earliest(current[step].done_at, next[step].done_at);
    if (at !== current[step].done_at) {
      merged[step] = { done_at: at };
      changed = true;
    }
  }
  return changed ? merged : current;
}
