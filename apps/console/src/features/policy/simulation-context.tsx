"use client";

import { createContext, type ReactNode, useActionState, useCallback, useContext, useMemo, useState } from "react";
import { type SimulationState, simulatePolicyAction } from "@/app/actions.ts";
import type { SimulationRun } from "./simulation.ts";

interface Simulation {
  /** The answer of the latest simulation of this page view, or null before the first. */
  state: SimulationState;
  /**
   * The last simulation of this page view that succeeded: what the result panel shows and the Rule list reads a
   * Rule's estimate from. A later failure does not take it away.
   */
  run: SimulationRun | null;
  /** The action the "Simulate" form sends its fields to: the Rules the page shows. */
  action: (formData: FormData) => void;
  /** The action the add-Rule form's button sends the form to: the Rules the page shows plus the Rule being typed. */
  draftAction: (formData: FormData) => void;
  /** True while a simulation is running. */
  pending: boolean;
}

const SimulationContext = createContext<Simulation | null>(null);

/**
 * Keeps the latest simulation of the Policy screen (slice 11) for the parts that show it: the result panel, the
 * add-Rule form and the promote confirmation. It lives in the state of this page view only: it is stored
 * nowhere, and a new Policy version, another Environment or a reload starts without one. A successful simulation
 * replaces the one before it; a failed one (too many simulations, the API down) leaves the last successful result
 * in place, and the panel shows the failure above it.
 */
export function PolicySimulation({ children }: { children: ReactNode }) {
  const [state, action, pending] = useActionState(simulatePolicyAction, null);
  // The last successful answer, kept across later failures. It follows `state` once per answer.
  const [run, setRun] = useState<SimulationRun | null>(null);
  const [answered, setAnswered] = useState(state);
  if (answered !== state) {
    setAnswered(state);
    if (state?.ok) setRun({ simulation: state.simulation, rules: state.rules, withDraft: state.withDraft });
  }
  // React leaves a button's own name and value out of the fields when the button names an action, so the
  // mark that asks for the typed Rule is added here.
  const draftAction = useCallback(
    (formData: FormData) => {
      formData.set("simulate", "draft");
      action(formData);
    },
    [action],
  );
  const value = useMemo<Simulation>(
    () => ({
      state,
      run,
      action,
      draftAction,
      pending,
    }),
    [state, run, action, draftAction, pending],
  );
  return <SimulationContext value={value}>{children}</SimulationContext>;
}

/** The simulation of the screen, or null where the screen keeps none: then nothing about simulating is shown. */
export function useSimulation(): Simulation | null {
  return useContext(SimulationContext);
}
