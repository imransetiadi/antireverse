"use client";

import { type AppSetup, AppSetupResponseSchema } from "@antireverse/protocol";
import { useCallback, useEffect, useRef, useState } from "react";
import { ROUTES } from "@/lib/routes.ts";
import { mergeSetup } from "./setup-state.ts";

/** How often the set-up is asked for while Guard or Harden is not done (plan 16, global constraints). */
export const SETUP_POLL_MS = 5_000;

export interface SetupProgress {
  setup: AppSetup;
  /** Shield was seen working: its first Event of this Environment was received at `at`. */
  shieldSeen(at: string): void;
}

const isHidden = (): boolean => typeof document !== "undefined" && document.visibilityState === "hidden";

/**
 * The set-up of one App Environment as it changes, without a reload.
 *
 * - Shield's step is reported by the live event stream (`shieldSeen`, from `ShieldWatcher`).
 * - While Guard or Harden is not done, the set-up proxy is asked every SETUP_POLL_MS, one request at a time — never while the tab is hidden;
 *   when it becomes visible again it is asked at once. Polling stops when both are done.
 * - Answers are merged: a step keeps its earliest time and never goes back to not done. An answer for another
 *   Environment, or one outside the contract, is ignored. 401 ends polling and runs `onSessionExpired`; 404 ends it.
 */
export function useSetupProgress(
  appId: string,
  initial: AppSetup,
  options: { onSessionExpired: () => void },
): SetupProgress {
  const [setup, setSetup] = useState(initial);
  const onSessionExpired = useRef(options.onSessionExpired);
  onSessionExpired.current = options.onSessionExpired;
  const { environment } = initial;
  const polling = setup.guard.done_at === null || setup.harden.done_at === null;

  useEffect(() => {
    if (!polling) return;
    let timer: ReturnType<typeof setInterval> | undefined;
    let ended = false;
    // At most one request at a time: a tick that comes while the previous answer is still awaited is skipped.
    let inFlight = false;

    const stop = (): void => {
      clearInterval(timer);
      timer = undefined;
    };
    const poll = async (): Promise<void> => {
      if (inFlight) return;
      inFlight = true;
      try {
        const response = await fetch(ROUTES.setupApi(appId, environment), {
          cache: "no-store",
          headers: { accept: "application/json" },
        });
        if (ended) return;
        if (response.status === 401 || response.status === 404) {
          ended = true;
          stop();
          if (response.status === 401) onSessionExpired.current();
          return;
        }
        if (!response.ok) return;
        const parsed = AppSetupResponseSchema.safeParse(await response.json());
        if (ended || !parsed.success || parsed.data.setup.environment !== environment) return;
        const next = parsed.data.setup;
        setSetup((current) => mergeSetup(current, next));
      } catch {
        // Unreachable for now: the next poll asks again.
      } finally {
        inFlight = false;
      }
    };
    const start = (): void => {
      if (timer === undefined && !ended) timer = setInterval(() => void poll(), SETUP_POLL_MS);
    };
    const onVisibility = (): void => {
      if (isHidden()) {
        stop();
      } else if (timer === undefined && !ended) {
        void poll();
        start();
      }
    };

    document.addEventListener("visibilitychange", onVisibility);
    if (!isHidden()) start();
    return () => {
      ended = true;
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [appId, environment, polling]);

  const shieldSeen = useCallback((at: string): void => {
    setSetup((current) => mergeSetup(current, { ...current, shield: { done_at: at } }));
  }, []);

  return { setup, shieldSeen };
}
