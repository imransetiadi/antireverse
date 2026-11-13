import {
  ID_PATTERNS,
  SIMULATION_LIMITS,
  SimulatePolicyRequestSchema,
  type SimulatePolicyResponse,
} from "@antireverse/protocol";
import { Hono } from "hono";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { prepareRules } from "../policy.ts";
import { problem } from "../problem.ts";
import { promotions, type ReplayEvent, replayAsync, simulationResult } from "../simulate/replay.ts";
import { allowlistCidrs } from "../stores/allowlist.ts";
import { findApp } from "../stores/apps.ts";
import { listReplayEvents } from "../stores/events.ts";
import { validateJson } from "../validate.ts";

/** The bounds of a simulation, for tests: left out, `SIMULATION_LIMITS` and the process clock. */
export interface SimulationOptions {
  /** Events replayed at most. Default `SIMULATION_LIMITS.eventsMax`. */
  eventsMax?: number;
  /** Events from before the period read at most to seed the limit counters. Default `SEED_EVENTS_MAX`. */
  seedEventsMax?: number;
  /** Milliseconds a simulation may run. Default `SIMULATION_LIMITS.timeLimitMs`. */
  timeLimitMs?: number;
  /** A clock that only moves forward, in milliseconds: what the time limit is measured with. Default `performance.now`. */
  elapsedMs?: () => number;
}

/** Organizations whose simulations are counted at once; beyond it a new one waits for a window to end. */
const BUDGET_KEYS_MAX = 10_000;
/** The span the budget of an Organization is counted over. */
const BUDGET_WINDOW_MS = 60_000;
/** How far ahead of the API's clock an Event may be stamped and still be replayed: the clock of a Shield's host runs a little fast (review F11). */
const CLOCK_AHEAD_MS = 5 * 60_000;
/**
 * Events from before the period read at most to seed the limit counters (plan 11 amendment A11), apart from
 * `SIMULATION_LIMITS.eventsMax` (fourth review: 20,000 bounds the memory of a seed under 50 limit Rules).
 */
export const SEED_EVENTS_MAX = 20_000;
/** The longest `latency_ms` Shield records: a request from before the seed may have been in flight that long. */
export const LATENCY_MAX_MS = 600_000;
/** The seed reaches back at most this far (twice the longest window a limit may have), plus `LATENCY_MAX_MS`. */
const SEED_REACH_MAX_MS = 2 * 3_600_000;

/**
 * How far before the period the Events are read to seed the counters of the draft's limit Rules: what Shield still
 * counted when the period began — twice the longest window (a limit above 1,000 reaches back that far), and the
 * longest a request may have been in flight. Zero without a limit Rule.
 */
function seedReachMs(rules: readonly { limit?: { window_s: number } | undefined }[]): number {
  const longest = Math.max(0, ...rules.map((rule) => rule.limit?.window_s ?? 0)) * 1_000;
  if (longest === 0) return 0;
  // One second more than the replay needs: its edges are a few milliseconds wide.
  return Math.min(2 * longest, SEED_REACH_MAX_MS) + LATENCY_MAX_MS + 1_000;
}

/**
 * At most `limit` simulations in any `BUDGET_WINDOW_MS` per Organization (review F10): the times of the last ones
 * are kept, so no burst at the turn of a fixed window gets twice the budget. In memory, per API process.
 */
function createBudget(limit: number) {
  /** Organization → the times of its simulations still in the window, oldest first. */
  const taken = new Map<string, number[]>();
  const current = (times: number[], ms: number): number[] =>
    times.filter((at) => ms - at < BUDGET_WINDOW_MS && at <= ms);
  return {
    /** Counts one simulation of `key` at `ms`, or refuses it: then `retryAfterS` > 0. */
    take(key: string, ms: number): { allowed: boolean; retryAfterS: number } {
      const times = current(taken.get(key) ?? [], ms);
      if (times.length >= limit) {
        taken.set(key, times);
        const oldest = times[0] as number;
        return { allowed: false, retryAfterS: Math.max(1, Math.ceil((oldest + BUDGET_WINDOW_MS - ms) / 1_000)) };
      }
      if (!taken.has(key) && taken.size >= BUDGET_KEYS_MAX) {
        // Room is made only from Organizations whose simulations have all left the window.
        for (const [other, held] of taken) if (current(held, ms).length === 0) taken.delete(other);
        if (taken.size >= BUDGET_KEYS_MAX) return { allowed: false, retryAfterS: 1 };
      }
      times.push(ms);
      taken.set(key, times);
      return { allowed: true, retryAfterS: 0 };
    },
  };
}

/**
 * Policy simulation (slice 11, D-066): what draft Rules would have done to the recorded requests of the last 24
 * hours. It reads Events and the never-block list and answers; it stores nothing and publishes nothing.
 */
export function simulateRoutes(deps: { db: Db; now?: () => Date; simulation?: SimulationOptions }): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const eventsMax = deps.simulation?.eventsMax ?? SIMULATION_LIMITS.eventsMax;
  const seedEventsMax = deps.simulation?.seedEventsMax ?? SEED_EVENTS_MAX;
  const timeLimitMs = deps.simulation?.timeLimitMs ?? SIMULATION_LIMITS.timeLimitMs;
  const elapsedMs = deps.simulation?.elapsedMs ?? (() => performance.now());
  const budget = createBudget(SIMULATION_LIMITS.perMinute);
  const routes = new Hono<AppEnv>();

  routes.post(
    "/v1/apps/:appId/policy/simulate",
    requireKey(db, "admin"),
    limitBody(),
    validateJson(SimulatePolicyRequestSchema),
    async (c) => {
      const { organizationId } = c.var.principal;
      const appId = c.req.param("appId");
      const { environment, rules } = c.req.valid("json");
      // The checks of a publish beyond the shape: an id that repeats, an enforced Rule for every path. The Rules
      // replayed are the ones sent: a Rule without an id gets none here.
      const prepared = prepareRules(rules);
      if ("errors" in prepared) return problem(c, "validation", prepared.errors);
      const exists =
        ID_PATTERNS.app.test(appId) && (await db.tx({ organizationId }, (q) => findApp(q, appId))) !== null;
      if (!exists) return problem(c, "not-found");

      // Counted only for a draft that is replayed: a refused body or an App that is not there costs nothing.
      const ranAt = now();
      const taken = budget.take(organizationId, ranAt.getTime());
      if (!taken.allowed) {
        c.header("Retry-After", String(taken.retryAfterS));
        return problem(c, "too-many-simulations");
      }

      const deadline = elapsedMs() + timeLimitMs;
      const shouldStop = () => elapsedMs() > deadline;
      const window = new Date(ranAt.getTime() - SIMULATION_LIMITS.windowHours * 3_600_000);
      const ahead = new Date(ranAt.getTime() + CLOCK_AHEAD_MS);
      // One more than the cap: its presence says that the window holds more than is replayed.
      const read = await db.tx({ organizationId }, async (q) => ({
        newest: await listReplayEvents(q, {
          organizationId,
          appId,
          environment,
          from: window,
          to: ahead,
          limit: eventsMax + 1,
        }),
        neverBlock: await allowlistCidrs(q),
      }));

      const capped = read.newest.length > eventsMax;
      const events = (capped ? read.newest.slice(0, eventsMax) : read.newest).reverse();
      // What Shield's counters held when the replayed period began (A11, review R1 and R4). Seeded from the Events
      // before the window; when the cap cut the window, the dropped Events are not read: the first reach of the
      // replayed period then passes no limit (`completeFrom`), and claims rest on what was replayed.
      const reach = seedReachMs(rules);
      let seed: ReplayEvent[] = [];
      let completeFrom: number | undefined;
      if (reach > 0 && capped) {
        completeFrom = events[0] === undefined ? undefined : Date.parse(events[0].ts);
      } else if (reach > 0) {
        const seedFrom = new Date(window.getTime() - reach);
        const before = await db.tx({ organizationId }, (q) =>
          listReplayEvents(q, {
            organizationId,
            appId,
            environment,
            from: seedFrom,
            // Up to the start of the window, which the period's read includes: no Event falls between the two.
            to: window,
            before: true,
            limit: seedEventsMax + 1,
          }),
        );
        const seedCut = before.length > seedEventsMax;
        seed = (seedCut ? before.slice(0, seedEventsMax) : before).reverse();
        // A cut seed holds only its newest Events: nothing is known from before its oldest.
        completeFrom = seedCut && seed[0] !== undefined ? Date.parse(seed[0].ts) : seedFrom.getTime();
      }
      const options = {
        shouldStop,
        neverBlock: read.neverBlock,
        seed,
        ...(completeFrom === undefined ? {} : { completeFrom }),
      };
      const replayed = await replayAsync(rules, events, options);
      // What promoting each monitor Rule would do, in the time that is left; none when the main replay was cut.
      const promoted = replayed.stopped ? undefined : await promotions(rules, events, options);

      // The period the figures cover: from the oldest Event replayed when the cap cut the window; up to the last
      // Event replayed when the time limit cut the replay (it runs oldest first), else up to now — or to the
      // newest Event, when a Shield's clock stamped it ahead of this one.
      const from = capped && events[0] !== undefined ? new Date(events[0].ts) : window;
      const last = events[replayed.replayed - 1];
      const newest = last === undefined ? from : new Date(last.ts);
      const to = replayed.stopped ? newest : new Date(Math.max(newest.getTime(), ranAt.getTime()));
      const simulation = simulationResult(replayed, {
        from,
        to,
        ranAt,
        truncated: capped,
        ...(promoted === undefined ? {} : { promoted }),
      });
      return c.json({ simulation } satisfies SimulatePolicyResponse);
    },
  );

  return routes;
}
