import {
  cidrOverlapsPrefix,
  LIMIT_FAILURE_STATUSES,
  type ParsedPolicyRuleInput,
  SIMULATION_LIMITS,
  SIMULATION_NOT_SIMULATED,
  type SimulationIfPromoted,
  type SimulationResult,
  type SimulationRuleResult,
} from "@antireverse/protocol";
import { asciiLower, coveragePattern, methodApplies } from "../detect/coverage.ts";

// Policy simulation (slice 11, D-066): replays recorded Events against draft Rules and counts what the Rules would
// have done in Enforce mode. Pure: no clock, no database, nothing stored. The figures are an estimate, and the
// replay is built so that it under-counts rather than over-counts: whatever it cannot judge is counted as
// `undecidable`, never as a match and never as a refusal. An independent review compared it with an enforcing
// Shield; the notes marked F1 to F11 below are its findings (plan 11 amendment A5).
//
// THE PROMISE (plan 11 amendment A11). For the recorded traffic, the replay never claims a refusal that Shield would
// not make, and never judges a request a certain pass that Shield would refuse — assuming Shield recorded every
// request (`unrecorded_requests`), kept its counters (`counter_eviction`), used its built-in counter store
// (`custom_counter_store`) and ran on a steady clock, off by no more than `EDGE_MS` (`timing`). Those four, with the
// limits of what an Event records, are listed in `SIMULATION_NOT_SIMULATED`. Before the period: Shield's counters
// already held what came before, so the caller hands the replay the Events from before the period as `seed` (they
// fill the counters, requests in flight included, and are reported nowhere) and says from when it was given every
// Event (`completeFrom`); until a request from before then can no longer count, no limit passes anything.
//
// Route. Shield matches a Rule's pattern against the concrete path; an Event carries the route template. Per Event
// and Rule the method is read as Shield reads it (`methodApplies`: none is every method, HEAD with GET); a Rule whose
// methods do not apply is not covered, whatever the route. Then the route is judged three ways (`judgeRoute`):
//   - undecidable, for every Rule: a route that is not a template the replay can read (F1). It reads a route that
//     starts with `/` and whose segments (one final slash aside) are each either plain text over the characters of a
//     Rule literal (`A-Z a-z 0-9 . _ ~ -`, not `.` or `..`) or one whole parameter (`:name`). Everything else Shield
//     records is not read: `(unmatched)`, `(mount)/…`, a regular expression (`/^\/admin/`), a list of paths
//     (`/api[/a|/b]`), a wildcard (`*path`), an optional group (`{/:id}`), a parameter beside other text
//     (`:name.:ext`), an escape, any other character — the path behind such a route is unknown, so every pattern
//     could apply;
//   - covered: the coverage matcher of slice 08 (`coveragePattern`) says every request of the template matches;
//   - not covered: no request of the template can match — a literal of the pattern meets another literal, or the
//     segment counts cannot agree;
//   - undecidable otherwise: every literal of the pattern met the same literal or a parameter (`:id` may or may not
//     take that value) and the segment counts agree.
// Only the text reading of a path is judged. Shield also matches the decoded and dot-resolved forms of a path, so a
// request such as `/api/x/%2e%2e/admin` recorded under a parameterised template can match a pattern this replay
// calls not covered (`decoded_paths` of `SIMULATION_NOT_SIMULATED`).
//
// Outcome, for an Event that reached the application. Shield's order: block Rules in Policy order, then signature
// Rules in Policy order, then the limits; the first Rule that refuses names the Event, and it is counted as a
// `would_*` of that Rule alone (`matched` is counted for every Rule that covers it).
//   - block Rule: `would_block`.
//   - signature Rule: `would_fail_signature` for a recorded signature that is not valid (missing, invalid, stale,
//     replayed). Only a valid signature of a request without a body (`body: "none"`) passes with certainty.
//     Undecidable instead: no recorded signature (a Shield from before slice 04); a valid signature of a request with
//     a body, whether the body was checked or not (F4 and the review's t3 B: an enforcing Shield refuses a signed body
//     at once unless `bodyVerified` lists its content type, then defers to the body hook; the Event records neither
//     whether the type was listed nor, when the hook never ran, what it would have said — `body_verification` of
//     `SIMULATION_NOT_SIMULATED`); an OPTIONS request (Shield exempts a CORS preflight, and an Event does not say
//     whether it was one).
//   - limit Rules, as Shield's limiter: every covering Rule is looked at; if one is over (its count in the window
//     plus this request passes `requests`) the first such Rule in order throttles and nothing is counted on any
//     Rule; otherwise the Event counts on every covering Rule — one request, or for `count: "failures"` one failure
//     when the recorded status is 401 or 403. The window is an exact sliding log at the Event's `ts`, per Rule,
//     Shield process and client (`instance_id`, `actor.ip_hash`).
//
//     PROCESSES AND TIME (plan 11 amendment A9; review B1 to B3, reproduced with Shield's real limiter):
//       · B1. Each Shield process keeps its own counters, and a restarted process starts empty with a new id. The
//         replay keeps a slot of counters per process and client. An Event that does not name its process (a
//         Shield from before A9) counts in a slot of its own, only ever as a possible hit, and never supports a
//         claim: it is never claimed, and its upper count is that of every slot of the client. The upper count of
//         an Event that names its process is its process's slot plus that unnamed slot;
//       · B2. Shield counts a failure when the response closes: the replay places it at `ts` + `latency_ms`, and it
//         counts for a claim only from 2 `EDGE_MS` after that (certainly closed before the request was read) until
//         2 `EDGE_MS` short of a window later; for a pass, from 2 `EDGE_MS` before it until 2 `EDGE_MS` past a
//         window. Shield may have counted it up to 2 `EDGE_MS` earlier than that: 5 ms between reading the clock and
//         stamping `ts`, and 5 ms between closing the response and measuring its latency (`timing`);
//       · B3. A failure limit also counts the requests of its client still in flight (each holds a slot from
//         arrival to close): every covered request Shield may have admitted counts in the upper count of a failure
//         limit until it closed, give or take 2 `EDGE_MS`;
//       · D-071. Shield holds a slot 600 s at most (`SLOT_HOLD_MS`, its `LIMIT_SLOT_HOLD_MS`): from the start of the
//         request up to, not including, start + 600 s, and a 401 or 403 that closes at or after that counts nothing.
//         So a slot whose close is unknown — no `latency_ms`, one at Shield's cap, or a request refused when recorded
//         (how long the application would have taken is unknown) — ends 600 s after `ts`, and a failure that may have
//         closed within `EDGE_MS` of the 600 s (Shield measures the latency with one clock and the hold with another)
//         or whose close is unknown is a possible hit at `ts` + 600 s at the latest, never a certain one. It also
//         bounds what a request from before `completeFrom` can do: hold a slot until 600 s after it began, or count a
//         failure that closed by then.
//
//     TWO COUNTS (D-070). Per counter (limit Rule and client) the replay keeps two logs of hits: the certain hits,
//     requests Shield certainly admitted (no Rule could have refused them) and certainly counted, and the possible
//     hits, requests Shield may have counted while the replay cannot tell — one whose outcome on that counter is
//     undecidable, of an uncovered route that could be the Rule's, or already refused when recorded (under the
//     draft it might have been admitted). The LOWER count is the certain hits; the UPPER count is the certain and
//     the possible hits together.
//     THE INVARIANT. For every counter, the lower count never exceeds Shield's, and Shield's never exceeds the
//     upper count. So a request the replay finds over a limit by its lower count is over it in Shield too — a
//     claimed throttle is always real — and a request that the upper count leaves room for is under it in Shield
//     too — a judged pass is always real, and Shield counted it, so it becomes a certain hit:
//       · a claim (`would_throttle`) needs the lower count over the limit even without the hits within `EDGE_MS`
//         of leaving the window (F8: Shield's limiter reads the clock a moment before the Event is stamped, so a
//         hit there may have left Shield's window). Not claimed, and undecidable, is any request past a limit above
//         1,000 (F2: Shield counts those with weighted sub-windows);
//       · a pass needs room under the upper count with the hits that left the window less than `EDGE_MS` ago (Shield
//         may still hold them), and for a limit above 1,000 with every hit of the last two windows (what a weighted
//         count can reach back to);
//       · in between, the request is undecidable, counted nowhere for certain, and a possible hit on every limit
//         that covers or may cover it — so a client that keeps sending close to a limit stays unjudged on it, while
//         one request that could not be judged costs a generous limit one unit of room, not every later pass;
//       · a request with a valid attestation is never judged by a `device` limit, pass or throttle: Shield holds its
//         device to the limit on a counter of its own, which the same device may fill from other addresses, and no
//         Event names the device (`device_limits`). Shield also counts it on the address, held to 5 times the
//         limit; an unattested request counts on the address alone, held to the limit — the counter the replay
//         keeps, so an unattested request is judged, and an attested one is a possible hit there.
//     The tainted counters of plan 11 amendment A7 were the special case of a limit with no room for one possible
//     hit: the two counts replace them. A possible hit of a failure limit is recorded only when the request may have
//     failed (a 401 or 403, or a request refused when recorded, whose response under the draft is unknown).
//     Undecidable for every covering limit Rule, and counted on none, is also an Event:
//       · without a client hash: there is no counter to replay it on;
//       · of a network that overlaps a range of the never-block list (F3): Shield limits no client on it, and the
//         Event carries the network, not the address. Block and signature Rules are not affected;
//       · that another Rule may have refused (a block, signature or limit Rule whose route could not be judged for
//         it, a signature outcome that could not be judged, a limit as above);
//       · of an OPTIONS request (a preflight is never counted);
//       · once the replay holds `timestampsMax` hit times (F9): from then on no limit is judged, and the result is
//         marked as cut short.
//     test/simulation-property.test.ts checks the consequence against Shield's own decision code over generated
//     sequences that hide from the replay what an Event hides.
//
// An Event that Shield refused when it happened (decision block or throttle, in Enforce mode) never reached the
// application: for every Rule that covers its recorded route it is `matched` and `already_refused`, it has no
// outcome, and it counts on no limit for certain. Under the draft it might have been admitted and counted, so it is a
// possible hit on the counters of the limit Rules that cover or may cover its route. Its route is the pattern of the
// Rule that refused it (or `(unmatched)` for a Containment), so here a segment may also be `*` or a
// final `**`, read as the wildcards they are: a draft Rule covers it only when it covers the whole pattern.
//
// Clients. `clients_affected` counts the distinct client hashes among the Events a Rule would refuse. An Event
// without a hash (a Shield without an actor key, an unknown address) is no client: it is counted in
// `unknown_client_events` (F6).
//
// Rules in force. The main replay treats every draft Rule as enforced, whatever its mode. `promotions` answers the
// other question — what promoting one monitor Rule would refuse (F5): a replay in which only the draft's Rules in
// Enforce mode and that one Rule are in force. A Rule not in force does nothing there: it refuses nothing, is not
// judged, and a monitor limit counts nothing (in Shield a monitor limit counts on its own counters only, which no
// other Rule reads).

/** What the replay reads of an Event. A `ShieldEvent` or a `StoredEvent` is one. */
export interface ReplayEvent {
  /** ISO-8601. The Events are replayed in the order given: oldest first. */
  ts: string;
  /** The Shield process that recorded it (A9); absent from a Shield from before A9. */
  instance_id?: string | null;
  /** `latency_ms`: from arrival to the close of the response. Absent: not known. */
  request: { method: string; route: string; status: number; latency_ms?: number };
  decision: { action: string; mode: string };
  actor: { ip_hash: string | null; ip_prefix?: string | null };
  signature: { status: string; body: string | null } | null;
  /** The recorded attestation; absent or null (a Shield from before slice 03) is no valid token. */
  attestation?: { status: string } | null;
}

export type RouteJudgement = "covered" | "not_covered" | "undecidable";

export interface Replay {
  /** Events replayed: all of them unless `stopped`. */
  replayed: number;
  /** `shouldStop` cut the replay short: the Events from `replayed` on were not looked at. */
  stopped: boolean;
  /** The replay held as many hit times as it may: from then on no limit was judged. */
  capped: boolean;
  /** Replayed Events that could not be judged for at least one Rule and that no Rule would refuse. */
  undecidable_events: number;
  rules: SimulationRuleResult[];
  totals: SimulationResult["totals"];
}

export interface ReplayOptions {
  /** Asked now and then; when it says so the replay ends and reports how far it came. */
  shouldStop?: () => boolean;
  /** The CIDRs of the Organization's never-block list. Left out: none. */
  neverBlock?: readonly string[];
  /** Hit times held at most for the period, all limits together. Left out: `TIMESTAMPS_MAX`. */
  timestampsMax?: number;
  /**
   * Hit times the seed may hold, apart from `timestampsMax`. When the seed runs out of it, the rest of the seed is
   * not replayed and counts as unseen (`completeFrom` moves to its newest Event); the period is not cut. Left out:
   * `SEED_TIMESTAMPS_MAX`.
   */
  seedTimestampsMax?: number;
  /** Per Rule, whether it is in force. Left out: every Rule is. */
  inForce?: readonly boolean[];
  /**
   * Events from before the period, oldest first (A11, review R1 and R4): replayed before `events` to fill the limit
   * counters as Shield held them when the period began, their requests in flight included. Nothing of them is
   * reported. Left out: none.
   */
  seed?: readonly ReplayEvent[];
  /**
   * The replay was given every Event stamped from this time on (milliseconds; the seed's included) and none from
   * before. A limit passes nothing while a request from before could still count on it — its reach, and for a
   * failure limit also the 600 s Shield holds a slot at most (D-071). Left out: every Event that ever counted was
   * given.
   */
  completeFrom?: number;
}

/** How often `shouldStop` is asked: once per this many Events. */
const STOP_CHECK_EVERY = 1_024;
/** Events `replayAsync` replays before it lets other work run. */
const YIELD_EVERY = 2_000;
/** Hit times a replay holds at most. A day of 50,000 Events under 50 limits would be 2,500,000. */
export const TIMESTAMPS_MAX = 2_000_000;
/** Hit times the seed holds at most, besides: 20,000 Events under 50 limits, a failure and a slot each. */
export const SEED_TIMESTAMPS_MAX = 2_000_000;
/** The largest limit Shield counts with an exact log (`EXACT_LIMIT_MAX` of Shield's counters). */
const EXACT_LIMIT_MAX = 1_000;
/** How far the limiter's reading of the clock may lie before the `ts` of the Event, in milliseconds. */
const EDGE_MS = 5;
/** The largest `latency_ms` Shield records; a request may have taken longer. */
export const LATENCY_MAX_MS = 600_000;
/** How long Shield holds a failure slot at most, and counts a failure in (D-071): its `LIMIT_SLOT_HOLD_MS`. */
export const SLOT_HOLD_MS = 600_000;
/** Rules per Policy at most: a counter key is the client's number times this plus the Rule's index. */
const KEY_RULES = 64;

/** A segment of a route template the replay reads: plain text of a Rule literal's characters, or one parameter. */
const PLAIN_SEGMENT = /^(?:[a-z0-9._~-]+|:[a-z_$][a-z0-9_$]*)$/;

/**
 * The segments of the ASCII-lowered route `lowered`, or null when it is not a template the replay reads. With
 * `pattern`, the route is the pattern of a Rule that refused the request: `*` and a final `**` are segments too.
 */
function templateSegments(lowered: string, pattern: boolean): string[] | null {
  if (!lowered.startsWith("/")) return null;
  const trimmed = lowered.length > 1 && lowered.endsWith("/") ? lowered.slice(0, -1) : lowered;
  if (trimmed === "/") return [];
  const segments = trimmed.slice(1).split("/");
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i] as string;
    if (pattern && (segment === "*" || (segment === "**" && i === segments.length - 1))) continue;
    if (!PLAIN_SEGMENT.test(segment) || segment === "." || segment === "..") return null;
  }
  return segments;
}

/** Whether some request of the template can match the Rule pattern `path`. */
function couldApply(path: string, template: readonly string[]): boolean {
  const pattern = path === "/" ? [] : asciiLower(path).slice(1).split("/");
  const everythingBelow = pattern.at(-1) === "**";
  if (everythingBelow) pattern.pop();
  for (let i = 0; ; i++) {
    const segment = template[i];
    // The template ends: the pattern must end here too (a final `**` takes nothing).
    if (segment === undefined) return i >= pattern.length;
    // A wildcard of a refusing Rule's pattern: any segment, or any number of them.
    if (segment === "*" || segment === "**") return true;
    const wanted = pattern[i];
    // The pattern ends and the template goes on: only `**` takes the rest.
    if (wanted === undefined) return everythingBelow;
    if (wanted === "*" || segment.startsWith(":")) continue;
    if (wanted !== segment) return false;
  }
}

/** `judgeRoute` with the Rule's compiled coverage pattern. */
function judge(path: string, pattern: RegExp, route: string, refused: boolean): RouteJudgement {
  const lowered = asciiLower(route);
  const template = templateSegments(lowered, refused);
  if (template === null) return "undecidable";
  if (pattern.test(lowered)) return "covered";
  return couldApply(path, template) ? "undecidable" : "not_covered";
}

/**
 * How the Rule pattern `path` stands to the route `route` of an Event (see the top of this file). `refused`: the
 * Event is of a request Shield refused, whose route is a Rule pattern.
 */
export function judgeRoute(path: string, route: string, options: { refused?: boolean } = {}): RouteJudgement {
  return judge(path, new RegExp(coveragePattern(path), "s"), route, options.refused === true);
}

interface DraftRule {
  index: number;
  kind: "block" | "signature" | "limit";
  path: string;
  methods: readonly string[];
  pattern: RegExp;
  requests: number;
  windowMs: number;
  failures: boolean;
  /** A `device` limit: an attested Event over it on its address cannot be judged. */
  device: boolean;
  row: SimulationRuleResult;
  /** The numbers of the clients this Rule would refuse. */
  clients: Set<number>;
  /** `METHOD route` → Events of it this Rule would refuse. */
  routes: Map<string, { route: string; method: string; count: number }>;
}

/** The hits of one Rule and client, oldest first; `head` is the first still in the window. */
interface Log {
  times: number[];
  head: number;
}

const isFailure = (status: number): boolean => (LIMIT_FAILURE_STATUSES as readonly number[]).includes(status);

/** One replay: Events are fed in order, then the result is read. */
function createReplay(rules: readonly ParsedPolicyRuleInput[], options: ReplayOptions) {
  const drafts = rules.map(
    (rule, index): DraftRule => ({
      index,
      kind: rule.limit !== undefined ? "limit" : rule.requires === "signature" ? "signature" : "block",
      path: rule.path,
      methods: rule.methods,
      pattern: new RegExp(coveragePattern(rule.path), "s"),
      requests: rule.limit?.requests ?? 0,
      windowMs: (rule.limit?.window_s ?? 0) * 1_000,
      failures: rule.limit?.count === "failures",
      device: rule.limit?.key === "device",
      row: {
        index,
        ...(rule.id === undefined ? {} : { id: rule.id }),
        name: rule.name,
        matched: 0,
        would_block: 0,
        would_fail_signature: 0,
        would_throttle: 0,
        already_refused: 0,
        undecidable: 0,
        clients_affected: 0,
        unknown_client_events: 0,
        sample_routes: [],
      },
      clients: new Set(),
      routes: new Map(),
    }),
  );
  const active = drafts.filter((draft) => options.inForce?.[draft.index] !== false);
  // Shield's order: the plain Rules, then the requirement Rules, each in Policy order; the limits come after both.
  const blocks = active.filter((draft) => draft.kind === "block");
  const signatures = active.filter((draft) => draft.kind === "signature");
  const limits = active.filter((draft) => draft.kind === "limit");
  const neverBlock = options.neverBlock ?? [];
  let completeFrom = options.completeFrom ?? Number.NEGATIVE_INFINITY;
  const timestampsMax = options.timestampsMax ?? TIMESTAMPS_MAX;
  /** Replaying the seed: its own budget of hit times, and running out of it cuts the seed, not the period. */
  let seeding = (options.seed?.length ?? 0) > 0;
  let seedFull = false;
  let budget = seeding ? (options.seedTimestampsMax ?? SEED_TIMESTAMPS_MAX) : timestampsMax;

  /** `METHOD route` → the judgement of every Rule: a day of traffic has few distinct routes. One per kind of Event. */
  const judged = [new Map<string, RouteJudgement[]>(), new Map<string, RouteJudgement[]>()] as const;
  const judgementsOf = (method: string, route: string, refused: boolean): RouteJudgement[] => {
    const cache = judged[refused ? 1 : 0];
    const key = `${method} ${route}`;
    let judgements = cache.get(key);
    if (judgements === undefined) {
      judgements = drafts.map((draft) =>
        methodApplies(draft.methods, method) ? judge(draft.path, draft.pattern, route, refused) : "not_covered",
      );
      cache.set(key, judgements);
    }
    return judgements;
  };

  /** Network prefix → whether a never-block range overlaps it. */
  const listed = new Map<string, boolean>();
  const onNeverBlockList = (prefix: string | null | undefined): boolean => {
    if (neverBlock.length === 0) return false;
    // A network nobody recorded cannot be shown to be off the list.
    if (prefix === null || prefix === undefined) return true;
    let known = listed.get(prefix);
    if (known === undefined) {
      known = neverBlock.some((cidr) => cidrOverlapsPrefix(cidr, prefix));
      listed.set(prefix, known);
    }
    return known;
  };

  /** Client hash → its number. */
  const clientNumbers = new Map<string, number>();
  /** Instance id, NUL, client number → its slot: the counters of one client in one Shield process (A9 B1). */
  const slotNumbers = new Map<string, number>();
  /** Client number → its slots. The instance id "" is the slot of the Events that do not name their process. */
  const clientSlots = new Map<number, number[]>();
  /** Slot × `KEY_RULES` + Rule index → the certain hits, in time order: one time, or a log of them. */
  const logs = new Map<number, number | Log>();
  /** Same key → the possible hits: requests Shield may have counted that the replay could not judge. */
  const possibles = new Map<number, number | Log>();
  /** Same key, failure limits only → when each request that may hold a slot there closed (A9 B3). */
  const flights = new Map<number, number | Log>();
  /** Times held now, in the three maps together. */
  let stored = 0;

  const slotOf = (instance: string, client: number): number => {
    const name = `${instance}\u0000${client}`;
    let slot = slotNumbers.get(name);
    if (slot === undefined) {
      slot = slotNumbers.size;
      slotNumbers.set(name, slot);
      const slots = clientSlots.get(client);
      if (slots === undefined) clientSlots.set(client, [slot]);
      else slots.push(slot);
    }
    return slot;
  };
  /**
   * The slots whose hits Shield may have counted on the counter that judges a request of `client`: its process's
   * and the slot of Events that do not name theirs; for a request that does not name its process, all of them.
   */
  const slotsFor = (own: number, client: number): readonly number[] => {
    // A client's first Event, naming no process: the slot of such Events, so that what the replay was not given
    // (`completeFrom`) still bounds it.
    if (own === -1) return clientSlots.get(client) ?? [slotOf("", client)];
    const unnamed = slotNumbers.get(`\u0000${client}`);
    return unnamed === undefined ? [own] : [own, unnamed];
  };

  /** The first position of `held` whose time is after `time`. */
  const after = (held: Log, time: number): number => {
    let low = held.head;
    let high = held.times.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if ((held.times[middle] as number) <= time) low = middle + 1;
      else high = middle;
    }
    return low;
  };
  /** The times of `key` in `store` after `from` and at most `to`; drops those at most `drop` first (never needed again). */
  const countIn = (store: Map<number, number | Log>, key: number, drop: number, from: number, to: number): number => {
    const held = store.get(key);
    if (held === undefined) return 0;
    if (typeof held === "number") {
      if (held <= drop) {
        store.delete(key);
        stored -= 1;
        return 0;
      }
      return held > from && held <= to ? 1 : 0;
    }
    const { times } = held;
    while (held.head < times.length && (times[held.head] as number) <= drop) {
      held.head += 1;
      stored -= 1;
    }
    if (held.head === times.length) {
      store.delete(key);
      return 0;
    }
    // Times that left the window are dropped once they are most of the log.
    if (held.head > 64 && held.head * 2 > times.length) {
      held.times = times.slice(held.head);
      held.head = 0;
    }
    return after(held, to) - after(held, from);
  };
  /** No room for more hit times: the seed is cut, or from here on no limit of the period is judged. */
  const full = (): void => {
    if (seeding) seedFull = true;
    else capped = true;
  };
  /** Holds `time` for `key` in `store`, in time order. False, and the replay full, when there is no room. */
  const insert = (store: Map<number, number | Log>, key: number, time: number): boolean => {
    if (stored + 1 > budget) {
      full();
      return false;
    }
    const held = store.get(key);
    if (held === undefined) store.set(key, time);
    else if (typeof held === "number") store.set(key, { times: held <= time ? [held, time] : [time, held], head: 0 });
    else {
      const at = after(held, time);
      if (at === held.times.length) held.times.push(time);
      else held.times.splice(at, 0, time);
    }
    stored += 1;
    return true;
  };

  /** How far back a hit of `draft` can count: twice the window above 1,000 (Shield's weighted count). */
  const reachOf = (draft: DraftRule): number =>
    draft.requests > EXACT_LIMIT_MAX ? 2 * draft.windowMs : draft.windowMs;
  /** Before this, nothing of `draft` can count at `now` again. */
  const dropOf = (draft: DraftRule, now: number): number => now - reachOf(draft) - 2 * EDGE_MS;
  /**
   * The certain hits of `key` that Shield counted at any reading of the clock for a request at `now`. A hit of a
   * request is stamped with its `ts`, and Shield's reading was up to `EDGE_MS` before each `ts`; a failure is stamped
   * with the time its response closed, `ts` plus `latency_ms`, and Shield counted it up to 2 `EDGE_MS` before that
   * (A9 B2: two pauses of `EDGE_MS` at most): it counts only once it has certainly happened, and until it may have
   * left the window.
   */
  const lowerOf = (draft: DraftRule, key: number, now: number): number =>
    draft.failures
      ? countIn(logs, key, dropOf(draft, now), now - draft.windowMs + 2 * EDGE_MS, now - 2 * EDGE_MS)
      : countIn(logs, key, dropOf(draft, now), now - draft.windowMs + EDGE_MS, Number.POSITIVE_INFINITY);
  /**
   * The hits, certain and possible, of `key` that Shield may have counted at a reading for a request at `now`; for a
   * failure limit also the requests that may still have held a slot (A9 B3: Shield counts them with the failures).
   */
  const upperOf = (draft: DraftRule, key: number, now: number): number => {
    // Hits from before what the replay was given may still count: no upper bound (A11).
    // A request from before holds a slot, or counts a failure, at most `SLOT_HOLD_MS` after it began (D-071).
    const unseen = completeFrom + reachOf(draft) + 2 * EDGE_MS + (draft.failures ? SLOT_HOLD_MS : 0);
    if (now < unseen) return Number.POSITIVE_INFINITY;
    const drop = dropOf(draft, now);
    if (!draft.failures) {
      const from = now - reachOf(draft) - EDGE_MS;
      return (
        countIn(logs, key, drop, from, Number.POSITIVE_INFINITY) +
        countIn(possibles, key, drop, from, Number.POSITIVE_INFINITY)
      );
    }
    const from = now - reachOf(draft) - 2 * EDGE_MS;
    const to = now + 2 * EDGE_MS;
    const closing = now - 3 * EDGE_MS;
    return (
      countIn(logs, key, drop, from, to) +
      countIn(possibles, key, drop, from, to) +
      countIn(flights, key, closing, closing, Number.POSITIVE_INFINITY)
    );
  };

  /**
   * An Event Shield may have counted and the replay did not: a possible hit on every limit that covers or may cover
   * it, in the slot of its process. `status` is null when the response under the draft is unknown (a request refused
   * when recorded); `closed` is when its response closed (when not known, when Shield stopped holding its slot).
   */
  const possibly = (
    judgements: readonly RouteJudgement[],
    client: number,
    instance: string,
    now: number,
    status: number | null,
    closed: number,
  ): void => {
    if (client === -1 || !Number.isFinite(now) || capped || seedFull) return;
    const slot = slotOf(instance, client);
    for (const draft of limits) {
      if (judgements[draft.index] === "not_covered") continue;
      const key = slot * KEY_RULES + draft.index;
      if (!draft.failures) {
        if (!insert(possibles, key, now)) return;
        continue;
      }
      // A slot from arrival to close, and a failure at close if it may have failed.
      if (!insert(flights, key, closed)) return;
      if ((status === null || isFailure(status)) && !insert(possibles, key, closed)) return;
    }
  };

  /** The number of a client hash, or -1 for none. */
  const clientOf = (hash: string | null): number => {
    if (hash === null) return -1;
    let known = clientNumbers.get(hash);
    if (known === undefined) {
      known = clientNumbers.size;
      clientNumbers.set(hash, known);
    }
    return known;
  };

  const allClients = new Set<number>();
  let wouldRefuse = 0;
  let unknownRefused = 0;
  let undecidableEvents = 0;
  let replayed = 0;
  let capped = false;

  function step(event: ReplayEvent): void {
    replayed += 1;
    const { method, route, status } = event.request;
    const { action, mode } = event.decision;
    const refused = mode === "enforce" && (action === "block" || action === "throttle");
    const judgements = judgementsOf(method, route, refused);
    let undecidable = false;

    if (refused) {
      for (const draft of active) {
        const judgement = judgements[draft.index];
        if (judgement === "covered") {
          draft.row.matched += 1;
          draft.row.already_refused += 1;
        } else if (judgement === "undecidable") {
          draft.row.undecidable += 1;
          undecidable = true;
        }
      }
      if (undecidable) undecidableEvents += 1;
      // Under the draft it might have reached the application: whatever it would have counted is not known.
      // How long the application would have taken is not known either: a slot for as long as Shield holds one.
      if (limits.length > 0) {
        const client = clientOf(event.actor.ip_hash);
        const at = Date.parse(event.ts);
        possibly(judgements, client, event.instance_id ?? "", at, null, at + SLOT_HOLD_MS);
      }
      return;
    }

    let refusedBy: DraftRule | null = null;
    /** A Rule looked at before may have refused the Event: nothing after it can be counted on. */
    let uncertain = false;
    for (const draft of blocks) {
      const judgement = judgements[draft.index];
      if (judgement === "covered") {
        draft.row.matched += 1;
        if (refusedBy === null) {
          refusedBy = draft;
          draft.row.would_block += 1;
        }
      } else if (judgement === "undecidable") {
        draft.row.undecidable += 1;
        undecidable = true;
        uncertain = true;
      }
    }
    for (const draft of signatures) {
      const judgement = judgements[draft.index];
      if (judgement === "covered") {
        draft.row.matched += 1;
        if (refusedBy !== null) continue;
        const signature = event.signature;
        if (signature === null || method === "OPTIONS" || (signature.status === "valid" && signature.body !== "none")) {
          draft.row.undecidable += 1;
          undecidable = true;
          uncertain = true;
        } else if (signature.status !== "valid") {
          refusedBy = draft;
          draft.row.would_fail_signature += 1;
        }
      } else if (judgement === "undecidable") {
        draft.row.undecidable += 1;
        undecidable = true;
        uncertain = true;
      }
    }

    const client = clientOf(event.actor.ip_hash);

    if (limits.length > 0) {
      const now = Date.parse(event.ts);
      // A limit that cannot be judged may have throttled the Event, and a throttled request counts on no limit.
      let covering = 0;
      for (const draft of limits) {
        const judgement = judgements[draft.index];
        if (judgement === "covered") covering += 1;
        else if (judgement === "undecidable") uncertain = true;
      }
      let countable =
        covering > 0 &&
        refusedBy === null &&
        !uncertain &&
        !capped &&
        !seedFull &&
        method !== "OPTIONS" &&
        client !== -1 &&
        Number.isFinite(now) &&
        !onNeverBlockList(event.actor.ip_prefix);
      const attested = event.attestation?.status === "valid";
      // The process that counted it (B1): none named, and no count of it supports a claim.
      const instance = event.instance_id ?? "";
      const own = countable && instance !== "" ? slotOf(instance, client) : -1;
      // When its response closed (B2, B3). Known only well short of Shield's hold of a slot (D-071): a latency
      // within `EDGE_MS` of it, at the cap or not recorded ends the slot at the hold, with a failure possible only.
      const latency = event.request.latency_ms;
      const closeKnown = latency !== undefined && latency >= 0 && latency < SLOT_HOLD_MS - EDGE_MS;
      const closed = closeKnown ? now + latency : now + Math.min(SLOT_HOLD_MS, LATENCY_MAX_MS);
      let over: DraftRule | null = null;
      /** The Event is past a limit, and whether Shield would throttle it cannot be told. */
      let unjudged = false;
      for (const draft of limits) {
        const judgement = judgements[draft.index];
        if (judgement === "covered") {
          draft.row.matched += 1;
          if (!countable || over !== null) continue;
          if (draft.device && attested) {
            // Shield holds the device to the limit, on a counter of its own that no Event names: the same device
            // may have spent it from another address. Never judged.
            unjudged = true;
            continue;
          }
          // Over by the lower count of its own process: a claim — never above 1,000 (F2: weighted sub-windows).
          if (
            own !== -1 &&
            draft.requests <= EXACT_LIMIT_MAX &&
            lowerOf(draft, own * KEY_RULES + draft.index, now) + 1 > draft.requests
          ) {
            over = draft;
            continue;
          }
          // A pass only if the upper count leaves room.
          let upper = 0;
          for (const slot of slotsFor(own, client)) upper += upperOf(draft, slot * KEY_RULES + draft.index, now);
          if (upper + 1 > draft.requests) unjudged = true;
        } else if (judgement === "undecidable") {
          draft.row.undecidable += 1;
          undecidable = true;
        }
      }
      if (over !== null) {
        refusedBy = over;
        over.row.would_throttle += 1;
      } else if (refusedBy === null && covering === 0 && uncertain) {
        // Only limits whose route could not be judged: Shield may have counted the Event on them.
        possibly(judgements, client, instance, now, status, closed);
      } else if (refusedBy === null && covering > 0) {
        const failed = isFailure(status);
        if (countable && !unjudged) {
          let needed = 0;
          for (const draft of limits) {
            if (judgements[draft.index] === "covered") needed += draft.failures ? (failed ? 2 : 1) : 1;
          }
          if (stored + needed > budget) {
            // No room to count this Event: the seed is cut, or from here on no limit is judged.
            full();
            countable = false;
          }
        }
        if (!countable || unjudged) possibly(judgements, client, instance, now, status, closed);
        // A pass: Shield admitted it. Certain on the counters of its process; possible on the slot of Events that do
        // not name theirs.
        const slot = !countable || unjudged ? -1 : own !== -1 ? own : slotOf("", client);
        for (const draft of limits) {
          if (judgements[draft.index] !== "covered") continue;
          if (slot === -1) {
            // Not judged: no outcome on any covering limit, and counted on none for certain.
            draft.row.undecidable += 1;
            undecidable = true;
            continue;
          }
          const key = slot * KEY_RULES + draft.index;
          if (!draft.failures) insert(own !== -1 ? logs : possibles, key, now);
          else {
            insert(flights, key, closed);
            if (failed) insert(own !== -1 && closeKnown ? logs : possibles, key, closed);
          }
        }
      }
    }

    if (refusedBy !== null) {
      wouldRefuse += 1;
      if (client === -1) {
        unknownRefused += 1;
        refusedBy.row.unknown_client_events += 1;
      } else {
        allClients.add(client);
        refusedBy.clients.add(client);
      }
      const key = `${method} ${route}`;
      const sample = refusedBy.routes.get(key);
      if (sample === undefined) refusedBy.routes.set(key, { route, method, count: 1 });
      else sample.count += 1;
    } else if (undecidable) {
      undecidableEvents += 1;
    }
  }

  function finish(stopped: boolean): Replay {
    for (const draft of drafts) {
      draft.row.clients_affected = draft.clients.size;
      draft.row.sample_routes = [...draft.routes.values()]
        .sort(
          (a, b) =>
            b.count - a.count || (a.route < b.route ? -1 : a.route > b.route ? 1 : a.method < b.method ? -1 : 1),
        )
        .slice(0, SIMULATION_LIMITS.sampleRoutesMax);
    }
    return {
      replayed,
      stopped,
      capped,
      undecidable_events: undecidableEvents,
      rules: drafts.map((draft) => draft.row),
      totals: { would_refuse: wouldRefuse, clients_affected: allClients.size, unknown_client_events: unknownRefused },
    };
  }

  /** Forgets every reported figure and keeps the counters: what the seed leaves behind. */
  function forgetReport(): void {
    for (const draft of drafts) {
      Object.assign(draft.row, {
        matched: 0,
        would_block: 0,
        would_fail_signature: 0,
        would_throttle: 0,
        already_refused: 0,
        undecidable: 0,
        clients_affected: 0,
        unknown_client_events: 0,
        sample_routes: [],
      });
      draft.clients.clear();
      draft.routes.clear();
    }
    allClients.clear();
    wouldRefuse = 0;
    unknownRefused = 0;
    undecidableEvents = 0;
    replayed = 0;
  }

  /**
   * The seed is over: nothing of it is reported, its counters stay, and the period gets its own budget. A seed cut
   * for room leaves its later Events unseen: `completeFrom` moves to the newest Event of the seed.
   */
  function beginPeriod(seed: readonly ReplayEvent[]): void {
    forgetReport();
    if (!seeding) return;
    if (seedFull) {
      let newest = Number.NEGATIVE_INFINITY;
      for (const event of seed) {
        const at = Date.parse(event.ts);
        // A time that cannot be read could be any: nothing before the period is known then.
        newest = Number.isFinite(at) ? Math.max(newest, at) : Number.POSITIVE_INFINITY;
        if (newest === Number.POSITIVE_INFINITY) break;
      }
      completeFrom = Math.max(completeFrom, newest);
    }
    seeding = false;
    seedFull = false;
    budget = stored + timestampsMax;
  }

  return { step, finish, beginPeriod, seedFull: () => seedFull };
}

/** Replays `events` (oldest first) against the draft `rules` (Policy order), in one go. */
export function replay(
  rules: readonly ParsedPolicyRuleInput[],
  events: readonly ReplayEvent[],
  options: ReplayOptions = {},
): Replay {
  const run = createReplay(rules, options);
  const seed = options.seed ?? [];
  // `n` counts the Events stepped, seed and period together: the stop is asked every `STOP_CHECK_EVERY` of them.
  let n = 0;
  for (let i = 0; i < seed.length && !run.seedFull(); i++, n++) {
    if (n % STOP_CHECK_EVERY === 0 && options.shouldStop?.() === true) {
      run.beginPeriod(seed);
      return run.finish(true);
    }
    run.step(seed[i] as ReplayEvent);
  }
  run.beginPeriod(seed);
  for (let i = 0; i < events.length; i++, n++) {
    if (n % STOP_CHECK_EVERY === 0 && options.shouldStop?.() === true) return run.finish(true);
    run.step(events[i] as ReplayEvent);
  }
  return run.finish(false);
}

const nextTurn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

/**
 * `replay`, letting other work of the process run after every `yieldEvery` Events (F9): a replay of a full day must
 * not hold up every other request of the API.
 */
export async function replayAsync(
  rules: readonly ParsedPolicyRuleInput[],
  events: readonly ReplayEvent[],
  options: ReplayOptions & { yieldEvery?: number } = {},
): Promise<Replay> {
  const run = createReplay(rules, options);
  const yieldEvery = Math.max(1, options.yieldEvery ?? YIELD_EVERY);
  // The seed first, reported as nothing; then the period. A stop, wherever it falls, reports the period alone.
  const seed = options.seed ?? [];
  let n = 0;
  for (let i = 0; i < seed.length && !run.seedFull(); i++, n++) {
    if (n % STOP_CHECK_EVERY === 0 && options.shouldStop?.() === true) {
      run.beginPeriod(seed);
      return run.finish(true);
    }
    if (n > 0 && n % yieldEvery === 0) await nextTurn();
    run.step(seed[i] as ReplayEvent);
  }
  run.beginPeriod(seed);
  for (let i = 0; i < events.length; i++, n++) {
    if (n % STOP_CHECK_EVERY === 0 && options.shouldStop?.() === true) return run.finish(true);
    if (n > 0 && n % yieldEvery === 0) await nextTurn();
    run.step(events[i] as ReplayEvent);
  }
  return run.finish(false);
}

/**
 * Per draft Rule in Monitor mode, what promoting it would refuse (`if_promoted`, F5): a replay with the draft's
 * Rules in Enforce mode and that one Rule in force. Undefined for a Rule in Enforce mode, and for the Rules that
 * `shouldStop` left no time for.
 */
export async function promotions(
  rules: readonly ParsedPolicyRuleInput[],
  events: readonly ReplayEvent[],
  options: Omit<ReplayOptions, "inForce"> & { yieldEvery?: number } = {},
): Promise<(SimulationIfPromoted | undefined)[]> {
  const promoted: (SimulationIfPromoted | undefined)[] = rules.map(() => undefined);
  for (const [index, rule] of rules.entries()) {
    if (rule.mode !== "monitor") continue;
    const inForce = rules.map((other, position) => position === index || other.mode === "enforce");
    const run = await replayAsync(rules, events, { ...options, inForce });
    if (run.stopped) break;
    const row = run.rules[index] as SimulationRuleResult;
    promoted[index] = {
      would_refuse: row.would_block + row.would_fail_signature + row.would_throttle,
      clients_affected: row.clients_affected,
      unknown_client_events: row.unknown_client_events,
      undecidable: row.undecidable,
    };
    await nextTurn();
  }
  return promoted;
}

/** The result of a simulation from its replay, the period it covers and, per Rule, what promoting it would do. */
export function simulationResult(
  replayed: Replay,
  run: {
    from: Date;
    to: Date;
    ranAt: Date;
    truncated: boolean;
    promoted?: readonly (SimulationIfPromoted | undefined)[];
  },
): SimulationResult {
  return {
    period: { from: run.from.toISOString(), to: run.to.toISOString() },
    ran_at: run.ranAt.toISOString(),
    events: replayed.replayed,
    truncated: run.truncated || replayed.stopped || replayed.capped,
    undecidable_events: replayed.undecidable_events,
    not_simulated: [...SIMULATION_NOT_SIMULATED],
    rules: replayed.rules.map((row) => {
      const promoted = run.promoted?.[row.index];
      return promoted === undefined ? row : { ...row, if_promoted: promoted };
    }),
    totals: replayed.totals,
  };
}
