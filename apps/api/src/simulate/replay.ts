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
//     when the recorded status is 401 or 403. The window is an exact sliding log at the Event's `ts`, per Rule and
//     client (`actor.ip_hash`).
//
//     THE INVARIANT. For every counter (limit Rule and client), the replay's count never exceeds Shield's. So a
//     request the replay finds over a limit is over it in Shield too, and a claimed throttle is always real. It
//     holds because the replay counts a request only when Shield certainly admitted it (no Rule could have refused
//     it) and certainly counted it; everything else leaves the counter short of Shield's at worst. Being short is
//     safe for a claim and unsafe for a pass, so:
//       · a claim (`would_throttle`) needs the replay's count over the limit even without the hits within `EDGE_MS`
//         of leaving the window (F8: Shield's limiter reads the clock a moment before the Event is stamped, so a
//         hit there may have left Shield's window). Not claimed, and undecidable, is any request past a limit above
//         1,000 (F2: Shield counts those with weighted sub-windows);
//       · a request with a valid attestation is never judged by a `device` limit, pass or throttle: Shield holds its
//         device to the limit on a counter of its own, which the same device may fill from other addresses, and no
//         Event names the device (`device_limits`). Shield also counts it on the address, held to 5 times the
//         limit; an unattested request counts on the address alone, held to the limit — the counter the replay
//         keeps, so an unattested request is judged;
//       · a pass is certain only if it holds with the hits that left the window less than `EDGE_MS` ago, for a
//         limit above 1,000 with every hit of the last two windows (what a weighted count can reach back to), and
//         on a counter that is not tainted. A counter is tainted by an Event that Shield may have counted while the
//         replay did not — one whose outcome on that counter is undecidable, of an uncovered route that could be
//         the Rule's, or already refused when recorded (under the draft it might have been admitted) — until that
//         Event has left any window Shield could count it in. An uncertain pass is undecidable, counted nowhere,
//         and taints in turn: a client that keeps sending within the window stays unjudged on that Rule.
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
// outcome, and it counts on no limit. Under the draft it might have been admitted and counted, so it taints the
// counters of the limit Rules that cover or may cover its route. Its route is the
// pattern of the Rule that refused it (or `(unmatched)` for a Containment), so here a segment may also be `*` or a
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
  request: { method: string; route: string; status: number };
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
  /** Hit times held at most, all limits together. Left out: `TIMESTAMPS_MAX`. */
  timestampsMax?: number;
  /** Per Rule, whether it is in force. Left out: every Rule is. */
  inForce?: readonly boolean[];
}

/** How often `shouldStop` is asked: once per this many Events. */
const STOP_CHECK_EVERY = 1_024;
/** Events `replayAsync` replays before it lets other work run. */
const YIELD_EVERY = 2_000;
/** Hit times a replay holds at most. A day of 50,000 Events under 50 limits would be 2,500,000. */
export const TIMESTAMPS_MAX = 2_000_000;
/** The largest limit Shield counts with an exact log (`EXACT_LIMIT_MAX` of Shield's counters). */
const EXACT_LIMIT_MAX = 1_000;
/** How far the limiter's reading of the clock may lie before the `ts` of the Event, in milliseconds. */
const EDGE_MS = 5;
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
  const timestampsMax = options.timestampsMax ?? TIMESTAMPS_MAX;

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
  /** Client number × `KEY_RULES` + Rule index → the hits: one time, or a log of them. */
  const logs = new Map<number, number | Log>();
  /** Hit times held now. */
  let stored = 0;
  /** Of the hits last counted by `countIn`, those within `EDGE_MS` of leaving the window. */
  let atEdge = 0;
  /** Of the hits last looked at by `countIn`, those that left the window less than `EDGE_MS` ago. */
  let justOut = 0;
  /**
   * The hits of `key` less than `windowMs` before `now`. Sets `atEdge` and `justOut`; drops the hits that left the
   * window more than `EDGE_MS` ago (no reading of the clock can bring those back).
   */
  const countIn = (key: number, windowMs: number, now: number): number => {
    atEdge = 0;
    justOut = 0;
    const held = logs.get(key);
    if (held === undefined) return 0;
    if (typeof held === "number") {
      const age = now - held;
      if (age >= windowMs + EDGE_MS) {
        logs.delete(key);
        stored -= 1;
        return 0;
      }
      if (age >= windowMs) {
        justOut = 1;
        return 0;
      }
      if (age >= windowMs - EDGE_MS) atEdge = 1;
      return 1;
    }
    const { times } = held;
    while (held.head < times.length && now - (times[held.head] as number) >= windowMs + EDGE_MS) {
      held.head += 1;
      stored -= 1;
    }
    if (held.head === times.length) {
      logs.delete(key);
      return 0;
    }
    let first = held.head;
    while (first < times.length && now - (times[first] as number) >= windowMs) first += 1;
    justOut = first - held.head;
    for (let i = first; i < times.length && now - (times[i] as number) >= windowMs - EDGE_MS; i++) atEdge += 1;
    const count = times.length - first;
    // Hits that left the window are dropped once they are most of the log.
    if (held.head > 64 && held.head * 2 > times.length) {
      held.times = times.slice(held.head);
      held.head = 0;
    }
    return count;
  };
  /** Counter key → until when the replay's count of it may be short of Shield's (milliseconds). */
  const tainted = new Map<number, number>();
  const isTainted = (key: number, now: number): boolean => {
    const until = tainted.get(key);
    if (until === undefined) return false;
    if (until > now) return true;
    tainted.delete(key);
    return false;
  };
  /** An Event Shield may have counted and the replay did not: its counters are short of Shield's while it lasts. */
  const taint = (judgements: readonly RouteJudgement[], client: number, now: number): void => {
    if (client === -1 || !Number.isFinite(now)) return;
    for (const draft of limits) {
      if (judgements[draft.index] === "not_covered") continue;
      const key = client * KEY_RULES + draft.index;
      // Twice the window for a limit above 1,000: Shield's weighted count reaches back that far.
      const until = now + (draft.requests > EXACT_LIMIT_MAX ? 2 : 1) * draft.windowMs + EDGE_MS;
      if ((tainted.get(key) ?? 0) < until) tainted.set(key, until);
    }
  };
  const hit = (key: number, now: number): void => {
    const held = logs.get(key);
    if (held === undefined) logs.set(key, now);
    else if (typeof held === "number") logs.set(key, { times: [held, now], head: 0 });
    else held.times.push(now);
    stored += 1;
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
      if (limits.length > 0) taint(judgements, clientOf(event.actor.ip_hash), Date.parse(event.ts));
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
        method !== "OPTIONS" &&
        client !== -1 &&
        Number.isFinite(now) &&
        !onNeverBlockList(event.actor.ip_prefix);
      const attested = event.attestation?.status === "valid";
      let over: DraftRule | null = null;
      /** The Event is past a limit, and whether Shield would throttle it cannot be told. */
      let unjudged = false;
      for (const draft of limits) {
        const judgement = judgements[draft.index];
        if (judgement === "covered") {
          draft.row.matched += 1;
          if (!countable || over !== null) continue;
          const key = client * KEY_RULES + draft.index;
          if (draft.requests > EXACT_LIMIT_MAX) {
            // Weighted sub-windows (F2): never a claim, and a pass only if two whole windows hold room.
            const reach = countIn(key, 2 * draft.windowMs, now) + justOut;
            if (reach + 1 > draft.requests || isTainted(key, now)) unjudged = true;
            continue;
          }
          if (draft.device && attested) {
            // Shield holds the device to the limit, on a counter of its own that no Event names: the same device
            // may have spent it from another address. Never judged.
            unjudged = true;
            continue;
          }
          const count = countIn(key, draft.windowMs, now);
          if (count + 1 > draft.requests) {
            // Over in the replay. A claim only when it holds in any reading of the clock; a tainted counter does
            // not matter here: Shield's count is at least the replay's.
            if (count - atEdge + 1 <= draft.requests) unjudged = true;
            else over = draft;
          } else if (count + justOut + 1 > draft.requests || isTainted(key, now)) {
            // Under in the replay, but Shield's count may be higher: a hit at the edge, or one the replay could
            // not count.
            unjudged = true;
          }
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
        taint(judgements, client, now);
      } else if (refusedBy === null && covering > 0) {
        if (countable && !unjudged && stored + covering > timestampsMax) {
          // No room to count this Event: from here on no limit is judged.
          capped = true;
          countable = false;
        }
        const failed = isFailure(status);
        if (!countable || unjudged) taint(judgements, client, now);
        for (const draft of limits) {
          if (judgements[draft.index] !== "covered") continue;
          if (!countable || unjudged) {
            // Not judged: no outcome on any covering limit, and counted on none.
            draft.row.undecidable += 1;
            undecidable = true;
          } else if (!draft.failures || failed) {
            hit(client * KEY_RULES + draft.index, now);
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

  return { step, finish };
}

/** Replays `events` (oldest first) against the draft `rules` (Policy order), in one go. */
export function replay(
  rules: readonly ParsedPolicyRuleInput[],
  events: readonly ReplayEvent[],
  options: ReplayOptions = {},
): Replay {
  const run = createReplay(rules, options);
  for (let i = 0; i < events.length; i++) {
    if (i % STOP_CHECK_EVERY === 0 && options.shouldStop?.() === true) return run.finish(true);
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
  for (let i = 0; i < events.length; i++) {
    if (i % STOP_CHECK_EVERY === 0 && options.shouldStop?.() === true) return run.finish(true);
    if (i > 0 && i % yieldEvery === 0) await nextTurn();
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
