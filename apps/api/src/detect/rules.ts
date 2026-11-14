import {
  DETECTION_RULES,
  type DetectionRule,
  type DetectionRuleKey,
  LIMIT_FAILURE_STATUSES,
  parseCanarySignal,
  type StoredEvent,
} from "@antireverse/protocol";
import { ASCII_LOWER_SQL } from "./coverage.ts";

// What each managed rule counts, defined once: as a predicate over an Event (the Detector) and as the same
// condition in SQL over a stored Event's `payload` (an Incident's evidence). The thresholds, windows and
// severities live in the protocol's table.

/** Shield applied a block: it answered the request itself (with 403), so the app never saw it. */
const enforcedBlock = (event: StoredEvent) => event.decision.action === "block" && event.decision.mode === "enforce";

/**
 * Distinct Canary ids an Event counts toward `canary-touched`, in signal order. At most this many: a Shield
 * matches one request against a few decoy keys and one decoy route, and each id costs the Detector a
 * transaction, so a forged Event with 32 Canary signals cannot cost 32.
 */
export const MAX_CANARIES_PER_EVENT = 4;

/** `parseCanarySignal`'s pattern as constant SQL regex text (POSIX), for the evidence condition. */
const CANARY_SIGNAL_SQL_PATTERN = "^canary\\.touched:cny_[0-9a-f]{24}$";

/** The Canaries an Event's signals name (`canary.touched:<id>`), each once, at most `MAX_CANARIES_PER_EVENT`. */
export function touchedCanaries(event: StoredEvent): string[] {
  const ids: string[] = [];
  for (const signal of event.signals) {
    const id = parseCanarySignal(signal.id);
    if (id === null || ids.includes(id)) continue;
    ids.push(id);
    if (ids.length === MAX_CANARIES_PER_EVENT) break;
  }
  return ids;
}

/**
 * Shield enforced a Containment (slice 09): an admin already acted on this Actor or network. Such a block is
 * the response to an Incident, not a new attack: counting it would open a second Incident for one attack.
 */
const containmentBlock = (event: StoredEvent) => event.decision.containment_id !== null;

/**
 * A Virtual patch decided the request (slice 20), recorded under monitor or refused under enforce. It counts toward
 * `exploit-attempt` only: an enforced patch block is the response to a known exploit, which already opens its own
 * Incident, so it does not count toward `blocked-burst` as well. A patch whose body condition was never checked
 * (`patch_body: "unchecked"`, recorded as allow; plan A6 F2) is not an exploit attempt and never counts; nor is one
 * whose body was in a character set Shield cannot read (`"undecodable"`, plan A11 M2) — refused under enforce, that
 * block counts like any other enforced block.
 */
const patchDecision = (event: StoredEvent) =>
  (event.decision.patch_id ?? null) !== null &&
  event.decision.patch_body !== "unchecked" &&
  event.decision.patch_body !== "undecodable";

/**
 * `decision.limit_rule_id` (plan 08 amendment A7): the login protection — a failure-counting limit Rule — that matched
 * the request, or null when none did. Undefined for an Event of a Shield from before A7, which does not have the
 * member: only such an Event is judged by the coverage guess (coverage.ts).
 */
const stampOf = (event: StoredEvent): string | null | undefined =>
  (event.decision as { limit_rule_id?: string | null }).limit_rule_id;

/** A limit Rule decided the request: the client was over the limit, and `rule_id` names the Rule. */
const throttleDecision = (event: StoredEvent) =>
  event.decision.action === "throttle" && event.decision.rule_id !== null;

/**
 * A 401 or 403 the app answered: Shield's own enforced block (a Rule's, a Containment's or a Virtual patch's) also
 * ends in 403, and is left out.
 */
const failedResponse = (event: StoredEvent) =>
  (LIMIT_FAILURE_STATUSES as readonly number[]).includes(event.request.status) && !enforcedBlock(event);

/**
 * What the coverage guess says of an Event of an older Shield: whether a login protection of the Policy version it
 * names covers its route, and whether its `rule_id` is one of those login protections.
 */
export interface LegacyCoverage {
  covered: boolean;
  limitRule: boolean;
}
const NOT_COVERED: LegacyCoverage = { covered: false, limitRule: false };

/**
 * How an Event counts toward `credential-stuffing` (D-064), or null when it does not:
 * - "failure": a 401 or 403 the app answered on a request a login protection matched;
 * - "throttle": a throttle by that login protection — counted once per client per window (`onceKey`), so that one
 *   client retrying against its own limit is not a wave, in Monitor mode as in Enforce mode.
 * Plain request limits count toward nothing, and nor does a throttle that names any other Rule. An Event of an older
 * Shield is judged by `legacy`.
 */
export function stuffingKind(event: StoredEvent, legacy: LegacyCoverage = NOT_COVERED): "failure" | "throttle" | null {
  const stamp = stampOf(event);
  if (stamp === null) return null;
  if (stamp !== undefined) {
    if (throttleDecision(event) && event.decision.rule_id === stamp) return "throttle";
    return failedResponse(event) ? "failure" : null;
  }
  if (throttleDecision(event)) return legacy.limitRule ? "throttle" : null;
  return failedResponse(event) && legacy.covered ? "failure" : null;
}

/**
 * The client and window a throttle counts once in: the actor hash (one unknown client when there is none) and the
 * fixed window of `windowS` seconds of the Event's `ts`. The evidence condition uses the same windows.
 */
export function onceKey(event: StoredEvent, windowS: number): string {
  return JSON.stringify([event.actor.ip_hash ?? null, Math.floor(Date.parse(event.ts) / (windowS * 1_000))]);
}

/**
 * Whether counting the Event depends on the coverage guess: an older Shield's failure or throttle. `matchingRules`
 * then needs to be told what the guess says.
 */
export function needsCoverage(event: StoredEvent): boolean {
  return stampOf(event) === undefined && (throttleDecision(event) || failedResponse(event));
}

/** `legacy`: what the coverage guess says of an Event of an older Shield; only two rules ask. */
const COUNTS: Record<DetectionRuleKey, (event: StoredEvent, legacy: LegacyCoverage) => boolean> = {
  "blocked-burst": (event) => enforcedBlock(event) && !containmentBlock(event) && !patchDecision(event),
  // A 401 or 403 from the app. Shield's own enforced block also ends in 403; counting it here would open a
  // second Incident for one blocked attack. Nor does a failure on a request a login protection matched (D-064): it
  // counts toward `credential-stuffing`, so that one wave of failed logins opens one Incident. A throttle is no
  // failed sign-in either.
  "failed-signin-burst": (event, legacy) => {
    const stamp = stampOf(event);
    return (
      failedResponse(event) && !throttleDecision(event) && (stamp === undefined ? !legacy.covered : stamp === null)
    );
  },
  // Counted once per Canary it names (`touchedCanaries`); whether the Canary is the Event's own App
  // Environment's is checked in the tenant transaction.
  "canary-touched": (event) => touchedCanaries(event).length > 0,
  // Counts Clone Beacon reports (`POST /v1/beacon`), never Events: no Event opens a clone Incident.
  "clone-origin": () => false,
  // Counts new Critical or High Findings (slice 19), never Events: no Event opens a vulnerable-component Incident.
  "vulnerable-component": () => false,
  // Counted per (App, Environment, advisory of the patch); the advisory is resolved in the tenant transaction.
  "exploit-attempt": patchDecision,
  // A failure or a throttle of a login protection (`stuffingKind`); the Detector counts a throttle once per client.
  "credential-stuffing": (event, legacy) => stuffingKind(event, legacy) !== null,
  // Counts integrity reports of an attestation (slice 21a), never Events: no Event opens a tampered-build Incident.
  "tampered-build": () => false,
};

const ENFORCED_BLOCK_SQL = "(payload->'decision'->>'action' = 'block' AND payload->'decision'->>'mode' = 'enforce')";
/** `containmentBlock`: `->>` is SQL NULL both for a JSON null and for a member an older Event does not have. */
const CONTAINMENT_BLOCK_SQL = "(payload->'decision'->>'containment_id' IS NOT NULL)";
/** `patchDecision`, likewise. */
const PATCH_DECISION_SQL =
  "(payload->'decision'->>'patch_id' IS NOT NULL AND COALESCE(payload->'decision'->>'patch_body', 'checked') NOT IN ('unchecked', 'undecodable'))";

/** SQL over the payload column `c` (`payload`, or a qualified one). `->>` is SQL NULL for JSON null and for absence. */
const sql = {
  /** `stampOf` is undefined: an older Shield's Event. */
  unstamped: (c: string) => `(NOT jsonb_exists(${c}->'decision', 'limit_rule_id'))`,
  stamp: (c: string) => `(${c}->'decision'->>'limit_rule_id')`,
  enforcedBlock: (c: string) => `(${c}->'decision'->>'action' = 'block' AND ${c}->'decision'->>'mode' = 'enforce')`,
  throttle: (c: string) => `(${c}->'decision'->>'action' = 'throttle' AND ${c}->'decision'->>'rule_id' IS NOT NULL)`,
  failed: (c: string) =>
    `((${c}->'request'->>'status') IN (${LIMIT_FAILURE_STATUSES.map((status) => `'${status}'`).join(", ")}) AND NOT ${sql.enforcedBlock(c)})`,
  /** `covers` of coverage.ts: a login protection of the version the Event names covers its method and route. */
  covered: (param: string, c: string) => `EXISTS (
    SELECT 1 FROM jsonb_array_elements(${param}::jsonb) AS limited
    WHERE limited->>'v' = ${c}->'decision'->>'policy_version'
      AND (jsonb_array_length(limited->'m') = 0
        OR jsonb_exists(limited->'m', ${c}->'request'->>'method')
        OR (${c}->'request'->>'method' = 'HEAD' AND jsonb_exists(limited->'m', 'GET')))
      AND ${ASCII_LOWER_SQL(`${c}->'request'->>'route'`)} ~ (limited->>'p'))`,
  /** `namesRule` of coverage.ts: the Event's `rule_id` is a login protection of the version it names. */
  namesLimitRule: (param: string, c: string) => `EXISTS (
    SELECT 1 FROM jsonb_array_elements(${param}::jsonb) AS limited
    WHERE limited->>'v' = ${c}->'decision'->>'policy_version' AND limited->>'i' = ${c}->'decision'->>'rule_id')`,
  /** `stuffingKind` is "throttle". */
  stuffingThrottle: (param: string, c: string) =>
    `(${sql.throttle(c)} AND ((${sql.stamp(c)} IS NOT NULL AND ${c}->'decision'->>'rule_id' = ${sql.stamp(c)}) OR (${sql.unstamped(c)} AND ${sql.namesLimitRule(param, c)})))`,
  /** `stuffingKind` is "failure". */
  stuffingFailure: (param: string, c: string) =>
    `(NOT ${sql.stuffingThrottle(param, c)} AND ${sql.failed(c)} AND ((${sql.stamp(c)} IS NOT NULL) OR (${sql.unstamped(c)} AND NOT ${sql.throttle(c)} AND ${sql.covered(param, c)})))`,
  /** The fixed window of `onceKey`, from the Event's own `ts`. */
  window: (c: string, windowS: number) =>
    `floor(extract(epoch FROM (${c}->>'ts')::timestamptz) * 1000 / ${windowS * 1_000})`,
};

/** The window `credential-stuffing` counts a client's throttles once in, in seconds. */
const STUFFING_WINDOW_S = DETECTION_RULES.find((rule) => rule.key === "credential-stuffing")?.window_s ?? 300;

/**
 * `onceKey` over the stored Events: the throttle is the first of its client (actor hash, App, Environment, prefix)
 * in its fixed window, by `ts` and then `event_id`. `outer` is the table the condition is evaluated for.
 */
function firstOfClient(param: string, outer: string): string {
  const c = `${outer}.payload`;
  const e = "earlier.payload";
  return `NOT EXISTS (
    SELECT 1 FROM events AS earlier
    WHERE earlier.organization_id = ${outer}.organization_id AND earlier.app_id = ${outer}.app_id
      AND earlier.environment = ${outer}.environment
      AND ${e}->'actor'->>'ip_prefix' = ${c}->'actor'->>'ip_prefix'
      AND ${e}->'actor'->'ip_hash' IS NOT DISTINCT FROM ${c}->'actor'->'ip_hash'
      AND ${sql.window(e, STUFFING_WINDOW_S)} = ${sql.window(c, STUFFING_WINDOW_S)}
      AND (earlier.ts, earlier.event_id) < (${outer}.ts, ${outer}.event_id)
      AND ${sql.stuffingThrottle(param, e)})`;
}

/**
 * `needsCoverage`: the Events whose counting depends on the coverage guess. The evidence query uses it to find the
 * Policy versions it has to read.
 */
export const NEEDS_COVERAGE_SQL = `(${sql.unstamped("payload")} AND (${sql.throttle("payload")} OR ${sql.failed("payload")}))`;

/**
 * The same conditions as `COUNTS`, over the `payload` column of `events`. Constant text: no value goes in.
 * `clone-origin`, `vulnerable-component` and `tampered-build` have none: their Incidents have no Events as evidence.
 * `canary-touched`, `credential-stuffing` and `failed-signin-burst` take a parameter and are written in
 * `ruleConditionSql`.
 */
const COUNTS_SQL: Record<
  Exclude<
    DetectionRuleKey,
    | "canary-touched"
    | "clone-origin"
    | "vulnerable-component"
    | "credential-stuffing"
    | "failed-signin-burst"
    | "tampered-build"
  >,
  string
> = {
  "blocked-burst": `(${ENFORCED_BLOCK_SQL} AND NOT ${CONTAINMENT_BLOCK_SQL} AND NOT ${PATCH_DECISION_SQL})`,
  "exploit-attempt": PATCH_DECISION_SQL,
};

/**
 * The managed rules an Event counts toward, in the order of `DETECTION_RULES`. `legacy` is what the coverage guess
 * says of it; it matters only when `needsCoverage(event)`. For `credential-stuffing` a throttle still counts only
 * once per client per window (`onceKey`), which the Detector keeps.
 */
export function matchingRules(event: StoredEvent, legacy: LegacyCoverage = NOT_COVERED): DetectionRule[] {
  return DETECTION_RULES.filter((rule) => COUNTS[rule.key](event, legacy));
}

const isParam = (param: string | undefined): param is `$${number}` =>
  param !== undefined && /^\$[1-9][0-9]*$/.test(param);

/**
 * An SQL condition over `events.payload` that holds exactly for the Events `rule` counts. The condition itself is
 * constant text; two rules take a query parameter, named by `param` (e.g. "$6"):
 * - `canary-touched` is about one Canary: the Events carrying its signal, `canary.touched:<id>`, whose text is the
 *   parameter;
 * - `credential-stuffing` is about the login protections of the Policy versions its older Shield's Events name: the
 *   parameter is the JSON text of an array of `CoverageEntry` (coverage.ts). With `outer`, the table the condition
 *   is evaluated for (e.g. "events"), a throttle counts only as its client's first in its window, as in the
 *   Detector; without it every such throttle holds.
 * - `failed-signin-burst` takes the same parameter: a failure those Rules cover is not its Event.
 */
export function ruleConditionSql(rule: DetectionRuleKey, param?: `$${number}`, outer?: string): string {
  if (rule === "clone-origin") throw new TypeError("clone-origin counts Clone Beacon reports, not Events.");
  if (rule === "vulnerable-component") throw new TypeError("vulnerable-component counts Findings, not Events.");
  if (rule === "tampered-build") throw new TypeError("tampered-build counts integrity reports, not Events.");
  if (rule === "credential-stuffing") {
    if (!isParam(param)) throw new TypeError("credential-stuffing needs the parameter holding the limit Rules.");
    if (outer !== undefined && !/^[a-z_]+$/.test(outer)) throw new TypeError("outer must be a table name.");
    const c = outer === undefined ? "payload" : `${outer}.payload`;
    const throttle =
      outer === undefined
        ? sql.stuffingThrottle(param, c)
        : `(${sql.stuffingThrottle(param, c)} AND ${firstOfClient(param, outer)})`;
    return `(${sql.stuffingFailure(param, c)} OR ${throttle})`;
  }
  if (rule === "failed-signin-burst") {
    if (!isParam(param)) throw new TypeError("failed-signin-burst needs the parameter holding the limit Rules.");
    const c = "payload";
    return `(${sql.failed(c)} AND NOT ${sql.throttle(c)} AND ((${sql.unstamped(c)} AND NOT ${sql.covered(param, c)}) OR (NOT ${sql.unstamped(c)} AND ${sql.stamp(c)} IS NULL)))`;
  }
  if (rule !== "canary-touched") return COUNTS_SQL[rule];
  if (!isParam(param)) throw new TypeError("canary-touched needs the parameter holding the Canary's signal id.");
  const signalParam = param;
  // Same rule as `touchedCanaries`: the Canary counts only if it is among the Event's first
  // MAX_CANARIES_PER_EVENT distinct Canary signals, in signal order (plan 07 amendment A12).
  return `(payload->'signals' @> jsonb_build_array(jsonb_build_object('id', ${signalParam}::text)) AND ${signalParam}::text IN (
    SELECT first.id FROM (
      SELECT s->>'id' AS id, min(ord) AS at
      FROM jsonb_array_elements(payload->'signals') WITH ORDINALITY AS t(s, ord)
      WHERE s->>'id' ~ '${CANARY_SIGNAL_SQL_PATTERN}'
      GROUP BY s->>'id'
      ORDER BY min(ord)
      LIMIT ${MAX_CANARIES_PER_EVENT}
    ) AS first))`;
}
