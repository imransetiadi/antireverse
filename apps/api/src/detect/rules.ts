import {
  DETECTION_RULES,
  type DetectionRule,
  type DetectionRuleKey,
  parseCanarySignal,
  type StoredEvent,
} from "@antireverse/protocol";

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

const COUNTS: Record<DetectionRuleKey, (event: StoredEvent) => boolean> = {
  "blocked-burst": (event) => enforcedBlock(event) && !containmentBlock(event),
  // A 401 or 403 from the app. Shield's own enforced block also ends in 403; counting it here would open a
  // second Incident for one blocked attack.
  "failed-signin-burst": (event) =>
    (event.request.status === 401 || event.request.status === 403) && !enforcedBlock(event),
  // Counted once per Canary it names (`touchedCanaries`); whether the Canary is the Event's own App
  // Environment's is checked in the tenant transaction.
  "canary-touched": (event) => touchedCanaries(event).length > 0,
  // Counts Clone Beacon reports (`POST /v1/beacon`), never Events: no Event opens a clone Incident.
  "clone-origin": () => false,
  // Counts new Critical or High Findings (slice 19), never Events: no Event opens a vulnerable-component Incident.
  "vulnerable-component": () => false,
};

const ENFORCED_BLOCK_SQL = "(payload->'decision'->>'action' = 'block' AND payload->'decision'->>'mode' = 'enforce')";
/** `containmentBlock`: `->>` is SQL NULL both for a JSON null and for a member an older Event does not have. */
const CONTAINMENT_BLOCK_SQL = "(payload->'decision'->>'containment_id' IS NOT NULL)";

/**
 * The same conditions as `COUNTS`, over the `payload` column of `events`. Constant text: no value goes in.
 * `clone-origin` and `vulnerable-component` have none: their Incidents have no Events as evidence.
 */
const COUNTS_SQL: Record<
  Exclude<DetectionRuleKey, "canary-touched" | "clone-origin" | "vulnerable-component">,
  string
> = {
  "blocked-burst": `(${ENFORCED_BLOCK_SQL} AND NOT ${CONTAINMENT_BLOCK_SQL})`,
  "failed-signin-burst": `((payload->'request'->>'status') IN ('401', '403') AND NOT ${ENFORCED_BLOCK_SQL})`,
};

/** The managed rules an Event counts toward, in the order of `DETECTION_RULES`. */
export function matchingRules(event: StoredEvent): DetectionRule[] {
  return DETECTION_RULES.filter((rule) => COUNTS[rule.key](event));
}

/**
 * An SQL condition over `events.payload` that holds exactly for the Events `rule` counts. For
 * `canary-touched` it is about one Canary: the Events carrying its signal, `canary.touched:<id>`, whose
 * text is passed as the query parameter `signalParam` (e.g. "$7"): the condition itself stays constant text.
 */
export function ruleConditionSql(rule: DetectionRuleKey, signalParam?: `$${number}`): string {
  if (rule === "clone-origin") throw new TypeError("clone-origin counts Clone Beacon reports, not Events.");
  if (rule === "vulnerable-component") throw new TypeError("vulnerable-component counts Findings, not Events.");
  if (rule !== "canary-touched") return COUNTS_SQL[rule];
  if (signalParam === undefined || !/^\$[1-9][0-9]*$/.test(signalParam)) {
    throw new TypeError("canary-touched needs the parameter holding the Canary's signal id.");
  }
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
