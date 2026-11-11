import type { DetectionRule, StoredEvent } from "@antireverse/protocol";
import type { EventBus } from "../bus.ts";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import type { Notifier } from "../notify/notifier.ts";
import { exploitAdvisory } from "../patches/activation.ts";
import { PATCH_CATALOG, type PatchCatalog } from "../patches/catalog.ts";
import { findCanaryBuild } from "../stores/canaries.ts";
import { recordDetection } from "../stores/incidents.ts";
import { currentVersion, findPolicyRules } from "../stores/policies.ts";
import { type Coverage, covers, limitCoverage, namesRule } from "./coverage.ts";
import { recordAndAlert } from "./record.ts";
import { type LegacyCoverage, matchingRules, needsCoverage, onceKey, stuffingKind, touchedCanaries } from "./rules.ts";

// The Detector: counts Events per (Organization, App, Environment, rule, Canary, network prefix) in a sliding
// window and records one Detection each time a managed rule's threshold is reached, grouped into an Incident.
// The Canary is null except for `canary-touched`, which counts each Canary an Event's signals name; in the
// tenant transaction it checks that the Canary is the Event's own App Environment's, and records nothing for an
// unknown or foreign id.
// It runs on the bus, after the ingest transaction committed, and never on the ingest path: an error here is
// logged without data and swallowed. Its memory is bounded: at most `maxKeysPerOrg` windows per Organization
// (over it, that Organization's least recently updated window is evicted), at most `maxKeys` windows in all
// (over it, the least recently updated window of the Organization holding the most is evicted), and at most
// `threshold` entries per window (a window is cleared when it crosses). One Organization flooding distinct
// prefixes therefore only ever evicts its own windows, never another Organization's.
//
// Credential stuffing (slice 08, plan amendment A7, D-064). A Shield of A7 stamps `decision.limit_rule_id` with the
// login protection that matched a request, and the Event is judged by that alone (`stuffingKind`). A throttle counts
// once per client per window: each window keeps the clients' keys (`onceKey`) with its entries.
//
// The coverage guess, for an Event of an older Shield (no `limit_rule_id` member) only: `credential-stuffing` counts
// a 401 or 403 on a route a login protection covers and a throttle that names one, and `failed-signin-burst` leaves
// such a failure to it. Which Rules those are is not in the Event: the Detector reads the Rules of the Policy version
// the Event names (`decision.policy_version`), in the Event's Organization, and keeps its login protections
// (`coverage.ts` says how a route is judged). Only such an Event with a network prefix asks; version 0 (the built-in
// Policy) has no Rules.
//
// - A published version never changes: it is read once and kept.
// - The same read gives the App Environment's latest published version, believed for `LATEST_VERSION_MS`. A version
//   above it was never published: its Events are judged not covered without a read. So made-up versions cost one
//   read per App Environment per `LATEST_VERSION_MS`, however many are named; and the Events of a version published
//   less than that ago may be judged not covered (they then count as failed sign-ins, where they are failures).
// - A publish or rollback through this process tells the Detector the new latest version at once
//   (`policyPublished`), so that window only exists for a version published by another process.
// - Reads of one App Environment run one after the other, so Events that arrive together share them.
// - Everything is kept per Organization, so that no Organization can evict or hold back another's: versions up to a
//   weight of `COVERAGE_VERSIONS_PER_ORG` (a version weighs its number of login protections, at least 1, so that a
//   few hundred versions of an ordinary Policy stay kept: review F9), and `COVERAGE_APPS_PER_ORG` latest versions (least recently used first
//   out), and at most `COVERAGE_WAITING_PER_ORG` Events waiting for a read. Over all Organizations: at most
//   `COVERAGE_ORGS` Organizations' coverage (the least recently used one with nothing waiting is dropped) and
//   `COVERAGE_WAITING_MAX` waiting Events.
// - An Event that waits counts toward every other rule at once, and toward the two rules that depend on coverage
//   when its read returns, with its own time of arrival. An Event over a waiting bound, and one whose read failed
//   (logged without data), is judged not covered.

export interface DetectorDeps {
  db: Db;
  bus: EventBus;
  /** Told about every newly opened Incident, after its transaction committed. */
  notifier: Pick<Notifier, "incidentOpened">;
  /** Places Events in the sliding windows (time of arrival) and stamps `detected_at`. Default: the system clock. */
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  /** Windows kept at once, all Organizations together. Default 10,000. */
  maxKeys?: number | undefined;
  /** Windows kept at once for one Organization. Default 1,000. */
  maxKeysPerOrg?: number | undefined;
  /** The Virtual patch catalog, for the advisory of an `exploit-attempt` Event. Default: `PATCH_CATALOG`. */
  patches?: PatchCatalog | undefined;
}

/** A Policy version that was just published (or rolled back to): the App Environment's new latest version. */
export interface PolicyPublished {
  organizationId: string;
  appId: string;
  environment: StoredEvent["environment"];
  version: number;
}

export interface Detector {
  /** Subscribes to every Event on the bus. Returns the function that stops it; calling it twice is harmless. */
  start(): () => void;
  /** Resolves when every Detection write started so far has finished (committed or failed). */
  flush(): Promise<void>;
  /** Windows currently kept, all Organizations together: never more than `maxKeys`. */
  trackedKeys(): number;
  /**
   * Tells the Detector the latest published version of an App Environment, after the publishing transaction
   * committed: Events that name it are judged by its Rules at once, without waiting for the belief in an older
   * latest version to run out. Never lowers a version it believes.
   */
  policyPublished(policy: PolicyPublished): void;
  /** Events currently waiting for a Policy version to be read: never more than `COVERAGE_WAITING_MAX`. */
  waitingEvents(): number;
}

export const DEFAULT_MAX_KEYS = 10_000;
export const DEFAULT_MAX_KEYS_PER_ORG = 1_000;
/**
 * The weight of the Policy versions kept for one Organization: a version weighs its number of login protections, and
 * at least 1. So an Organization keeps up to this many versions, and at most this many compiled patterns.
 */
export const COVERAGE_VERSIONS_PER_ORG = 256;
/** App Environments whose latest published version is kept for one Organization. */
export const COVERAGE_APPS_PER_ORG = 200;
/** Organizations whose coverage is kept at once. */
export const COVERAGE_ORGS = 1_000;
/** How long the latest published version of an App Environment is believed. */
export const LATEST_VERSION_MS = 10_000;
/** Events of one Organization that may wait for a Policy version to be read. */
export const COVERAGE_WAITING_PER_ORG = 1_000;
/** Events that may wait for a Policy version to be read, all Organizations together. */
export const COVERAGE_WAITING_MAX = 10_000;

/** The rules whose counting depends on coverage: an Event that waits for its Policy counts toward these afterwards. */
const dependsOnCoverage = (rule: DetectionRule): boolean =>
  rule.key === "credential-stuffing" || rule.key === "failed-signin-burst";

/** What the Detector knows of one Organization's Policies. Maps are in order of use, oldest first. */
interface OrgCoverage {
  /** The login protections of published versions, by (App, Environment, version). */
  versions: Map<string, Coverage>;
  /** The weight of `versions`: each version's number of login protections, at least 1. */
  weight: number;
  /** The latest published version of an App Environment, believed until `until`. */
  latest: Map<string, { version: number; until: number }>;
  /** The last of the reads queued for an App Environment. */
  tails: Map<string, Promise<void>>;
  waiting: number;
}

interface Entry {
  /** Arrival time on the Detector's clock, in milliseconds. */
  at: number;
  /** The Event's own `ts` in milliseconds, for the Detection's `window_start` and `window_end`. */
  ts: number;
  /** For a throttle counted toward `credential-stuffing`: its client and window (`onceKey`), counted once. */
  once?: string | undefined;
}

interface Window {
  organizationId: string;
  appId: string;
  environment: StoredEvent["environment"];
  rule: DetectionRule;
  /** The Canary counted, for `canary-touched`; null for every other rule. */
  canaryId: string | null;
  /** The Virtual patch the Event names, for `exploit-attempt`; null for every other rule. */
  patchId: string | null;
  /** The network prefix counted; null only for `exploit-attempt`, which counts Events without one too. */
  ipPrefix: string | null;
  entries: Entry[];
}

export function createDetector(deps: DetectorDeps): Detector {
  const { db, bus, notifier } = deps;
  const now = deps.now ?? (() => new Date());
  const logger = redacting(deps.logger ?? consoleLogger);
  const maxKeys = deps.maxKeys ?? DEFAULT_MAX_KEYS;
  const maxKeysPerOrg = deps.maxKeysPerOrg ?? DEFAULT_MAX_KEYS_PER_ORG;
  const catalog = deps.patches ?? PATCH_CATALOG;

  // Windows per Organization. Insertion order is recency: a window is deleted and re-inserted on every update,
  // so the first key of an Organization's map is its least recently updated window.
  const windows = new Map<string, Map<string, Window>>();
  let total = 0;

  function remove(organizationId: string, key: string): void {
    const own = windows.get(organizationId);
    if (own === undefined || !own.delete(key)) return;
    total--;
    if (own.size === 0) windows.delete(organizationId);
  }

  /** Evicts the least recently updated window of an Organization. */
  function evictOldest(organizationId: string): void {
    const oldest = windows.get(organizationId)?.keys().next().value;
    if (oldest !== undefined) remove(organizationId, oldest);
  }
  const writes = new Set<Promise<void>>();
  let unsubscribe: (() => void) | undefined;

  const coverage = new Map<string, OrgCoverage>();
  let waiting = 0;

  /** The kind of error only: a message could quote a value from an Event. */
  const failed = (error: unknown) => {
    logger.warn(`detector failed ${error instanceof Error ? error.name : "error"}`);
  };

  function write(window: Window, entries: Entry[], detectedAt: Date): void {
    const times = entries.map((entry) => entry.ts).sort((a, b) => a - b);
    const windowStart = times[0];
    const windowEnd = times.at(-1);
    if (windowStart === undefined || windowEnd === undefined) return;
    const { organizationId, appId, environment, canaryId, patchId } = window;
    // Shared with the Clone Beacon: retry once on a unique violation (join the Incident another writer opened),
    // alert only a new Incident. A second failure is logged and the Detection dropped.
    const promise = recordAndAlert(db, notifier, organizationId, async (q) => {
      let canary: { id: string; buildId: string } | undefined;
      if (canaryId !== null) {
        const buildId = await findCanaryBuild(q, { organizationId, appId, environment }, canaryId);
        // Unknown, or another Organization's, App's or Environment's: not this App's Canary.
        if (buildId === null) return null;
        canary = { id: canaryId, buildId };
      }
      let exploit: { advisoryId: string } | undefined;
      if (patchId !== null) {
        const advisoryId = await exploitAdvisory(q, catalog, { appId, environment }, patchId);
        // A patch id the catalog does not know: stored with its Event, but no Incident.
        if (advisoryId === null) return null;
        exploit = { advisoryId };
      }
      return recordDetection(q, {
        organizationId,
        appId,
        environment,
        rule: window.rule,
        ipPrefix: window.ipPrefix,
        count: entries.length,
        windowStart: new Date(windowStart).toISOString(),
        windowEnd: new Date(windowEnd).toISOString(),
        detectedAt,
        canary,
        exploit,
      });
    }).then(() => {}, failed);
    writes.add(promise);
    void promise.finally(() => writes.delete(promise));
  }

  /** The Organization's coverage, marked as used; made when there is none. */
  function coverageOfOrg(organizationId: string): OrgCoverage {
    const state = coverage.get(organizationId) ?? {
      versions: new Map(),
      weight: 0,
      latest: new Map(),
      tails: new Map(),
      waiting: 0,
    };
    coverage.delete(organizationId);
    coverage.set(organizationId, state);
    if (coverage.size > COVERAGE_ORGS) {
      // The least recently used Organization that nothing waits for; its coverage is read again when needed.
      for (const [candidate, held] of coverage) {
        if (held.waiting > 0 || candidate === organizationId) continue;
        coverage.delete(candidate);
        break;
      }
    }
    return state;
  }

  const appKey = (event: StoredEvent) => JSON.stringify([event.app_id, event.environment]);
  const versionKey = (event: StoredEvent) =>
    JSON.stringify([event.app_id, event.environment, event.decision.policy_version]);

  const NOT_COVERED: LegacyCoverage = { covered: false, limitRule: false };
  const judged = (rules: Coverage, event: StoredEvent): LegacyCoverage => ({
    covered: covers(rules, event.request.method, event.request.route),
    limitRule: namesRule(rules, event.decision.rule_id),
  });

  /** What the coverage guess says of the Event, from what is kept; undefined when it takes a read. */
  function knownCoverage(state: OrgCoverage, event: StoredEvent, ms: number): LegacyCoverage | undefined {
    const latest = state.latest.get(appKey(event));
    // Never published, as far as a recent read knows: not covered, and not worth a read.
    if (latest !== undefined && latest.until > ms && event.decision.policy_version > latest.version) {
      return NOT_COVERED;
    }
    const key = versionKey(event);
    const rules = state.versions.get(key);
    if (rules === undefined) return undefined;
    state.versions.delete(key);
    state.versions.set(key, rules);
    return judged(rules, event);
  }

  const weightOf = (rules: Coverage) => Math.max(1, rules.length);

  /** Keeps a version's login protections, dropping the least recently used versions over the weight. */
  function keep(state: OrgCoverage, key: string, rules: Coverage): void {
    const previous = state.versions.get(key);
    if (previous !== undefined) state.weight -= weightOf(previous);
    state.versions.delete(key);
    state.versions.set(key, rules);
    state.weight += weightOf(rules);
    for (const [oldest, held] of state.versions) {
      if (state.weight <= COVERAGE_VERSIONS_PER_ORG || oldest === key) break;
      state.versions.delete(oldest);
      state.weight -= weightOf(held);
    }
  }

  /** Drops the least recently used entries over `max`. */
  function trim(map: Map<string, unknown>, max: number): void {
    while (map.size > max) {
      const oldest = map.keys().next().value;
      if (oldest === undefined) return;
      map.delete(oldest);
    }
  }

  /**
   * Reads, in the Event's Organization, the latest published version of its App Environment and, when the version
   * the Event names is not above it, that version's Rules; keeps both. Returns whether a limit Rule covers the
   * Event's route.
   */
  async function readCoverage(state: OrgCoverage, event: StoredEvent, ms: number): Promise<LegacyCoverage> {
    const target = { organizationId: event.organization_id, appId: event.app_id, environment: event.environment };
    const version = event.decision.policy_version;
    const read = await db.tx({ organizationId: target.organizationId }, async (q) => {
      const latest = await currentVersion(q, target);
      return { latest, rules: version > latest ? null : await findPolicyRules(q, target, version) };
    });
    const app = appKey(event);
    state.latest.delete(app);
    state.latest.set(app, { version: read.latest, until: ms + LATEST_VERSION_MS });
    trim(state.latest, COVERAGE_APPS_PER_ORG);
    if (read.rules === null) return NOT_COVERED;
    const rules = limitCoverage(read.rules);
    keep(state, versionKey(event), rules);
    return judged(rules, event);
  }

  /** Counts an Event as it arrives. One that waits for its Policy counts toward the coverage rules afterwards. */
  function receive(event: StoredEvent): void {
    const at = now();
    if (!needsCoverage(event) || event.actor.ip_prefix === null || event.decision.policy_version === 0) {
      count(event, matchingRules(event), at);
      return;
    }
    const ms = at.getTime();
    const state = coverageOfOrg(event.organization_id);
    const known = knownCoverage(state, event, ms);
    if (known !== undefined || state.waiting >= COVERAGE_WAITING_PER_ORG || waiting >= COVERAGE_WAITING_MAX) {
      // Over a bound the Event does not wait: it is judged not covered.
      const legacy = known ?? NOT_COVERED;
      count(event, matchingRules(event, legacy), at, legacy);
      return;
    }
    count(
      event,
      matchingRules(event).filter((rule) => !dependsOnCoverage(rule)),
      at,
    );
    state.waiting++;
    waiting++;
    // After the reads already queued for this App Environment: what they bring may answer this Event as well.
    const app = appKey(event);
    const counted: Promise<void> = (state.tails.get(app) ?? Promise.resolve())
      .then(() => knownCoverage(state, event, ms) ?? readCoverage(state, event, ms))
      .catch((error: unknown) => {
        failed(error);
        return NOT_COVERED;
      })
      .then((legacy) => {
        // Stopped meanwhile: nothing is counted any more.
        if (unsubscribe === undefined) return;
        count(event, matchingRules(event, legacy).filter(dependsOnCoverage), at, legacy);
      })
      .catch(failed)
      .finally(() => {
        state.waiting--;
        waiting--;
        writes.delete(counted);
        if (state.tails.get(app) === counted) state.tails.delete(app);
      });
    state.tails.set(app, counted);
    writes.add(counted);
  }

  /**
   * Adds the Event, arrived at `at`, to the windows of `matching` (rules it counts toward). `legacy` is what the
   * coverage guess said of it, for an older Shield's Event.
   */
  function count(
    event: StoredEvent,
    matching: readonly DetectionRule[],
    at: Date,
    legacy: LegacyCoverage = NOT_COVERED,
  ): void {
    const ipPrefix = event.actor.ip_prefix;
    // Without a prefix only `exploit-attempt` counts: its Incident is grouped by advisory, not by network.
    const rules = matching.filter((rule) => ipPrefix !== null || rule.key === "exploit-attempt");
    if (rules.length === 0) return;
    const ms = at.getTime();
    const counted = rules.flatMap((rule): { rule: DetectionRule; canaryId: string | null; patchId: string | null }[] =>
      rule.key === "canary-touched"
        ? touchedCanaries(event).map((canaryId) => ({ rule, canaryId, patchId: null }))
        : rule.key === "exploit-attempt"
          ? [{ rule, canaryId: null, patchId: event.decision.patch_id ?? null }]
          : [{ rule, canaryId: null, patchId: null }],
    );
    for (const { rule, canaryId, patchId } of counted) {
      const key = JSON.stringify([
        event.organization_id,
        event.app_id,
        event.environment,
        rule.key,
        canaryId,
        patchId,
        ipPrefix,
      ]);
      const organizationId = event.organization_id;
      const window: Window = windows.get(organizationId)?.get(key) ?? {
        organizationId: event.organization_id,
        appId: event.app_id,
        environment: event.environment,
        rule,
        canaryId,
        patchId,
        ipPrefix,
        entries: [],
      };
      remove(organizationId, key);
      const horizon = ms - rule.window_s * 1_000;
      window.entries = window.entries.filter((entry) => entry.at > horizon);
      // A throttle of a login protection counts once per client per window (D-064).
      const once =
        rule.key === "credential-stuffing" && stuffingKind(event, legacy) === "throttle"
          ? onceKey(event, rule.window_s)
          : undefined;
      if (once === undefined || !window.entries.some((entry) => entry.once === once)) {
        window.entries.push({ at: ms, ts: Date.parse(event.ts), once });
      }
      if (window.entries.length >= rule.threshold) {
        // One Detection per crossing: the window starts again from nothing.
        write(window, window.entries, at);
        continue;
      }
      let own = windows.get(organizationId);
      if (own === undefined) {
        own = new Map();
        windows.set(organizationId, own);
      }
      own.set(key, window);
      total++;
      if (own.size > maxKeysPerOrg) evictOldest(organizationId);
      if (total > maxKeys) {
        // The global bound: take from the Organization holding the most windows.
        let largest: string | undefined;
        let most = 0;
        for (const [candidate, held] of windows) {
          if (held.size > most) {
            most = held.size;
            largest = candidate;
          }
        }
        if (largest !== undefined) evictOldest(largest);
      }
    }
  }

  return {
    start() {
      unsubscribe ??= bus.subscribeAll((event) => {
        try {
          receive(event);
        } catch (error) {
          failed(error);
        }
      });
      return () => {
        unsubscribe?.();
        unsubscribe = undefined;
        windows.clear();
        total = 0;
        coverage.clear();
      };
    },

    async flush() {
      while (writes.size > 0) await Promise.allSettled([...writes]);
    },

    trackedKeys: () => total,
    waitingEvents: () => waiting,

    policyPublished(policy) {
      const state = coverageOfOrg(policy.organizationId);
      const app = JSON.stringify([policy.appId, policy.environment]);
      const ms = now().getTime();
      const believed = state.latest.get(app);
      // A publish that committed later may be told earlier: the higher version stands.
      const version =
        believed !== undefined && believed.until > ms ? Math.max(believed.version, policy.version) : policy.version;
      state.latest.delete(app);
      state.latest.set(app, { version, until: ms + LATEST_VERSION_MS });
      trim(state.latest, COVERAGE_APPS_PER_ORG);
    },
  };
}
