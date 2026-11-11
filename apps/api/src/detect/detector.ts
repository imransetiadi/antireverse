import type { DetectionRule, StoredEvent } from "@antireverse/protocol";
import type { EventBus } from "../bus.ts";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import type { Notifier } from "../notify/notifier.ts";
import { findCanaryBuild } from "../stores/canaries.ts";
import { recordDetection } from "../stores/incidents.ts";
import { recordAndAlert } from "./record.ts";
import { matchingRules, touchedCanaries } from "./rules.ts";

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
}

export interface Detector {
  /** Subscribes to every Event on the bus. Returns the function that stops it; calling it twice is harmless. */
  start(): () => void;
  /** Resolves when every Detection write started so far has finished (committed or failed). */
  flush(): Promise<void>;
  /** Windows currently kept, all Organizations together: never more than `maxKeys`. */
  trackedKeys(): number;
}

export const DEFAULT_MAX_KEYS = 10_000;
export const DEFAULT_MAX_KEYS_PER_ORG = 1_000;

interface Entry {
  /** Arrival time on the Detector's clock, in milliseconds. */
  at: number;
  /** The Event's own `ts` in milliseconds, for the Detection's `window_start` and `window_end`. */
  ts: number;
}

interface Window {
  organizationId: string;
  appId: string;
  environment: StoredEvent["environment"];
  rule: DetectionRule;
  /** The Canary counted, for `canary-touched`; null for every other rule. */
  canaryId: string | null;
  ipPrefix: string;
  entries: Entry[];
}

export function createDetector(deps: DetectorDeps): Detector {
  const { db, bus, notifier } = deps;
  const now = deps.now ?? (() => new Date());
  const logger = redacting(deps.logger ?? consoleLogger);
  const maxKeys = deps.maxKeys ?? DEFAULT_MAX_KEYS;
  const maxKeysPerOrg = deps.maxKeysPerOrg ?? DEFAULT_MAX_KEYS_PER_ORG;

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

  /** The kind of error only: a message could quote a value from an Event. */
  const failed = (error: unknown) => {
    logger.warn(`detector failed ${error instanceof Error ? error.name : "error"}`);
  };

  function write(window: Window, entries: Entry[], detectedAt: Date): void {
    const times = entries.map((entry) => entry.ts).sort((a, b) => a - b);
    const windowStart = times[0];
    const windowEnd = times.at(-1);
    if (windowStart === undefined || windowEnd === undefined) return;
    const { organizationId, appId, environment, canaryId } = window;
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
      });
    }).then(() => {}, failed);
    writes.add(promise);
    void promise.finally(() => writes.delete(promise));
  }

  function count(event: StoredEvent): void {
    const ipPrefix = event.actor.ip_prefix;
    if (ipPrefix === null) return;
    const rules = matchingRules(event);
    if (rules.length === 0) return;
    const at = now();
    const ms = at.getTime();
    const counted = rules.flatMap((rule): { rule: DetectionRule; canaryId: string | null }[] =>
      rule.key === "canary-touched"
        ? touchedCanaries(event).map((canaryId) => ({ rule, canaryId }))
        : [{ rule, canaryId: null }],
    );
    for (const { rule, canaryId } of counted) {
      const key = JSON.stringify([
        event.organization_id,
        event.app_id,
        event.environment,
        rule.key,
        canaryId,
        ipPrefix,
      ]);
      const organizationId = event.organization_id;
      const window: Window = windows.get(organizationId)?.get(key) ?? {
        organizationId: event.organization_id,
        appId: event.app_id,
        environment: event.environment,
        rule,
        canaryId,
        ipPrefix,
        entries: [],
      };
      remove(organizationId, key);
      const horizon = ms - rule.window_s * 1_000;
      window.entries = window.entries.filter((entry) => entry.at > horizon);
      window.entries.push({ at: ms, ts: Date.parse(event.ts) });
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
          count(event);
        } catch (error) {
          failed(error);
        }
      });
      return () => {
        unsubscribe?.();
        unsubscribe = undefined;
        windows.clear();
        total = 0;
      };
    },

    async flush() {
      while (writes.size > 0) await Promise.allSettled([...writes]);
    },

    trackedKeys: () => total,
  };
}
