import {
  BEACON_LIMITS,
  BeaconReportSchema,
  canonicalOrigin,
  DETECTION_RULES,
  type DetectionRule,
  isLocalOrigin,
} from "@antireverse/protocol";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import type { Notifier } from "../notify/notifier.ts";
import { addressPrefix } from "../prefix.ts";
import { type BeaconBuild, findBeaconBuild } from "../stores/beacons.ts";
import { recordDetection } from "../stores/incidents.ts";
import { recordAndAlert } from "./record.ts";

// The Clone Beacon recorder: judges the reports of `POST /v1/beacon` and records a `clone-origin` Detection for
// the ones that count, through the Detector's write path (grouping, retry on a unique violation, alerts).
// It runs after the response: the endpoint answers 204 whatever happens here, so nothing a client sends changes
// the response or waits for the database.
//
// A report counts only when its body parses to `{ a, t, o }`; `o` is a canonical, non-local origin equal to the
// request's `Origin` header; `t` names a registered beacon of the App `a` (tokens are unique per App); and `o` is
// not one of that Build's allowed origins. A host with one trailing dot is its dotless form throughout: the allowed
// check, the limits and the stored origin of the Incident and its Detections. Then, per API
// process: per Build at most `BEACON_LIMITS.reportsPerHour` reports and `BEACON_LIMITS.newOriginsPerHour` new
// origins per hour; per App Environment at most `BEACON_LIMITS.newOriginsPerHour` distinct new origins per hour
// across its Builds; one Detection per Build and origin per hour (the rule's window). Every other report is
// dropped with one log line naming the reason and, once known, the Build: never the token, the App id from the
// body, the origin, the address or the body.
//
// The database is protected from anonymous floods before any lookup: a token found unknown is not looked up
// again for 10 minutes, a token found known is answered from a cache for 10 minutes (both bounded, both cleared
// when a Build registers the token), and the remaining lookups are capped per reporter prefix (per minute) and in
// all (a token bucket). After a lookup, the reports one Organization has in flight are capped, so one tenant's
// flood never takes another's place. Every structure is bounded; the oldest entry goes first.

const CLONE_RULE: DetectionRule = (() => {
  const rule = DETECTION_RULES.find((candidate) => candidate.key === "clone-origin");
  if (rule === undefined) throw new Error("The protocol has no clone-origin rule.");
  return rule;
})();

/** The span of the per-Build and per-App-Environment limits. */
const HOUR_MS = 3_600_000;
/** One Detection per Build and origin per window of the rule. */
const REPEAT_MS = CLONE_RULE.window_s * 1_000;
/** The span of the per-prefix lookup cap. */
const MINUTE_MS = 60_000;

export const DEFAULT_MAX_BUILDS = 10_000;
export const DEFAULT_MAX_BUILDS_PER_ORG = 1_000;
export const DEFAULT_MAX_PENDING = 1_000;
export const DEFAULT_MAX_IN_FLIGHT_PER_ORG = 100;
/** Entries of each token cache (unknown and known tokens). */
export const DEFAULT_MAX_CACHED_TOKENS = 10_000;
/** How long a token's lookup result is reused (unless a Build registers the token meanwhile). */
export const TOKEN_CACHE_TTL_MS = 10 * 60_000;
/** Database lookups per reporter prefix (/24 or /48; unknown addresses share one) per minute. */
export const LOOKUPS_PER_PREFIX_PER_MINUTE = 60;
/** Reporter prefixes whose lookups are counted at once. */
export const DEFAULT_MAX_PREFIXES = 10_000;
/** The global token bucket of database lookups: refill per second, and burst. */
export const LOOKUPS_PER_SECOND = 50;
export const LOOKUP_BURST = 200;

export const BEACON_DROP_REASONS = [
  "oversize",
  "malformed",
  "not-canonical",
  "local",
  "origin-header",
  "busy",
  "prefix-limit",
  "unknown-token",
  "allowed",
  "report-limit",
  "repeat",
  "origin-limit",
  "app-origin-limit",
  "failed",
] as const;
export type BeaconDropReason = (typeof BEACON_DROP_REASONS)[number];

/** One request to `POST /v1/beacon`, as the route read it. */
export interface BeaconRequest {
  /** The body, at most `BEACON_LIMITS.bodyBytesMax` bytes; empty when the request had none. */
  body: Uint8Array;
  /** The body was larger than `BEACON_LIMITS.bodyBytesMax`: dropped unread. */
  oversize: boolean;
  /** The request's `Origin` header. */
  originHeader: string | undefined;
  /** The client address: reduced to its /24 or /48 at once, never kept. */
  address: string | undefined;
}

export interface BeaconRecorderDeps {
  db: Db;
  /** Told about every newly opened Incident, after its transaction committed. */
  notifier: Pick<Notifier, "incidentOpened">;
  /** Stamps the Detection and drives every limit and cache. Default: the system clock. */
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  /** Builds (and App Environments) tracked at once, all Organizations together. Default 10,000. */
  maxBuilds?: number | undefined;
  /** Builds (and App Environments) tracked at once for one Organization. Default 1,000. */
  maxBuildsPerOrg?: number | undefined;
  /** Reports being judged at once, all together; more are dropped. Default 1,000. */
  maxPending?: number | undefined;
  /** Reports of one Organization between its lookup and its Detection; more are dropped. Default 100. */
  maxInFlightPerOrg?: number | undefined;
  /** Unknown tokens remembered at once, oldest evicted. Default 10,000. */
  maxUnknownTokens?: number | undefined;
  /** Known tokens remembered at once, oldest evicted. Default 10,000. */
  maxKnownTokens?: number | undefined;
}

export interface BeaconRecorder {
  /** Judges one report after the response. Never throws, never waits. */
  report(request: BeaconRequest): void;
  /** A Build of this App registered this token: both token caches forget it. */
  tokenRegistered(appId: string, token: string): void;
  /** Resolves when every report started so far has been judged and its Detection written (or dropped). */
  flush(): Promise<void>;
  /** Builds whose limits are currently tracked: never more than `maxBuilds`. */
  trackedBuilds(): number;
  /** Reports dropped since start, by reason. */
  dropped(): Readonly<Record<BeaconDropReason, number>>;
}

/**
 * Per-Organization state with two bounds: at most `perOrg` entries for one Organization (over it, its least
 * recently used entry is evicted) and `total` in all (over it, the least recently used entry of the Organization
 * holding the most). One Organization's churn therefore only ever evicts its own entries.
 */
function orgBounded<T>(perOrg: number, max: number) {
  const byOrg = new Map<string, Map<string, T>>();
  let total = 0;

  function evictOldest(organizationId: string): void {
    const own = byOrg.get(organizationId);
    const oldest = own?.keys().next().value;
    if (own === undefined || oldest === undefined) return;
    own.delete(oldest);
    total--;
    if (own.size === 0) byOrg.delete(organizationId);
  }

  return {
    /** The entry, now the most recently used; created when absent. */
    use(organizationId: string, key: string, create: () => T): T {
      let own = byOrg.get(organizationId);
      const existing = own?.get(key);
      if (own !== undefined && existing !== undefined) {
        own.delete(key);
        own.set(key, existing);
        return existing;
      }
      const created = create();
      if (own === undefined) {
        own = new Map();
        byOrg.set(organizationId, own);
      }
      own.set(key, created);
      total++;
      if (own.size > perOrg) evictOldest(organizationId);
      if (total > max) {
        let largest: string | undefined;
        let most = 0;
        for (const [candidate, held] of byOrg) {
          if (held.size > most) {
            most = held.size;
            largest = candidate;
          }
        }
        if (largest !== undefined) evictOldest(largest);
      }
      return created;
    },
    size: () => total,
  };
}

/** A map whose oldest entry goes first over `max`; entries expire `ttl` after they were set. */
function expiringCache<T>(max: number, ttl: number) {
  const entries = new Map<string, { value: T; at: number }>();
  return {
    get(key: string, ms: number): T | undefined {
      const entry = entries.get(key);
      if (entry === undefined) return undefined;
      if (ms - entry.at < ttl) return entry.value;
      entries.delete(key);
      return undefined;
    },
    set(key: string, value: T, ms: number): void {
      entries.delete(key);
      entries.set(key, { value, at: ms });
      while (entries.size > max) {
        const oldest = entries.keys().next().value;
        if (oldest === undefined) break;
        entries.delete(oldest);
      }
    },
    delete: (key: string) => entries.delete(key),
  };
}

interface BuildState {
  /** Start of the current hour of this Build's limits, on the recorder's clock (ms). */
  hourStart: number;
  /** Reports counted in the current hour. */
  reports: number;
  /** Origins that got a Detection in the current hour. */
  newOrigins: number;
  /** Origin → time of its last Detection (ms); entries a window old are pruned when the hour turns. */
  detected: Map<string, number>;
}

interface AppEnvState {
  hourStart: number;
  /** Distinct origins that got a Detection in the current hour, from any Build of the App Environment. */
  origins: Set<string>;
}

type Judged = { appId: string; token: string; origin: string } | BeaconDropReason;

const decoder = new TextDecoder("utf-8", { fatal: true });

/** The report's App, token and origin when it can count, before any lookup; else why not. */
function judge(request: BeaconRequest): Judged {
  if (request.oversize) return "oversize";
  let value: unknown;
  try {
    value = JSON.parse(decoder.decode(request.body));
  } catch {
    return "malformed";
  }
  const parsed = BeaconReportSchema.safeParse(value);
  if (!parsed.success) return "malformed";
  const { a: appId, t: token, o: origin } = parsed.data;
  if (canonicalOrigin(origin) !== origin) return "not-canonical";
  if (isLocalOrigin(origin)) return "local";
  // A browser sets `Origin` on sendBeacon itself; a page cannot. A forger must at least send the same text twice.
  if (request.originHeader !== origin) return "origin-header";
  return { appId, token, origin };
}

/** A canonical origin with one trailing dot removed from its host (`https://a.example.:8443` → `…example:8443`). */
export function dotlessOrigin(origin: string): string {
  return origin.replace(/^(https?:\/\/[^/[\]]+?)\.(:[0-9]+)?$/, "$1$2");
}

export function createBeaconRecorder(deps: BeaconRecorderDeps): BeaconRecorder {
  const { db, notifier } = deps;
  const now = deps.now ?? (() => new Date());
  const logger = redacting(deps.logger ?? consoleLogger);
  const maxBuilds = deps.maxBuilds ?? DEFAULT_MAX_BUILDS;
  const maxBuildsPerOrg = deps.maxBuildsPerOrg ?? DEFAULT_MAX_BUILDS_PER_ORG;
  const maxPending = deps.maxPending ?? DEFAULT_MAX_PENDING;
  const maxInFlightPerOrg = deps.maxInFlightPerOrg ?? DEFAULT_MAX_IN_FLIGHT_PER_ORG;

  const counts = Object.fromEntries(BEACON_DROP_REASONS.map((reason) => [reason, 0])) as Record<
    BeaconDropReason,
    number
  >;
  const builds = orgBounded<BuildState>(maxBuildsPerOrg, maxBuilds);
  const appEnvs = orgBounded<AppEnvState>(maxBuildsPerOrg, maxBuilds);
  const unknownTokens = expiringCache<true>(deps.maxUnknownTokens ?? DEFAULT_MAX_CACHED_TOKENS, TOKEN_CACHE_TTL_MS);
  const knownTokens = expiringCache<BeaconBuild>(deps.maxKnownTokens ?? DEFAULT_MAX_CACHED_TOKENS, TOKEN_CACHE_TTL_MS);
  // Lookups per reporter prefix in the current minute; insertion order is age, the oldest goes first over the bound.
  const prefixes = new Map<string, { start: number; lookups: number }>();
  const bucket = { tokens: LOOKUP_BURST, at: now().getTime() };
  const inFlight = new Map<string, number>();
  const pending = new Set<Promise<void>>();
  // Counts token registrations: a lookup that overlapped one does not cache its result, which may be stale.
  let registrations = 0;

  const cacheKey = (appId: string, token: string) => `${appId}\n${token}`;

  function drop(reason: BeaconDropReason, buildId?: string): void {
    counts[reason]++;
    logger.info(`beacon dropped reason=${reason}${buildId === undefined ? "" : ` build=${buildId}`}`);
  }

  /** Spends one lookup of the reporter's prefix in the current minute; false when it has none left. */
  function prefixAllows(prefix: string | null, ms: number): boolean {
    const key = prefix ?? "unknown";
    let entry = prefixes.get(key);
    if (entry === undefined || ms - entry.start >= MINUTE_MS) {
      entry = { start: ms, lookups: 0 };
      prefixes.delete(key);
      prefixes.set(key, entry);
      while (prefixes.size > DEFAULT_MAX_PREFIXES) {
        const oldest = prefixes.keys().next().value;
        if (oldest === undefined) break;
        prefixes.delete(oldest);
      }
    }
    if (entry.lookups >= LOOKUPS_PER_PREFIX_PER_MINUTE) return false;
    entry.lookups++;
    return true;
  }

  /** Takes one lookup from the global bucket; false when it is empty. */
  function bucketAllows(ms: number): boolean {
    bucket.tokens = Math.min(LOOKUP_BURST, bucket.tokens + (Math.max(0, ms - bucket.at) * LOOKUPS_PER_SECOND) / 1_000);
    bucket.at = ms;
    if (bucket.tokens < 1) return false;
    bucket.tokens--;
    return true;
  }

  /** Applies the per-Build and per-App-Environment limits to a report that otherwise counts: null admits it. */
  function admit(build: BeaconBuild, origin: string, ms: number): BeaconDropReason | null {
    const state = builds.use(build.organizationId, `${build.appId}/${build.buildId}`, () => ({
      hourStart: ms,
      reports: 0,
      newOrigins: 0,
      detected: new Map(),
    }));
    if (ms - state.hourStart >= HOUR_MS) {
      state.hourStart = ms;
      state.reports = 0;
      state.newOrigins = 0;
      for (const [seen, at] of state.detected) if (ms - at >= REPEAT_MS) state.detected.delete(seen);
    }
    const shared = appEnvs.use(build.organizationId, `${build.appId}/${build.environment}`, () => ({
      hourStart: ms,
      origins: new Set(),
    }));
    if (ms - shared.hourStart >= HOUR_MS) {
      shared.hourStart = ms;
      shared.origins.clear();
    }
    if (state.reports >= BEACON_LIMITS.reportsPerHour) return "report-limit";
    state.reports++;
    const last = state.detected.get(origin);
    if (last !== undefined && ms - last < REPEAT_MS) return "repeat";
    if (state.newOrigins >= BEACON_LIMITS.newOriginsPerHour) return "origin-limit";
    if (!shared.origins.has(origin) && shared.origins.size >= BEACON_LIMITS.newOriginsPerHour) {
      return "app-origin-limit";
    }
    state.newOrigins++;
    state.detected.set(origin, ms);
    shared.origins.add(origin);
    return null;
  }

  async function lookup(appId: string, token: string): Promise<BeaconBuild | null> {
    const before = registrations;
    const build = await db.tx("none", (q) => findBeaconBuild(q, appId, token));
    if (registrations === before) {
      const key = cacheKey(appId, token);
      if (build === null) unknownTokens.set(key, true, now().getTime());
      else knownTokens.set(key, build, now().getTime());
    }
    return build;
  }

  async function handle(known: BeaconBuild | undefined, judged: Exclude<Judged, string>, ipPrefix: string | null) {
    // One spelling per host: one trailing dot is dropped before the allowed check, the limits and the Incident.
    const origin = dotlessOrigin(judged.origin);
    const build = known ?? (await lookup(judged.appId, judged.token));
    if (build === null) return drop("unknown-token");
    if (build.origins.some((allowed) => dotlessOrigin(allowed) === origin)) return drop("allowed", build.buildId);
    const { organizationId, appId, environment, buildId } = build;
    const busy = inFlight.get(organizationId) ?? 0;
    if (busy >= maxInFlightPerOrg) return drop("busy", buildId);
    const at = now();
    const refused = admit(build, origin, at.getTime());
    if (refused !== null) return drop(refused, buildId);
    inFlight.set(organizationId, busy + 1);
    try {
      const result = await recordAndAlert(db, notifier, organizationId, (q) =>
        recordDetection(q, {
          organizationId,
          appId,
          environment,
          rule: CLONE_RULE,
          ipPrefix,
          count: 1,
          windowStart: at.toISOString(),
          windowEnd: at.toISOString(),
          detectedAt: at,
          clone: { origin, buildId },
        }),
      );
      if (result !== null) {
        logger.info(`beacon detection organization=${organizationId} build=${buildId} incident=${result.incident.id}`);
      }
    } finally {
      const left = (inFlight.get(organizationId) ?? 1) - 1;
      if (left <= 0) inFlight.delete(organizationId);
      else inFlight.set(organizationId, left);
    }
  }

  return {
    report(request) {
      // The address is reduced first and never kept.
      const ipPrefix = addressPrefix(request.address);
      const judged = judge(request);
      if (typeof judged === "string") return drop(judged);
      const ms = now().getTime();
      const key = cacheKey(judged.appId, judged.token);
      if (unknownTokens.get(key, ms) === true) return drop("unknown-token");
      const known = knownTokens.get(key, ms);
      if (pending.size >= maxPending) return drop("busy");
      if (known === undefined) {
        // Only a lookup costs the database: capped per reporter prefix, then in all.
        if (!prefixAllows(ipPrefix, ms)) return drop("prefix-limit");
        if (!bucketAllows(ms)) return drop("busy");
      }
      const promise = handle(known, judged, ipPrefix).catch((error: unknown) => {
        // The kind of error only: a message could quote a value from the report.
        counts.failed++;
        logger.warn(`beacon failed ${error instanceof Error ? error.name : "error"}`);
      });
      pending.add(promise);
      void promise.finally(() => pending.delete(promise));
    },

    tokenRegistered(appId, token) {
      registrations++;
      const key = cacheKey(appId, token);
      unknownTokens.delete(key);
      knownTokens.delete(key);
    },

    async flush() {
      while (pending.size > 0) await Promise.allSettled([...pending]);
    },

    trackedBuilds: () => builds.size(),

    dropped: () => ({ ...counts }),
  };
}
