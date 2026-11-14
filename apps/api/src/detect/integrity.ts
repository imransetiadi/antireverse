import {
  canonicalOrigin,
  DETECTION_RULES,
  type DetectionRule,
  INTEGRITY_LIMITS,
  type IntegrityReport,
  isLocalOrigin,
} from "@antireverse/protocol";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import type { Notifier } from "../notify/notifier.ts";
import { addressPrefix } from "../prefix.ts";
import { recordDetection } from "../stores/incidents.ts";
import {
  admitObservation,
  armBuild,
  findIntegrityBuilds,
  type IntegrityBuild,
  type IntegrityFile,
  loadRecentHashes,
  markCapped,
  type RecentHashes,
} from "../stores/integrity.ts";
import { dotlessOrigin } from "./beacon.ts";
import { recordAndAlert } from "./record.ts";

// The integrity recorder (slice 21a, D-100): judges the integrity report an attestation may carry and records a
// `tampered-build` Detection for a file whose observed hash is not the registered Build's, through the Detector's
// write path (grouping, retry on a unique violation, alerts). It runs after the response and is never awaited by
// the attest handler: nothing a client reports changes the token, the verdict or the time the answer takes. Only a
// handshake that passed the nonce, the key binding and the App limiter is handed over, so the App id is the one the
// nonce was issued for.
//
// A report is judged only when the request's `Origin` header is a canonical, non-local origin (a host with one
// trailing dot is its dotless form), it lists at least one file, the Build it names is a registered Build of that
// App with an integrity marker, and every index it uses is one of the marker's. Then:
//
// - Arming. A Build is armed by its first fully matching report: at least one file, every reported file equal to the
//   registered digest. The list may be partial and `skipped` is ignored (a page hashes only the files it loaded; one
//   verified file shows that the origin served this Build's bytes). A report with no files never arms. Before that,
//   a mismatch records nothing: a Build never seen clean is not judged (a pipeline that rewrites files after Harden
//   never arms it). A mismatch that arrives while the Build is being armed waits for the arming.
// - Stale, not tampered. A hash that is the registered digest of the same path in any recent Build of the App
//   Environment (the last 20 Builds, or the last 30 days), whatever those Builds' own markers list, is a mixed
//   deploy: dropped, never a Detection, and never counted against a limit. The other way round is a known limit: a
//   Build that is no longer recent, still served somewhere, is not explained by this and its file is a mismatch.
// - Anything else on an armed Build is a mismatch: one Detection per Build, file and observed hash per window of the
//   rule, grouped into one Incident per (App, Environment, Build). The origin is not part of that key: the first
//   report of a file and hash in a window fixes the origin its Detection names.
//
// The hashes are compared as bytes: the wire carries base64url, the Manifest lowercase hex; a report's hash is
// decoded to hex first.
//
// What a report may cost (review H1). All of this shares one database connection with every other request, so a
// public, forgeable report must never be able to queue work in front of them:
// - Everything that needs only memory comes before anything is read or written: the repeat window, the stale check,
//   the per-Build report and new-hash limits. Once a Build's hour is spent, further reports of it start no
//   transaction at all.
// - The stale check reads no Manifest per report. The recent Builds' digests are kept in memory per App Environment
//   (`loadRecentHashes`: one query) for the paths of the markers of the Builds judged there, loaded when first
//   needed, again after `RECENT_TTL_MS`, again when a judged Build's marker names a path not yet covered, and again
//   after a Build of the App Environment is registered (`buildRegistered`). Reports that need a load in progress
//   wait for that one load, outside the Organization's in-flight count; at most `RECENT_LOADS_MAX` loads run at
//   once, for all tenants together. The API is the single owner of its data directory, so the registration hook is
//   authoritative: no other process can register a Build behind it, and a Build registered a moment ago is seen by
//   the next report. Memory: at most `RECENT_PATHS_MAX` paths per App Environment, each with at most 200 digests
//   (one per Build read), `DEFAULT_MAX_RECENT` App Environments, and `RECENT_HASHES_MAX` digests in all; over a
//   bound the least recently used App Environment goes first.
// - What remains is at most `newHashesPerHour` short write transactions per Build per hour.
//
// Limits (review M1, M2). Per API process and Build: at most `reportsPerHour` reports per hour that still carry a
// mismatch after the stale and repeat checks (a fully matching report of an armed Build is free, and so is one whose
// mismatches are all stale or repeats: both are the normal traffic of a healthy site and must not spend the budget a
// real mismatch needs) and `newHashesPerHour` new observed hashes per hour. A Build's limits are never forgotten
// while its hour or a repeat window runs: when the recorder has no room for another Build, the new Build's report is
// dropped as busy. In the database, inside the write transaction: one Detection per Build, file and hash per window
// of the rule, and at most `hashesPerDay` distinct observed hashes per Build in any 24 hours, so both hold across
// processes and restarts and a Build is never blinded for longer than a day. No limit is shared between Builds: one
// Build's forged reports cannot silence another. When a cap drops a distinct hash while the Build's Incident is
// open, the Incident is marked (`detections_capped`): it then says that more was reported than it shows.
//
// Lookups (review M3, L1; second review M2). A registered Build is handed to the recorder by the registration hook
// and needs no lookup at all. After a restart one lookup answers the named Build and the App's newest 20 Builds, so
// an App is warmed by one query, not one per Build; concurrent reports of one App wait for that query. A Build found
// unknown or known is remembered for 10 minutes (both memories bounded; the unknown one cleared when the Build is
// registered). Every report shares the one remembered object, so a Build armed during a burst is armed for all of
// them. A known Build whose entry has expired is still judged from it while it is refreshed: a refresh never drops a
// report. New lookups are capped per reporter prefix, per App, per Organization (once a lookup or a registration
// told which Organization the App belongs to) and in all; a lookup one of them refuses is charged to none, so one
// prefix, App or Organization spends only its own share and leaves the rest to the others. The reports one
// Organization has at the database are capped too.
//
// An Organization with a pending deletion is judged like any other until it is purged (D-082: the keyless public
// recorders stay open during the grace, as the Clone Beacon does). A report in flight while its Organization is
// purged finds its Build gone (a foreign-key violation on the write, or no row to arm): it is dropped as an unknown
// Build and the Build is forgotten. A report leaves at most one log line: the reason it was dropped, a failure, or
// what was recorded and how many observations each reason dropped, with the Build once it is known. Never a hash, a
// path, the origin, the address or the App id. A logger that throws is ignored: it reaches neither the attest
// handler nor an unhandled rejection.

const TAMPER_RULE: DetectionRule = (() => {
  const rule = DETECTION_RULES.find((candidate) => candidate.key === "tampered-build");
  if (rule === undefined) throw new Error("The protocol has no tampered-build rule.");
  return rule;
})();

/** The span of the per-Build limits. */
const HOUR_MS = 3_600_000;
/** One Detection per Build, file and observed hash per window of the rule. */
const REPEAT_MS = TAMPER_RULE.window_s * 1_000;
/** The span of the per-prefix lookup cap. */
const MINUTE_MS = 60_000;

export const DEFAULT_MAX_BUILDS = 10_000;
export const DEFAULT_MAX_BUILDS_PER_ORG = 1_000;
export const DEFAULT_MAX_PENDING = 1_000;
export const DEFAULT_MAX_IN_FLIGHT_PER_ORG = 100;
/** Entries of each Build cache (unknown and known Builds). */
export const DEFAULT_MAX_CACHED_BUILDS = 10_000;
/** How long a Build's lookup result is fresh (unless the Build is registered meanwhile). */
export const BUILD_CACHE_TTL_MS = 10 * 60_000;
/** Database lookups per reporter prefix (/24 or /48; unknown addresses share one) per minute. */
export const LOOKUPS_PER_PREFIX_PER_MINUTE = 60;
/** Reporter prefixes, and Apps, whose lookups are counted at once (each). */
export const DEFAULT_MAX_PREFIXES = 10_000;
/** The token bucket of one App's database lookups: refill per second, and burst. A tenth of the global one. */
export const LOOKUPS_PER_APP_PER_SECOND = 1;
export const LOOKUP_APP_BURST = 20;
/** The token bucket of the lookups of all Apps of one Organization together: refill per second, and burst. */
export const LOOKUPS_PER_ORG_PER_SECOND = 2;
export const LOOKUP_ORG_BURST = 40;
/** The global token bucket of database lookups: refill per second, and burst. */
export const LOOKUPS_PER_SECOND = 50;
export const LOOKUP_BURST = 200;
/** App Environments whose recent digests are kept at once; the least recently used goes first. */
export const DEFAULT_MAX_RECENT = 1_000;
/** Paths one App Environment's recent digests cover: the markers of the Builds judged there (32 paths each). */
export const RECENT_PATHS_MAX = 256;
/** Digests kept for all App Environments together (about 100 MB of text at most). */
export const RECENT_HASHES_MAX = 1_000_000;
/** How long an App Environment's recent digests are used before they are read again (the 30-day edge moves). */
export const RECENT_TTL_MS = 5 * 60_000;
/** Loads of recent digests running at once, all tenants together. */
export const RECENT_LOADS_MAX = 2;

export const INTEGRITY_DROP_REASONS = [
  "no-origin",
  "not-canonical",
  "local",
  "empty",
  "busy",
  "prefix-limit",
  "app-limit",
  "org-limit",
  "unknown-build",
  "no-marker",
  "bad-index",
  "report-limit",
  "unarmed",
  "repeat",
  "stale",
  "hash-cap",
  "hash-limit",
  "failed",
] as const;
export type IntegrityDropReason = (typeof INTEGRITY_DROP_REASONS)[number];

/** One integrity report, as the attest route hands it over after a handshake that passed. */
export interface IntegrityRequest {
  /** The App of the handshake: the nonce was issued for it. */
  appId: string;
  /** The report, as `AttestRequestSchema` parsed it. */
  report: IntegrityReport;
  /** The request's `Origin` header. */
  originHeader: string | undefined;
  /** The client address: reduced to its /24 or /48 at once, never kept. */
  address: string | undefined;
}

export interface IntegrityRecorderDeps {
  db: Db;
  /** Told about every newly opened Incident, after its transaction committed. */
  notifier: Pick<Notifier, "incidentOpened">;
  /** Stamps the Detection and drives every limit and cache. Default: the system clock. */
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  /** Builds tracked at once, all Organizations together. Default 10,000. */
  maxBuilds?: number | undefined;
  /** Builds tracked at once for one Organization. Default 1,000. */
  maxBuildsPerOrg?: number | undefined;
  /** Reports being judged at once, all together; more are dropped. Default 1,000. */
  maxPending?: number | undefined;
  /** Reports of one Organization at the database at once; more are dropped. Default 100. */
  maxInFlightPerOrg?: number | undefined;
  /** Unknown Builds remembered at once, oldest evicted. Default 10,000. */
  maxUnknownBuilds?: number | undefined;
  /** Known Builds remembered at once, oldest evicted. Default 10,000. */
  maxKnownBuilds?: number | undefined;
}

export interface IntegrityRecorder {
  /** Judges one report after the response. Never throws, never waits. */
  report(request: IntegrityRequest): void;
  /**
   * A Build was registered (`integrityBuildOf` of its Manifest): it is known from now on without a lookup, and its
   * App Environment's recent digests are read again before the next report is judged against them.
   */
  buildRegistered(build: IntegrityBuild): void;
  /** Resolves when every report started so far has been judged and its Detections written (or dropped). */
  flush(): Promise<void>;
  /** Builds whose limits are currently tracked: never more than `maxBuilds`. */
  trackedBuilds(): number;
  /** Forgets everything kept for an Organization (called once the Organization is purged). */
  forget(organizationId: string): void;
  /** Reports and observations dropped since start, by reason. */
  dropped(): Readonly<Record<IntegrityDropReason, number>>;
}

/**
 * Per-Organization state with two bounds: at most `perOrg` entries for one Organization and `max` in all. Over a
 * bound, room is made only by dropping an entry that `idle` says holds nothing any more (the least recently used
 * such entry of the Organization, or of the Organization that holds the most); when there is none, the new entry is
 * refused. A limit that is still running is therefore never forgotten, and one Organization's churn only ever
 * costs its own entries.
 */
function orgBounded<T>(perOrg: number, max: number, idle: (entry: T, ms: number) => boolean) {
  const byOrg = new Map<string, Map<string, T>>();
  let total = 0;

  /** Drops the least recently used idle entry of the Organization; false when it has none. */
  function evictIdle(organizationId: string, ms: number): boolean {
    const own = byOrg.get(organizationId);
    if (own === undefined) return false;
    for (const [key, entry] of own) {
      if (!idle(entry, ms)) continue;
      own.delete(key);
      total--;
      if (own.size === 0) byOrg.delete(organizationId);
      return true;
    }
    return false;
  }

  return {
    /** The entry, now the most recently used, or undefined. */
    get(organizationId: string, key: string): T | undefined {
      const own = byOrg.get(organizationId);
      const existing = own?.get(key);
      if (own === undefined || existing === undefined) return undefined;
      own.delete(key);
      own.set(key, existing);
      return existing;
    },
    /** A new entry; null when there is no room and nothing idle to drop for it. */
    add(organizationId: string, key: string, created: T, ms: number): T | null {
      if ((byOrg.get(organizationId)?.size ?? 0) >= perOrg && !evictIdle(organizationId, ms)) return null;
      if (total >= max) {
        let largest: string | undefined;
        let most = 0;
        for (const [candidate, held] of byOrg) {
          if (held.size > most) {
            most = held.size;
            largest = candidate;
          }
        }
        if (largest === undefined || !evictIdle(largest, ms)) return null;
      }
      let own = byOrg.get(organizationId);
      if (own === undefined) {
        own = new Map();
        byOrg.set(organizationId, own);
      }
      own.set(key, created);
      total++;
      return created;
    },
    delete(organizationId: string, key: string): void {
      const own = byOrg.get(organizationId);
      if (own?.delete(key) !== true) return;
      total--;
      if (own.size === 0) byOrg.delete(organizationId);
    },
    size: () => total,
    forget(organizationId: string): void {
      const own = byOrg.get(organizationId);
      if (own === undefined) return;
      total -= own.size;
      byOrg.delete(organizationId);
    },
  };
}

/** A map bounded to `max` entries: the least recently set goes first. Entries carry the time they were set. */
function boundedCache<T>(max: number) {
  const entries = new Map<string, { value: T; at: number }>();
  return {
    /** The entry whatever its age: the caller decides what an old one is good for. */
    get: (key: string) => entries.get(key),
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
    deleteWhere(matches: (value: T) => boolean): void {
      for (const [key, entry] of entries) if (matches(entry.value)) entries.delete(key);
    },
  };
}

/** A token bucket. */
interface Bucket {
  tokens: number;
  at: number;
}

interface BuildState {
  /** Start of the current hour of this Build's limits, on the recorder's clock (ms). */
  hourStart: number;
  /** Reports counted in the current hour: those that still carried a mismatch after the stale and repeat checks. */
  reports: number;
  /** Observations admitted in the current hour. */
  newHashes: number;
  /** Observation → time it was last admitted (ms); entries a window old are pruned when the hour turns. */
  detected: Map<string, number>;
  /** When an observation was last admitted (ms): until a window after it, the state holds a running repeat window. */
  lastAdmit: number;
  /** The Build's open Incident was told, this hour, that a cap dropped a distinct hash. */
  cappedMarked: boolean;
}

/** The recent digests of one App Environment, as kept in memory. */
interface RecentEntry {
  organizationId: string;
  /** The paths covered: the marker paths of the Builds judged in this App Environment. */
  paths: Set<string>;
  hashes: RecentHashes | null;
  /** Digests held (the sum over the paths). */
  size: number;
  loadedAt: number;
  /** Raised by a registration or a new path: a load that started before it is not the answer. */
  generation: number;
  loading: Promise<RecentHashes> | null;
}

/** One observed file of a report: the marker's path and the hash the browser saw, as lowercase hex. */
type Observation = IntegrityFile;

const observationKey = (observation: Observation) => `${observation.path}\n${observation.sha256}`;

/** The SHA-256 of a report (43 base64url characters) as the Manifest spells one: 64 lowercase hex characters. */
export function hashToHex(base64url: string): string {
  return Buffer.from(base64url, "base64url").toString("hex");
}

/** SQL state of a foreign-key violation: here, a write for an Organization that was purged meanwhile. */
const FOREIGN_KEY_VIOLATION = "23503";

/** A map of at most `max` entries; the oldest goes first. */
function remember<V>(map: Map<string, V>, key: string, value: V, max: number): void {
  map.delete(key);
  map.set(key, value);
  while (map.size > max) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) break;
    map.delete(oldest);
  }
}

export function createIntegrityRecorder(deps: IntegrityRecorderDeps): IntegrityRecorder {
  const { db, notifier } = deps;
  const now = deps.now ?? (() => new Date());
  const sink = redacting(deps.logger ?? consoleLogger);
  // A logger that throws must not undo the work a line reports, fail the attestation that carried the report, or
  // leave a rejection nobody handles.
  const logger: Logger = {
    info(line) {
      try {
        sink.info(line);
      } catch {}
    },
    warn(line) {
      try {
        sink.warn(line);
      } catch {}
    },
  };
  const maxBuilds = deps.maxBuilds ?? DEFAULT_MAX_BUILDS;
  const maxBuildsPerOrg = deps.maxBuildsPerOrg ?? DEFAULT_MAX_BUILDS_PER_ORG;
  const maxPending = deps.maxPending ?? DEFAULT_MAX_PENDING;
  const maxInFlightPerOrg = deps.maxInFlightPerOrg ?? DEFAULT_MAX_IN_FLIGHT_PER_ORG;

  const counts = Object.fromEntries(INTEGRITY_DROP_REASONS.map((reason) => [reason, 0])) as Record<
    IntegrityDropReason,
    number
  >;
  // A Build's limits are kept until its hour is over and no repeat window runs.
  const builds = orgBounded<BuildState>(
    maxBuildsPerOrg,
    maxBuilds,
    (state, ms) => ms - state.hourStart >= HOUR_MS && ms - state.lastAdmit >= REPEAT_MS,
  );
  const unknownBuilds = boundedCache<true>(deps.maxUnknownBuilds ?? DEFAULT_MAX_CACHED_BUILDS);
  const knownBuilds = boundedCache<IntegrityBuild>(deps.maxKnownBuilds ?? DEFAULT_MAX_CACHED_BUILDS);
  /** The lookup running now for an App: reports of the App's other Builds wait for it, as it may answer them too. */
  const lookups = new Map<string, Promise<void>>();
  /** Builds being armed now. */
  const arming = new Map<string, Promise<void>>();
  // Lookups per reporter prefix in the current minute; insertion order is age, the oldest goes first over the bound.
  const prefixes = new Map<string, { start: number; lookups: number }>();
  const appBuckets = new Map<string, Bucket>();
  const orgBuckets = new Map<string, Bucket>();
  /** App → its Organization, as lookups and registrations told it. */
  const orgOfApp = new Map<string, string>();
  const bucket: Bucket = { tokens: LOOKUP_BURST, at: now().getTime() };
  /** Recent digests by App Environment (`<app>/<environment>`), least recently used first. */
  const recent = new Map<string, RecentEntry>();
  let recentHashes = 0;
  let recentLoads = 0;
  const recentWaiters: (() => void)[] = [];
  const inFlight = new Map<string, number>();
  const pending = new Set<Promise<void>>();
  // Counts purges: a lookup that overlapped one does not remember its result, which may be stale.
  let purges = 0;

  const cacheKey = (appId: string, buildId: string) => `${appId}\n${buildId}`;

  /** Tracks background work, so that `flush` waits for it; a failure is counted and logged, never thrown. */
  function track(work: Promise<unknown>): void {
    const promise = work.then(
      () => {},
      (error: unknown) => {
        // The kind of error only: a message could quote a value from the report.
        counts.failed++;
        logger.warn(`integrity failed ${error instanceof Error ? error.name : "error"}`);
      },
    );
    pending.add(promise);
    void promise.finally(() => pending.delete(promise));
  }

  /** A report dropped whole: counted, and its one log line. */
  function drop(reason: IntegrityDropReason, buildId?: string): void {
    counts[reason]++;
    logger.info(`integrity dropped reason=${reason}${buildId === undefined ? "" : ` build=${buildId}`}`);
  }

  function bucketOf(map: Map<string, Bucket>, key: string, burst: number, ms: number): Bucket {
    let own = map.get(key);
    if (own === undefined) {
      own = { tokens: burst, at: ms };
      remember(map, key, own, DEFAULT_MAX_PREFIXES);
    }
    return own;
  }

  /** Refills the bucket; whether it holds a token (not taken yet). */
  function has(own: Bucket, ms: number, perSecond: number, burst: number): boolean {
    own.tokens = Math.min(burst, own.tokens + (Math.max(0, ms - own.at) * perSecond) / 1_000);
    own.at = ms;
    return own.tokens >= 1;
  }

  /**
   * One database lookup for a report of `appId` from `prefix`: allowed only when the prefix, the App, the App's
   * Organization (when known) and the global budget all have room, and charged to all of them only then. What one of
   * them refuses costs the others nothing. Null when the lookup may run.
   */
  function lookupBudget(appId: string, prefix: string | null, ms: number): IntegrityDropReason | null {
    const prefixKey = prefix ?? "unknown";
    let minute = prefixes.get(prefixKey);
    if (minute === undefined || ms - minute.start >= MINUTE_MS) {
      minute = { start: ms, lookups: 0 };
      remember(prefixes, prefixKey, minute, DEFAULT_MAX_PREFIXES);
    }
    if (minute.lookups >= LOOKUPS_PER_PREFIX_PER_MINUTE) return "prefix-limit";
    const ofApp = bucketOf(appBuckets, appId, LOOKUP_APP_BURST, ms);
    if (!has(ofApp, ms, LOOKUPS_PER_APP_PER_SECOND, LOOKUP_APP_BURST)) return "app-limit";
    const organizationId = orgOfApp.get(appId);
    const ofOrg = organizationId === undefined ? undefined : bucketOf(orgBuckets, organizationId, LOOKUP_ORG_BURST, ms);
    if (ofOrg !== undefined && !has(ofOrg, ms, LOOKUPS_PER_ORG_PER_SECOND, LOOKUP_ORG_BURST)) return "org-limit";
    if (!has(bucket, ms, LOOKUPS_PER_SECOND, LOOKUP_BURST)) return "busy";
    minute.lookups++;
    ofApp.tokens--;
    if (ofOrg !== undefined) ofOrg.tokens--;
    bucket.tokens--;
    return null;
  }

  /** The App belongs to this Organization. A lookup that found it out is charged to the Organization afterwards. */
  function learnOrganization(appId: string, organizationId: string, ms: number, charge: boolean): void {
    if (orgOfApp.get(appId) === organizationId) return;
    remember(orgOfApp, appId, organizationId, DEFAULT_MAX_PREFIXES);
    if (!charge) return;
    const ofOrg = bucketOf(orgBuckets, organizationId, LOOKUP_ORG_BURST, ms);
    has(ofOrg, ms, LOOKUPS_PER_ORG_PER_SECOND, LOOKUP_ORG_BURST);
    ofOrg.tokens = Math.max(0, ofOrg.tokens - 1);
  }

  /**
   * Remembers a Build as known. One already remembered keeps its object (every report in flight shares it) and is
   * only brought up to date; it stays armed if either the memory or the database says so. `refresh` restarts its 10
   * minutes.
   */
  function keep(found: IntegrityBuild, ms: number, refresh: boolean): void {
    const key = cacheKey(found.appId, found.buildId);
    const held = knownBuilds.get(key);
    unknownBuilds.delete(key);
    if (held === undefined) {
      knownBuilds.set(key, found, ms);
      return;
    }
    held.value.files = found.files;
    held.value.environment = found.environment;
    held.value.organizationId = found.organizationId;
    held.value.armed = held.value.armed || found.armed;
    if (refresh) knownBuilds.set(key, held.value, ms);
  }

  /** Forgets a Build that turned out to be gone: its next report is answered from the unknown-Build memory. */
  function evict(build: IntegrityBuild): void {
    const key = cacheKey(build.appId, build.buildId);
    knownBuilds.delete(key);
    unknownBuilds.set(key, true, now().getTime());
    builds.delete(build.organizationId, `${build.appId}/${build.buildId}`);
  }

  /**
   * One lookup: the named Build and the App's newest Builds, all remembered. The caller has paid for it
   * (`lookupBudget`) and made sure none runs for the App.
   */
  function lookup(appId: string, buildId: string): Promise<void> {
    const before = purges;
    const hadOrganization = orgOfApp.has(appId);
    const started = db
      .tx("none", (q) => findIntegrityBuilds(q, appId, buildId))
      .then((found) => {
        if (purges !== before) return;
        const ms = now().getTime();
        if (found.organizationId !== null) learnOrganization(appId, found.organizationId, ms, !hadOrganization);
        let named = false;
        for (const build of found.builds) {
          const isNamed = build.buildId === buildId;
          named ||= isNamed;
          keep(build, ms, isNamed);
        }
        if (!named) {
          knownBuilds.delete(cacheKey(appId, buildId));
          unknownBuilds.set(cacheKey(appId, buildId), true, ms);
        }
      })
      .finally(() => lookups.delete(appId));
    lookups.set(appId, started);
    return started;
  }

  /**
   * The Build a report names, looked up when it is not remembered: after the lookup running for its App, if one is,
   * which may answer it; else by a lookup of its own, when the budgets allow one. The reason it was dropped
   * otherwise.
   */
  async function resolve(
    appId: string,
    buildId: string,
    prefix: string | null,
  ): Promise<IntegrityBuild | IntegrityDropReason> {
    const key = cacheKey(appId, buildId);
    for (;;) {
      const known = knownBuilds.get(key);
      if (known !== undefined) return known.value;
      const ms = now().getTime();
      const unknown = unknownBuilds.get(key);
      if (unknown !== undefined && ms - unknown.at < BUILD_CACHE_TTL_MS) return "unknown-build";
      const running = lookups.get(appId);
      if (running !== undefined) {
        await running;
        continue;
      }
      const refused = lookupBudget(appId, prefix, ms);
      if (refused !== null) return refused;
      await lookup(appId, buildId);
      const found = knownBuilds.get(key);
      // A purge overlapped the lookup and nothing was remembered: unknown for this report.
      return found === undefined ? "unknown-build" : found.value;
    }
  }

  /** The Build's limits, with a new hour started when the last one is over; undefined when none are kept. */
  function stateOf(build: IntegrityBuild, ms: number): BuildState | undefined {
    const state = builds.get(build.organizationId, `${build.appId}/${build.buildId}`);
    if (state !== undefined && ms - state.hourStart >= HOUR_MS) {
      state.hourStart = ms;
      state.reports = 0;
      state.newHashes = 0;
      state.cappedMarked = false;
      for (const [seen, at] of state.detected) if (ms - at >= REPEAT_MS) state.detected.delete(seen);
    }
    return state;
  }

  /** Runs `work` as one of the Organization's reports at the database; "busy" when it has too many there. */
  async function inFlightOf<T>(organizationId: string, work: () => Promise<T>): Promise<T | "busy"> {
    const busy = inFlight.get(organizationId) ?? 0;
    if (busy >= maxInFlightPerOrg) return "busy";
    inFlight.set(organizationId, busy + 1);
    try {
      return await work();
    } finally {
      const left = (inFlight.get(organizationId) ?? 1) - 1;
      if (left <= 0) inFlight.delete(organizationId);
      else inFlight.set(organizationId, left);
    }
  }

  /** One of the `RECENT_LOADS_MAX` places of a load of recent digests; the rest wait their turn. */
  async function loadSlot<T>(work: () => Promise<T>): Promise<T> {
    if (recentLoads >= RECENT_LOADS_MAX) await new Promise<void>((resolve) => recentWaiters.push(resolve));
    else recentLoads++;
    try {
      return await work();
    } finally {
      // The place goes straight to the next waiter, if there is one.
      const next = recentWaiters.shift();
      if (next === undefined) recentLoads--;
      else next();
    }
  }

  function dropRecent(key: string): void {
    const entry = recent.get(key);
    if (entry === undefined) return;
    recentHashes -= entry.size;
    recent.delete(key);
  }

  /**
   * The recent digests of the Build's App Environment for (at least) the Build's marker paths: from memory when
   * they are loaded, fresh, cover those paths and no Build was registered since; otherwise the one load every report
   * of the App Environment waits for.
   */
  function recentOf(build: IntegrityBuild, ms: number): RecentHashes | Promise<RecentHashes> {
    const key = `${build.appId}/${build.environment}`;
    let entry = recent.get(key);
    if (entry === undefined) {
      entry = {
        organizationId: build.organizationId,
        paths: new Set(),
        hashes: null,
        size: 0,
        loadedAt: 0,
        generation: 0,
        loading: null,
      };
    } else {
      recent.delete(key);
    }
    recent.set(key, entry);
    while (recent.size > DEFAULT_MAX_RECENT) {
      const oldest = recent.keys().next().value;
      if (oldest === undefined) break;
      dropRecent(oldest);
    }
    // The judged Build's own marker paths are always covered, also when the Build is no longer a recent one.
    if (build.files.some((file) => !entry.paths.has(file.path))) {
      if (entry.paths.size + build.files.length > RECENT_PATHS_MAX) entry.paths.clear();
      for (const file of build.files) entry.paths.add(file.path);
      entry.generation++;
      recentHashes -= entry.size;
      entry.size = 0;
      entry.hashes = null;
    }
    if (entry.hashes !== null && ms - entry.loadedAt < RECENT_TTL_MS) return entry.hashes;
    if (entry.loading !== null) return entry.loading;
    const held = entry;
    const load = async (): Promise<RecentHashes> => {
      for (;;) {
        const generation = held.generation;
        const at = now();
        const paths = [...held.paths];
        const hashes = await loadSlot(() =>
          db.tx({ organizationId: build.organizationId }, (q) => loadRecentHashes(q, build, paths, at)),
        );
        // A Build registered, or a path added, while this load ran is not in it: read again.
        if (held.generation !== generation) continue;
        let size = 0;
        for (const known of hashes.values()) size += known.size;
        if (recent.get(key) === held) {
          recentHashes += size - held.size;
          held.size = size;
          held.hashes = hashes;
          held.loadedAt = at.getTime();
          // Over the bound in all: the least recently used App Environments go, this one last.
          for (const other of [...recent.keys()]) {
            if (recentHashes <= RECENT_HASHES_MAX || other === key) break;
            dropRecent(other);
          }
        }
        return hashes;
      }
    };
    held.loading = load().finally(() => {
      held.loading = null;
    });
    return held.loading;
  }

  /** Arms the Build, once however many matching reports ask at the same time. */
  function arm(build: IntegrityBuild, at: Date): Promise<void> {
    const key = cacheKey(build.appId, build.buildId);
    const running = arming.get(key);
    if (running !== undefined) return running;
    const { organizationId, buildId } = build;
    const started = (async () => {
      const outcome = await inFlightOf(organizationId, () => db.tx({ organizationId }, (q) => armBuild(q, build, at)));
      if (outcome === "busy") return drop("busy", buildId);
      if (outcome === "gone") {
        // No row to arm: the Organization was purged while the report was in flight.
        evict(build);
        return drop("unknown-build");
      }
      build.armed = true;
      // The remembered object may be another one after a purge and a new registration of the same id.
      const held = knownBuilds.get(key)?.value;
      if (held !== undefined) held.armed = true;
      if (outcome === "armed") logger.info(`integrity armed build=${buildId}`);
    })().finally(() => arming.delete(key));
    arming.set(key, started);
    return started;
  }

  /** Tells the Build's open Incident, once an hour at most, that a cap dropped a distinct hash. */
  async function markCappedOnce(build: IntegrityBuild, state: BuildState, at: Date): Promise<void> {
    if (state.cappedMarked) return;
    state.cappedMarked = true;
    try {
      await db.tx({ organizationId: build.organizationId }, (q) => markCapped(q, build, at));
    } catch (error) {
      state.cappedMarked = false;
      throw error;
    }
  }

  async function judge(build: IntegrityBuild, request: IntegrityRequest, origin: string, ipPrefix: string | null) {
    const { report } = request;
    const { organizationId, buildId } = build;
    if (build.files.length === 0) return drop("no-marker", buildId);
    if (report.files.some((file) => file.i >= build.files.length)) return drop("bad-index", buildId);

    // The comparison: the wire's base64url against the Manifest's hex, as bytes.
    const mismatches: Observation[] = [];
    for (const file of report.files) {
      const registered = build.files[file.i] as IntegrityFile;
      const observed = hashToHex(file.h);
      if (observed !== registered.sha256) mismatches.push({ path: registered.path, sha256: observed });
    }

    const at = now();
    const ms = at.getTime();
    if (mismatches.length === 0) {
      // A fully matching report: free for an armed Build, and the first one arms it.
      if (!build.armed) await arm(build, at);
      return;
    }
    if (!build.armed) {
      // A matching report of the same burst may be arming the Build right now.
      await arming.get(cacheKey(build.appId, buildId))?.catch(() => {});
      if (!build.armed) return drop("unarmed", buildId);
    }

    // From here on: memory only, until an observation is admitted.
    const stateKey = `${build.appId}/${buildId}`;
    let state = stateOf(build, ms);
    /** What this report's observations were dropped for. */
    const tally = new Map<IntegrityDropReason, number>();
    const dropped = (reason: IntegrityDropReason, n = 1) => {
      counts[reason] += n;
      tally.set(reason, (tally.get(reason) ?? 0) + n);
    };
    let recorded = 0;
    let incidentId: string | undefined;
    /** One line for the whole report: what was recorded, and how many observations each reason dropped. */
    const finish = () => {
      const reasons = INTEGRITY_DROP_REASONS.filter((reason) => tally.has(reason))
        .map((reason) => `${reason}:${tally.get(reason)}`)
        .join(",");
      logger.info(
        `integrity report organization=${organizationId} build=${buildId} recorded=${recorded}${
          incidentId === undefined ? "" : ` incident=${incidentId}`
        }${reasons === "" ? "" : ` dropped=${reasons}`}`,
      );
    };
    const isRepeat = (key: string) => {
      const last = state?.detected.get(key);
      return last !== undefined && ms - last < REPEAT_MS;
    };

    // By path, then hash: the order they are recorded in, and so the one an Incident names its first Detection by.
    mismatches.sort((a, b) => (observationKey(a) < observationKey(b) ? -1 : 1));
    const fresh = mismatches.filter((observation) => {
      if (!isRepeat(observationKey(observation))) return true;
      dropped("repeat");
      return false;
    });
    if (fresh.length === 0) return finish();

    // Stale files of a mixed deploy, from memory: one load per App Environment, shared by every report and not
    // counted as this report being at the database.
    const known = recentOf(build, ms);
    const hashes = known instanceof Map ? known : await known;
    state = stateOf(build, ms);
    const candidates = fresh.filter((observation) => {
      if (hashes.get(observation.path)?.has(observation.sha256) === true) dropped("stale");
      // Checked again: another report of the burst may have been admitted while this one waited for the load.
      else if (isRepeat(observationKey(observation))) dropped("repeat");
      else return true;
      return false;
    });
    // Only a report that still carries a mismatch now uses the Build's budgets.
    if (candidates.length === 0) return finish();

    if (state === undefined) {
      state =
        builds.add(
          organizationId,
          stateKey,
          { hourStart: ms, reports: 0, newHashes: 0, detected: new Map(), lastAdmit: 0, cappedMarked: false },
          ms,
        ) ?? undefined;
      // No room, and every Build held still has a limit running: this one waits its turn rather than cost another
      // Build its repeat window or its hourly cap.
      if (state === undefined) {
        dropped("busy", candidates.length);
        return finish();
      }
    }
    const held = state;
    if (held.reports >= INTEGRITY_LIMITS.reportsPerHour) {
      dropped("report-limit");
      return finish();
    }
    held.reports++;

    let capped = false;
    const admitted: Observation[] = [];
    for (const observation of candidates) {
      if (held.newHashes >= INTEGRITY_LIMITS.newHashesPerHour) {
        // The Build's hour is spent: nothing is read or written for this one.
        dropped("hash-limit");
        capped = true;
      } else {
        held.newHashes++;
        held.detected.set(observationKey(observation), ms);
        held.lastAdmit = ms;
        admitted.push(observation);
      }
    }
    /** Gives an admitted observation's places back: nothing was recorded for it. */
    const release = (observation: Observation) => {
      held.newHashes = Math.max(0, held.newHashes - 1);
      held.detected.delete(observationKey(observation));
    };

    if (admitted.length > 0) {
      const outcome = await inFlightOf(organizationId, async () => {
        for (const [index, observation] of admitted.entries()) {
          let verdict: "ok" | "repeat" | "cap" = "ok";
          try {
            const result = await recordAndAlert(db, notifier, organizationId, async (q) => {
              // Decided here, in the write transaction, so that it holds across processes and restarts: one
              // Detection per file and hash per window, and the daily cap.
              verdict = await admitObservation(q, build, observation, at, TAMPER_RULE.window_s);
              if (verdict === "repeat") return null;
              if (verdict === "cap") {
                await markCapped(q, build, at);
                return null;
              }
              return recordDetection(q, {
                organizationId,
                appId: build.appId,
                environment: build.environment,
                rule: TAMPER_RULE,
                ipPrefix,
                count: 1,
                windowStart: at.toISOString(),
                windowEnd: at.toISOString(),
                detectedAt: at,
                tamper: { buildId, artifactPath: observation.path, observedSha256: observation.sha256, origin },
              });
            });
            // TypeScript does not follow the assignment inside the transaction.
            const decided = verdict as "ok" | "repeat" | "cap";
            if (decided === "repeat") {
              // Recorded before this process knew of it: a repeat from now on, and no new hash of this hour.
              held.newHashes = Math.max(0, held.newHashes - 1);
              dropped("repeat");
            } else if (decided === "cap") dropped("hash-cap");
            else if (result !== null) {
              recorded++;
              incidentId = result.incident.id;
            }
          } catch (error) {
            // Nothing was recorded for this observation or the ones after it.
            for (const unwritten of admitted.slice(index)) release(unwritten);
            if ((error as { code?: unknown }).code === FOREIGN_KEY_VIOLATION) {
              // The Organization was purged while the report was in flight: its Build is gone.
              evict(build);
              drop("unknown-build");
              return "ended" as const;
            }
            // One line: the kind of error and the Build, never the message (it could quote a value).
            counts.failed++;
            logger.warn(`integrity failed ${error instanceof Error ? error.name : "error"} build=${buildId}`);
            return "ended" as const;
          }
        }
        return "done" as const;
      });
      if (outcome === "ended") return;
      if (outcome === "busy") {
        for (const observation of admitted) release(observation);
        dropped("busy", admitted.length);
      }
    }
    // After the writes: the Incident a first Detection of this report opened is there to be marked.
    if (capped) await markCappedOnce(build, held, at);
    finish();
  }

  /** The part of a report's judgement that runs before the attest handler returns: memory only, no I/O. */
  function start(request: IntegrityRequest) {
    // The address is reduced first and never kept.
    const ipPrefix = addressPrefix(request.address);
    const header = request.originHeader;
    if (header === undefined) return drop("no-origin");
    if (canonicalOrigin(header) !== header) return drop("not-canonical");
    if (isLocalOrigin(header)) return drop("local");
    if (request.report.files.length === 0) return drop("empty");
    const ms = now().getTime();
    const { appId } = request;
    const buildId = request.report.build;
    const key = cacheKey(appId, buildId);
    const unknown = unknownBuilds.get(key);
    if (unknown !== undefined) {
      if (ms - unknown.at < BUILD_CACHE_TTL_MS) return drop("unknown-build");
      unknownBuilds.delete(key);
    }
    if (pending.size >= maxPending) return drop("busy");
    // One spelling per host: one trailing dot is dropped before the origin is stored.
    const origin = dotlessOrigin(header);
    const known = knownBuilds.get(key);
    if (known !== undefined) {
      // An expired entry still judges the report while it is refreshed, when there is budget for the refresh.
      if (ms - known.at >= BUILD_CACHE_TTL_MS && !lookups.has(appId) && lookupBudget(appId, ipPrefix, ms) === null) {
        track(lookup(appId, buildId));
      }
      return track(judge(known.value, request, origin, ipPrefix));
    }
    // Only a new lookup costs the database; a report of an App being looked up waits for that lookup first.
    if (!lookups.has(appId)) {
      const refused = lookupBudget(appId, ipPrefix, ms);
      if (refused !== null) return drop(refused);
      void lookup(appId, buildId).catch(() => {});
    }
    track(
      (async () => {
        await lookups.get(appId);
        const build = await resolve(appId, buildId, ipPrefix);
        if (typeof build === "string") return drop(build);
        await judge(build, request, origin, ipPrefix);
      })(),
    );
  }

  return {
    report(request) {
      // Whatever happens here, the attestation that carried the report is answered as if it carried none.
      try {
        start(request);
      } catch (error) {
        counts.failed++;
        logger.warn(`integrity failed ${error instanceof Error ? error.name : "error"}`);
      }
    },

    buildRegistered(build) {
      const ms = now().getTime();
      learnOrganization(build.appId, build.organizationId, ms, false);
      // Known from now on, without a lookup: what the Manifest registered is what a report is judged against.
      knownBuilds.delete(cacheKey(build.appId, build.buildId));
      keep({ ...build, files: [...build.files] }, ms, true);
      // The new Build's files are another recent Build's files from now on: the next report reads them.
      const entry = recent.get(`${build.appId}/${build.environment}`);
      if (entry !== undefined) {
        entry.generation++;
        recentHashes -= entry.size;
        entry.size = 0;
        entry.hashes = null;
      }
    },

    async flush() {
      while (pending.size > 0) await Promise.allSettled([...pending]);
    },

    trackedBuilds: () => builds.size(),

    forget(organizationId) {
      builds.forget(organizationId);
      knownBuilds.deleteWhere((build) => build.organizationId === organizationId);
      for (const [key, entry] of recent) if (entry.organizationId === organizationId) dropRecent(key);
      for (const [appId, owner] of orgOfApp) if (owner === organizationId) orgOfApp.delete(appId);
      orgBuckets.delete(organizationId);
      // A lookup in flight may still remember the Organization's Builds: it no longer will.
      purges++;
    },

    dropped: () => ({ ...counts }),
  };
}
