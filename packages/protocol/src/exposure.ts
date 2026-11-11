// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ENVIRONMENTS, ID_PATTERNS } from "./constants.ts";
import { deepFreeze, isoDateTime, text, trimmedText } from "./shared.ts";

// The Exposure contract (slice 19, D-059): the components an App ships (Harden, from the lockfile) and runs
// (Shield, at start), the advisories they are matched against (a subset of the OSV schema, synced locally),
// and the Findings the matches become. Only package names and versions ever leave the customer: an inventory
// carries nothing else. Also here, dependency-free: semver 2.0 precedence, OSV range matching and the CVSS v3
// base score. Every object schema is a plain `z.object`, which strips unknown keys; only a range event is
// strict, because an event with two keys is malformed rather than extended.

export const EXPOSURE_LIMITS = {
  /** Components of one inventory (a Build registration's `components` or a Shield inventory). */
  componentsMax: 5000,
  /** Bytes of a serialised component list (2 MB). Enforced by the API where the body is read, not here. */
  componentsBytesMax: 2_097_152,
  /** Characters of an npm package name. */
  nameMax: 214,
  /** Characters of a version (npm's own limit). */
  versionMax: 256,
  /** Characters of an advisory summary. */
  summaryMax: 500,
  /** Aliases of one advisory. */
  aliasesMax: 50,
  /** Affected entries of one advisory. */
  affectedMax: 100,
  /** Ranges of one affected entry. */
  rangesMax: 50,
  /** Events of one range; also the bound of a Finding's fixed versions. */
  eventsMax: 200,
  /** Explicit versions of one affected entry. */
  versionsMax: 10_000,
  /** Findings returned by the Finding list. */
  findingsListed: 200,
  /** Items of a findings summary. */
  summaryItemsMax: 50,
  /** Characters of an ignore reason, after trimming. */
  ignoreReasonMax: 200,
  /** Days an ignore may reach ahead. Enforced by the API (it depends on the current time), not here. */
  ignoreDaysMax: 90,
} as const;

/** A Finding's severity: the advisory's GHSA rating, else its CVSS v3 band, else unknown. */
export const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

/** Where a component was seen: a registered Build (Harden) or a running server (Shield). */
export const FINDING_SOURCES = ["build", "runtime"] as const;
export type FindingSource = (typeof FINDING_SOURCES)[number];

/**
 * open → fixed when the version left the inventory; open → ignored by an admin until an expiry; any → withdrawn
 * (D-060) when a sync finds the advisory withdrawn or its ranges no longer covering the version, and back to open
 * if a later sync covers it again. Only open counts (summary, `--fail-on`, Incidents).
 */
export const FINDING_STATUSES = ["open", "fixed", "ignored", "withdrawn"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

/** The GHSA ratings of `database_specific.severity`, mapped to Finding severities. */
const GHSA_SEVERITIES = { LOW: "low", MODERATE: "medium", HIGH: "high", CRITICAL: "critical" } as const;
type GhsaSeverity = keyof typeof GHSA_SEVERITIES;

// --- Semver 2.0 ------------------------------------------------------------------------------------------

/** A parsed semver 2.0 version. Numeric pre-release identifiers are numbers; the result is frozen. */
export interface ParsedSemver {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly prerelease: readonly (string | number)[];
  readonly build: readonly string[];
}

// The regular expression of semver.org (§ "Is there a suggested regular expression"), anchored.
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
const NUMERIC = /^\d+$/;

/**
 * Parses a full semver 2.0 version (`1.2.3`, `1.0.0-rc.1+build.5`), or returns null: no `v` prefix, no range,
 * no leading zeros, at most 256 characters, and, as npm, every number within `Number.MAX_SAFE_INTEGER`.
 */
export function parseSemver(version: string): ParsedSemver | null {
  if (typeof version !== "string" || version.length > EXPOSURE_LIMITS.versionMax) return null;
  const match = SEMVER.exec(version);
  if (match === null) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor) || !Number.isSafeInteger(patch)) return null;
  const prerelease: (string | number)[] = [];
  for (const identifier of match[4] === undefined ? [] : match[4].split(".")) {
    if (NUMERIC.test(identifier)) {
      const value = Number(identifier);
      if (!Number.isSafeInteger(value)) return null;
      prerelease.push(value);
    } else {
      prerelease.push(identifier);
    }
  }
  const build = match[5] === undefined ? [] : match[5].split(".");
  return deepFreeze({ major, minor, patch, prerelease, build });
}

const sign = (difference: number): -1 | 0 | 1 => (difference < 0 ? -1 : difference > 0 ? 1 : 0);

function compareIdentifiers(a: string | number, b: string | number): -1 | 0 | 1 {
  if (typeof a === "number" && typeof b === "number") return sign(a - b);
  // A numeric identifier has lower precedence than an alphanumeric one.
  if (typeof a === "number") return -1;
  if (typeof b === "number") return 1;
  // ASCII order; every identifier character is ASCII, so UTF-16 code-unit order is ASCII order.
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareParsed(a: ParsedSemver, b: ParsedSemver): -1 | 0 | 1 {
  const core = sign(a.major - b.major) || sign(a.minor - b.minor) || sign(a.patch - b.patch);
  if (core !== 0) return core;
  // A version without pre-release identifiers ranks above one with them.
  if (a.prerelease.length === 0 || b.prerelease.length === 0) {
    return sign(b.prerelease.length - a.prerelease.length);
  }
  const shared = Math.min(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < shared; index++) {
    const order = compareIdentifiers(a.prerelease[index] as string | number, b.prerelease[index] as string | number);
    if (order !== 0) return order;
  }
  // All shared identifiers equal: the larger set ranks higher.
  return sign(a.prerelease.length - b.prerelease.length);
}

/**
 * Semver 2.0 precedence (§11) of two versions: -1, 0 or 1. Build metadata is ignored, so `1.0.0+a` and
 * `1.0.0+b` compare equal. Throws a RangeError when either is not a semver 2.0 version (`parseSemver`).
 */
export function compareSemver(a: string, b: string): -1 | 0 | 1 {
  const left = parseSemver(a);
  const right = parseSemver(b);
  if (left === null || right === null) throw new RangeError("compareSemver needs two semver 2.0 versions.");
  return compareParsed(left, right);
}

/** A semver 2.0 version string (`parseSemver` accepts it). */
export const SemverSchema = z
  .string()
  .max(EXPOSURE_LIMITS.versionMax)
  .refine((value) => parseSemver(value) !== null, "Must be a semver 2.0 version.");

// --- Components and inventories --------------------------------------------------------------------------

// npm's naming rules for legacy packages, which lockfiles still hold (JSONStream): any case, URL-safe
// (`encodeURIComponent` leaves it unchanged, which allows npm's legacy special characters ~'!()*), not starting
// with "." or "_", at most 214 characters. A scope is an npm user or organisation name, which is always lower
// case. Names stay case-sensitive, as npm resolves them: JSONStream and jsonstream are two packages.
const NPM_SCOPE = "(?![._])[a-z0-9._~'!()*-]+";
const NPM_NAME_PART = "(?![._])[A-Za-z0-9._~'!()*-]+";
const NPM_NAME = new RegExp(`^(?:@${NPM_SCOPE}/)?${NPM_NAME_PART}$`);

/** An npm package name (legacy rules: any case), optionally under a lower-case scope, at most 214 characters. */
const ComponentNameSchema = z.string().max(EXPOSURE_LIMITS.nameMax).regex(NPM_NAME);

/** One installed package: its npm name, its semver version, and whether it is a development dependency. */
export const ComponentSchema = z.object({
  name: ComponentNameSchema,
  version: SemverSchema,
  dev: z.boolean(),
});
export type Component = z.infer<typeof ComponentSchema>;

/** At most 5,000 components, each name@version once. Shared by the Build registration's `components` (build.ts). */
export const ComponentListSchema = z
  .array(ComponentSchema)
  .max(EXPOSURE_LIMITS.componentsMax)
  .refine(
    (components) =>
      new Set(components.map((component) => `${component.name}@${component.version}`)).size === components.length,
    { message: "Must not list a name@version twice." },
  );

/**
 * Body of `POST /v1/inventory` (Shield key): the packages installed where Shield runs, and the random id of the
 * Shield process that sent them (plan A7): the API keeps one inventory per live instance of an App Environment.
 * An older Shield sends no id; the API treats all of those as one shared legacy instance.
 */
export const InventorySchema = z.object({
  components: ComponentListSchema,
  instance_id: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .optional(),
});
export type Inventory = z.infer<typeof InventorySchema>;

// --- Advisories (an OSV subset) --------------------------------------------------------------------------

// Advisory ids and aliases as published: GHSA-xxxx-xxxx-xxxx, CVE-YYYY-NNNN, MAL-YYYY-N, …
const ADVISORY_ID = /^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;

/** An advisory id or alias as published (`GHSA-…`, `CVE-…`). */
export const AdvisoryIdSchema = z.string().regex(ADVISORY_ID);

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;

/** Keeps the array entries whose `type` is one of `types`, and turns a missing array into an empty one. */
const onlyTypes =
  (types: readonly string[]) =>
  (value: unknown): unknown =>
    value === undefined
      ? []
      : Array.isArray(value)
        ? value.filter((entry) => isRecord(entry) && types.includes(entry.type as string))
        : value;

/** One CVSS rating: a v3.x vector (scored) or a v4.0 vector (kept for display only). */
const AdvisorySeveritySchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("CVSS_V3"),
    score: z
      .string()
      .max(512)
      .regex(/^CVSS:3\.[01]\/[A-Za-z0-9:/]+$/),
  }),
  z.object({
    type: z.literal("CVSS_V4"),
    score: z
      .string()
      .max(512)
      .regex(/^CVSS:4\.0\/[A-Za-z0-9:/]+$/),
  }),
]);

const EventVersionSchema = text(EXPOSURE_LIMITS.versionMax).min(1);

/** One OSV range event: exactly one of `introduced`, `fixed`, `last_affected` and `limit`. */
const RangeEventSchema = z.union([
  z.strictObject({ introduced: EventVersionSchema }),
  z.strictObject({ fixed: EventVersionSchema }),
  z.strictObject({ last_affected: EventVersionSchema }),
  z.strictObject({ limit: EventVersionSchema }),
]);

/** A version range. `GIT` ranges (commit hashes) carry nothing to match a version against and are dropped. */
const RangeSchema = z.object({
  type: z.enum(["SEMVER", "ECOSYSTEM"]),
  events: z.array(RangeEventSchema).min(1).max(EXPOSURE_LIMITS.eventsMax),
});

const AffectedSchema = z.object({
  /** Entries of another ecosystem are kept but never match (`isAffected`). */
  package: z.object({ ecosystem: text(64).min(1), name: text(EXPOSURE_LIMITS.nameMax).min(1) }),
  ranges: z.preprocess(onlyTypes(["SEMVER", "ECOSYSTEM"]), z.array(RangeSchema).max(EXPOSURE_LIMITS.rangesMax)),
  versions: z.array(EventVersionSchema).max(EXPOSURE_LIMITS.versionsMax).optional(),
});

const OsvTimeSchema = z.iso.datetime({ offset: true });

/**
 * An advisory as stored: the OSV fields matching and display need, everything else (details, references,
 * CVSS v2, GIT ranges, purl, …) stripped. Missing aliases, summary and severity default to empty; an unknown
 * GHSA rating is dropped.
 */
export const AdvisorySchema = z.object({
  id: AdvisoryIdSchema,
  aliases: z.array(AdvisoryIdSchema).max(EXPOSURE_LIMITS.aliasesMax).default([]),
  summary: text(EXPOSURE_LIMITS.summaryMax).default(""),
  severity: z.preprocess(onlyTypes(["CVSS_V3", "CVSS_V4"]), z.array(AdvisorySeveritySchema).max(10)),
  database_specific: z
    .object({
      severity: z
        .enum(Object.keys(GHSA_SEVERITIES) as [GhsaSeverity, ...GhsaSeverity[]])
        .optional()
        .catch(undefined),
    })
    .optional(),
  affected: z.array(AffectedSchema).min(1).max(EXPOSURE_LIMITS.affectedMax),
  published: OsvTimeSchema,
  modified: OsvTimeSchema,
  withdrawn: OsvTimeSchema.optional(),
});
export type Advisory = z.infer<typeof AdvisorySchema>;
export type AdvisoryInput = z.input<typeof AdvisorySchema>;

type Range = z.infer<typeof RangeSchema>;
type Bound = { kind: "introduced" | "fixed" | "last_affected" | "limit"; at: ParsedSemver | null };

/**
 * Whether `version` lies in one OSV range: events sorted by version (`introduced: "0"` first), then walked in
 * order — introduced opens, fixed closes (exclusive), last_affected closes after itself (inclusive); a limit
 * excludes every version at or above it. An event whose version is not semver is skipped.
 */
function inRange(version: ParsedSemver, range: Range): boolean {
  const bounds: Bound[] = [];
  for (const event of range.events) {
    const [kind, value] = Object.entries(event)[0] as [Bound["kind"], string];
    if (kind === "introduced" && value === "0") {
      bounds.push({ kind, at: null });
      continue;
    }
    const at = parseSemver(value);
    if (at !== null) bounds.push({ kind, at });
  }
  // Array#sort is stable: events at the same version keep their published order.
  bounds.sort((a, b) => (a.at === null ? (b.at === null ? 0 : -1) : b.at === null ? 1 : compareParsed(a.at, b.at)));
  let affected = false;
  const limits: ParsedSemver[] = [];
  for (const { kind, at } of bounds) {
    if (kind === "limit") {
      if (at !== null) limits.push(at);
    } else if (kind === "introduced") {
      if (at === null || compareParsed(version, at) >= 0) affected = true;
    } else if (kind === "fixed") {
      if (at !== null && compareParsed(version, at) >= 0) affected = false;
    } else if (at !== null && compareParsed(version, at) > 0) {
      affected = false;
    }
  }
  return affected && (limits.length === 0 || limits.some((limit) => compareParsed(version, limit) < 0));
}

/**
 * Whether the npm package `name` at `version` is affected by the advisory (OSV semantics): an exact entry of
 * an affected `versions` list, or any range (the union). A withdrawn advisory, a version that is not semver
 * and entries of another ecosystem never match. Names compare exactly.
 */
export function isAffected(advisory: Advisory, name: string, version: string): boolean {
  if (advisory.withdrawn !== undefined) return false;
  const parsed = parseSemver(version);
  if (parsed === null) return false;
  for (const entry of advisory.affected) {
    if (entry.package.ecosystem !== "npm" || entry.package.name !== name) continue;
    if (entry.versions?.includes(version)) return true;
    if (entry.ranges.some((range) => inRange(parsed, range))) return true;
  }
  return false;
}

/** The `fixed` versions the advisory names for the npm package `name`: semver only, each once, ascending. */
export function fixedVersions(advisory: Advisory, name: string): string[] {
  const fixed = new Set<string>();
  for (const entry of advisory.affected) {
    if (entry.package.ecosystem !== "npm" || entry.package.name !== name) continue;
    for (const range of entry.ranges) {
      for (const event of range.events) {
        if ("fixed" in event && parseSemver(event.fixed) !== null) fixed.add(event.fixed);
      }
    }
  }
  return [...fixed].sort(compareSemver);
}

// --- CVSS v3 ---------------------------------------------------------------------------------------------

const CIA = { H: 0.56, L: 0.22, N: 0 } as const;
const BASE_WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 0, C: 0 },
  C: CIA,
  I: CIA,
  A: CIA,
};
/** Privileges Required when the scope changes. */
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
/** Temporal and environmental metrics: allowed in a vector, ignored by the base score. */
const OTHER_METRICS = new Set(["E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]);

/**
 * Roundup of CVSS v3.1 (Appendix A): the smallest number with one decimal at or above the input, computed on
 * integers so floating-point noise (4.000000001) does not round up. Used for v3.0 vectors too.
 */
function roundup(value: number): number {
  const scaled = Math.round(value * 100_000);
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10;
}

/**
 * The CVSS v3.0/v3.1 base score (0.0–10.0) of a vector such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
 * per the FIRST.org specification. The eight base metrics must each appear once, in any order; temporal and
 * environmental metrics are allowed and ignored. Anything else returns null.
 */
export function cvss3BaseScore(vector: string): number | null {
  if (typeof vector !== "string" || vector.length > 512) return null;
  if (!vector.startsWith("CVSS:3.0/") && !vector.startsWith("CVSS:3.1/")) return null;
  const metrics = new Map<string, string>();
  for (const part of vector.slice("CVSS:3.x/".length).split("/")) {
    const match = /^([A-Z]{1,3}):([A-Z])$/.exec(part);
    if (match === null) return null;
    const [, key, value] = match as unknown as [string, string, string];
    if (metrics.has(key)) return null;
    const weights = BASE_WEIGHTS[key];
    if (weights === undefined ? !OTHER_METRICS.has(key) : !(value in weights)) return null;
    metrics.set(key, value);
  }
  for (const key of Object.keys(BASE_WEIGHTS)) if (!metrics.has(key)) return null;
  const weight = (key: string): number => BASE_WEIGHTS[key]?.[metrics.get(key) as string] as number;
  const changed = metrics.get("S") === "C";
  const iss = 1 - (1 - weight("C")) * (1 - weight("I")) * (1 - weight("A"));
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const privileges = changed ? (PR_CHANGED[metrics.get("PR") as string] as number) : weight("PR");
  const exploitability = 8.22 * weight("AV") * weight("AC") * privileges * weight("UI");
  if (impact <= 0) return 0;
  return roundup(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

/**
 * An advisory's severity: its GHSA rating (LOW, MODERATE, HIGH, CRITICAL) first; else the highest CVSS v3
 * base score among its vectors, banded 0.1–3.9 low, 4.0–6.9 medium, 7.0–8.9 high, 9.0–10.0 critical; else
 * unknown. A 0.0 score lies in no band and is unknown. CVSS v4 vectors are not scored.
 */
export function severityOf(advisory: Advisory): FindingSeverity {
  const label = advisory.database_specific?.severity;
  if (label !== undefined) return GHSA_SEVERITIES[label];
  let best = 0;
  for (const rating of advisory.severity) {
    if (rating.type !== "CVSS_V3") continue;
    const score = cvss3BaseScore(rating.score);
    if (score !== null && score > best) best = score;
  }
  if (best >= 9) return "critical";
  if (best >= 7) return "high";
  if (best >= 4) return "medium";
  if (best > 0) return "low";
  return "unknown";
}

// --- Findings ---------------------------------------------------------------------------------------------

const FindingSeveritySchema = z.enum(FINDING_SEVERITIES);
const FixedVersionsSchema = z.array(SemverSchema).max(EXPOSURE_LIMITS.eventsMax);

/** Why, until when and by which admin key a Finding is ignored. */
const FindingIgnoreSchema = z.object({
  reason: text(EXPOSURE_LIMITS.ignoreReasonMax).min(1),
  until: isoDateTime(),
  by: z.string().regex(ID_PATTERNS.key),
});

/**
 * One advisory matched by one component of one App Environment, from one source. A build Finding names its
 * Build; a runtime Finding none. An ignored Finding carries its ignore; an open, fixed or withdrawn one carries null.
 */
export const FindingSchema = z
  .object({
    id: z.string().regex(ID_PATTERNS.fnd),
    app_id: z.string().regex(ID_PATTERNS.app),
    environment: z.enum(ENVIRONMENTS),
    source: z.enum(FINDING_SOURCES),
    build_id: z.string().regex(ID_PATTERNS.bld).nullable(),
    package: ComponentNameSchema,
    version: SemverSchema,
    dev: z.boolean(),
    advisory_id: AdvisoryIdSchema,
    aliases: z.array(AdvisoryIdSchema).max(EXPOSURE_LIMITS.aliasesMax),
    summary: text(EXPOSURE_LIMITS.summaryMax),
    severity: FindingSeveritySchema,
    fixed_versions: FixedVersionsSchema,
    status: z.enum(FINDING_STATUSES),
    ignore: FindingIgnoreSchema.nullable(),
    first_seen: z.iso.datetime(),
    last_seen: z.iso.datetime(),
  })
  .refine((finding) => (finding.source === "build") === (finding.build_id !== null), {
    message: "A build Finding names its Build; a runtime Finding names none.",
    path: ["build_id"],
  })
  .refine((finding) => (finding.status === "ignored") === (finding.ignore !== null), {
    message: "An ignored Finding carries its ignore; any other carries null.",
    path: ["ignore"],
  });
export type Finding = z.infer<typeof FindingSchema>;

/** 200 of `GET /v1/findings`: newest first, at most `EXPOSURE_LIMITS.findingsListed`. */
export const ListFindingsResponseSchema = z.object({
  findings: z.array(FindingSchema).max(EXPOSURE_LIMITS.findingsListed),
});
export type ListFindingsResponse = z.infer<typeof ListFindingsResponseSchema>;

/** 200 of `GET /v1/findings/:findingId`: the Finding and its advisory (affected ranges, fixed versions). */
export const FindingDetailResponseSchema = z.object({ finding: FindingSchema, advisory: AdvisorySchema });
export type FindingDetailResponse = z.infer<typeof FindingDetailResponseSchema>;

/** 200 of `POST /v1/findings/:findingId/ignore` and `/reopen`. */
export const FindingResponseSchema = z.object({ finding: FindingSchema });
export type FindingResponse = z.infer<typeof FindingResponseSchema>;

/**
 * Body of `POST /v1/findings/:findingId/ignore`: a reason and an expiry. That the expiry lies in the future and
 * at most `EXPOSURE_LIMITS.ignoreDaysMax` days ahead is the API's check: it depends on the current time.
 */
export const IgnoreFindingRequestSchema = z.object({
  reason: trimmedText(EXPOSURE_LIMITS.ignoreReasonMax),
  until: isoDateTime(),
});
export type IgnoreFindingRequestInput = z.input<typeof IgnoreFindingRequestSchema>;
export type IgnoreFindingRequest = z.infer<typeof IgnoreFindingRequestSchema>;

const CountSchema = z.int().min(0);

/**
 * The open Findings of a registered Build, returned with its registration (`findings` of the 201): counts per
 * severity and at most `EXPOSURE_LIMITS.summaryItemsMax` items. The harden CLI's `--fail-on` gate reads it.
 */
export const FindingsSummarySchema = z.object({
  open: z.object({
    critical: CountSchema,
    high: CountSchema,
    medium: CountSchema,
    low: CountSchema,
    unknown: CountSchema,
  }),
  items: z
    .array(
      z.object({
        advisory: AdvisoryIdSchema,
        package: ComponentNameSchema,
        version: SemverSchema,
        severity: FindingSeveritySchema,
        fixed: FixedVersionsSchema,
      }),
    )
    .max(EXPOSURE_LIMITS.summaryItemsMax),
});
export type FindingsSummary = z.infer<typeof FindingsSummarySchema>;

// Documented examples, reused by the tests of every workspace. They are synthetic (no real package or
// advisory) and deeply frozen: build a variant by spreading, e.g. `{ ...EXAMPLE_FINDING, status: "fixed" }`.

/** Three components: a vulnerable runtime dependency, a scoped pre-release and a development dependency. */
export const EXAMPLE_INVENTORY: Inventory = deepFreeze({
  components: [
    { name: "example-parser", version: "1.2.3", dev: false },
    { name: "@example/ui", version: "4.0.0-rc.1", dev: false },
    { name: "example-test-runner", version: "9.1.0", dev: true },
  ],
});

/** A GHSA advisory rated HIGH for `example-parser` below 1.2.4, and from 2.0.0 below 2.1.1. */
export const EXAMPLE_ADVISORY: Advisory = deepFreeze({
  id: "GHSA-2c3m-4p5q-6r7v",
  aliases: ["CVE-2026-10001"],
  summary: "Denial of service in example-parser",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
  database_specific: { severity: "HIGH" },
  affected: [
    {
      package: { ecosystem: "npm", name: "example-parser" },
      ranges: [
        {
          type: "SEMVER",
          events: [{ introduced: "0" }, { fixed: "1.2.4" }, { introduced: "2.0.0" }, { fixed: "2.1.1" }],
        },
      ],
    },
  ],
  published: "2026-10-01T00:00:00Z",
  modified: "2026-10-02T00:00:00Z",
});

/** The open Finding `EXAMPLE_ADVISORY` makes of `EXAMPLE_INVENTORY`'s first component in `EXAMPLE_BUILD`. */
export const EXAMPLE_FINDING: Finding = deepFreeze({
  id: "fnd_0123456789abcdef01234567",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  source: "build",
  build_id: "bld_0123456789abcdef01234567",
  package: "example-parser",
  version: "1.2.3",
  dev: false,
  advisory_id: "GHSA-2c3m-4p5q-6r7v",
  aliases: ["CVE-2026-10001"],
  summary: "Denial of service in example-parser",
  severity: "high",
  fixed_versions: ["1.2.4", "2.1.1"],
  status: "open",
  ignore: null,
  first_seen: "2026-11-10T08:30:01.000Z",
  last_seen: "2026-11-10T08:30:01.000Z",
});

/** The findings summary of `EXAMPLE_BUILD`'s registration: `EXAMPLE_FINDING` alone. */
export const EXAMPLE_FINDINGS_SUMMARY: FindingsSummary = deepFreeze({
  open: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
  items: [
    {
      advisory: "GHSA-2c3m-4p5q-6r7v",
      package: "example-parser",
      version: "1.2.3",
      severity: "high",
      fixed: ["1.2.4", "2.1.1"],
    },
  ],
});
