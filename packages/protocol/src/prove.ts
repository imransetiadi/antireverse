// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ID_PATTERNS } from "./constants.ts";
import { deepFreeze, isoDateTime, text } from "./shared.ts";

// The Prove contract (slice 14, D-069): Verified Targets, signed Rules of Engagement and the authorization
// check every future test must pass. An Organization proves it controls a host by a DNS TXT record or a
// well-known HTTPS file holding a random token; it then signs immutable Rules of Engagement versions (scope,
// excluded paths, intensity, a UTC window, contacts); `authorizeTest` is the pure reference of the check the
// API exposes and slice 15 must call before any traffic. Every object schema is a plain `z.object`, which
// strips unknown keys. The token generator and the content hash need node:crypto and live in prove-crypto.ts.

export const TARGET_LIMITS = deepFreeze({
  /** Characters of a host, without a trailing dot. */
  hostMax: 253,
  /** Characters of one host label. */
  labelMax: 63,
  /** Targets of one Organization. Enforced by the API. */
  targetsPerOrganization: 50,
  /**
   * Verification attempts of one host of an Organization per hour, kept across deleting and adding the host again.
   * Enforced by the API.
   */
  verifyAttemptsPerHour: 10,
  /** Verification attempts of one Organization per hour, all its hosts together. Enforced by the API. */
  verifyAttemptsPerOrganizationPerHour: 60,
  /** Seconds after which a verified target is checked again. */
  recheckIntervalS: 86_400,
  /** Total milliseconds of one file fetch. */
  fetchTimeoutMs: 5000,
  /** Bytes of the verification file read at most. */
  fetchBodyBytesMax: 1024,
  /** Characters of the reason a target lapsed. */
  lapsedReasonMax: 200,
  /**
   * Seconds between a target's last successful ownership check (`verified_at`) and the time of a test beyond
   * which `authorizeTest` no longer counts the target as verified: the 24-hour re-check plus 2 hours of slack.
   */
  authorizeFreshnessS: 93_600,
  /** Seconds a successful ownership check may lie after the time of a test (clock skew) and still count. */
  authorizeClockSkewS: 300,
} as const);

export const ROE_LIMITS = deepFreeze({
  /** Targets in the scope of one version. */
  scopeMax: 50,
  /** Excluded path prefixes of one version. */
  exclusionsMax: 50,
  /** Characters of one excluded path prefix. */
  exclusionMax: 256,
  /** Contact emails of one version. */
  contactsMax: 5,
  /** Characters of one contact email. */
  emailMax: 254,
  /** Characters of the path of an authorization request. */
  pathMax: 2048,
} as const);

/** pending → verified (method, at) → lapsed (reason, at) → verified again. Only verified counts. */
export const TARGET_STATUSES = ["pending", "verified", "lapsed"] as const;
export type TargetStatus = (typeof TARGET_STATUSES)[number];

/** How ownership was proven: the DNS TXT record (tried first) or the well-known file. */
export const VERIFICATION_METHODS = ["dns", "file"] as const;
export type VerificationMethod = (typeof VERIFICATION_METHODS)[number];

/** Why the DNS method failed. */
export const DNS_VERIFY_FAILURES = ["no_record", "mismatch", "lookup_failed"] as const;
export type DnsVerifyFailure = (typeof DNS_VERIFY_FAILURES)[number];

/**
 * Why the file method failed. `not_reachable`: the host did not resolve, or an address it resolves to is not public
 * (SSRF guard) — one reason for both, so that a response never tells which internal address check refused a host.
 */
export const FILE_VERIFY_FAILURES = [
  "not_reachable",
  "connect_failed",
  "tls_failed",
  "redirect",
  "status",
  "timeout",
  "too_large",
  "mismatch",
] as const;
export type FileVerifyFailure = (typeof FILE_VERIFY_FAILURES)[number];

// --- Host ------------------------------------------------------------------------------------------------

/** A host equal to or under one of these suffixes is never a target: it names a private or reserved space. */
export const PRIVATE_HOST_SUFFIXES = deepFreeze([
  "localhost",
  "local",
  "internal",
  "intranet",
  "lan",
  "home.arpa",
  "example",
  "invalid",
  "test",
  "onion",
  "example.com",
  "example.net",
  "example.org",
  // Review F4: names that resolve only inside corporate, home, container and cluster networks, and reverse DNS.
  "corp",
  "home",
  "svc",
  "cluster.local",
  "default",
  "localdomain",
  "arpa",
] as const);

// Longer input is refused before any other work (a host has at most 253 characters plus a dot).
const HOST_INPUT_MAX = 512;
// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point.
const CONTROL = /[\u0000-\u001f\u007f]/;
const HOST_CHARACTERS = /^[A-Za-z0-9.-]+$/;
const LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
// A last label a URL parser reads as a number (decimal, or hex with 0x, even empty) makes the name an IPv4
// address in the WHATWG URL standard ("ends in a number"): 127.1, 0x7f.1, 1.2.3.0x4. Octal (0177) is decimal digits.
const NUMERIC_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/;

/**
 * The host as stored: trimmed, ASCII lower case, one trailing dot removed; or null unless it is a DNS name of
 * 1–253 characters with at least two labels of 1–63 characters over `a-z 0-9 -`, not starting or ending with `-`
 * (punycode `xn--` labels are allowed; Unicode is refused, not converted). IP literals in any form (dotted,
 * shortened, decimal, hex, octal, IPv6) and names equal to or under `PRIVATE_HOST_SUFFIXES` are refused.
 */
export function normaliseHost(value: unknown): string | null {
  if (typeof value !== "string" || value.length > HOST_INPUT_MAX || CONTROL.test(value)) return null;
  let host = value.trim();
  if (!HOST_CHARACTERS.test(host)) return null;
  host = host.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.length === 0 || host.length > TARGET_LIMITS.hostMax) return null;
  const labels = host.split(".");
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (label.length > TARGET_LIMITS.labelMax || !LABEL.test(label)) return null;
  }
  if (NUMERIC_LABEL.test(labels[labels.length - 1] as string)) return null;
  for (const suffix of PRIVATE_HOST_SUFFIXES) {
    if (host === suffix || host.endsWith(`.${suffix}`)) return null;
  }
  return host;
}

const HOST_MESSAGE =
  "Must be a public DNS name such as shop.acme-shop.io: no IP address and no name under localhost, local, internal, intranet, lan, home.arpa, example, invalid, test, onion, example.com, example.net, example.org, corp, home, svc, cluster.local, default, localdomain or arpa.";

/** A host as a client sends it: normalised by `normaliseHost` (the parsed value is the stored form). */
export const HostSchema = z.string().transform((value, context) => {
  const host = normaliseHost(value);
  if (host === null) {
    context.addIssue({ code: "custom", message: HOST_MESSAGE });
    return z.NEVER;
  }
  return host;
});

/** A host as stored: already normalised. Anything else is refused, not rewritten. */
const StoredHostSchema = z.string().refine((value) => normaliseHost(value) === value, HOST_MESSAGE);

// --- Verification token and instructions -----------------------------------------------------------------

/** A verification token: 32 random bytes as 43 base64url characters (`generateVerificationToken`). */
export const VERIFICATION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The TXT record is published at `<CHALLENGE_RECORD_PREFIX>.<host>`. */
export const CHALLENGE_RECORD_PREFIX = "_airverse-challenge";
/** The TXT record's value is this prefix followed by the token. */
export const DNS_VALUE_PREFIX = "airverse-verification=";
/** The file is served at `https://<host><VERIFICATION_FILE_PATH>`; its content is the token. */
export const VERIFICATION_FILE_PATH = "/.well-known/airverse-verification.txt";

function storedHost(host: string): string {
  if (normaliseHost(host) !== host) throw new TypeError("A target host must be a normalised public DNS name.");
  return host;
}

function validToken(token: string): string {
  if (typeof token !== "string" || !VERIFICATION_TOKEN_PATTERN.test(token)) {
    throw new TypeError("A verification token is 43 base64url characters.");
  }
  return token;
}

/** `_airverse-challenge.<host>`. Throws a TypeError unless the host is normalised (`normaliseHost`). */
export function challengeRecordName(host: string): string {
  return `${CHALLENGE_RECORD_PREFIX}.${storedHost(host)}`;
}

/** `airverse-verification=<token>`. Throws a TypeError for a malformed token. */
export function dnsChallengeValue(token: string): string {
  return `${DNS_VALUE_PREFIX}${validToken(token)}`;
}

/** `https://<host>/.well-known/airverse-verification.txt`. Throws a TypeError unless the host is normalised. */
export function verificationFileUrl(host: string): string {
  return `https://${storedHost(host)}${VERIFICATION_FILE_PATH}`;
}

/** The two ways to prove ownership of a host, as the API returns them to an admin. */
export const TargetVerificationSchema = z.object({
  /** Name of the TXT record. */
  dns_name: z.string(),
  /** Value of the TXT record. */
  dns_value: z.string(),
  /** URL of the file. */
  file_url: z.string(),
  /** Exact content of the file (surrounding whitespace is ignored when checked). */
  file_content: z.string().regex(VERIFICATION_TOKEN_PATTERN),
});
export type TargetVerification = z.infer<typeof TargetVerificationSchema>;

/** The instructions for one host and token. Throws a TypeError for a host that is not normalised or a bad token. */
export function verificationInstructions(host: string, token: string): TargetVerification {
  return {
    dns_name: challengeRecordName(host),
    dns_value: dnsChallengeValue(token),
    file_url: verificationFileUrl(host),
    file_content: validToken(token),
  };
}

/**
 * Whether one of the TXT records (each a list of chunks, as `dns.resolveTxt` returns them; the chunks of one
 * record are joined) equals `airverse-verification=<token>` exactly. False for a malformed token or records.
 */
export function matchesDnsChallenge(records: readonly (readonly string[])[], token: string): boolean {
  if (typeof token !== "string" || !VERIFICATION_TOKEN_PATTERN.test(token) || !Array.isArray(records)) return false;
  const expected = `${DNS_VALUE_PREFIX}${token}`;
  return records.some(
    (record) =>
      Array.isArray(record) && record.every((chunk) => typeof chunk === "string") && record.join("") === expected,
  );
}

/** Whether the file body, surrounding whitespace removed, is exactly the token. False for a malformed token. */
export function matchesFileChallenge(body: string, token: string): boolean {
  if (typeof token !== "string" || !VERIFICATION_TOKEN_PATTERN.test(token) || typeof body !== "string") return false;
  return body.trim() === token;
}

// --- Targets ---------------------------------------------------------------------------------------------

/** One Verified Target of an Organization. The token is never part of it (see `TargetResponseSchema`). */
export const TargetSchema = z
  .object({
    id: z.string().regex(ID_PATTERNS.tgt),
    host: StoredHostSchema,
    status: z.enum(TARGET_STATUSES),
    /** The method of the last successful verification. */
    method: z.enum(VERIFICATION_METHODS).nullable(),
    /**
     * The time of the last successful ownership check, the first verification or any later re-check; `authorizeTest`
     * needs it at most `TARGET_LIMITS.authorizeFreshnessS` before the test and no more than
     * `TARGET_LIMITS.authorizeClockSkewS` after it.
     */
    verified_at: z.iso.datetime().nullable(),
    /** The time of the last check, successful or not. */
    last_checked_at: z.iso.datetime().nullable(),
    /** Why the last re-check failed; set only while lapsed. */
    lapsed_reason: text(TARGET_LIMITS.lapsedReasonMax).min(1).nullable(),
    created_at: z.iso.datetime(),
  })
  .refine(
    (target) =>
      target.status === "pending"
        ? target.method === null && target.verified_at === null && target.lapsed_reason === null
        : target.method !== null &&
          target.verified_at !== null &&
          (target.status === "lapsed") === (target.lapsed_reason !== null),
    {
      message:
        "A pending target has no method, verification time or lapse reason; a verified or lapsed one has a method and a verification time; only a lapsed one has a reason.",
      path: ["status"],
    },
  );
export type Target = z.infer<typeof TargetSchema>;

/** Body of `POST /v1/targets`. The host is normalised. */
export const CreateTargetRequestSchema = z.object({ host: HostSchema });
export type CreateTargetRequest = z.infer<typeof CreateTargetRequestSchema>;

/** 201 of `POST /v1/targets` and 200 of `GET /v1/targets/:id`: the target and how to verify it (admins only). */
export const TargetResponseSchema = z.object({ target: TargetSchema, verification: TargetVerificationSchema }).refine(
  ({ target, verification }) => {
    try {
      const expected = verificationInstructions(target.host, verification.file_content);
      return (
        verification.dns_name === expected.dns_name &&
        verification.dns_value === expected.dns_value &&
        verification.file_url === expected.file_url
      );
    } catch {
      // A malformed host or token is already an issue of its own field.
      return false;
    }
  },
  { message: "The instructions must be those of the target's host and token.", path: ["verification"] },
);
export type TargetResponse = z.infer<typeof TargetResponseSchema>;

/** 200 of `GET /v1/targets`. */
export const ListTargetsResponseSchema = z.object({
  targets: z.array(TargetSchema).max(TARGET_LIMITS.targetsPerOrganization),
});
export type ListTargetsResponse = z.infer<typeof ListTargetsResponseSchema>;

/** The outcome of one verification: the method that passed, or why each method failed. */
export const VerifyResultSchema = z.discriminatedUnion("verified", [
  z.object({ verified: z.literal(true), method: z.enum(VERIFICATION_METHODS), checked_at: z.iso.datetime() }),
  z.object({
    verified: z.literal(false),
    dns: z.enum(DNS_VERIFY_FAILURES),
    file: z.enum(FILE_VERIFY_FAILURES),
    checked_at: z.iso.datetime(),
  }),
]);
export type VerifyResult = z.infer<typeof VerifyResultSchema>;

/** 200 of `POST /v1/targets/:id/verify`: the target after the check and the check's outcome. */
export const VerifyTargetResponseSchema = z.object({ target: TargetSchema, result: VerifyResultSchema });
export type VerifyTargetResponse = z.infer<typeof VerifyTargetResponseSchema>;

// --- Rules of Engagement ---------------------------------------------------------------------------------

/** How hard a test may be, weakest first: the order is `intensityRank`. */
export const INTENSITIES = ["passive", "safe-active", "full"] as const;
export type Intensity = (typeof INTENSITIES)[number];

/** 0 for passive, 1 for safe-active, 2 for full. Throws a TypeError for anything else. */
export function intensityRank(intensity: Intensity): number {
  const rank = INTENSITIES.indexOf(intensity);
  if (rank === -1) throw new TypeError(`An intensity is one of ${INTENSITIES.join(", ")}.`);
  return rank;
}

/** UTC days of the week, Monday first. */
export const WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
export type Weekday = (typeof WEEKDAYS)[number];

const TIME_OF_DAY = /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/;
const END_OF_DAY = "24:00";
const SHA256_HEX = /^[0-9a-f]{64}$/;
const KeyIdSchema = z.string().regex(ID_PATTERNS.key);
const distinct = (values: readonly unknown[]): boolean => new Set(values).size === values.length;

/**
 * When tests may run, in UTC: `from` inclusive to `to` exclusive (`HH:MM`; `from` 00:00–23:59, `to` 00:00–24:00)
 * on each listed day. `to` 24:00 is the end of the day, so 00:00–24:00 is the whole listed day. `to` before `from`
 * crosses midnight: the hours after midnight belong to the listed day the window began on. `to` equal to `from`
 * is refused.
 */
export const RoeWindowSchema = z
  .object({
    days: z.array(z.enum(WEEKDAYS)).min(1).max(WEEKDAYS.length).refine(distinct, "Each day may be listed once."),
    from: z.string().regex(TIME_OF_DAY, "Must be HH:MM, 00:00 to 23:59."),
    to: z.string().refine((value) => value === END_OF_DAY || TIME_OF_DAY.test(value), "Must be HH:MM, 00:00 to 24:00."),
  })
  .refine((window) => window.from !== window.to, {
    message: "The window must not be empty: `to` differs from `from`.",
    path: ["to"],
  });
export type RoeWindow = z.infer<typeof RoeWindowSchema>;

/**
 * An excluded path prefix: starts with `/`, at most 256 characters, already normalised (`normaliseTestPath`
 * leaves it unchanged: no dot segment, percent-encoding, query or fragment) and without a trailing `/` unless
 * it is `/` itself, which excludes every path.
 */
const ExclusionSchema = text(ROE_LIMITS.exclusionMax)
  .regex(/^\//, "Must start with /.")
  .refine(
    (value) => normaliseTestPath(value) === value && (value === "/" || !value.endsWith("/")),
    "Must be a normalised path prefix without a trailing /, such as /admin.",
  );

/** What an admin signs: the five content fields that `rulesOfEngagementSha256` hashes. */
export const RulesOfEngagementContentSchema = z.object({
  /** Targets of the Organization, each verified at signing (the API's check). */
  scope: z
    .array(z.string().regex(ID_PATTERNS.tgt))
    .min(1)
    .max(ROE_LIMITS.scopeMax)
    .refine(distinct, "Each target may be listed once."),
  /** Path prefixes never tested; a path is excluded when it equals one or starts with it followed by `/`. */
  exclusions: z
    .array(ExclusionSchema)
    .max(ROE_LIMITS.exclusionsMax)
    .refine(distinct, "Each prefix may be listed once."),
  intensity: z.enum(INTENSITIES),
  window: RoeWindowSchema,
  contacts: z
    .array(z.email().max(ROE_LIMITS.emailMax))
    .min(1)
    .max(ROE_LIMITS.contactsMax)
    .refine(distinct, "Each contact may be listed once."),
});
export type RulesOfEngagementContent = z.infer<typeof RulesOfEngagementContentSchema>;

/** The exact phrase an admin types to sign: `I authorise <intensity> testing`. */
export function confirmationPhrase(intensity: Intensity): string {
  if (!INTENSITIES.includes(intensity)) throw new TypeError(`An intensity is one of ${INTENSITIES.join(", ")}.`);
  return `I authorise ${intensity} testing`;
}

/** Body of `POST /v1/rules-of-engagement`: the content and `confirm`, exactly `confirmationPhrase(intensity)`. */
export const SignRulesOfEngagementRequestSchema = RulesOfEngagementContentSchema.extend({
  confirm: z.string(),
}).refine(
  (request) => INTENSITIES.includes(request.intensity) && request.confirm === confirmationPhrase(request.intensity),
  {
    message: "Type the exact phrase: I authorise <intensity> testing.",
    path: ["confirm"],
  },
);
export type SignRulesOfEngagementRequest = z.infer<typeof SignRulesOfEngagementRequestSchema>;

/** One signed, immutable version. The newest is current. */
export const RulesOfEngagementVersionSchema = RulesOfEngagementContentSchema.extend({
  id: z.string().regex(ID_PATTERNS.roe),
  /** The id of the admin key that signed. */
  signed_by: KeyIdSchema,
  signed_at: z.iso.datetime(),
  /** SHA-256 hex of the canonical JSON of the content (`rulesOfEngagementSha256` of the server entry). */
  content_sha256: z.string().regex(SHA256_HEX),
});
export type RulesOfEngagementVersion = z.infer<typeof RulesOfEngagementVersionSchema>;

/** 201 of `POST /v1/rules-of-engagement`: the version signed. */
export const RulesOfEngagementResponseSchema = z.object({ version: RulesOfEngagementVersionSchema });
export type RulesOfEngagementResponse = z.infer<typeof RulesOfEngagementResponseSchema>;

/** 200 of `GET /v1/rules-of-engagement`: every version, newest first. */
export const ListRulesOfEngagementResponseSchema = z.object({ versions: z.array(RulesOfEngagementVersionSchema) });
export type ListRulesOfEngagementResponse = z.infer<typeof ListRulesOfEngagementResponseSchema>;

/** 200 of `GET /v1/rules-of-engagement/current`: the newest version, or null before the first is signed. */
export const CurrentRulesOfEngagementResponseSchema = z.object({ version: RulesOfEngagementVersionSchema.nullable() });
export type CurrentRulesOfEngagementResponse = z.infer<typeof CurrentRulesOfEngagementResponseSchema>;

/**
 * Canonical JSON: object keys sorted by UTF-16 code unit at every depth, arrays in order, no whitespace,
 * strings and numbers as `JSON.stringify` writes them. Only null, booleans, finite numbers, strings, arrays
 * and plain objects are accepted; anything else (undefined, NaN, a Date, a function, a bigint) throws a TypeError.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("Canonical JSON has finite numbers only.");
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError("Canonical JSON has plain objects only.");
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
    }
    default:
      throw new TypeError(`Canonical JSON cannot hold a value of type ${typeof value}.`);
  }
}

// --- Authorization ---------------------------------------------------------------------------------------

/** Why a test is refused, in the order the rules are checked; `authorizeTest` returns the first that fails. */
export const AUTHORIZE_REASONS = [
  "target_unknown",
  "target_not_verified",
  "no_rules_of_engagement",
  "out_of_scope",
  "path_excluded",
  "intensity_exceeds",
  "outside_window",
] as const;
export type AuthorizeReason = (typeof AUTHORIZE_REASONS)[number];

/** Body of `POST /v1/prove/authorize` (a dry check; nothing is started). The host is normalised. */
export const AuthorizeRequestSchema = z.object({
  host: HostSchema,
  /** The request path, starting with `/`; normalised before the exclusion test. */
  path: text(ROE_LIMITS.pathMax).regex(/^\//, "Must start with /."),
  intensity: z.enum(INTENSITIES),
  /** When the test would run. */
  at: isoDateTime(),
});
export type AuthorizeRequest = z.infer<typeof AuthorizeRequestSchema>;

/** 200 of `POST /v1/prove/authorize`, and what the API's `authorize` returns. */
export const AuthorizeResultSchema = z.discriminatedUnion("allowed", [
  z.object({ allowed: z.literal(true), roe_id: z.string().regex(ID_PATTERNS.roe) }),
  z.object({ allowed: z.literal(false), reason: z.enum(AUTHORIZE_REASONS) }),
]);
export type AuthorizeResult = z.infer<typeof AuthorizeResultSchema>;

/** What `authorizeTest` reads: the Organization's targets and its current signed version, if any. */
export interface AuthorizeState {
  /** `verified_at` is the last successful ownership check; it must be at most 26 hours before the test (5 minutes after it allowed for clock skew). */
  readonly targets: readonly Pick<Target, "id" | "host" | "status" | "verified_at">[];
  readonly current: Pick<RulesOfEngagementVersion, "id" | "scope" | "exclusions" | "intensity" | "window"> | null;
}

const PERCENT_RUN = /(?:%[0-9A-Fa-f]{2})+/g;
const UTF8 = new TextDecoder("utf-8");

function percentDecodeOnce(value: string): string {
  return value.replace(PERCENT_RUN, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] = Number.parseInt(run.slice(index * 3 + 1, index * 3 + 3), 16);
    }
    return UTF8.decode(bytes);
  });
}

/**
 * The path an exclusion is tested against: the query and fragment dropped, percent-decoding applied exactly once
 * (so `%2e%2e` is `..` and `%2f` a separator, but `%252e` stays `%2e`; invalid UTF-8 becomes U+FFFD), then the
 * dot segments removed as RFC 3986 section 5.2.4 does (`..` never climbs above `/`). Case is kept.
 */
export function normaliseTestPath(path: string): string {
  let rest = String(path);
  const end = rest.search(/[?#]/);
  if (end !== -1) rest = rest.slice(0, end);
  rest = percentDecodeOnce(rest);
  if (!rest.startsWith("/")) rest = `/${rest}`;
  const segments = rest.split("/").slice(1);
  const output: string[] = [];
  segments.forEach((segment, index) => {
    const last = index === segments.length - 1;
    if (segment === "." || segment === "..") {
      if (segment === "..") output.pop();
      if (last) output.push("");
      return;
    }
    output.push(segment);
  });
  return `/${output.join("/")}`;
}

/** Percent-decoding passes `exclusionMatchPath` applies at most. */
const EXCLUSION_DECODE_PASSES = 5;
const UPPER_ASCII = /[A-Z]/g;
// Control and format characters (zero-width spaces and joiners, U+2060, the BOM, soft hyphen, bidi marks): removed.
const INVISIBLE = /[\p{Cc}\p{Cf}]/gu;
// After folding, a replacement character (undecodable bytes) or a non-ASCII letter or mark means a server might read
// the path as something else: the path then counts as excluded whenever there is any exclusion.
const UNSETTLED = /\uFFFD|(?=\P{ASCII})[\p{L}\p{M}]/u;
const IIS_UNICODE = /%u([0-9A-Fa-f]{4})/g;

/** One decoding pass of an exclusion match: `%uXXXX` (IIS) and `%XX` (UTF-8), once each. */
function decodeForExclusion(value: string): string {
  return percentDecodeOnce(
    value.replace(IIS_UNICODE, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16))),
  );
}

// One segment as a lenient server may read it: `;params` and `:stream` suffixes dropped, trailing dots and spaces
// removed (Windows), a segment of dots and spaces only read as a dot segment.
function canonicalSegment(segment: string): string {
  let rest = segment;
  const semicolon = rest.indexOf(";");
  if (semicolon !== -1) rest = rest.slice(0, semicolon);
  const colon = rest.indexOf(":");
  if (colon !== -1) rest = rest.slice(0, colon);
  if (rest === "." || rest === "..") return rest;
  if (rest !== "" && /^[. ]+$/.test(rest)) return rest.includes("..") ? ".." : ".";
  return rest.replace(/[. ]+$/, "");
}

// One conservative canonicalisation step: cut at a NUL, Unicode NFKC, control and format characters removed, `\`
// as `/`, repeated slashes collapsed, each segment folded (`canonicalSegment`), dot segments resolved, ASCII lower
// case.
function canonicalSegments(value: string): string {
  let rest = value;
  const nul = rest.indexOf("\u0000");
  if (nul !== -1) rest = rest.slice(0, nul);
  rest = rest.normalize("NFKC").replace(INVISIBLE, "");
  rest = rest.replace(/\\/g, "/");
  if (!rest.startsWith("/")) rest = `/${rest}`;
  rest = rest.replace(/\/{2,}/g, "/");
  const segments = rest.split("/").slice(1).map(canonicalSegment);
  const output: string[] = [];
  segments.forEach((segment, index) => {
    const last = index === segments.length - 1;
    if (segment === "." || segment === "..") {
      if (segment === "..") output.pop();
      if (last) output.push("");
      return;
    }
    output.push(segment);
  });
  return `/${output.join("/")}`.replace(/\/{2,}/g, "/").replace(UPPER_ASCII, (letter) => letter.toLowerCase());
}

/**
 * The conservative form an exclusion is matched in, so that any spelling a server might read as an excluded
 * path counts as excluded: the query and fragment dropped, then repeatedly cut at a NUL, Unicode NFKC, control and
 * zero-width characters removed, `\` read as `/`, repeated slashes collapsed, `;params` and `:stream` suffixes and
 * trailing dots and spaces dropped from each segment, dot segments resolved and ASCII case folded, with one decoding
 * pass (`%uXXXX`, then `%XX`) between rounds until nothing changes. Null when it still changes after 5 decoding
 * passes, or when the result still holds U+FFFD or a non-ASCII letter (`isPathExcluded` then counts the path as
 * excluded).
 */
export function exclusionMatchPath(path: string): string | null {
  let rest = String(path);
  const end = rest.search(/[?#]/);
  if (end !== -1) rest = rest.slice(0, end);
  let current = canonicalSegments(rest);
  for (let pass = 0; pass < EXCLUSION_DECODE_PASSES; pass++) {
    const next = canonicalSegments(decodeForExclusion(current));
    if (next === current) return UNSETTLED.test(current) ? null : current;
    current = next;
  }
  return null;
}

/**
 * Whether the path is excluded, conservatively: in its `exclusionMatchPath` form it equals an excluded prefix
 * (in the same form) or starts with it followed by `/`; `/` excludes every path. A path whose form does not
 * settle is excluded whenever there is any exclusion.
 */
export function isPathExcluded(path: string, exclusions: readonly string[]): boolean {
  if (exclusions.length === 0) return false;
  const subject = exclusionMatchPath(path);
  if (subject === null) return true;
  return exclusions.some((exclusion) => {
    let prefix = exclusionMatchPath(exclusion);
    if (prefix === null || prefix === "/") return true;
    if (prefix.endsWith("/")) prefix = prefix.slice(0, -1);
    return subject === prefix || subject.startsWith(`${prefix}/`);
  });
}

const minutesOf = (time: string): number => Number(time.slice(0, 2)) * 60 + Number(time.slice(3, 5));

/** Whether the time (ISO text or a Date) falls inside the UTC window (see `RoeWindowSchema`). False if unparseable. */
export function isInsideWindow(window: RoeWindow, at: string | Date): boolean {
  const time = at instanceof Date ? at.getTime() : Date.parse(at);
  if (!Number.isFinite(time)) return false;
  const date = new Date(time);
  const dayIndex = (date.getUTCDay() + 6) % 7;
  const minute = date.getUTCHours() * 60 + date.getUTCMinutes();
  const from = minutesOf(window.from);
  const to = minutesOf(window.to);
  const listed = (index: number): boolean => window.days.includes(WEEKDAYS[(index + 7) % 7] as Weekday);
  if (from < to) return listed(dayIndex) && minute >= from && minute < to;
  if (from > to) return (listed(dayIndex) && minute >= from) || (listed(dayIndex - 1) && minute < to);
  return false;
}

const refuse = (reason: AuthorizeReason): AuthorizeResult => ({ allowed: false, reason });

// Whether the last successful ownership check happened before the test (up to `authorizeClockSkewS` after it
// counts, for clock skew) and at most `authorizeFreshnessS` before it.
// False when either time is missing or unparseable.
function recentlyVerified(verifiedAt: string | null, at: string): boolean {
  if (typeof verifiedAt !== "string") return false;
  const verified = Date.parse(verifiedAt);
  const time = Date.parse(at);
  if (!Number.isFinite(verified) || !Number.isFinite(time)) return false;
  return (
    verified <= time + TARGET_LIMITS.authorizeClockSkewS * 1000 &&
    time - verified <= TARGET_LIMITS.authorizeFreshnessS * 1000
  );
}

/** Options of `authorizeTest`. */
export interface AuthorizeTestOptions {
  /**
   * The time freshness is judged at: the API passes its own clock, so that a caller-supplied `at` in the past can
   * never make a stale target count as verified (review F6). Default: the request's `at`.
   */
  readonly freshAt?: string;
}

/**
 * The reference authorization check, pure: allowed only when the host (normalised) is a target of the
 * Organization, verified with a successful ownership check at most 26 hours before `freshAt` (default `at`; 5
 * minutes of skew allowed), in the scope of the current signed version, the path not excluded, the intensity at most
 * the signed one and `at` inside the window. Otherwise the first failing reason of `AUTHORIZE_REASONS`.
 */
export function authorizeTest(
  state: AuthorizeState,
  request: AuthorizeRequest,
  options: AuthorizeTestOptions = {},
): AuthorizeResult {
  const host = normaliseHost(request.host);
  const target = host === null ? undefined : state.targets.find((candidate) => candidate.host === host);
  if (target === undefined) return refuse("target_unknown");
  if (target.status !== "verified" || !recentlyVerified(target.verified_at, options.freshAt ?? request.at)) {
    return refuse("target_not_verified");
  }
  const current = state.current;
  if (current === null) return refuse("no_rules_of_engagement");
  if (!current.scope.includes(target.id)) return refuse("out_of_scope");
  if (isPathExcluded(request.path, current.exclusions)) return refuse("path_excluded");
  const requested = INTENSITIES.indexOf(request.intensity);
  if (requested === -1 || requested > INTENSITIES.indexOf(current.intensity)) return refuse("intensity_exceeds");
  if (!isInsideWindow(current.window, request.at)) return refuse("outside_window");
  return { allowed: true, roe_id: current.id };
}

// Documented examples, reused by the tests of every workspace. They are synthetic and deeply frozen.

/** A target verified through DNS. */
export const EXAMPLE_TARGET: Target = deepFreeze({
  id: "tgt_0123456789abcdef01234567",
  host: "shop.acme-shop.io",
  status: "verified",
  method: "dns",
  verified_at: "2026-11-12T08:05:00.000Z",
  last_checked_at: "2026-11-12T08:05:00.000Z",
  lapsed_reason: null,
  created_at: "2026-11-12T08:00:00.000Z",
});

/** A signed version covering `EXAMPLE_TARGET` on weekdays 09:00–17:00 UTC; the hash is that of its content. */
export const EXAMPLE_RULES_OF_ENGAGEMENT: RulesOfEngagementVersion = deepFreeze({
  id: "roe_0123456789abcdef01234567",
  scope: ["tgt_0123456789abcdef01234567"],
  exclusions: ["/admin", "/checkout"],
  intensity: "safe-active",
  window: { days: ["mon", "tue", "wed", "thu", "fri"], from: "09:00", to: "17:00" },
  contacts: ["security@example.com"],
  signed_by: "key_0123456789abcdef01234567",
  signed_at: "2026-11-12T08:10:00.000Z",
  content_sha256: "fb90b621f043ffa777aa343210f540b709b08ab7046c7efb4723947bee5d0135",
});
