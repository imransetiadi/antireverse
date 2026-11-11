// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ID_PATTERNS } from "./constants.ts";
import { deepFreeze, text } from "./shared.ts";

// The Canary and leak-scan contract. A Canary is a decoy planted in a Build that only an attacker would use:
// a decoy API key (`key`) or a decoy route on the customer's own origin (`route`). Its values derive from the
// build seed (`deriveCanaries` of the server entry), so the same input and seed reproduce the output. Decoy
// values are not secrets. The leak scan runs in the customer's CI; only its summary (status and suppressed
// count) travels in the Manifest, never a finding and never a value. Every object schema is a plain
// `z.object`, which strips unknown keys.

export const CANARY_KINDS = ["key", "route"] as const;
export type CanaryKind = (typeof CANARY_KINDS)[number];

/** Canaries planted per Build, by kind: one decoy key and two decoy routes. */
export const CANARY_PLAN = deepFreeze({ key: 1, route: 2 } as const satisfies Record<CanaryKind, number>);

export const CANARY_LIMITS = {
  /** Canaries a Manifest may carry. */
  perBuild: 10,
  /** Canaries a Policy Bundle may carry. */
  perBundle: 100,
  /** The most recent Builds of an App Environment whose Canaries go into its bundle. */
  buildsInBundle: 20,
} as const;

/** The last segment of a decoy route, chosen by the HMAC. */
export const CANARY_ROUTE_WORDS = deepFreeze(["export", "debug", "config", "backup", "sync"] as const);

/**
 * The value of each kind of Canary. A decoy key looks like the customer's own key and never carries a
 * third-party provider's prefix; a decoy route is a path on the customer's own origin. Only the record is
 * frozen: a frozen RegExp cannot be used (matching writes its `lastIndex`).
 */
export const CANARY_VALUE_PATTERNS = Object.freeze({
  key: /^ak_live_[0-9A-Za-z]{32}$/,
  route: /^\/api\/internal\/[0-9a-z]{8}\/(export|debug|config|backup|sync)$/,
} as const satisfies Record<CanaryKind, RegExp>);

const CanaryIdSchema = z.string().regex(ID_PATTERNS.cny);

/** One Canary: its identifier, its kind and its decoy value (which must match the pattern of its kind). */
export const CanarySchema = z.discriminatedUnion("kind", [
  z.object({ id: CanaryIdSchema, kind: z.literal("key"), value: z.string().regex(CANARY_VALUE_PATTERNS.key) }),
  z.object({ id: CanaryIdSchema, kind: z.literal("route"), value: z.string().regex(CANARY_VALUE_PATTERNS.route) }),
]);
export type Canary = z.infer<typeof CanarySchema>;

/**
 * A Canary as a Build response shows it: id and kind only. The decoy value goes to Shield in the signed
 * bundle and stays in the developer's local report; the API never returns it (plan 07 amendment A4).
 */
export const BuildCanarySummarySchema = z.object({ id: CanaryIdSchema, kind: z.enum(CANARY_KINDS) });
export type BuildCanarySummary = z.infer<typeof BuildCanarySummarySchema>;

/** The leak-scan rules, by stable id, each with the title a report shows. Deeply frozen. */
export const LEAK_RULES = deepFreeze([
  { id: "source-map", title: "Source map" },
  { id: "private-key", title: "Private key" },
  { id: "aws-access-key", title: "AWS access key" },
  { id: "github-token", title: "GitHub token" },
  { id: "stripe-secret", title: "Stripe secret key" },
  { id: "slack-token", title: "Slack token" },
  { id: "google-api-key", title: "Google API key" },
  { id: "secret-assignment", title: "Secret assigned to a secret-like name" },
  { id: "internal-url", title: "Internal URL" },
] as const satisfies readonly { id: string; title: string }[]);
export type LeakRule = (typeof LEAK_RULES)[number];
export type LeakRuleId = LeakRule["id"];

export const LEAK_LIMITS = {
  /** Entries of a leak allowlist. */
  allowMax: 1000,
  /** Characters of an allowlist entry's reason. */
  reasonMax: 200,
} as const;

/**
 * The outcome of a leak scan that let the harden continue: `clean` (nothing found) or `suppressed` (every
 * finding was allowlisted; at least one). A scan with an unsuppressed finding fails the harden and produces
 * no Manifest, so it has no status here.
 */
export const LeakScanSummarySchema = z
  .object({
    status: z.enum(["clean", "suppressed"]),
    suppressed: z.int().min(0),
  })
  .refine((summary) => (summary.status === "clean") === (summary.suppressed === 0), {
    message: "A clean scan suppressed nothing; a suppressed scan suppressed at least one finding.",
    path: ["suppressed"],
  });
export type LeakScanSummary = z.infer<typeof LeakScanSummarySchema>;

/** A finding's fingerprint: the first 32 hex characters of a SHA-256 (`leakFingerprint` of the server entry). */
const FingerprintSchema = z.string().regex(/^[0-9a-f]{32}$/);

/** The committed allowlist file (default `.antireverse/leak-allow.json`): reviewed findings, by fingerprint. */
export const LeakAllowlistSchema = z.object({
  version: z.literal(1),
  allow: z
    .array(z.object({ fingerprint: FingerprintSchema, reason: text(LEAK_LIMITS.reasonMax).min(1) }))
    .max(LEAK_LIMITS.allowMax),
});
export type LeakAllowlist = z.infer<typeof LeakAllowlistSchema>;

/** The Event signal id a Shield adds when a request uses a Canary: `canary.touched:<cny id>`. */
export const CANARY_SIGNAL_PREFIX = "canary.touched:";

const CANARY_SIGNAL = /^canary\.touched:(cny_[0-9a-f]{24})$/;

/** The signal id for a Canary. Throws a TypeError for anything but a Canary id. */
export function canarySignalId(id: string): string {
  if (typeof id !== "string" || !ID_PATTERNS.cny.test(id)) throw new TypeError("A Canary id is cny_<24 hex>.");
  return CANARY_SIGNAL_PREFIX + id;
}

/** The Canary id a signal id names exactly; null for any other signal or value. */
export function parseCanarySignal(signalId: unknown): string | null {
  if (typeof signalId !== "string") return null;
  return CANARY_SIGNAL.exec(signalId)?.[1] ?? null;
}

// Documented examples, reused by the tests of every workspace. They are synthetic and deeply frozen.

/** The Canaries of seed 1: `deriveCanaries(1)` of the server entry (the known-answer vector). */
export const EXAMPLE_CANARIES: readonly Canary[] = deepFreeze([
  { id: "cny_33d265fca16c848eb2f23f43", kind: "key", value: "ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE" },
  { id: "cny_4cb3bd4c9b67d9590fb16b6b", kind: "route", value: "/api/internal/un539n4s/backup" },
  { id: "cny_555fa5c968f7ce38bbcd6c3d", kind: "route", value: "/api/internal/60nekyby/backup" },
]);
