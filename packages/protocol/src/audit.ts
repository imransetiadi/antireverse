// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ID_PATTERNS } from "./constants.ts";
import { deepFreeze, isoDateTime, nameText, text } from "./shared.ts";

// The audit log (slice 18a, FR-CON-06, SECURITY O6 / SC-LOG-01): one entry per administrative change, written by the
// API in the change's own transaction, hash-chained per Organization. `hash = sha256(prev_hash ‖ canonicalJson(entry
// without hash))` (`auditHash` of the server entry); the first entry's `prev_hash` is `AUDIT_GENESIS_HASH`; `seq` runs
// from 1 per Organization without gaps. A summary never holds a key, a token, a secret, an email address or a Canary
// value: it names identifiers and counts.

/**
 * Every action an entry can name, `<resource>.<verb>`: a closed list. Each mutating administrative route maps to one
 * (the API's route-table test enforces it).
 */
export const AUDIT_ACTIONS = deepFreeze([
  "organization.create",
  "app.create",
  "build.register",
  "assessment.create",
  "finding.ignore",
  "finding.reopen",
  "policy.publish",
  "policy.rule.promote",
  "policy.rollback",
  "patch.promote",
  "patch.demote",
  "incident.acknowledge",
  "incident.resolve",
  "containment.create",
  "containment.lift",
  "allowlist_entry.create",
  "allowlist_entry.delete",
  "alert_channel.create",
  "alert_channel.delete",
  "alert_channel.test",
  "alert_recipient.resend",
  "target.create",
  "target.delete",
  "target.verify",
  "rules_of_engagement.sign",
] as const);
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

/** What an entry's target is. */
export const AUDIT_TARGET_KINDS = deepFreeze([
  "organization",
  "app",
  "build",
  "assessment",
  "finding",
  "policy",
  "patch",
  "incident",
  "containment",
  "allowlist_entry",
  "alert_channel",
  "alert_recipient",
  "target",
  "rules_of_engagement",
] as const);
export type AuditTargetKind = (typeof AUDIT_TARGET_KINDS)[number];

export const AUDIT_LIMITS = {
  /** Characters of a reason, after trimming. */
  reasonMax: 500,
  /** Characters of a summary. */
  summaryMax: 500,
  /** Characters of a target id (a policy's is `<app id>/<environment>`). */
  targetIdMax: 128,
  /** Entries of a list page without `limit`. */
  listDefault: 50,
  /** Largest `limit` of a list page. */
  listMax: 200,
} as const;

/**
 * The request header that carries the reason of a change. Optional on every mutating route, required on some.
 *
 * Its value is the reason as percent-encoded UTF-8 (`encodeAuditReason`), so that any script fits in a header. The API
 * decodes it strictly: a `%` not followed by two hex digits, or bytes that are not valid UTF-8, is a 400. The 1–500
 * character limit and the refusal of control characters apply to the decoded text, which is what the entry stores.
 * Plain ASCII without `%` is its own encoding and needs no change; a literal `%` must be sent as `%25` (an unescaped
 * one is refused, never guessed at). `+` is a plus, not a space. A raw header character outside printable ASCII
 * (0x20–0x7E) is a 400 before decoding. The decoded text must pass `AuditReasonSchema`, and a reason holding anything
 * shaped like a key, a token, a secret or an email address is a 400: it is stored as given, never rewritten.
 */
export const AUDIT_REASON_HEADER = "X-Airverse-Reason";

/**
 * Why a reason header was refused: the `code` member of the 400 `validation` problem (the error's `path` is
 * `headers.x-airverse-reason`). A client acts on the code, never on the message text.
 * - `reason-not-ascii`: a raw header character outside printable ASCII (0x20–0x7E); percent-encode it.
 * - `reason-bad-encoding`: a `%` that does not start a two-hex-digit escape, or bytes that are not UTF-8.
 * - `reason-empty`: nothing left after decoding and trimming.
 * - `reason-too-long`: more than 500 characters after decoding and trimming.
 * - `reason-unsafe-characters`: a character `AuditReasonSchema` refuses (controls, separators, bidi, zero-width).
 * - `reason-holds-secret`: anything shaped like a key, a token, a secret or an email address (`holdsSecretShape`).
 */
export const AUDIT_REASON_ERROR_CODES = deepFreeze([
  "reason-not-ascii",
  "reason-bad-encoding",
  "reason-empty",
  "reason-too-long",
  "reason-unsafe-characters",
  "reason-holds-secret",
] as const);
export type AuditReasonErrorCode = (typeof AUDIT_REASON_ERROR_CODES)[number];

/**
 * Shapes of what must never reach an audit entry: admin and Shield keys and webhook signing secrets (`aro_`, `ark_`,
 * `whsec_` and 8 or more characters), Canary keys (`ak_live_` and 8 or more) and routes, beacon tokens (`bcn_` and 24
 * hex), any run of 43 or more base64url characters (the secret part of a key, a verification or a confirmation
 * token), and email addresses. A prefix counts wherever no letter or digit precedes it, so `k_aro_…` counts too.
 */
// Not deep-frozen: a frozen global RegExp cannot reset its lastIndex, which `replace` does.
const SECRET_SHAPES: ReadonlyArray<readonly [RegExp, string]> = Object.freeze([
  [/(?<![A-Za-z0-9])(?:aro|ark|whsec)_[A-Za-z0-9_-]{8,}/g, "[key]"],
  [/(?<![A-Za-z0-9])ak_live_[0-9A-Za-z]{8,}/g, "[key]"],
  [/(?<![A-Za-z0-9])bcn_[0-9a-f]{24}/g, "[token]"],
  [/\/api\/internal\/[0-9a-z]{8}\/(?:export|debug|config|backup|sync)/g, "[canary]"],
  [/[A-Za-z0-9_-]{43,}/g, "[token]"],
  [/[^\s"'<>()[\]]+@[^\s"'<>()[\]]+/g, "[email]"],
] as const);

/**
 * True when `text` holds anything shaped like a key, a token, a secret or an email address (see `SECRET_SHAPES`):
 * the API refuses such a reason (`reason-holds-secret`); a client can check before sending.
 */
export function holdsSecretShape(text: string): boolean {
  return SECRET_SHAPES.some(([pattern]) => new RegExp(pattern.source).test(text));
}

/** `text` with every secret shape replaced by `[key]`, `[token]`, `[canary]` or `[email]`: how summaries are kept. */
export function scrubSecretShapes(text: string): string {
  let scrubbed = text;
  for (const [pattern, replacement] of SECRET_SHAPES) scrubbed = scrubbed.replace(pattern, replacement);
  return scrubbed;
}

/**
 * A reason as the value of `AUDIT_REASON_HEADER`: percent-encoded UTF-8 (`encodeURIComponent`), only printable ASCII.
 * Throws a TypeError for text with a lone surrogate, which has no UTF-8 form.
 */
export function encodeAuditReason(text: string): string {
  try {
    return encodeURIComponent(text);
  } catch {
    throw new TypeError("A reason must not contain a lone surrogate.");
  }
}

/** The `prev_hash` of an Organization's first entry. */
export const AUDIT_GENESIS_HASH = "0".repeat(64);

/** Media type of `GET /v1/audit/export`: one entry per line, oldest first. */
export const AUDIT_EXPORT_CONTENT_TYPE = "application/x-ndjson";

const HashSchema = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * A reason after decoding the header (`AUDIT_REASON_HEADER`): trimmed, then 1..500 characters, none of the characters
 * refused in a name (C0 and C1 controls, line and paragraph separators, bidi embeddings, overrides and isolates,
 * zero-width space, BOM, lone surrogates). The API also refuses a reason holding anything shaped like a key, a token,
 * a secret or an email address.
 */
export const AuditReasonSchema = nameText(AUDIT_LIMITS.reasonMax);

/** One audit entry. Optional members are absent, never null: the hash covers exactly the members present. */
export const AuditEntrySchema = z.object({
  id: z.string().regex(ID_PATTERNS.aud),
  organization_id: z.string().regex(ID_PATTERNS.org),
  seq: z.int().min(1).max(Number.MAX_SAFE_INTEGER),
  at: isoDateTime(),
  /** Who acted: the admin key (there are no user accounts yet). */
  actor: z.object({ kind: z.literal("admin_key"), key_id: z.string().regex(ID_PATTERNS.key) }),
  action: z.enum(AUDIT_ACTIONS),
  app_id: z.string().regex(ID_PATTERNS.app).optional(),
  target: z.object({ kind: z.enum(AUDIT_TARGET_KINDS), id: text(AUDIT_LIMITS.targetIdMax).min(1) }),
  reason: text(AUDIT_LIMITS.reasonMax).min(1).optional(),
  summary: text(AUDIT_LIMITS.summaryMax).min(1),
  /** The id of the request that made the change (its `X-Request-Id` response header). */
  request_id: z.uuid(),
  prev_hash: HashSchema,
  hash: HashSchema,
});
export type AuditEntry = z.infer<typeof AuditEntrySchema>;

/**
 * One entry line of the NDJSON export (every line after the first, `AuditExportHeadLineSchema`): an entry with its
 * hashes, so that anyone can recompute the chain. Strict: a line with other members (the head line) is not an entry.
 */
export const AuditExportLineSchema = AuditEntrySchema.strict();

const listLimit = z
  .string()
  .regex(/^[0-9]{1,9}$/, `Expected an integer from 1 to ${AUDIT_LIMITS.listMax}.`)
  .transform(Number)
  .pipe(z.int().min(1).max(AUDIT_LIMITS.listMax));

/**
 * Query of `GET /v1/audit`, newest first. Every filter optional: `from` inclusive, `to` exclusive; `cursor` is the
 * `next_cursor` of the previous page (entries with a lower `seq`).
 */
export const AuditQuerySchema = z.object({
  action: z.enum(AUDIT_ACTIONS).optional(),
  app_id: z.string().regex(ID_PATTERNS.app, "Expected an App id.").optional(),
  target_id: text(AUDIT_LIMITS.targetIdMax).min(1).optional(),
  from: isoDateTime().optional(),
  to: isoDateTime().optional(),
  cursor: z
    .string()
    .regex(/^[1-9][0-9]{0,15}$/, "Expected the next_cursor of a previous page.")
    .transform(Number)
    .optional(),
  limit: listLimit.default(AUDIT_LIMITS.listDefault),
});
export type AuditQuery = z.infer<typeof AuditQuerySchema>;

export const ListAuditResponseSchema = z.object({
  entries: z.array(AuditEntrySchema),
  /** Pass as `cursor` for the next page; null on the last page. */
  next_cursor: z.string().nullable(),
});
export type ListAuditResponse = z.infer<typeof ListAuditResponseSchema>;

/**
 * The meaning of `first_broken_seq` in `GET /v1/audit/verify`: the first seq at which the chain no longer holds; the
 * entry before it may be the altered one. (Re-hashing an altered entry makes it hold again by itself, so the break
 * shows at the next entry, whose `prev_hash` no longer matches.)
 */
export const AUDIT_VERIFY_DOC =
  "valid is true when every entry from seq 1 to the head holds. first_broken_seq is the first seq at which the chain no longer holds; the entry before it may be the altered one. null when valid.";

/**
 * The chain head of an Organization as the API states it: its last `seq` (0 before any entry), that entry's `hash`
 * (`AUDIT_GENESIS_HASH` before any), and when it was read.
 */
export const AuditHeadSchema = z.object({
  organization_id: z.string().regex(ID_PATTERNS.org),
  seq: z.int().min(0).max(Number.MAX_SAFE_INTEGER),
  hash: HashSchema,
  at: isoDateTime(),
});
export type AuditHead = z.infer<typeof AuditHeadSchema>;

/**
 * The head signed with the API's audit key (Ed25519; never the Policy key): `signature` is over the UTF-8 bytes of
 * `canonicalJson(head)`, 64 bytes as 86 base64url characters; `key_id` names the key (`GET /v1/audit/public-key`).
 * A verifier that keeps a signed head can later tell a truncated or rewritten chain: the chain must still hold the
 * entry with that `seq` and `hash`.
 */
export const SignedAuditHeadSchema = z.object({
  head: AuditHeadSchema,
  key_id: z.string().regex(/^[0-9a-f]{16}$/),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
});
export type SignedAuditHead = z.infer<typeof SignedAuditHeadSchema>;

/** The first line of the NDJSON export: the signed head the export runs up to. Entry lines carry no `type`. */
export const AuditExportHeadLineSchema = SignedAuditHeadSchema.extend({ type: z.literal("audit_head") });
export type AuditExportHeadLine = z.infer<typeof AuditExportHeadLineSchema>;

/** `GET /v1/audit/public-key`: the public half of the audit key. Public, like the Policy signing key. */
export const AuditPublicKeyResponseSchema = z.object({
  key_id: z.string().regex(/^[0-9a-f]{16}$/),
  algorithm: z.literal("Ed25519"),
  /** The raw public key: 32 bytes as 43 base64url characters. */
  public_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});
export type AuditPublicKeyResponse = z.infer<typeof AuditPublicKeyResponseSchema>;

/**
 * `GET /v1/audit/verify`: the chain recomputed from the first entry up to the head, and the head signed.
 * `first_broken_seq`: see `AUDIT_VERIFY_DOC`. `last_seq` is the head's.
 */
export const AuditVerifyResponseSchema = z.object({
  verify: z
    .object({
      valid: z.boolean(),
      entries: z.int().min(0),
      last_seq: z.int().min(0),
      first_broken_seq: z.int().min(1).nullable(),
    })
    .refine((result) => result.valid === (result.first_broken_seq === null), "valid iff nothing is broken")
    .describe(AUDIT_VERIFY_DOC),
  signed_head: SignedAuditHeadSchema,
});
export type AuditVerifyResponse = z.infer<typeof AuditVerifyResponseSchema>;

/** An Organization's first entry. Its `hash` is `auditHash` of the rest (a protocol test checks it). */
export const EXAMPLE_AUDIT_ENTRY: AuditEntry = deepFreeze({
  id: "aud_0123456789abcdef01234567",
  organization_id: "org_0123456789abcdef01234567",
  seq: 1,
  at: "2026-11-13T09:00:00.000Z",
  actor: { kind: "admin_key", key_id: "key_0123456789abcdef01234567" },
  action: "policy.rule.promote",
  app_id: "app_0123456789abcdef01234567",
  target: { kind: "policy", id: "app_0123456789abcdef01234567/production" },
  reason: "Credential stuffing on /login since 08:40; monitor showed no false positives.",
  summary: "Published version 3 (2 Rules, 1 enforced); promoted to enforce: rul_0123456789abcdef01234567.",
  request_id: "6f1c2a4e-8d3b-4c5a-9e7f-0a1b2c3d4e5f",
  prev_hash: AUDIT_GENESIS_HASH,
  hash: "47b2c9768cb0f368ddb91cb5e6ef805ed4c777fce86565c46e33dc173296e6ad",
});

/** A signed head (its signature is illustrative: the example key is not published). */
export const EXAMPLE_SIGNED_AUDIT_HEAD: SignedAuditHead = deepFreeze({
  head: {
    organization_id: EXAMPLE_AUDIT_ENTRY.organization_id,
    seq: EXAMPLE_AUDIT_ENTRY.seq,
    hash: EXAMPLE_AUDIT_ENTRY.hash,
    at: "2026-11-13T09:05:00.000Z",
  },
  key_id: "0123456789abcdef",
  signature: "A".repeat(86),
});
