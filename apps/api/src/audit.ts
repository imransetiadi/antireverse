import { randomUUID } from "node:crypto";
import {
  AUDIT_LIMITS,
  AUDIT_REASON_HEADER,
  type AuditAction,
  type AuditEntry,
  type AuditReasonErrorCode,
  AuditReasonSchema,
  type AuditTargetKind,
  holdsSecretShape,
  scrubSecretShapes,
} from "@antireverse/protocol";
import { auditHash, newId } from "@antireverse/protocol/server";
import type { Context, MiddlewareHandler } from "hono";
import { createMiddleware } from "hono/factory";
import type { AppEnv } from "./auth/authenticate.ts";
import type { Queryable } from "./db/db.ts";
import { problem } from "./problem.ts";

// The audit log (slice 18a). Every mutating administrative route calls `audit` inside the transaction of its change:
// the entry commits with the change or not at all. The chain head row is locked first (`audit_head_lock()`), so the
// entries of one Organization get consecutive `seq` values even under concurrent requests; the database's trigger
// refuses an entry that does not follow the head and moves the head (migration 0032).

/**
 * Who acts, in which request, and why: everything an entry takes from the request. An admin key's entry names the key
 * (`keyId`). Slice 15a: the API itself (`kind: "system"`: a Campaign it started, ended or refused) and the operator
 * (`kind: "operator"`, through the operator routes) act without a key.
 */
interface ActorBase {
  organizationId: string;
  requestId: string;
  reason?: string | undefined;
}
/** An admin key as the actor: what `auditActor` reads from a request. */
export type AdminAuditActor = ActorBase & { keyId: string; kind?: undefined };
export type AuditActor = AdminAuditActor | (ActorBase & { kind: "system" | "operator"; keyId?: undefined });

/** The API itself as the actor of an entry in `organizationId`'s chain, with a request id of its own. */
export function systemActor(organizationId: string): AuditActor {
  return { organizationId, kind: "system", requestId: randomUUID() };
}

/** The operator as the actor of an entry in `organizationId`'s chain. */
export function operatorActor(organizationId: string, requestId: string, reason: string): AuditActor {
  return { organizationId, kind: "operator", requestId, reason };
}

/** What an entry says about the change. */
export interface AuditChange {
  action: AuditAction;
  target: { kind: AuditTargetKind; id: string };
  appId?: string | undefined;
  /** Short and without secrets: identifiers and counts, never a key, token, secret, email address or Canary value. */
  summary: string;
  at: Date;
}

/** The summary as stored: scrubbed, without control characters, at most 500 characters. */
export function cleanSummary(summary: string): string {
  let cleaned = scrubSecretShapes(summary);
  // biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point.
  cleaned = cleaned.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  if (cleaned.length > AUDIT_LIMITS.summaryMax) cleaned = `${cleaned.slice(0, AUDIT_LIMITS.summaryMax - 1)}…`;
  return cleaned === "" ? "(no summary)" : cleaned;
}

/** Quotes a name a person gave, bounded, for a summary. */
export function quoted(name: string, max = 80): string {
  return JSON.stringify(name.length > max ? `${name.slice(0, max - 1)}…` : name);
}

interface HeadRow {
  seq: string | number;
  hash: string;
}

/**
 * Appends one entry to the Organization's chain, in the caller's transaction (whose tenant is the Organization).
 * Throws when it cannot: the transaction then rolls back, change included.
 */
export async function audit(q: Queryable, actor: AuditActor, change: AuditChange): Promise<AuditEntry> {
  // The transaction's own Organization's head, locked (created at seq 0 when missing).
  const { rows } = await q.query<HeadRow>("SELECT seq, hash FROM audit_head_lock()");
  const head = rows[0];
  if (head === undefined) throw new Error("The audit chain head is not visible to this transaction.");
  const unhashed: Omit<AuditEntry, "hash"> = {
    id: newId("aud"),
    organization_id: actor.organizationId,
    seq: Number(head.seq) + 1,
    at: change.at.toISOString(),
    actor: actor.kind === undefined ? { kind: "admin_key", key_id: actor.keyId } : { kind: actor.kind },
    action: change.action,
    ...(change.appId === undefined ? {} : { app_id: change.appId }),
    target: change.target,
    ...(actor.reason === undefined ? {} : { reason: actor.reason }),
    summary: cleanSummary(change.summary),
    request_id: actor.requestId,
    prev_hash: head.hash,
  };
  const entry: AuditEntry = { ...unhashed, hash: auditHash(unhashed) };
  await q.query(
    `INSERT INTO audit_entries (id, organization_id, seq, at, actor_kind, actor_key_id, action, app_id, target_kind,
       target_id, reason, summary, request_id, prev_hash, hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
    [
      entry.id,
      entry.organization_id,
      entry.seq,
      change.at,
      entry.actor.kind,
      entry.actor.key_id ?? null,
      entry.action,
      entry.app_id ?? null,
      entry.target.kind,
      entry.target.id,
      entry.reason ?? null,
      entry.summary,
      entry.request_id,
      entry.prev_hash,
      entry.hash,
    ],
  );
  // The trigger checked that the entry follows the head and moved the head to it.
  return entry;
}

// --- The request side ------------------------------------------------------------------------------------------

const REASON_PATH = `headers.${AUDIT_REASON_HEADER.toLowerCase()}`;
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/** One fixed text per refusal: it never quotes the reason. Clients act on the code (`AUDIT_REASON_ERROR_CODES`). */
const REFUSALS: Readonly<Record<AuditReasonErrorCode, string>> = {
  "reason-not-ascii": "Must be printable ASCII: percent-encode any other character as UTF-8.",
  "reason-bad-encoding": "Must be percent-encoded UTF-8; send a literal % as %25.",
  "reason-empty": "Must not be empty.",
  "reason-too-long": `Must be at most ${AUDIT_LIMITS.reasonMax} characters after decoding.`,
  "reason-unsafe-characters":
    "Must not contain control characters, line separators, bidi overrides, zero-width spaces or lone surrogates.",
  "reason-holds-secret": "Must not contain a key, a token, a secret or an email address.",
};

/**
 * The reason header judged in order: raw characters (bytes outside printable ASCII would be read as Latin-1 and
 * stored garbled), encoding, emptiness and length after decoding and trimming, characters, and secret shapes (a reason
 * is stored as given, so one that holds a secret is refused rather than silently rewritten).
 */
export function checkReason(raw: string): { reason: string } | { code: AuditReasonErrorCode } {
  if (!PRINTABLE_ASCII.test(raw)) return { code: "reason-not-ascii" };
  const decoded = decodeReason(raw);
  if (decoded === null) return { code: "reason-bad-encoding" };
  const trimmed = decoded.trim();
  if (trimmed === "") return { code: "reason-empty" };
  if (trimmed.length > AUDIT_LIMITS.reasonMax) return { code: "reason-too-long" };
  const parsed = AuditReasonSchema.safeParse(decoded);
  if (!parsed.success) return { code: "reason-unsafe-characters" };
  if (holdsSecretShape(parsed.data)) return { code: "reason-holds-secret" };
  return { reason: parsed.data };
}

/**
 * The reason header decoded (see `AUDIT_REASON_HEADER`): null for a `%` that does not start a two-hex-digit escape or
 * for bytes that are not valid UTF-8 (overlong forms and encoded surrogates included: `decodeURIComponent` refuses
 * them). Plain ASCII without `%` comes back unchanged.
 */
export function decodeReason(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/** The response header that names a request's id: the `request_id` of the entry it wrote. */
export const REQUEST_ID_HEADER = "X-Request-Id";

/**
 * Gives every request an id and validates the reason header of a mutating request that can write an entry: one with
 * a key, or the Organization signup. A header that is present but not printable ASCII, not percent-encoded UTF-8,
 * whose decoded text fails `AuditReasonSchema`, or that holds a secret's shape, is a 400 before any route runs. The public
 * endpoints without a key (beacon, attestation, email confirmation) write no entry: they ignore the header and answer
 * exactly as before.
 */
export function auditRequest(): MiddlewareHandler<AppEnv> {
  return createMiddleware<AppEnv>(async (c, next) => {
    c.set("requestId", randomUUID());
    const raw = c.req.header(AUDIT_REASON_HEADER);
    const auditable = c.req.header("authorization") !== undefined || c.req.path === "/v1/organizations";
    if (raw !== undefined && auditable && MUTATING.has(c.req.method)) {
      const checked = checkReason(raw);
      if ("code" in checked) {
        return problem(
          c,
          "validation",
          [{ path: REASON_PATH, message: REFUSALS[checked.code] }],
          undefined,
          checked.code,
        );
      }
      c.set("reason", checked.reason);
    }
    return next();
  });
}

/**
 * The request's id, answered as `X-Request-Id` from here on: a route that may write an entry calls this, so that the
 * client can find the entry its request wrote. Other responses do not carry it.
 */
export function requestIdOf(c: Context): string {
  const variables = c.var as AuditVariables;
  const requestId = variables.requestId ?? randomUUID();
  c.header(REQUEST_ID_HEADER, requestId);
  return requestId;
}

/** What the audit helpers read from a request's context (any route's environment extends `AppEnv`). */
type AuditVariables = Partial<AppEnv["Variables"]>;

/** The actor of an admin request: its key, its request id and its reason, if any. */
export function auditActor(c: Context): AdminAuditActor {
  const { principal, reason } = c.var as AuditVariables;
  if (principal?.kind !== "admin") throw new Error("Only an admin key's changes are audited.");
  return {
    organizationId: principal.organizationId,
    keyId: principal.keyId,
    requestId: requestIdOf(c),
    ...(reason === undefined ? {} : { reason }),
  };
}

/** The 400 of a sensitive change sent without a reason; null when the request has one. */
export function reasonMissing(c: Context): Response | null {
  return (c.var as AuditVariables).reason === undefined ? problem(c, "reason-required") : null;
}
