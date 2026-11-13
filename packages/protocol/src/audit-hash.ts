import { createHash } from "node:crypto";
import { type AuditEntry, AuditEntrySchema } from "./audit.ts";
import { ACTOR_HASH_PATTERN, ID_PATTERNS } from "./constants.ts";
import { canonicalJson } from "./prove.ts";

const UnhashedEntrySchema = AuditEntrySchema.omit({ hash: true });

/**
 * The hash of an audit entry (slice 18a): the SHA-256 hex of its `prev_hash` followed by the canonical JSON
 * (`canonicalJson`: keys sorted, no whitespace) of the entry without `hash`, after validation (unknown keys stripped;
 * an optional member that is undefined is left out, as an absent one). Throws a TypeError for an entry that is not
 * valid (`AuditEntrySchema` without `hash`). The input is not changed.
 */
export function auditHash(entry: Omit<AuditEntry, "hash">): string {
  const parsed = UnhashedEntrySchema.safeParse(entry);
  if (!parsed.success) throw new TypeError("An audit entry must be valid to be hashed.");
  const members = Object.fromEntries(Object.entries(parsed.data).filter(([, value]) => value !== undefined));
  return createHash("sha256")
    .update(parsed.data.prev_hash + canonicalJson(members), "utf8")
    .digest("hex");
}

/**
 * How the audit log names an end user (slice 18b review): never by the actor hash, which a subject erasure must be able
 * to remove from everywhere but an append-only chain cannot, but by `subj_` + the first 32 hex characters of
 * SHA-256("antireverse/audit-subject/v1\n" + organization id + "\n" + actor hash). Anyone holding the hash can find
 * the entries; the entries alone do not give the hash back. Throws a TypeError for an id or a hash that is not one.
 */
export function auditSubjectRef(organizationId: string, ipHash: string): string {
  if (!ID_PATTERNS.org.test(organizationId) || !ACTOR_HASH_PATTERN.test(ipHash)) {
    throw new TypeError("An audit subject reference needs an Organization id and an actor hash.");
  }
  return `subj_${createHash("sha256")
    .update(`antireverse/audit-subject/v1\n${organizationId}\n${ipHash}`, "utf8")
    .digest("hex")
    .slice(0, 32)}`;
}
