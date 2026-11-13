import { createHash } from "node:crypto";
import { type AuditEntry, AuditEntrySchema } from "./audit.ts";
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
