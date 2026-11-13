import { createHash, randomBytes } from "node:crypto";
import { canonicalJson, type RulesOfEngagementContent, RulesOfEngagementContentSchema } from "./prove.ts";

// The Node-only half of the Prove contract (slice 14): verification tokens and the content hash of a signed
// Rules of Engagement version.

const TOKEN_BYTES = 32;

/** A new verification token: 32 random bytes as 43 base64url characters. Shown to admins only; never logged. */
export function generateVerificationToken(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

/**
 * `content_sha256` of a Rules of Engagement version: the SHA-256 hex of the canonical JSON (`canonicalJson`) of
 * its five content fields (scope, exclusions, intensity, window, contacts) as given. Any other key (id, signer,
 * time, the hash itself) is ignored. Throws a TypeError unless the content is valid.
 */
export function rulesOfEngagementSha256(content: RulesOfEngagementContent): string {
  const parsed = RulesOfEngagementContentSchema.safeParse(content);
  if (!parsed.success) throw new TypeError("Rules of Engagement content is not valid.");
  const { scope, exclusions, intensity, window, contacts } = parsed.data;
  const canonical = canonicalJson({ scope, exclusions, intensity, window, contacts });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}
