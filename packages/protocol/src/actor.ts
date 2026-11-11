import { createHmac } from "node:crypto";
import { parseAddress } from "./containment.ts";

// The actor hash (D-017): a per-tenant keyed hash of the client address, computed by Shield. The API holds
// only the SHA-256 of the Shield key, so it can neither compute nor reverse it.
//
//   hash    = "iph_" + the first 32 hex characters of HMAC-SHA256(key, "antireverse/actor/v1\n" + subject)
//   key     = the Shield key string (UTF-8)
//   subject = IPv4: the whole address in dotted decimal without leading zeros, e.g. "203.0.113.7"
//             IPv6: its /64, the first four groups each as 4 lowercase hex digits joined by ":",
//                   e.g. "2001:0db8:0000:0001"
// An IPv4-mapped IPv6 address is hashed as its IPv4 address; a zone id is stripped.

const DOMAIN = "antireverse/actor/v1\n";

/**
 * The actor hash of a client address for one Shield key; null when the address is unknown or cannot be
 * parsed. An empty or missing key is a TypeError. Never log the address or the key.
 */
export function actorHash(shieldKey: string, address: string | null | undefined): string | null {
  if (typeof shieldKey !== "string" || shieldKey.length === 0) {
    throw new TypeError("A Shield key is a non-empty string.");
  }
  const parsed = parseAddress(address);
  if (parsed === null) return null;
  const [a, b, c, d] = parsed.words as [number, number, number, number];
  const subject =
    parsed.version === 4
      ? `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`
      : [a, b, c, d].map((word) => word.toString(16).padStart(4, "0")).join(":");
  return `iph_${createHmac("sha256", shieldKey)
    .update(DOMAIN + subject, "utf8")
    .digest("hex")
    .slice(0, 32)}`;
}
