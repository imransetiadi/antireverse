import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

// Webhook alert signatures. The sender puts `AR-Signature: t=<unix seconds>,v1=<signature>` on the request,
// where the signature is the lowercase hex HMAC-SHA256 of `<t>.<body>` keyed with the channel's signing secret.
// The sender sends one `v1` today; receivers accept several (any match passes) so a future secret rotation,
// which signs with both the old and the new secret, does not break them.

const SECRET_BYTES = 32;
/** The default tolerance between the signed time and the receiver's clock, in seconds. */
const DEFAULT_TOLERANCE_S = 300;
/** Decimal digits only, no sign, at most 15 digits (a safe integer). */
const TIME_PATTERN = /^[0-9]{1,15}$/;
const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;
/** `v1` values one header may carry (several during a secret rotation). */
const MAX_SIGNATURES = 8;

/** A new signing secret: `whsec_` followed by 32 random bytes as 43 base64url characters. Shown once. */
export function generateSigningSecret(): string {
  return `whsec_${randomBytes(SECRET_BYTES).toString("base64url")}`;
}

/** The lowercase hex HMAC-SHA256, keyed with `secret`, of `${t}.${body}` (UTF-8). `t` is unix seconds. */
export function signWebhookBody(secret: string, t: number, body: string): string {
  if (!Number.isSafeInteger(t) || t < 0) throw new TypeError("The signed time is a non-negative integer of seconds.");
  return createHmac("sha256", secret).update(`${t}.${body}`, "utf8").digest("hex");
}

/** `t` and every `v1` of an `AR-Signature` header; null when it is malformed. Unknown fields are ignored. */
function parseSignatureHeader(header: string): { t: number; v1: string[] } | null {
  let t: string | undefined;
  const v1: string[] = [];
  for (const part of header.split(",")) {
    const separator = part.indexOf("=");
    if (separator <= 0) return null;
    const name = part.slice(0, separator);
    const value = part.slice(separator + 1);
    if (name === "t") {
      if (t !== undefined || !TIME_PATTERN.test(value)) return null;
      t = value;
    } else if (name === "v1") {
      if (v1.length === MAX_SIGNATURES || !SIGNATURE_PATTERN.test(value)) return null;
      v1.push(value);
    }
  }
  if (t === undefined || v1.length === 0) return null;
  return { t: Number(t), v1 };
}

/**
 * Whether `header` is a valid signature of `body` under `secret`, signed within `toleranceS` seconds of
 * `nowS`. Never throws.
 *
 * The header is `t=<int>,v1=<64 hex>[,v1=<64 hex>...]`; unknown fields are ignored. It may carry one to
 * `MAX_SIGNATURES` (8) `v1` values, so that a sender can sign with an old and a new secret during a rotation:
 * receivers must loop over every `v1` and accept when any matches, as this function does. A duplicate `t`,
 * a malformed `v1` or more than 8 `v1` values reject the whole header. Every candidate is compared in
 * constant time; the loop does not stop at the first match.
 */
export function verifyWebhookSignature(
  secret: string,
  header: string,
  body: string,
  nowS: number,
  toleranceS = DEFAULT_TOLERANCE_S,
): boolean {
  if (typeof secret !== "string" || typeof header !== "string" || typeof body !== "string") return false;
  const parsed = parseSignatureHeader(header);
  if (parsed === null) return false;
  if (!(Math.abs(nowS - parsed.t) <= toleranceS)) return false;
  const expected = Buffer.from(signWebhookBody(secret, parsed.t, body), "hex");
  let matched = false;
  for (const candidate of parsed.v1) {
    const received = Buffer.from(candidate, "hex");
    if (received.length === expected.length && timingSafeEqual(expected, received)) matched = true;
  }
  return matched;
}
