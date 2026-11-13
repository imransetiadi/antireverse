// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
// Internal: the building blocks that events.ts and policy.ts share. No entry re-exports this module.
import { z } from "zod";

// Control characters (NUL included) and lone surrogates cannot be stored as text and have no place in a
// route template, an identifier or a name.
// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point.
const UNSTORABLE = /[\u0000-\u001f\u007f]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

const storable = (value: string): boolean => !UNSTORABLE.test(value);
const NOT_STORABLE = "Must not contain control characters or lone surrogates.";

/** Bounded text without control characters or lone surrogates. */
export function text(max: number) {
  return z.string().max(max).refine(storable, NOT_STORABLE);
}

/** Storable text as a client sends it: trimmed first, then 1..max characters. */
export function trimmedText(max: number) {
  return z.string().trim().min(1).max(max).refine(storable, NOT_STORABLE);
}

/**
 * Refused inside a name a person gives (an App, an alert channel; slice 06b), because names reach alert mails and
 * messages: C0 and C1 controls (tab and NEL included), DEL, the line and paragraph separators, bidi embeddings,
 * overrides and isolates, the BOM and the zero-width space, and lone surrogates. Allowed: ZWJ and ZWNJ (emoji and
 * scripts need them) and the LRM and RLM marks (right-to-left text).
 */
const UNSAFE_IN_NAME =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point.
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200b\ufeff]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/** A name as a person types it: trimmed first, then 1..max characters, none of `UNSAFE_IN_NAME`. */
export function nameText(max: number) {
  return z
    .string()
    .trim()
    .min(1)
    .max(max)
    .refine(
      (value) => !UNSAFE_IN_NAME.test(value),
      "Must not contain control characters, line separators, bidi overrides, zero-width spaces or lone surrogates.",
    );
}

const TS_MIN = Date.UTC(2000, 0, 1);
const TS_MAX = Date.UTC(2100, 0, 1);

/** ISO-8601 UTC datetime in the years 2000..2099, the form `Date#toISOString` produces. */
export function isoDateTime() {
  return z.iso.datetime().refine((value) => {
    const time = Date.parse(value);
    return time >= TS_MIN && time < TS_MAX;
  }, "Must be a time in the years 2000 to 2099.");
}

/** HTTP method: 1..16 characters, uppercase letters and hyphen only (every method of `node:http`). */
export const HttpMethodSchema = z
  .string()
  .min(1)
  .max(16)
  .regex(/^[A-Z-]+$/);

/** Characters of a path pattern (`POLICY_LIMITS.pathMax`). */
export const RULE_PATH_MAX = 256;

const SEGMENT = "(?:[A-Za-z0-9._~-]+|\\*)";
/**
 * The path pattern of a Rule and of a Virtual patch (`PATH_PATTERN` of policy.ts): `/` alone, or `/`-separated
 * segments without a trailing slash, each literal text over `A-Z a-z 0-9 . _ ~ -` or `*`, the last one also `**`.
 */
export const RULE_PATH_PATTERN = new RegExp(`^(?=.{1,${RULE_PATH_MAX}}$)(?:/|(?:/${SEGMENT})*/(?:${SEGMENT}|\\*\\*))$`);

export function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

/**
 * The UTF-8 byte length of a string without encoding it, as `TextEncoder` would produce: a lone surrogate counts as
 * its replacement character (3 bytes). Stops counting once `max` is exceeded and returns `max + 1`.
 */
export function utf8Bytes(value: string, max = Number.POSITIVE_INFINITY): number {
  if (value.length > max) return max + 1; // Every UTF-16 code unit is at least one byte.
  let bytes = 0;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index++;
      } else bytes += 3;
    } else bytes += 3;
    if (bytes > max) return max + 1;
  }
  return bytes;
}
