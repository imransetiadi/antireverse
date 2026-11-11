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
