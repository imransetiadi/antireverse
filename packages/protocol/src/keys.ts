import { createHash, randomBytes } from "node:crypto";
import {
  ADMIN_KEY_PATTERN,
  ENVIRONMENTS,
  type Environment,
  SHIELD_KEY_ENVIRONMENT_TAGS,
  SHIELD_KEY_PATTERN,
} from "./constants.ts";

export type KeyKind = "admin" | "shield";

export interface GeneratedKey {
  /** The whole key. Returned to the caller exactly once and never stored or logged. */
  key: string;
  /** The scheme plus the first 6 secret characters, e.g. `aro_AbCdEf` or `ark_prod_AbCdEf`. */
  prefix: string;
  /** The last 4 characters of the key. */
  last4: string;
}

export type ParsedKey = { kind: "admin" } | { kind: "shield"; environment: Environment };

const SECRET_BYTES = 32;
const PREFIX_SECRET_CHARS = 6;

function schemeOf(kind: KeyKind, environment: Environment | undefined): string {
  if (kind === "admin") return "aro_";
  if (kind === "shield" && environment !== undefined && ENVIRONMENTS.includes(environment)) {
    return `ark_${SHIELD_KEY_ENVIRONMENT_TAGS[environment]}_`;
  }
  throw new TypeError(`A Shield key needs an Environment: ${ENVIRONMENTS.join(", ")}.`);
}

/** A new admin key `aro_<43 base64url characters>` or Shield key `ark_<prod|stg|dev>_<43 base64url characters>`. */
export function generateKey(kind: "admin"): GeneratedKey;
export function generateKey(kind: "shield", environment: Environment): GeneratedKey;
export function generateKey(kind: KeyKind, environment?: Environment): GeneratedKey {
  const scheme = schemeOf(kind, environment);
  const secret = randomBytes(SECRET_BYTES).toString("base64url");
  const key = scheme + secret;
  return { key, prefix: scheme + secret.slice(0, PREFIX_SECRET_CHARS), last4: key.slice(-4) };
}

/** The kind (and, for a Shield key, the Environment) a well-formed key claims; null for anything else. */
export function parseKey(key: unknown): ParsedKey | null {
  if (typeof key !== "string") return null;
  if (ADMIN_KEY_PATTERN.test(key)) return { kind: "admin" };
  const tag = SHIELD_KEY_PATTERN.exec(key)?.[1];
  const environment = ENVIRONMENTS.find((candidate) => SHIELD_KEY_ENVIRONMENT_TAGS[candidate] === tag);
  return environment === undefined ? null : { kind: "shield", environment };
}

/** SHA-256 of the key as 64 lowercase hex characters: the only form in which a key is stored. */
export function hashKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

/**
 * The audience of a Policy Bundle: the first 32 hex characters of the SHA-256 of the Shield key the bundle
 * is issued for. It names the key without revealing it.
 */
export function bundleAudience(shieldKey: string): string {
  return hashKey(shieldKey).slice(0, 32);
}

const ED25519_PUBLIC_KEY_BYTES = 32;

/**
 * The identifier of a signing key: the first 16 hex characters of the SHA-256 of the raw public key,
 * the 32 bytes that travel as 43 base64url characters. An encoded key (SPKI, PEM, base64url text) is refused.
 */
export function keyIdOf(publicKeyRaw: Uint8Array): string {
  if (!(publicKeyRaw instanceof Uint8Array) || publicKeyRaw.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    throw new TypeError("An Ed25519 public key is 32 raw bytes.");
  }
  return createHash("sha256").update(publicKeyRaw).digest("hex").slice(0, 16);
}
