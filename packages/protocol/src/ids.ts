import { createHash, randomBytes } from "node:crypto";
import type { IdPrefix } from "./constants.ts";

/** A new identifier: `<prefix>_<24 lowercase hex characters>` from 12 random bytes. */
export function newId(prefix: IdPrefix): string {
  return `${prefix}_${randomBytes(12).toString("hex")}`;
}

/**
 * The fingerprint of a build seed: the first 16 hex characters of the SHA-256 of the seed value. It lets a
 * Manifest identify the seed without revealing it.
 */
export function seedId(seedValue: string): string {
  return createHash("sha256").update(seedValue, "utf8").digest("hex").slice(0, 16);
}
