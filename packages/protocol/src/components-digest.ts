import { createHash } from "node:crypto";
import type { Component } from "./exposure.ts";

/**
 * The digest of a component list, as a Manifest's `components_digest`: the SHA-256 hex of the JSON of
 * `[{name, version, dev}]`, sorted by name, then version, both by UTF-16 code unit (plain string order, not
 * semver order). Input order and extra keys do not change it; the input is not changed.
 */
export function componentsDigest(components: readonly Component[]): string {
  const canonical = components
    .map(({ name, version, dev }) => ({ name, version, dev }))
    .sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : a.version > b.version ? 1 : 0,
    );
  return createHash("sha256").update(JSON.stringify(canonical), "utf8").digest("hex");
}
