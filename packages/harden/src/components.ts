// The component inventory (slice 19): an npm lockfile read into `{ name, version, dev }` per installed package.
// Only names, versions and the dev flag come out — nothing else of the lockfile (no resolved URL, integrity,
// workspace path or project name). Supported: package-lock v2/v3 (`packages` map; preferred when present) and
// v1 (`dependencies` tree). Rules (plan 19, Global Constraints "Harden"):
//   - the "" key (the root project) is skipped; so are `link: true` entries and keys outside `node_modules/`
//     (workspace sources: the project's own code, not a dependency);
//   - name = the entry's `name` field when present (an alias), else the part after the last `node_modules/`;
//   - dev = `dev || devOptional`; a name@version seen several times is dev only if every occurrence is dev;
//   - an entry without a semver version (git, file:, URL, npm: alias in v1) or with a name npm forbids is
//     skipped and counted; more than 5,000 distinct components is an error.
import { readFileSync } from "node:fs";
import { type Component, ComponentSchema, EXPOSURE_LIMITS } from "@antireverse/protocol";

export interface ComponentInventory {
  /** De-duplicated by name@version, sorted by name then version (plain string order). */
  components: Component[];
  /** Entries skipped because their version is not semver or their name or version is invalid. */
  skipped: number;
}

export type ComponentsResult = ComponentInventory | { error: string };

type Entry = { name: string; version: unknown; dev: boolean };

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const NODE_MODULES = "node_modules/";

/** Entries of a v2/v3 `packages` map; non-object entries come back as invalid (version undefined). */
function packagesEntries(packages: Record<string, unknown>): Entry[] {
  const entries: Entry[] = [];
  for (const [key, raw] of Object.entries(packages)) {
    if (key === "") continue;
    const at = key.lastIndexOf(NODE_MODULES);
    if (at === -1) continue;
    if (!isObject(raw)) {
      entries.push({ name: key.slice(at + NODE_MODULES.length), version: undefined, dev: false });
      continue;
    }
    if (raw.link === true) continue;
    const name = typeof raw.name === "string" ? raw.name : key.slice(at + NODE_MODULES.length);
    entries.push({ name, version: raw.version, dev: raw.dev === true || raw.devOptional === true });
  }
  return entries;
}

/** Entries of a v1 `dependencies` tree, walked iteratively (no recursion depth limit to hit). */
function dependencyEntries(root: Record<string, unknown>): Entry[] {
  const entries: Entry[] = [];
  const stack: Array<Record<string, unknown>> = [root];
  while (stack.length > 0) {
    const level = stack.pop() as Record<string, unknown>;
    for (const [name, raw] of Object.entries(level)) {
      if (!isObject(raw)) {
        entries.push({ name, version: undefined, dev: false });
        continue;
      }
      entries.push({ name, version: raw.version, dev: raw.dev === true });
      if (isObject(raw.dependencies)) stack.push(raw.dependencies);
    }
  }
  return entries;
}

/** The components of a parsed lockfile, or an error when it is not a lockfile or lists too many. */
export function componentsFromLockfile(lockfile: unknown): ComponentsResult {
  if (!isObject(lockfile)) return { error: "is not an npm lockfile (expected a JSON object)" };
  let entries: Entry[];
  if (isObject(lockfile.packages)) entries = packagesEntries(lockfile.packages);
  else if (isObject(lockfile.dependencies)) entries = dependencyEntries(lockfile.dependencies);
  else return { error: "is not an npm lockfile (no `packages` or `dependencies` object)" };

  const byKey = new Map<string, Component>();
  let skipped = 0;
  for (const entry of entries) {
    const parsed = ComponentSchema.safeParse(entry);
    if (!parsed.success) {
      skipped++;
      continue;
    }
    const key = `${parsed.data.name}@${parsed.data.version}`;
    const seen = byKey.get(key);
    if (seen) seen.dev = seen.dev && parsed.data.dev;
    else byKey.set(key, { name: parsed.data.name, version: parsed.data.version, dev: parsed.data.dev });
  }

  if (byKey.size > EXPOSURE_LIMITS.componentsMax) {
    return {
      error: `lists ${byKey.size.toLocaleString("en-US")} components; at most ${EXPOSURE_LIMITS.componentsMax.toLocaleString("en-US")} are supported`,
    };
  }
  const components = [...byKey.values()].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : a.version > b.version ? 1 : 0,
  );
  if (Buffer.byteLength(JSON.stringify(components), "utf8") > EXPOSURE_LIMITS.componentsBytesMax) {
    return { error: `component list is over ${EXPOSURE_LIMITS.componentsBytesMax} bytes` };
  }
  return { components, skipped };
}

/**
 * Reads and parses the lockfile at `path`. An error never quotes the file's content (a JSON parse message can
 * carry a snippet of it), only a short reason.
 */
export function readComponents(path: string): ComponentsResult {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    return { error: code === "ENOENT" ? "not found" : `cannot be read (${typeof code === "string" ? code : "error"})` };
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { error: "is not valid JSON" };
  }
  return componentsFromLockfile(json);
}
