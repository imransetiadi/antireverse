// The runtime dependency closure of a packed package, read from package-lock.json (slice 23): `dependencies`,
// `optionalDependencies` and required peer dependencies, followed the way Node resolves them (the nearest
// node_modules first). Development dependencies are never followed. A dependency that is a workspace link —
// another package of this repository, which no registry has — is refused: a packed package depends on none (D-140).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { SDK_PACKAGES } from "./packages.ts";

export interface LockEntry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  license?: string;
  link?: boolean;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  hasInstallScript?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
}

export interface Lockfile {
  lockfileVersion: number;
  packages: Record<string, LockEntry>;
}

export interface ClosureEntry {
  /** name@version */
  id: string;
  name: string;
  version: string;
  /** Where the lockfile has it (several when one version is installed in several places). */
  paths: string[];
  integrity?: string;
  resolved?: string;
  license?: string;
  /** The ids of what it depends on at run time. */
  dependsOn: string[];
  hasInstallScript: boolean;
}

export interface Closure {
  /** The ids of the direct dependencies. */
  direct: string[];
  /** Everything reachable, sorted by id, each once. */
  entries: ClosureEntry[];
}

export function readLockfile(path = join(REPO_ROOT, "package-lock.json")): Lockfile {
  return JSON.parse(readFileSync(path, "utf8")) as Lockfile;
}

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** The lockfile key a dependency `name` of the package at `from` resolves to. */
function resolveKey(lock: Lockfile, from: string, name: string): string | null {
  let at = from;
  for (;;) {
    const key = `${at === "" ? "" : `${at}/`}node_modules/${name}`;
    if (lock.packages[key] !== undefined) return key;
    if (at === "") return null;
    const cut = at.lastIndexOf("/node_modules/");
    at = cut >= 0 ? at.slice(0, cut) : "";
  }
}

function runtimeDependencies(entry: LockEntry): { required: string[]; optional: string[] } {
  const required = new Set(Object.keys(entry.dependencies ?? {}));
  for (const name of Object.keys(entry.peerDependencies ?? {})) {
    if (entry.peerDependenciesMeta?.[name]?.optional !== true) required.add(name);
  }
  return { required: [...required], optional: Object.keys(entry.optionalDependencies ?? {}) };
}

/**
 * The closure of the package at lockfile key `start` (a workspace folder such as packages/harden). `extra`: names it
 * also depends on in its packed form although its lockfile entry does not say so (the dependencies of what it vendors).
 */
export function closureOf(lock: Lockfile, start: string, extra: readonly string[] = []): Closure {
  if (lock.lockfileVersion !== 3)
    throw new Error(`package-lock.json must be lockfile version 3, found ${lock.lockfileVersion}`);
  const root = lock.packages[start];
  if (root === undefined) throw new Error(`${start} is not in the lockfile`);
  const found = new Map<string, ClosureEntry>();

  /** Resolves one dependency and returns its id; visits it when new. */
  const follow = (from: string, name: string, optional: boolean): string | null => {
    const key = resolveKey(lock, from, name);
    if (key === null) {
      if (optional) return null;
      throw new Error(`${name}, a dependency of ${from}, is not in the lockfile`);
    }
    const entry = lock.packages[key] as LockEntry;
    if (entry.link === true) {
      throw new Error(
        `${name}, a dependency of ${from}, is a workspace package (${entry.resolved}): no registry has it, so a packed package may not depend on it`,
      );
    }
    if (entry.version === undefined) throw new Error(`${key} has no version in the lockfile`);
    const id = `${name}@${entry.version}`;
    const known = found.get(id);
    if (known !== undefined) {
      if (known.integrity !== entry.integrity) {
        throw new Error(`${id} is in the lockfile with two different integrities (${known.paths[0]} and ${key})`);
      }
      if (!known.paths.includes(key)) known.paths.push(key);
      return id;
    }
    const item: ClosureEntry = {
      id,
      name,
      version: entry.version,
      paths: [key],
      ...(entry.integrity === undefined ? {} : { integrity: entry.integrity }),
      ...(entry.resolved === undefined ? {} : { resolved: entry.resolved }),
      ...(entry.license === undefined ? {} : { license: entry.license }),
      dependsOn: [],
      hasInstallScript: entry.hasInstallScript === true,
    };
    found.set(id, item);
    const deps = runtimeDependencies(entry);
    const ids = [
      ...deps.required.map((dep) => follow(key, dep, false)),
      ...deps.optional.map((dep) => follow(key, dep, true)),
    ].filter((dep): dep is string => dep !== null);
    item.dependsOn = [...new Set(ids)].sort(byText);
    return id;
  };

  const deps = runtimeDependencies(root);
  const direct = [
    ...deps.required.map((dep) => follow(start, dep, false)),
    ...deps.optional.map((dep) => follow(start, dep, true)),
    ...extra.map((dep) => follow(start, dep, false)),
  ].filter((dep): dep is string => dep !== null);
  for (const entry of found.values()) entry.paths.sort(byText);
  return { direct: [...new Set(direct)].sort(byText), entries: [...found.values()].sort((a, b) => byText(a.id, b.id)) };
}

/** The closure of each SDK package. `extra`: per package, the dependencies its vendored packages add. */
export function sdkClosures(
  lock: Lockfile,
  extra: Readonly<Record<string, readonly string[]>> = {},
): Record<string, Closure> {
  return Object.fromEntries(
    SDK_PACKAGES.map((pkg) => [pkg.name, closureOf(lock, `packages/${pkg.short}`, extra[pkg.name] ?? [])]),
  );
}

/** The dependencies each package gets from what it vendors, by the lockfile. */
export function vendoredDependencies(lock: Lockfile): Record<string, string[]> {
  const extra: Record<string, string[]> = {};
  for (const pkg of SDK_PACKAGES) {
    extra[pkg.name] = (pkg.vendors ?? []).flatMap((name) => {
      const short = SDK_PACKAGES.find((other) => other.name === name)?.short;
      return Object.keys(lock.packages[`packages/${short}`]?.dependencies ?? {});
    });
  }
  return extra;
}
