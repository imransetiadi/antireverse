// The dependency allowlist (slice 23, D-134; SECURITY SC-SUP-03): tools/sdk/allowlist.json names every runtime
// dependency of each packed package, direct or transitive, by name and exact version, with the integrity the
// lockfile has for it (review L7). The check fails on anything in the closure that is not listed, on a listed
// entry that is gone, on other bytes under a listed name and version, on a package that does not come from the
// npm registry, on an install script anywhere in the closure,
// and on any dependency at all of a package that must have none (Shield, Guard) — whatever the list says.
// `npm run sdk:allowlist` prints today's closure in the list's form, for a person to review and commit.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import type { Closure, ClosureEntry } from "./closure.ts";
import { SDK_PACKAGES } from "./packages.ts";

export interface Allowlist {
  about: string;
  /** Per packed package: the SDK packages it carries a copy of, and every third-party runtime dependency. */
  packages: Record<string, { vendored: string[]; thirdParty: Record<string, string> }>;
}

export const ALLOWLIST_FILE = join(REPO_ROOT, "tools/sdk/allowlist.json");
const ABOUT =
  "Every runtime dependency of each packed SDK package, by name and exact version (slice 23, SECURITY SC-SUP-03). A change here is a reviewed change of what a project installs. Print today's closure with `npm run sdk:allowlist`.";

export function readAllowlist(path = ALLOWLIST_FILE): Allowlist {
  return JSON.parse(readFileSync(path, "utf8")) as Allowlist;
}

/** Today's closure in the list's form. */
export function currentAllowlist(closures: Readonly<Record<string, Closure>>): Allowlist {
  const packages: Allowlist["packages"] = {};
  for (const pkg of SDK_PACKAGES) {
    const entries = closures[pkg.name]?.entries ?? [];
    packages[pkg.name] = {
      vendored: [...(pkg.vendors ?? [])],
      thirdParty: Object.fromEntries(entries.map((entry) => [entry.id, entry.integrity ?? ""])),
    };
  }
  return { about: ABOUT, packages };
}

const NPM_REGISTRY = "https://registry.npmjs.org/";
const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"] as const;

/** The install scripts a closure package has on disk: its package.json scripts, and a binding.gyp (npm builds it). */
export function installScripts(entry: Pick<ClosureEntry, "paths">, root = REPO_ROOT): string[] {
  const found = new Set<string>();
  for (const path of entry.paths) {
    const manifest = join(root, path, "package.json");
    if (!existsSync(manifest)) {
      found.add(`${path} is not installed, so its scripts cannot be read`);
      continue;
    }
    const scripts = (JSON.parse(readFileSync(manifest, "utf8")) as { scripts?: Record<string, string> }).scripts ?? {};
    for (const name of INSTALL_SCRIPTS) if (typeof scripts[name] === "string") found.add(name);
    if (existsSync(join(root, path, "binding.gyp"))) found.add("binding.gyp");
  }
  return [...found];
}

export function checkAllowlist(
  closures: Readonly<Record<string, Closure>>,
  allowlist: Allowlist,
  scriptsOf: (entry: ClosureEntry) => string[],
): string[] {
  const problems: string[] = [];
  for (const pkg of SDK_PACKAGES) {
    const closure = closures[pkg.name];
    const listed = allowlist.packages[pkg.name];
    if (closure === undefined) {
      problems.push(`${pkg.name}: no closure`);
      continue;
    }
    if (listed === undefined) {
      problems.push(`${pkg.name}: no allowlist entry`);
      continue;
    }
    if (pkg.zeroDependencies) {
      const named = [...listed.vendored, ...Object.keys(listed.thirdParty)];
      if (closure.entries.length > 0) {
        problems.push(
          `${pkg.name} must have no runtime dependency (SC-SUP-03), found ${closure.entries.map((entry) => entry.id).join(", ")}`,
        );
      } else if (named.length > 0) {
        problems.push(
          `${pkg.name} must have no runtime dependency (SC-SUP-03), but the allowlist names ${named.join(", ")}`,
        );
      }
      continue;
    }
    const vendored = [...(pkg.vendors ?? [])];
    for (const name of vendored) {
      if (!listed.vendored.includes(name)) problems.push(`${pkg.name}: the vendored ${name} is not on the allowlist`);
    }
    for (const name of listed.vendored) {
      if (!vendored.includes(name))
        problems.push(`${pkg.name}: the allowlist names the vendored ${name}, which is not vendored`);
    }
    for (const entry of closure.entries) {
      if (!(entry.id in listed.thirdParty)) {
        problems.push(`${pkg.name}: ${entry.id} is not on the allowlist`);
        continue;
      }
      if (entry.integrity === undefined) problems.push(`${pkg.name}: ${entry.id} has no integrity in the lockfile`);
      else if (entry.integrity !== listed.thirdParty[entry.id]) {
        problems.push(`${pkg.name}: ${entry.id} has the integrity ${entry.integrity}, the allowlist has another`);
      }
      if (entry.resolved === undefined || !entry.resolved.startsWith(NPM_REGISTRY)) {
        problems.push(
          `${pkg.name}: ${entry.id} comes from ${entry.resolved ?? "nowhere the lockfile names"}, not from ${NPM_REGISTRY}`,
        );
      }
    }
    for (const id of Object.keys(listed.thirdParty)) {
      if (!closure.entries.some((entry) => entry.id === id)) {
        problems.push(`${pkg.name}: the allowlist names ${id}, which is no longer a dependency`);
      }
    }
    for (const entry of closure.entries) {
      const scripts = [...(entry.hasInstallScript ? ["the lockfile says so"] : []), ...scriptsOf(entry)];
      if (scripts.length > 0) problems.push(`${pkg.name}: ${entry.id} has an install script (${scripts.join(", ")})`);
    }
  }
  for (const name of Object.keys(allowlist.packages)) {
    if (!SDK_PACKAGES.some((pkg) => pkg.name === name))
      problems.push(`${name}: on the allowlist but not an SDK package`);
  }
  return problems;
}
