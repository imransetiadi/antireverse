// The only code in the SDK tooling's source (tools/sdk/src) that removes a folder (slice 23, lesson L-009): every
// command goes through it. (The tests remove the temporary folder they made with mkdtemp themselves, by the path
// mkdtemp returned.) A build folder is one of:
//   - in the repository: packages/{protocol,shield-node,guard,harden}/dist, dist/sdk, dist/sdk-work — nothing else;
//   - in a test: a folder of the same three kinds — …/build/<package>, …/work, …/out — inside a folder named
//     airverse-sdk-* directly under the operating system's temporary directory. The kinds are the same on purpose:
//     code that would remove some other folder is refused in a test exactly as it would be in the repository.
// The repository root comes from this file's own location, never from a caller. A target is refused when it is
// relative or not normalised, when a symbolic link on the way leads somewhere else, when it is itself a symbolic link
// or not a folder, and when it holds anything while lacking the marker file that every build folder gets when it is
// created: only what this tooling made is ever removed.
import { existsSync, lstatSync, mkdirSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { SDK_PACKAGES, type SdkPackage } from "./packages.ts";

export const BUILD_MARKER = ".airverse-sdk-build";
export const MARKER_TEXT =
  "Build output of Airverse's SDK tooling (npm run sdk:build, npm run sdk:pack). This folder is removed and written again by those commands.\n";
/** A test's temporary folder: `mkdtemp(join(tmpdir(), "airverse-sdk-…"))`. */
export const TEMP_PREFIX = "airverse-sdk-";

const REPO_BUILD_DIRS: readonly string[] = [
  ...SDK_PACKAGES.map((pkg) => `packages/${pkg.short}/dist`),
  "dist/sdk",
  "dist/sdk-work",
];

/** The kinds of folder a temporary layout has (see tempLayout). */
const TEMP_BUILD_DIRS: readonly string[] = [...SDK_PACKAGES.map((pkg) => `build/${pkg.short}`), "work", "out"];

export interface Layout {
  /** Where a package's compiled files go. */
  dist(pkg: SdkPackage): string;
  /** Staging folders, the npm cache and the npm configuration files of the pack. */
  work: string;
  /** The tarballs, the bills of materials and the manifest. */
  out: string;
}

/** The nearest existing ancestor's real path, with the missing rest appended. */
function realOf(path: string): string {
  let existing = path;
  const rest: string[] = [];
  while (!existsSync(existing)) {
    const parent = dirname(existing);
    if (parent === existing) break;
    rest.unshift(basename(existing));
    existing = parent;
  }
  return join(realpathSync.native(existing), ...rest);
}

/** Why `target` is not a build folder, or null when it is one. */
function notABuildDir(target: string): string | null {
  if (typeof target !== "string" || target === "" || !isAbsolute(target)) return "the path is not absolute";
  if (resolve(target) !== target) return "the path is not normalised";
  // The folder as the file system sees it: its parent's real path and its own name.
  const real = join(realOf(dirname(target)), basename(target));
  const inRepo = relative(realpathSync.native(REPO_ROOT), real);
  if (REPO_BUILD_DIRS.includes(inRepo.split(sep).join("/"))) return null;
  const inTemp = relative(realpathSync.native(tmpdir()), real);
  if (!inTemp.startsWith("..") && !isAbsolute(inTemp)) {
    const parts = inTemp.split(sep);
    const tail = parts.slice(1).join("/");
    if (
      (parts[0] as string).startsWith(TEMP_PREFIX) &&
      TEMP_BUILD_DIRS.some((kind) => tail === kind || tail.endsWith(`/${kind}`))
    ) {
      return null;
    }
  }
  return "it is not a build folder of the SDK tooling";
}

export interface CleanOptions {
  /** For tests: called instead of removing. */
  remove?: (path: string) => void;
}

/** Removes a build folder, or throws naming it. A folder that does not exist is left alone. */
export function cleanBuildDir(target: string, options: CleanOptions = {}): void {
  const reason = notABuildDir(target);
  if (reason !== null) throw new Error(`refusing to remove ${JSON.stringify(target)}: ${reason}`);
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(target);
  } catch {
    return;
  }
  if (stat.isSymbolicLink()) throw new Error(`refusing to remove ${target}: it is a symbolic link`);
  if (!stat.isDirectory()) throw new Error(`refusing to remove ${target}: it is not a folder`);
  if (readdirSync(target).length > 0 && !existsSync(join(target, BUILD_MARKER))) {
    throw new Error(
      `refusing to remove ${target}: it holds files and no ${BUILD_MARKER} marker, so this tooling did not make it; move it away or remove it yourself`,
    );
  }
  (options.remove ?? ((path: string) => rmSync(path, { recursive: true })))(target);
}

/** Removes a build folder and creates it again, empty but for the marker. */
export function prepareBuildDir(target: string): void {
  cleanBuildDir(target);
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, BUILD_MARKER), MARKER_TEXT);
}

/** The repository's own build folders. */
export function repoLayout(): Layout {
  return {
    dist: (pkg) => join(REPO_ROOT, "packages", pkg.short, "dist"),
    work: join(REPO_ROOT, "dist/sdk-work"),
    out: join(REPO_ROOT, "dist/sdk"),
  };
}

/** Build folders inside `base`, which must be a temporary folder of ours (or lie inside one). */
export function tempLayout(base: string): Layout {
  const layout: Layout = {
    dist: (pkg) => join(base, "build", pkg.short),
    work: join(base, "work"),
    out: join(base, "out"),
  };
  for (const target of [layout.work, layout.out, ...SDK_PACKAGES.map((pkg) => layout.dist(pkg))]) {
    const reason = notABuildDir(target);
    if (reason !== null || !inTemp(target)) {
      throw new Error(
        `refusing ${JSON.stringify(base)} as a build base: it is not inside a ${TEMP_PREFIX}* folder of the temporary directory`,
      );
    }
  }
  return layout;
}

function inTemp(target: string): boolean {
  const rel = relative(realpathSync.native(tmpdir()), join(realOf(dirname(target)), basename(target)));
  return !rel.startsWith("..") && !isAbsolute(rel);
}
