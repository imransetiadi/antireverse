// Behaviour equivalence (slice 23, D-132): a Vitest plugin that makes the existing test suites of the compiled
// packages run against the compiled output instead of the source.
//   - resolve: a module under packages/<name>/src becomes the compiled file of the same name in the build folder, and
//     the package names (@antireverse/protocol, …) become the compiled entries. A package imported by a compiled file
//     (zod, Babel) is resolved as if the source file had imported it.
//   - load guard: loading any module from one of those src folders fails the run — in Vitest through this plugin,
//     and in every Node process a test starts through child-guard.mjs, which the compiled run's configuration puts
//     into NODE_OPTIONS.
// What neither guard can see is a test that reads a source file as text: those tests are about the source by
// construction and say the same thing in both runs. They, and every test file that starts a process, are named in
// DIST_OUTSIDE_THE_GUARD. The test files that are left out, each with its reason, are DIST_EXCLUDED.
import { existsSync, realpathSync } from "node:fs";
import { isBuiltin } from "node:module";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { SDK_PACKAGES, type SdkPackage } from "./packages.ts";

/** The packages whose suites run on the compiled output: the three that are compiled. */
export const DIST_PACKAGES: readonly SdkPackage[] = SDK_PACKAGES.filter((pkg) => pkg.kind === "tsc");

/** Test files that cannot run against the compiled output, relative to the repository root, with the reason. */
export const DIST_EXCLUDED: ReadonlyArray<{ file: string; reason: string }> = [
  {
    file: "packages/harden/test/cli-bin.test.ts",
    reason:
      "starts real Node processes on src/cli.ts by path, with type stripping: it is about the source entry by construction. The packed bin is started the same ways by tools/sdk/test/install-smoke.test.ts",
  },
];

/**
 * Every test file of the compiled packages that starts a process or reads the source as text (review M1), with what
 * the compiled run does about it. A test of the SDK tooling fails when a file of that kind is not listed here.
 */
export const DIST_OUTSIDE_THE_GUARD: ReadonlyArray<{
  file: string;
  /** compiled: its child runs the compiled files. source-text: it reads source text only. excluded: not run. */
  runs: "compiled" | "source-text" | "excluded";
  how: string;
}> = [
  {
    file: "packages/shield-node/test/shield.test.ts",
    runs: "compiled",
    how: "starts fixtures/exit.mjs in a child process (three tests); in the compiled run AR_SDK_COMPILED_ROOT makes the test start it with plain node and the fixture import the compiled files. One more test of the file reads src as text (the import check): it is about the source in both runs",
  },
  {
    file: "packages/shield-node/test/fixtures/exit.mjs",
    runs: "compiled",
    how: "the child of shield.test.ts: imports the compiled emitter, transport and index when AR_SDK_COMPILED_ROOT is set, the source otherwise; the child guard refuses the source in the compiled run",
  },
  {
    file: "packages/protocol/test/entrypoints.test.ts",
    runs: "source-text",
    how: "its import-graph tests read the files of src as text; the exports they compare are those of the compiled entries in the compiled run",
  },
  {
    file: "packages/harden/test/cli-bin.test.ts",
    runs: "excluded",
    how: "starts src/cli.ts by path in child processes: left out (DIST_EXCLUDED); the packed command is started by install-smoke",
  },
];

interface PluginContext {
  resolve(source: string, importer?: string, options?: { skipSelf?: boolean }): Promise<{ id: string } | null>;
  error(message: string): never;
}

export interface DistRedirectPlugin {
  name: string;
  enforce: "pre";
  resolveId(this: PluginContext, source: string, importer?: string): Promise<string | { id: string } | null>;
  load(this: PluginContext, id: string): null;
}

const clean = (id: string): string => id.replace(/[?#].*$/, "").replace(/^\/@fs\//, "/");
const inside = (dir: string, path: string): boolean => {
  const rel = relative(dir, path);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
};

/** `buildRoot`: the folder holding one compiled folder per package short name. */
export function distRedirect(options: { repoRoot: string; buildRoot: string }): DistRedirectPlugin {
  // Real paths: Vite resolves relative imports to real paths, and one file under two names would be two modules.
  const repoRoot = realpathSync(options.repoRoot);
  const buildRoot = realpathSync(options.buildRoot);
  const srcOf = (pkg: SdkPackage) => join(repoRoot, "packages", pkg.short, "src");
  const builtOf = (pkg: SdkPackage) => join(buildRoot, pkg.short);
  /** The compiled file of a source module, or null when `path` is not a source module of a compiled package. */
  const compiled = (path: string): string | null => {
    for (const pkg of DIST_PACKAGES) {
      if (!inside(srcOf(pkg), path)) continue;
      const to = join(builtOf(pkg), relative(srcOf(pkg), path).replace(/\.ts$/, ".js"));
      if (!existsSync(to)) throw new Error(`no compiled file for ${relative(repoRoot, path)} (expected ${to})`);
      return to;
    }
    return null;
  };
  return {
    name: "airverse-sdk-dist-redirect",
    enforce: "pre",
    async resolveId(source, importer) {
      const from = importer === undefined ? undefined : clean(importer);
      // A package of ours by name: its compiled entry.
      for (const pkg of DIST_PACKAGES) {
        if (source !== pkg.name && !source.startsWith(`${pkg.name}/`)) continue;
        const entry = pkg.entries[`.${source.slice(pkg.name.length)}`];
        if (entry === undefined) return this.error(`${source} is not an entry of ${pkg.name}`);
        return join(builtOf(pkg), `${entry}.js`);
      }
      // A source module, by relative or absolute path.
      const path = clean(source);
      if (path.startsWith(".") && from !== undefined) {
        const target = compiled(resolve(dirname(from), path));
        if (target !== null) return target;
      } else if (isAbsolute(path)) {
        const target = compiled(path);
        if (target !== null) return target;
      }
      // A package imported by a compiled file: resolved from where its source lives, so node_modules is found.
      if (
        from !== undefined &&
        inside(buildRoot, from) &&
        !path.startsWith(".") &&
        !isAbsolute(path) &&
        !isBuiltin(path)
      ) {
        const short = relative(buildRoot, from).split(sep)[0];
        const pkg = DIST_PACKAGES.find((candidate) => candidate.short === short);
        if (pkg !== undefined) return this.resolve(source, join(srcOf(pkg), "index.ts"), { skipSelf: true });
      }
      return null;
    },
    load(id) {
      const path = clean(id);
      for (const pkg of DIST_PACKAGES) {
        if (inside(srcOf(pkg), path)) {
          return this.error(`a source module was loaded in a run on the compiled output: ${relative(repoRoot, path)}`);
        }
      }
      return null;
    },
  };
}
