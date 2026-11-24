// Staging (slice 23, D-128): the published shape of a package, made in a folder of its own from the compiled files.
// The source package.json is read, never written. The staged manifest points at ./dist, keeps "private": true (so
// `npm publish` refuses it: nothing here is a release, D-130) and lists runtime dependencies only: the source
// manifest's `dependencies` and those of the packages it vendors, all of which must be exact versions. No packed
// package depends on another @antireverse package (D-140): compiled code that still imports one fails the staging.
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { bareImports } from "./build.ts";
import { SDK_NAMES, SDK_PACKAGES, type SdkPackage, sdkPackage } from "./packages.ts";
import { BUILD_MARKER, type Layout, prepareBuildDir } from "./safe.ts";

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

interface SourceManifest {
  name: string;
  version: string;
  private?: boolean;
  license?: string;
  type?: string;
  sideEffects?: boolean;
  dependencies?: Record<string, string>;
}

export interface StagedPackage {
  pkg: SdkPackage;
  version: string;
  /** The staging folder: what `npm pack` packs. */
  dir: string;
  manifest: Record<string, unknown>;
  dependencies: Record<string, string>;
  /** The SDK packages whose compiled files this one carries. */
  vendored: string[];
  /** Declared in the source manifest but imported by no compiled module. Kept: the dependency set is the source's. */
  unusedDependencies: string[];
}

export function readSourceManifest(pkg: SdkPackage): SourceManifest {
  return JSON.parse(readFileSync(join(REPO_ROOT, "packages", pkg.short, "package.json"), "utf8")) as SourceManifest;
}

/** The one version of the four packages (D-130); throws when they differ. */
export function sdkVersion(): string {
  const versions = SDK_PACKAGES.map((pkg) => `${pkg.name} ${readSourceManifest(pkg).version}`);
  const distinct = new Set(SDK_PACKAGES.map((pkg) => readSourceManifest(pkg).version));
  if (distinct.size !== 1) throw new Error(`the SDK packages do not share one version: ${versions.join(", ")}`);
  const version = [...distinct][0] as string;
  if (!EXACT_VERSION.test(version)) throw new Error(`not a version: ${version}`);
  return version;
}

/**
 * The packed package.json. `imports`: the npm packages the compiled JavaScript imports (its vendored copies
 * included); `vendored`: the source manifests of the packages it vendors.
 */
export function stagedManifest(
  pkg: SdkPackage,
  source: SourceManifest,
  imports: readonly string[],
  version: string,
  vendored: readonly SourceManifest[] = [],
  engines: string = REPO_NODE,
): { manifest: Record<string, unknown>; dependencies: Record<string, string>; unused: string[] } {
  if (source.name !== pkg.name) throw new Error(`${pkg.short}: the source manifest is named ${source.name}`);
  if (source.private !== true) throw new Error(`${pkg.name}: the source manifest is not private`);
  const declared = source.dependencies ?? {};
  const dependencies: Record<string, string> = {};
  for (const from of [source, ...vendored]) {
    for (const [name, range] of Object.entries(from.dependencies ?? {})) {
      if (!EXACT_VERSION.test(range))
        throw new Error(`${from.name}: the dependency ${name} is not pinned to an exact version (${range})`);
      if (dependencies[name] !== undefined && dependencies[name] !== range) {
        throw new Error(`${pkg.name}: ${name} is wanted at ${dependencies[name]} and, by ${from.name}, at ${range}`);
      }
      dependencies[name] = range;
    }
  }
  for (const name of imports) {
    if (name === pkg.name) continue;
    if (SDK_NAMES.includes(name)) {
      throw new Error(
        `${pkg.name}: the compiled code imports ${name}; a packed package may not depend on another @antireverse package (D-140): vendor it`,
      );
    }
    if (!(name in dependencies))
      throw new Error(`${pkg.name}: the compiled code imports ${name}, which is not a dependency`);
  }
  if (pkg.zeroDependencies && Object.keys(dependencies).length > 0) {
    throw new Error(
      `${pkg.name} must have no runtime dependency (SC-SUP-03), found ${Object.keys(dependencies).join(", ")}`,
    );
  }
  const sorted = Object.fromEntries(Object.entries(dependencies).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  const exports: Record<string, { types: string; default: string }> = {};
  for (const [subpath, entry] of Object.entries(pkg.entries)) {
    exports[subpath] = { types: `./dist/${entry}.d.ts`, default: `./dist/${entry}.js` };
  }
  const manifest: Record<string, unknown> = {
    name: pkg.name,
    version,
    private: true,
    description: pkg.description,
    license: source.license,
    type: source.type,
    ...(source.sideEffects === undefined ? {} : { sideEffects: source.sideEffects }),
    engines: { node: engines },
    exports,
    types: `./dist/${pkg.entries["."]}.d.ts`,
    ...(pkg.bin
      ? { bin: Object.fromEntries(Object.entries(pkg.bin).map(([name, entry]) => [name, `./dist/${entry}.js`])) }
      : {}),
    files: ["dist", "NOTICE"],
    dependencies: sorted,
  };
  return { manifest, dependencies: sorted, unused: Object.keys(declared).filter((name) => !imports.includes(name)) };
}

/** The repository's own minimum Node version (root package.json). */
const REPO_NODE = ">=22.12";

/**
 * The Node range a packed package declares (D-142): the one its direct dependencies declare, so that the package
 * never promises more than what it depends on supports; the repository's minimum when none of them declares one.
 * Dependencies that disagree are refused: a person has to look.
 */
export function enginesOf(dependencyRanges: ReadonlyArray<string | undefined>): string {
  const distinct = [...new Set(dependencyRanges.filter((range): range is string => typeof range === "string"))];
  if (distinct.length === 0) return REPO_NODE;
  if (distinct.length > 1) throw new Error(`the dependencies declare different Node ranges: ${distinct.join(" / ")}`);
  return distinct[0] as string;
}

/** The engines.node of an installed direct dependency of `pkg`, read from node_modules. */
function dependencyEngines(pkg: SdkPackage, name: string): string | undefined {
  for (const base of [join(REPO_ROOT, "packages", pkg.short), REPO_ROOT]) {
    const manifest = join(base, "node_modules", name, "package.json");
    if (existsSync(manifest)) {
      return (JSON.parse(readFileSync(manifest, "utf8")) as { engines?: { node?: string } }).engines?.node;
    }
  }
  throw new Error(`${pkg.name}: the dependency ${name} is not installed, so its Node range cannot be read`);
}

const MD_LINK = /\[([^\]]+)\]\((?!#|https?:)([^)#\s]+)(?:#[^)]*)?\)/g;

/**
 * A guide from docs/ as it goes into a tarball (D-137, review L8). The guides are written for the repository; a
 * packed README must not need it: what is said about getting the package becomes one sentence, the clone's commands
 * and paths become the installed package's, and a link to another file becomes its text and where that file is.
 * Each replacement must find its text: when a guide changes so that one does not, staging fails.
 */
export function packedGuide(pkg: SdkPackage, guide: string): string {
  let text = guide;
  const must = (pattern: RegExp, replacement: string): void => {
    const next = text.replace(pattern, replacement);
    if (next === text)
      throw new Error(`${pkg.guide} no longer holds ${pattern}: update packedGuide in tools/sdk/src/stage.ts`);
    text = next;
  };
  if (pkg.short === "shield-node") {
    must(
      /^`@antireverse\/shield-node` is not published to npm yet;.*$/m,
      "This is `@antireverse/shield-node`, installed from its tarball: plain JavaScript with no dependency, for Node 22.12 and newer.",
    );
  } else if (pkg.short === "guard") {
    must(
      /^`@antireverse\/guard` is not published to npm yet\..*$/m,
      "This is `@antireverse/guard`, installed from its tarball. Its files are in `node_modules/@antireverse/guard/dist`.",
    );
    must(/packages\/guard\/src/g, "node_modules/@antireverse/guard/dist");
  } else if (pkg.short === "harden") {
    must(
      /^## Running it\n[\s\S]*?(?=^## )/m,
      "## Running it\n\nRun it as `npx antireverse …` in the project where this package is installed. `npx antireverse --help` prints the full list of options and exit codes. Babel, which Harden depends on, supports Node 22.18 and newer (not 23, and 24 from 24.11): on Node 22.12 npm warns at install and the command was seen to work.\n\n",
    );
    must(/npx tsx packages\/harden\/src\/cli\.ts/g, "npx antireverse");
  }
  text = text.replace(MD_LINK, (_all, label: string, file: string) => {
    const name = file.replace(/^(\.\.\/)+/, "").replace(/^docs\//, "");
    return `${label} (\`${/^[A-Z]+\.md$/.test(name) ? name : `docs/${name}`}\` in the Airverse repository)`;
  });
  return text;
}

/** The README of a tarball (D-137): a generated header, then the package's guide from docs/, made to fit. */
export function stagedReadme(pkg: SdkPackage, version: string): string {
  const header = [
    `# ${pkg.name}`,
    "",
    `> Version ${version}, built from the Airverse repository by \`npm run sdk:pack\`. **Pre-release:** this package is not published to npm and this tarball is not a release. It comes with a signed manifest (\`sdk-manifest.json\`) and a bill of materials; the signature is a local one by whoever built it, not provenance. The guide below is the repository's, with its commands and paths written for the installed package.`,
    "",
  ].join("\n");
  if (pkg.guide === undefined) {
    return `${header}\n${pkg.description} \`@antireverse/harden\` carries its own copy of it, so installing Harden does not need this package.\n`;
  }
  return `${header}\n---\n\n${packedGuide(pkg, readFileSync(join(REPO_ROOT, pkg.guide), "utf8"))}`;
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}

export function stageDir(layout: Layout, pkg: SdkPackage): string {
  return join(layout.work, "stage", pkg.short);
}

/** Writes the staging folder of one package from its compiled files. */
export function stagePackage(pkg: SdkPackage, distDir: string, dir: string, version: string): StagedPackage {
  const files = walk(distDir).filter((file) => relative(distDir, file) !== BUILD_MARKER);
  const imports = new Set<string>();
  for (const file of files)
    if (file.endsWith(".js")) for (const name of bareImports(readFileSync(file, "utf8"))) imports.add(name);
  const vendored = (pkg.vendors ?? []).map((name) => readSourceManifest(sdkPackage(name)));
  const source = readSourceManifest(pkg);
  // The Node range of the package's own direct dependencies (what it vendors is ours and adds none).
  const engines = enginesOf(Object.keys(source.dependencies ?? {}).map((name) => dependencyEngines(pkg, name)));
  const { manifest, dependencies, unused } = stagedManifest(
    pkg,
    source,
    [...imports].sort(),
    version,
    vendored,
    engines,
  );
  const executables = new Set(Object.values(pkg.bin ?? {}).map((entry) => `${entry}.js`));
  // Inside the work folder, which stageAll has just emptied: nothing is removed here.
  if (existsSync(dir)) throw new Error(`the staging folder ${dir} exists already`);
  mkdirSync(dir, { recursive: true });
  const put = (to: string, write: () => void, mode: number): void => {
    mkdirSync(dirname(to), { recursive: true });
    write();
    chmodSync(to, mode);
  };
  for (const file of files) {
    const rel = relative(distDir, file);
    const to = join(dir, "dist", rel);
    put(to, () => copyFileSync(file, to), executables.has(rel) ? 0o755 : 0o644);
  }
  for (const name of ["LICENSE", "NOTICE"])
    put(join(dir, name), () => copyFileSync(join(REPO_ROOT, name), join(dir, name)), 0o644);
  put(join(dir, "README.md"), () => writeFileSync(join(dir, "README.md"), stagedReadme(pkg, version)), 0o644);
  put(
    join(dir, "package.json"),
    () => writeFileSync(join(dir, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`),
    0o644,
  );
  return { pkg, version, dir, manifest, dependencies, vendored: [...(pkg.vendors ?? [])], unusedDependencies: unused };
}

/** Stages the four packages below the layout's work folder, which is emptied first. */
export function stageAll(layout: Layout): StagedPackage[] {
  const version = sdkVersion();
  prepareBuildDir(layout.work);
  return SDK_PACKAGES.map((pkg) => stagePackage(pkg, layout.dist(pkg), stageDir(layout, pkg), version));
}
