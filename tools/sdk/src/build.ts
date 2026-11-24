// The build (slice 23, D-128, D-129): protocol, shield-node and harden compiled by tsc into a given folder, Guard's
// plain modules copied. Nothing is written beside the folder it is given. After tsc:
//   - relative `.ts` specifiers in declaration files become `.js` (tsc rewrites them in JavaScript only);
//   - declaration files that no public entry reaches are removed: nobody can import them through the package's
//     exports, and for Shield they are the only files that mention the protocol;
//   - the result is checked: one .js per source module, no other file;
//   - a package that vendors another (Harden vendors the protocol, D-140) gets that package's compiled files copied
//     into dist/_<name>, and its own imports of that package rewritten to relative paths.
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { isBuiltin } from "node:module";
import { dirname, join, relative } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { exec } from "./exec.ts";
import { SDK_PACKAGES, type SdkPackage, sdkPackage } from "./packages.ts";
import { BUILD_MARKER, type Layout, prepareBuildDir } from "./safe.ts";

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}

/** `from "./x.ts"`, `import("./x.ts")` → `.js`, in a declaration file. Declaration specifiers (`.d.ts`) stay. */
export function rewriteDeclarationSpecifiers(text: string): string {
  return text.replace(
    /((?:\bfrom\s*|\bimport\s*\(\s*)["'])(\.{1,2}\/[^"']+?)(?<!\.d)\.ts(["'])/g,
    (_all, head: string, path: string, tail: string) => `${head}${path}.js${tail}`,
  );
}

/** The source without comments: block comments, and lines that are a comment. */
function withoutComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("//"))
    .join("\n");
}

function specifiers(source: string): string[] {
  const code = withoutComments(source);
  const found: string[] = [];
  for (const match of code.matchAll(/^[ \t]*(?:import|export)\s[^;'"]*?\bfrom\s*["']([^"']+)["']/gm))
    found.push(match[1] as string);
  for (const match of code.matchAll(/^[ \t]*import\s*["']([^"']+)["']/gm)) found.push(match[1] as string);
  for (const match of code.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)) {
    // A dynamic import inside a string literal ("… import(\"x\") …") is text, not code.
    const before = code.slice(Math.max(0, (match.index ?? 0) - 1), match.index ?? 0);
    if (before !== "\\" && before !== '"' && before !== "'") found.push(match[1] as string);
  }
  return found;
}

/** The npm packages a compiled module imports: sorted, without Node's own modules and relative files. */
export function bareImports(source: string): string[] {
  const names = new Set<string>();
  for (const specifier of specifiers(source)) {
    if (specifier.startsWith(".") || specifier.startsWith("/") || isBuiltin(specifier)) continue;
    const parts = specifier.split("/");
    names.add(specifier.startsWith("@") ? `${parts[0]}/${parts[1]}` : (parts[0] as string));
  }
  return [...names].sort();
}

/** The declaration files reachable from the package's public entries. */
function reachableDeclarations(distDir: string, pkg: SdkPackage): Set<string> {
  const seen = new Set<string>();
  const visit = (file: string): void => {
    if (seen.has(file)) return;
    if (!existsSync(file)) throw new Error(`${pkg.name}: the declaration ${relative(distDir, file)} is missing`);
    seen.add(file);
    for (const specifier of specifiers(readFileSync(file, "utf8"))) {
      if (specifier.startsWith(".")) visit(join(dirname(file), specifier.replace(/\.js$/, ".d.ts")));
    }
  };
  for (const entry of Object.values(pkg.entries)) visit(join(distDir, `${entry}.d.ts`));
  return seen;
}

export async function buildPackage(pkg: SdkPackage, distDir: string): Promise<void> {
  const packageDir = join(REPO_ROOT, "packages", pkg.short);
  const srcDir = join(packageDir, "src");
  prepareBuildDir(distDir);
  if (pkg.kind === "copy") {
    for (const file of walk(srcDir)) {
      const to = join(distDir, relative(srcDir, file));
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(file, to);
    }
  } else {
    const tsc = join(REPO_ROOT, "node_modules/typescript/bin/tsc");
    const result = await exec(
      process.execPath,
      [tsc, "-p", join(packageDir, "tsconfig.build.json"), "--outDir", distDir],
      {
        cwd: packageDir,
      },
    );
    if (result.code !== 0)
      throw new Error(`tsc failed for ${pkg.name} (exit ${result.code}):\n${result.stdout}${result.stderr}`);
    for (const file of walk(distDir)) {
      if (!file.endsWith(".d.ts")) continue;
      const text = readFileSync(file, "utf8");
      const rewritten = rewriteDeclarationSpecifiers(text);
      if (rewritten !== text) writeFileSync(file, rewritten);
    }
    const keep = reachableDeclarations(distDir, pkg);
    for (const file of walk(distDir)) if (file.endsWith(".d.ts") && !keep.has(file)) rmSync(file);
  }
  // What must be there, and nothing else.
  const built = walk(distDir).map((file) => relative(distDir, file));
  const expected = walk(srcDir)
    .map((file) => relative(srcDir, file))
    .filter((file) => pkg.kind === "copy" || !file.endsWith(".d.ts"))
    .map((file) => (pkg.kind === "copy" ? file : file.replace(/\.ts$/, ".js")));
  const modules = built.filter((file) => (pkg.kind === "copy" ? file !== BUILD_MARKER : file.endsWith(".js")));
  const missing = expected.filter((file) => !modules.includes(file));
  const extra = modules.filter((file) => !expected.includes(file));
  const strangers = built.filter(
    (file) => pkg.kind === "tsc" && !file.endsWith(".js") && !file.endsWith(".d.ts") && file !== BUILD_MARKER,
  );
  if (missing.length + extra.length + strangers.length > 0) {
    throw new Error(
      `${pkg.name}: the build is not what the source says (missing: ${missing.join(", ") || "none"}; unexpected: ${[...extra, ...strangers].join(", ") || "none"})`,
    );
  }
  for (const name of [...Object.values(pkg.entries), ...Object.values(pkg.bin ?? {})]) {
    if (!built.includes(`${name}.js`)) throw new Error(`${pkg.name}: the entry ${name}.js was not built`);
  }
  for (const name of Object.values(pkg.entries)) {
    if (!built.includes(`${name}.d.ts`)) throw new Error(`${pkg.name}: the declaration ${name}.d.ts was not built`);
  }
}

/** The folder inside a package's dist that holds a vendored package. */
export const vendorDirOf = (vendored: SdkPackage): string => `_${vendored.short}`;

/**
 * Imports of a vendored package, in a compiled file `depth` folders below dist, as relative paths into its copy:
 * `"@antireverse/protocol/server"` → `"./_protocol/server.js"`. Specifiers only: text in comments stays.
 */
export function rewriteVendoredSpecifiers(text: string, depth: number, vendored: SdkPackage): string {
  const up = depth === 0 ? "./" : "../".repeat(depth);
  const escaped = vendored.name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  return text.replace(
    new RegExp(`((?:\\bfrom\\s*|\\bimport\\s*\\(\\s*)["'])${escaped}(/[^"']*)?(["'])`, "g"),
    (_all, head: string, sub: string | undefined, tail: string) => {
      const entry = vendored.entries[`.${sub ?? ""}`];
      if (entry === undefined) throw new Error(`${vendored.name}${sub ?? ""} is not an entry of the vendored package`);
      return `${head}${up}${vendorDirOf(vendored)}/${entry}.js${tail}`;
    },
  );
}

/** Copies each vendored package's compiled files into `pkg`'s dist and rewrites `pkg`'s imports of it. */
function vendor(pkg: SdkPackage, layout: Layout): void {
  const distDir = layout.dist(pkg);
  for (const name of pkg.vendors ?? []) {
    const vendored = sdkPackage(name);
    const own = walk(distDir);
    for (const file of own) {
      const depth = relative(distDir, dirname(file)).split(/[\\/]/).filter(Boolean).length;
      const text = readFileSync(file, "utf8");
      const rewritten = rewriteVendoredSpecifiers(text, depth, vendored);
      if (rewritten !== text) writeFileSync(file, rewritten);
    }
    const from = layout.dist(vendored);
    for (const file of walk(from)) {
      const rel = relative(from, file);
      if (rel === BUILD_MARKER) continue;
      const to = join(distDir, vendorDirOf(vendored), rel);
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(file, to);
    }
  }
}

/** Builds the four packages, each into its folder of the layout, then vendors what is vendored. */
export async function buildAll(layout: Layout): Promise<void> {
  await Promise.all(SDK_PACKAGES.map((pkg) => buildPackage(pkg, layout.dist(pkg))));
  for (const pkg of SDK_PACKAGES) vendor(pkg, layout);
}
