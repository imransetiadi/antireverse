// Slice 23, criteria 1 and 2 (the shapes): the compiled output of each package, and the source manifests untouched.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { bareImports, buildAll, rewriteDeclarationSpecifiers, rewriteVendoredSpecifiers } from "../src/build.ts";
import { SDK_PACKAGES, sdkPackage } from "../src/packages.ts";
import { BUILD_MARKER } from "../src/safe.ts";
import { filesOf, layoutIn, tempBase } from "./helpers.ts";

const base = tempBase("build");
const layout = layoutIn(base, "a");
const dist = (short: string) => layout.dist(sdkPackage(short));
const sourceFiles = (short: string) => filesOf(join(REPO_ROOT, "packages", short, "src"));
const read = (short: string, file: string) => readFileSync(join(dist(short), file), "utf8");

beforeAll(async () => {
  await buildAll(layout);
});

describe("the compiled packages", () => {
  it.each(["protocol", "shield-node", "harden"])(
    "%s: one .js per source module, and nothing else but declarations",
    (short) => {
      const built = filesOf(dist(short)).filter((file) => !file.startsWith("_protocol/"));
      const js = built.filter((file) => file.endsWith(".js"));
      expect(js).toEqual(sourceFiles(short).map((file) => file.replace(/\.ts$/, ".js")));
      expect(built.filter((file) => !file.endsWith(".js") && !file.endsWith(".d.ts"))).toEqual([BUILD_MARKER]);
      expect(built).toContain("index.js");
      expect(built).toContain("index.d.ts");
    },
  );

  it("no compiled file names a .ts module, in code or in declarations", () => {
    for (const pkg of SDK_PACKAGES) {
      for (const file of filesOf(dist(pkg.short))) {
        if (file === BUILD_MARKER) continue;
        const text = read(pkg.short, file);
        expect(text, `${pkg.short}/${file}`).not.toMatch(/(?:from\s*|import\s*\(?\s*)["'][^"']+(?<!\.d)\.ts["']/);
      }
    }
  });

  it("every relative import of a compiled file leads to a compiled file", () => {
    for (const pkg of SDK_PACKAGES) {
      const built = new Set(filesOf(dist(pkg.short)));
      for (const file of built) {
        if (file === BUILD_MARKER) continue;
        const text = read(pkg.short, file);
        for (const match of text.matchAll(/(?:from\s*|import\s*\(\s*)["'](\.{1,2}\/[^"']+)["']/g)) {
          const target = join(file, "..", match[1] as string).replace(/\\/g, "/");
          const wanted = file.endsWith(".d.ts") ? target.replace(/\.js$/, ".d.ts") : target;
          expect(built.has(wanted), `${pkg.short}/${file} imports ${match[1]}`).toBe(true);
        }
      }
    }
  });

  it("Shield: the declarations are the four its entry reaches, and nothing names another @antireverse package", () => {
    const built = filesOf(dist("shield-node"));
    expect(built.filter((file) => file.endsWith(".d.ts"))).toEqual([
      "counters.d.ts",
      "index.d.ts",
      "shield.d.ts",
      "types.d.ts",
    ]);
    for (const file of built) {
      if (file === BUILD_MARKER) continue;
      expect(bareImports(read("shield-node", file)), file).toEqual([]);
      // Not even in a comment: no other @antireverse package is named anywhere in the packed Shield.
      expect(read("shield-node", file), file).not.toMatch(/@antireverse\/(?!shield-node\b)/);
    }
  });

  it("Shield's compiled code imports only Node's own modules; the protocol's zod; Harden's Babel and, through its copy of the protocol, zod", () => {
    const packagesOf = (short: string) =>
      [
        ...new Set(
          filesOf(dist(short))
            .filter((f) => f.endsWith(".js"))
            .flatMap((f) => bareImports(read(short, f))),
        ),
      ].sort();
    expect(packagesOf("shield-node")).toEqual([]);
    expect(packagesOf("guard")).toEqual([]);
    expect(packagesOf("protocol")).toEqual(["zod"]);
    expect(packagesOf("harden")).toEqual([
      "@babel/generator",
      "@babel/parser",
      "@babel/traverse",
      "@babel/types",
      "zod",
    ]);
  });

  it("Harden carries the compiled protocol, byte for byte, and imports it by relative path: no @antireverse specifier is left (D-140)", () => {
    const protocol = filesOf(dist("protocol")).filter((file) => file !== BUILD_MARKER);
    const copy = filesOf(dist("harden")).filter((file) => file.startsWith("_protocol/"));
    expect(copy).toEqual(protocol.map((file) => `_protocol/${file}`));
    for (const file of protocol) expect(read("harden", `_protocol/${file}`), file).toBe(read("protocol", file));
    for (const file of filesOf(dist("harden"))) {
      if (file === BUILD_MARKER) continue;
      // Declarations too: bareImports reads `import type … from` like any other import.
      expect(
        bareImports(read("harden", file)).filter((name) => name.startsWith("@antireverse/")),
        file,
      ).toEqual([]);
    }
    expect(read("harden", "engine.js")).toContain('from "./_protocol/server.js"');
    expect(read("harden", "leaks/scan.js")).toContain('from "../_protocol/index.js"');
    expect(read("harden", "types.d.ts")).toContain('from "./_protocol/index.js"');
    // The source still imports the package by name.
    expect(readFileSync(join(REPO_ROOT, "packages/harden/src/engine.ts"), "utf8")).toContain(
      'from "@antireverse/protocol/server"',
    );
  });

  it("Harden's command keeps its first line, so the file runs as a command", () => {
    expect(read("harden", "cli.js").startsWith("#!/usr/bin/env node\n")).toBe(true);
  });

  it("Guard is copied byte for byte", () => {
    const src = join(REPO_ROOT, "packages/guard/src");
    expect(filesOf(dist("guard")).filter((file) => file !== BUILD_MARKER)).toEqual(filesOf(src));
    for (const file of filesOf(src)) expect(read("guard", file)).toBe(readFileSync(join(src, file), "utf8"));
  });
});

describe("rewriteDeclarationSpecifiers", () => {
  it("turns relative .ts specifiers into .js and leaves everything else", () => {
    const before = [
      'import { type A } from "./a.ts";',
      'export { b } from "../b/index.ts";',
      'export type C = import("./c.ts").C;',
      'import type { Z } from "zod";',
      'import type { D } from "./d.d.ts";',
      "/** see ./e.ts */",
    ].join("\n");
    expect(rewriteDeclarationSpecifiers(before)).toBe(
      [
        'import { type A } from "./a.js";',
        'export { b } from "../b/index.js";',
        'export type C = import("./c.js").C;',
        'import type { Z } from "zod";',
        'import type { D } from "./d.d.ts";',
        "/** see ./e.ts */",
      ].join("\n"),
    );
  });
});

describe("rewriteVendoredSpecifiers", () => {
  const protocol = sdkPackage("protocol");
  it("turns imports of the vendored package into relative paths, by depth, and leaves comments and other packages", () => {
    const before = [
      'import { a } from "@antireverse/protocol";',
      'import type { B } from "@antireverse/protocol/server";',
      'export type C = import("@antireverse/protocol").C;',
      'import { z } from "zod";',
      "// Equal to the constant of @antireverse/protocol.",
      'import { d } from "@antireverse/protocol-extra";',
    ].join("\n");
    expect(rewriteVendoredSpecifiers(before, 0, protocol)).toBe(
      [
        'import { a } from "./_protocol/index.js";',
        'import type { B } from "./_protocol/server.js";',
        'export type C = import("./_protocol/index.js").C;',
        'import { z } from "zod";',
        "// Equal to the constant of @antireverse/protocol.",
        'import { d } from "@antireverse/protocol-extra";',
      ].join("\n"),
    );
    expect(rewriteVendoredSpecifiers('export * from "@antireverse/protocol";', 2, protocol)).toBe(
      'export * from "../../_protocol/index.js";',
    );
    expect(() => rewriteVendoredSpecifiers('import x from "@antireverse/protocol/internal";', 0, protocol)).toThrow(
      /not an entry/,
    );
  });
});

describe("bareImports", () => {
  it("names the packages a module imports, not Node's own modules, relative files or words in comments", () => {
    const source = [
      'import { a } from "node:fs";',
      'import b from "./b.js";',
      "import {",
      "  c,",
      '} from "@scope/pkg/deep";',
      'export * from "plain/sub";',
      'const d = await import("lazy");',
      'import "side-effect";',
      '// import x from "commented";',
      '/* export * from "blocked"; */',
      'const text = "import y from \\"quoted\\"";',
    ].join("\n");
    expect(bareImports(source)).toEqual(["@scope/pkg", "lazy", "plain", "side-effect"]);
  });
});

describe("the workspace shape is untouched", () => {
  it("the source manifests still export the TypeScript source and are private", () => {
    const manifest = (short: string) =>
      JSON.parse(readFileSync(join(REPO_ROOT, "packages", short, "package.json"), "utf8"));
    expect(manifest("protocol").exports).toEqual({ ".": "./src/index.ts", "./server": "./src/server.ts" });
    expect(manifest("shield-node").exports).toEqual({ ".": "./src/index.ts" });
    expect(manifest("harden").exports).toEqual({ ".": "./src/index.ts" });
    expect(manifest("harden").bin).toEqual({ antireverse: "./src/cli.ts" });
    expect(manifest("guard").exports).toEqual({ ".": { types: "./src/index.d.ts", default: "./src/index.js" } });
    for (const pkg of SDK_PACKAGES) expect(manifest(pkg.short).private).toBe(true);
  });

  it("inside the repository the packages resolve to their TypeScript source", async () => {
    expect(import.meta.resolve("@antireverse/shield-node")).toMatch(/packages\/shield-node\/src\/index\.ts$/);
    expect(import.meta.resolve("@antireverse/protocol/server")).toMatch(/packages\/protocol\/src\/server\.ts$/);
    expect(import.meta.resolve("@antireverse/harden")).toMatch(/packages\/harden\/src\/index\.ts$/);
    expect(import.meta.resolve("@antireverse/guard")).toMatch(/packages\/guard\/src\/index\.js$/);
  });
});
