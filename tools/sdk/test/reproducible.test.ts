// Slice 23, criteria 2 and 3: the packed shape, and two clean builds giving byte-identical tarballs.
import { chmodSync, readFileSync, utimesSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { buildAll } from "../src/build.ts";
import { type PackedTarball, packStaged } from "../src/pack.ts";
import { SDK_PACKAGES, sdkPackage } from "../src/packages.ts";
import { BUILD_MARKER } from "../src/safe.ts";
import { enginesOf, packedGuide, type StagedPackage, sdkVersion, stageAll, stagedManifest } from "../src/stage.ts";
import { filesOf, layoutIn, tarEntries, tempBase } from "./helpers.ts";

const base = tempBase("repro");
const first = layoutIn(base, "first");
const second = layoutIn(base, "second-in-a-folder-with-another-name");
let stagedA: StagedPackage[];
let packedA: PackedTarball[];
let packedB: PackedTarball[];

beforeAll(async () => {
  await buildAll(first);
  stagedA = stageAll(first);
  packedA = await packStaged(stagedA, first);
  // A second clean build, somewhere else, whose compiled files then get other modes and other times.
  await buildAll(second);
  for (const pkg of SDK_PACKAGES) {
    for (const file of filesOf(second.dist(pkg))) {
      const path = join(second.dist(pkg), file);
      chmodSync(path, file.endsWith(".d.ts") ? 0o600 : 0o775);
      utimesSync(path, new Date("2001-02-03T04:05:06Z"), new Date("2001-02-03T04:05:06Z"));
    }
  }
  packedB = await packStaged(stageAll(second), second);
});

describe("reproducible tarballs", () => {
  it("two clean builds give the same four files, byte for byte", () => {
    expect(packedA.map((t) => t.file)).toEqual(
      ["protocol", "shield-node", "guard", "harden"].map((name) => `antireverse-${name}-${sdkVersion()}.tgz`),
    );
    expect(packedB.map((t) => [t.file, t.size, t.sha256])).toEqual(packedA.map((t) => [t.file, t.size, t.sha256]));
    for (const [index, a] of packedA.entries()) {
      expect(readFileSync(a.path).equals(readFileSync((packedB[index] as PackedTarball).path)), a.file).toBe(true);
    }
  });

  it("the output folder holds the four tarballs and the marker, nothing else", () => {
    expect(filesOf(first.out)).toEqual([BUILD_MARKER, ...packedA.map((t) => t.file)].sort());
  });

  it("every entry has npm's fixed time and owner, mode 644, and 755 for the command", () => {
    for (const tarball of packedA) {
      const entries = tarEntries(gunzipSync(readFileSync(tarball.path)));
      expect(entries.length).toBeGreaterThan(3);
      for (const entry of entries) {
        expect([entry.uid, entry.gid], `${tarball.file} ${entry.name}`).toEqual([0, 0]);
        // 1985-10-26T08:15:00Z, the time npm gives every packed file.
        expect(entry.mtime, `${tarball.file} ${entry.name}`).toBe(499_162_500);
        expect(entry.mode & 0o777, `${tarball.file} ${entry.name}`).toBe(
          entry.name === "package/dist/cli.js" ? 0o755 : 0o644,
        );
      }
    }
  });
});

describe("the packed shape", () => {
  const entriesOf = (short: string) =>
    tarEntries(gunzipSync(readFileSync((packedA.find((t) => t.name === sdkPackage(short).name) as PackedTarball).path)))
      .map((entry) => entry.name)
      .sort();
  const staged = (short: string) => stagedA.find((entry) => entry.pkg.short === short) as StagedPackage;

  it("each tarball holds package.json, README.md, LICENSE, NOTICE and dist/, and no TypeScript source", () => {
    for (const pkg of SDK_PACKAGES) {
      const names = entriesOf(pkg.short);
      const top = names.filter((name) => !name.startsWith("package/dist/"));
      expect(top, pkg.short).toEqual([
        "package/LICENSE",
        "package/NOTICE",
        "package/README.md",
        "package/package.json",
      ]);
      expect(
        names.filter((name) => name.endsWith(".ts") && !name.endsWith(".d.ts")),
        pkg.short,
      ).toEqual([]);
      expect(
        names.filter((name) => /node_modules|\.test\.|\/test\/|\/bench\/|tsconfig|\.airverse/.test(name)),
        pkg.short,
      ).toEqual([]);
      expect(names, pkg.short).toContain("package/dist/index.js");
      expect(names, pkg.short).toContain("package/dist/index.d.ts");
    }
    expect(entriesOf("harden")).toContain("package/dist/cli.js");
    expect(entriesOf("harden")).toContain("package/dist/_protocol/server.js");
    expect(entriesOf("protocol")).toContain("package/dist/server.d.ts");
  });

  it("the manifests point at ./dist, keep private, share one version and list runtime dependencies only", () => {
    const version = sdkVersion();
    expect(staged("protocol").manifest).toEqual({
      name: "@antireverse/protocol",
      version,
      private: true,
      description: sdkPackage("protocol").description,
      license: "Apache-2.0",
      type: "module",
      engines: { node: ">=22.12" },
      exports: {
        ".": { types: "./dist/index.d.ts", default: "./dist/index.js" },
        "./server": { types: "./dist/server.d.ts", default: "./dist/server.js" },
      },
      types: "./dist/index.d.ts",
      files: ["dist", "NOTICE"],
      dependencies: { zod: "4.6.7" },
    });
    expect(staged("shield-node").manifest).toMatchObject({
      name: "@antireverse/shield-node",
      version,
      private: true,
      exports: { ".": { types: "./dist/index.d.ts", default: "./dist/index.js" } },
      dependencies: {},
    });
    expect(staged("guard").manifest).toMatchObject({
      name: "@antireverse/guard",
      version,
      private: true,
      sideEffects: false,
      exports: { ".": { types: "./dist/index.d.ts", default: "./dist/index.js" } },
      dependencies: {},
    });
    expect(staged("harden").manifest).toMatchObject({
      name: "@antireverse/harden",
      version,
      private: true,
      bin: { antireverse: "./dist/cli.js" },
    });
    // Babel from its own manifest, zod from the protocol it carries; no @antireverse package (D-140).
    expect(staged("harden").manifest.dependencies).toEqual({
      "@babel/generator": "8.1.0",
      "@babel/parser": "8.1.0",
      "@babel/traverse": "8.1.0",
      "@babel/types": "8.1.0",
      zod: "4.6.7",
    });
    expect(staged("harden").vendored).toEqual(["@antireverse/protocol"]);
    for (const entry of stagedA) {
      expect(
        Object.keys(entry.dependencies).filter((name) => name.startsWith("@antireverse/")),
        entry.pkg.short,
      ).toEqual([]);
      expect(Object.keys(entry.manifest), entry.pkg.short).not.toContain("devDependencies");
      expect(Object.keys(entry.manifest), entry.pkg.short).not.toContain("scripts");
      expect(JSON.stringify(entry.manifest), entry.pkg.short).not.toMatch(/src\/|\.ts"(?<!\.d\.ts")|workspace|"\*"/);
      // The packed manifest is the staged one, byte for byte.
      expect(JSON.parse(readFileSync(join(entry.dir, "package.json"), "utf8"))).toEqual(entry.manifest);
    }
  });

  // Review S1 (slice 23b): every declared dependency is imported by the compiled code — nothing is installed for nothing.
  it("no packed package declares a dependency its compiled code does not import", () => {
    for (const entry of stagedA) expect(entry.unusedDependencies, entry.pkg.short).toEqual([]);
  });

  it("refuses a dependency that is a range, an import that is not declared, and any dependency of Shield or Guard", () => {
    const source = {
      name: "@antireverse/harden",
      version: "0.0.0",
      private: true,
      license: "Apache-2.0",
      type: "module",
    };
    const harden = sdkPackage("harden");
    expect(() => stagedManifest(harden, { ...source, dependencies: { zod: "^4.6.7" } }, [], "0.0.0")).toThrow(
      /exact version/,
    );
    expect(() => stagedManifest(harden, { ...source, dependencies: {} }, ["left-pad"], "0.0.0")).toThrow(
      /left-pad.*not a dependency/,
    );
    expect(() => stagedManifest(harden, { ...source, private: false }, [], "0.0.0")).toThrow(/not private/);
    const shield = sdkPackage("shield-node");
    const shieldSource = { ...source, name: "@antireverse/shield-node" };
    expect(() => stagedManifest(shield, { ...shieldSource, dependencies: { zod: "4.6.7" } }, [], "0.0.0")).toThrow(
      /no runtime dependency/,
    );
    // No packed package may depend on another: an import of one that was not vendored away fails the staging.
    expect(() => stagedManifest(shield, shieldSource, ["@antireverse/protocol"], "0.0.0")).toThrow(
      /may not depend on another @antireverse package/,
    );
    expect(() => stagedManifest(harden, source, ["@antireverse/protocol"], "0.0.0")).toThrow(
      /may not depend on another @antireverse package/,
    );
    // What a vendored package needs becomes a dependency; two versions of one name are refused.
    const protocol = { ...source, name: "@antireverse/protocol", dependencies: { zod: "4.6.7" } };
    expect(stagedManifest(harden, source, ["zod"], "0.0.0", [protocol]).dependencies).toEqual({ zod: "4.6.7" });
    expect(() =>
      stagedManifest(harden, { ...source, dependencies: { zod: "4.0.0" } }, [], "0.0.0", [protocol]),
    ).toThrow(/zod is wanted at 4\.0\.0 and, by @antireverse\/protocol, at 4\.6\.7/);
  });

  it("the README is a header that says local build and not a release, then the guide from docs/ made to fit the package", () => {
    for (const pkg of SDK_PACKAGES) {
      const readme = readFileSync(join(staged(pkg.short).dir, "README.md"), "utf8");
      expect(readme.startsWith(`# ${pkg.name}\n`), pkg.short).toBe(true);
      expect(readme, pkg.short).toMatch(/Local build.*not the package published on npm.*not a release/);
      expect(readme, pkg.short).toMatch(/not provenance/);
      // Review L8: nothing in a packed README needs the clone — no clone path, no clone-only command, and no link
      // to a file that is not in the tarball.
      expect(readme, pkg.short).not.toMatch(/packages\/(shield-node|guard|harden|protocol)/);
      expect(readme, pkg.short).not.toMatch(/npx tsx|experimental-strip-types|ERR_UNKNOWN_FILE_EXTENSION/);
      expect(readme, pkg.short).not.toMatch(/\]\((?!#|https?:)[^)]*\)/);
    }
    const guide = (short: string) => readFileSync(join(staged(short).dir, "README.md"), "utf8");
    expect(guide("harden")).toMatch(/npx --no-install antireverse harden <bundle-dir> --profile balanced/);
    expect(guide("harden")).toMatch(
      /## Running it\n\nThis package is installed in your project from its tarball\. Run it as `npx --no-install antireverse/,
    );
    expect(guide("harden")).toMatch(/`docs\/reverse-assessment\.md` in the Airverse repository/);
    expect(guide("guard")).toMatch(/node_modules\/@antireverse\/guard\/dist/);
    expect(guide("shield-node")).toMatch(/app\.use\(shield\.express\(\)\)/);
    // The guide itself shows the installed form in its commands (D-151) and still tells a clone its own form.
    const own = readFileSync(join(REPO_ROOT, "docs/harden.md"), "utf8");
    expect(own).toMatch(/^npx --no-install antireverse harden <bundle-dir> --profile balanced/m);
    expect(own.match(/npx tsx packages\/harden\/src\/cli\.ts/g)).toHaveLength(1);
  });

  it("packedGuide fails when a guide no longer holds what it replaces, instead of packing clone-only text", () => {
    expect(() => packedGuide(sdkPackage("harden"), "# Harden\n\nNo such section.\n")).toThrow(
      /docs\/harden\.md no longer holds/,
    );
    expect(() => packedGuide(sdkPackage("guard"), "# Guard\n")).toThrow(/docs\/guard\.md no longer holds/);
  });

  // Review L2: a package does not promise more than what it depends on supports.
  it("Harden declares the Node versions Babel declares; the others the repository's own minimum", () => {
    const babel = JSON.parse(readFileSync(join(REPO_ROOT, "node_modules/@babel/parser/package.json"), "utf8")) as {
      engines: { node: string };
    };
    expect(babel.engines.node).toBe("^22.18.0 || >=24.11.0");
    expect(staged("harden").manifest.engines).toEqual({ node: babel.engines.node });
    for (const short of ["protocol", "shield-node", "guard"])
      expect(staged(short).manifest.engines, short).toEqual({ node: ">=22.12" });
    expect(enginesOf(["^22.18.0 || >=24.11.0", undefined, "^22.18.0 || >=24.11.0"])).toBe("^22.18.0 || >=24.11.0");
    expect(enginesOf([undefined])).toBe(">=22.12");
    expect(enginesOf([])).toBe(">=22.12");
    expect(() => enginesOf([">=20", ">=22.18"])).toThrow(/different Node ranges/);
  });
});
