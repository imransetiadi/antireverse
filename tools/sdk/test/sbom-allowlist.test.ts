// Slice 23, criterion 6: the packed runtime closure from the lockfile, its CycloneDX bill of materials, and the
// allowlist check (names and exact versions, install scripts, zero dependencies for Shield and Guard).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { type Allowlist, checkAllowlist, currentAllowlist, installScripts, readAllowlist } from "../src/allowlist.ts";
import {
  type Closure,
  closureOf,
  type Lockfile,
  readLockfile,
  sdkClosures,
  vendoredDependencies,
} from "../src/closure.ts";
import { SDK_PACKAGES, sdkPackage } from "../src/packages.ts";
import { sbomOf, serializeSbom } from "../src/sbom.ts";
import { sdkVersion } from "../src/stage.ts";

const version = sdkVersion();
const lock = readLockfile();
const closures = sdkClosures(lock, vendoredDependencies(lock));
const closure = (short: string) => closures[sdkPackage(short).name] as Closure;
const ids = (short: string) => closure(short).entries.map((entry) => entry.id);
const noScripts = () => [];

describe("the packed runtime closure", () => {
  it("Shield and Guard have none; the protocol has zod; Harden has Babel's tree and, for the protocol it carries, zod", () => {
    expect(vendoredDependencies(lock)).toEqual({
      "@antireverse/protocol": [],
      "@antireverse/shield-node": [],
      "@antireverse/guard": [],
      "@antireverse/harden": ["zod"],
    });
    expect(ids("shield-node")).toEqual([]);
    expect(ids("guard")).toEqual([]);
    expect(ids("protocol")).toEqual(["zod@4.6.7"]);
    const harden = ids("harden");
    expect(harden.filter((id) => id.startsWith("@antireverse/"))).toEqual([]);
    expect(harden).toContain("zod@4.6.7");
    for (const name of ["generator", "parser", "traverse", "types"]) expect(harden).toContain(`@babel/${name}@8.1.0`);
    // Slice 23b review S1: @babel/core, which no code imported, is gone, and with it twenty packages.
    expect(harden.filter((id) => /^(@babel\/core|browserslist|json5|gensync|convert-source-map)@/.test(id))).toEqual(
      [],
    );
    expect(harden.length).toBe(18);
    expect(harden).toEqual([...harden].sort());
    expect(new Set(harden).size).toBe(harden.length);
  });

  it("holds no development dependency: nothing of TypeScript, Vitest, Express or the type packages of Babel 7", () => {
    for (const pkg of SDK_PACKAGES) {
      for (const id of ids(pkg.short))
        expect(id).not.toMatch(/^(typescript|vitest|express|tsx|@types\/(express|babel__\w+|node))@/);
    }
  });

  it("every third-party entry has the lockfile's integrity and the registry it came from", () => {
    for (const entry of closure("harden").entries) {
      expect(entry.integrity, entry.id).toMatch(/^sha512-[A-Za-z0-9+/]+=*$/);
      expect(entry.resolved, entry.id).toMatch(/^https:\/\/registry\.npmjs\.org\//);
      expect(entry.paths.length, entry.id).toBeGreaterThan(0);
    }
  });

  it("follows the nearest node_modules, optional and required peer dependencies, and never development ones", () => {
    const fake: Lockfile = {
      lockfileVersion: 3,
      packages: {
        "": {},
        "packages/app": {
          name: "app",
          version: "1.0.0",
          dependencies: { a: "1.0.0" },
          devDependencies: { dev: "1.0.0" },
        },
        "node_modules/a": {
          version: "1.0.0",
          dependencies: { b: "^1" },
          optionalDependencies: { opt: "1" },
          peerDependencies: { peer: "1", "soft-peer": "1" },
          peerDependenciesMeta: { "soft-peer": { optional: true } },
        },
        "node_modules/a/node_modules/b": { version: "1.5.0" },
        "node_modules/b": { version: "2.0.0" },
        "node_modules/opt": { version: "1.0.0", optional: true },
        "node_modules/peer": { version: "1.0.0", peer: true },
        "node_modules/soft-peer": { version: "1.0.0" },
        "node_modules/dev": { version: "1.0.0", dev: true },
      },
    };
    expect(closureOf(fake, "packages/app").entries.map((entry) => entry.id)).toEqual([
      "a@1.0.0",
      "b@1.5.0",
      "opt@1.0.0",
      "peer@1.0.0",
    ]);
    expect(() => closureOf(fake, "packages/none")).toThrow(/not in the lockfile/);
    const broken: Lockfile = {
      lockfileVersion: 3,
      packages: { "packages/app": { name: "app", version: "1.0.0", dependencies: { gone: "1" } } },
    };
    expect(() => closureOf(broken, "packages/app")).toThrow(/gone.*not in the lockfile/);
    expect(() => closureOf({ lockfileVersion: 2, packages: {} }, "packages/app")).toThrow(/lockfile version 3/);
  });

  it("refuses a dependency on another package of the repository: no registry has it (D-140)", () => {
    expect(() => closureOf(lock, "packages/harden", ["@antireverse/protocol"])).toThrow(
      /@antireverse\/protocol.*workspace package.*may not depend/,
    );
    expect(() => closureOf(lock, "tools/gate", ["@antireverse/api"])).toThrow(/workspace package/);
  });
});

describe("the allowlist", () => {
  const committed = readAllowlist();

  it("the committed list is exactly today's closure", () => {
    expect(checkAllowlist(closures, committed, installScripts)).toEqual([]);
    expect(committed).toEqual(currentAllowlist(closures));
    expect(committed.packages["@antireverse/shield-node"]).toEqual({ vendored: [], thirdParty: {} });
    expect(committed.packages["@antireverse/guard"]).toEqual({ vendored: [], thirdParty: {} });
    expect(committed.packages["@antireverse/harden"]?.vendored).toEqual(["@antireverse/protocol"]);
    expect(JSON.stringify(committed.packages).match(/@antireverse\/[a-z-]+@/g)).toBeNull();
    for (const entry of Object.values(committed.packages)) {
      for (const integrity of Object.values(entry.thirdParty)) expect(integrity).toMatch(/^sha512-[A-Za-z0-9+/]+=*$/);
    }
  });

  const mutate = (change: (list: Allowlist) => void): Allowlist => {
    const copy = JSON.parse(JSON.stringify(committed)) as Allowlist;
    change(copy);
    return copy;
  };
  const withEntry = (short: string, change: (c: Closure) => Closure): Record<string, Closure> => ({
    ...closures,
    [sdkPackage(short).name]: change(JSON.parse(JSON.stringify(closure(short))) as Closure),
  });
  const ZOD_INTEGRITY = (lock.packages["node_modules/zod"] as { integrity: string }).integrity;
  const extra = (id: string) => ({
    id,
    name: id.slice(0, id.lastIndexOf("@")),
    version: id.slice(id.lastIndexOf("@") + 1),
    paths: [`node_modules/${id.slice(0, id.lastIndexOf("@"))}`],
    integrity: "sha512-AAAA",
    resolved: `https://registry.npmjs.org/${id.slice(0, id.lastIndexOf("@"))}/-/x.tgz`,
    dependsOn: [],
    hasInstallScript: false,
  });

  it("fails on a dependency that is not listed, direct or transitive", () => {
    const list = mutate((l) => {
      const harden = l.packages["@antireverse/harden"] as Allowlist["packages"][string];
      for (const id of Object.keys(harden.thirdParty)) if (id.startsWith("jsesc@")) delete harden.thirdParty[id];
    });
    expect(checkAllowlist(closures, list, noScripts)).toEqual([
      expect.stringMatching(/@antireverse\/harden: jsesc@\S+ is not on the allowlist/),
    ]);
    const grown = withEntry("protocol", (c) => ({ ...c, entries: [...c.entries, extra("left-pad@1.3.0")] }));
    expect(checkAllowlist(grown, committed, noScripts)).toEqual([
      "@antireverse/protocol: left-pad@1.3.0 is not on the allowlist",
    ]);
  });

  it("fails on a changed version, and on a listed entry that is gone", () => {
    const bumped = withEntry("protocol", (c) => ({ ...c, entries: [extra("zod@4.6.8")] }));
    expect(checkAllowlist(bumped, committed, noScripts).sort()).toEqual([
      "@antireverse/protocol: the allowlist names zod@4.6.7, which is no longer a dependency",
      "@antireverse/protocol: zod@4.6.8 is not on the allowlist",
    ]);
  });

  it("fails on any dependency of Shield or Guard, even a listed one", () => {
    const grown = withEntry("shield-node", (c) => ({ ...c, entries: [extra("zod@4.6.7")] }));
    const list = mutate((l) => {
      l.packages["@antireverse/shield-node"] = { vendored: [], thirdParty: { "zod@4.6.7": ZOD_INTEGRITY } };
    });
    expect(checkAllowlist(grown, list, noScripts)).toEqual([
      "@antireverse/shield-node must have no runtime dependency (SC-SUP-03), found zod@4.6.7",
    ]);
    expect(checkAllowlist(closures, list, noScripts)).toEqual([
      "@antireverse/shield-node must have no runtime dependency (SC-SUP-03), but the allowlist names zod@4.6.7",
    ]);
  });

  it("fails on an install script in the closure", () => {
    const scripted = (entry: { id: string }) => (entry.id.startsWith("zod@") ? ["postinstall"] : []);
    const problems = checkAllowlist(closures, committed, scripted);
    expect(problems).toContain("@antireverse/protocol: zod@4.6.7 has an install script (postinstall)");
    expect(problems).toContain("@antireverse/harden: zod@4.6.7 has an install script (postinstall)");
    const flagged = withEntry("protocol", (c) => ({
      ...c,
      entries: c.entries.map((e) => ({ ...e, hasInstallScript: true })),
    }));
    expect(checkAllowlist(flagged, committed, installScripts)).toEqual([
      "@antireverse/protocol: zod@4.6.7 has an install script (the lockfile says so)",
    ]);
  });

  it("fails on a package the list does not know, and on a package the list has that is not packed", () => {
    const list = mutate((l) => {
      delete l.packages["@antireverse/guard"];
      l.packages["@antireverse/other"] = { vendored: [], thirdParty: {} };
    });
    expect(checkAllowlist(closures, list, noScripts).sort()).toEqual([
      "@antireverse/guard: no allowlist entry",
      "@antireverse/other: on the allowlist but not an SDK package",
    ]);
  });

  // Review L7: the same name and version with other bytes, or from another place, is another package.
  it("fails on a listed version whose integrity changed, has none, or does not come from the npm registry", () => {
    expect(committed.packages["@antireverse/protocol"]?.thirdParty).toEqual({ "zod@4.6.7": ZOD_INTEGRITY });
    const other = withEntry("protocol", (c) => ({
      ...c,
      entries: c.entries.map((e) => ({ ...e, integrity: "sha512-BBBB" })),
    }));
    expect(checkAllowlist(other, committed, noScripts)).toEqual([
      "@antireverse/protocol: zod@4.6.7 has the integrity sha512-BBBB, the allowlist has another",
    ]);
    const none = withEntry("protocol", (c) => ({
      ...c,
      entries: c.entries.map(({ integrity: _integrity, ...rest }) => rest),
    }));
    expect(checkAllowlist(none, committed, noScripts)).toEqual([
      "@antireverse/protocol: zod@4.6.7 has no integrity in the lockfile",
    ]);
    const mirror = withEntry("protocol", (c) => ({
      ...c,
      entries: c.entries.map((e) => ({ ...e, resolved: "https://registry.example.test/zod/-/zod-4.6.7.tgz" })),
    }));
    expect(checkAllowlist(mirror, committed, noScripts)).toEqual([
      "@antireverse/protocol: zod@4.6.7 comes from https://registry.example.test/zod/-/zod-4.6.7.tgz, not from https://registry.npmjs.org/",
    ]);
    // One version installed in two places with different bytes cannot be pinned at all.
    const twice: Lockfile = {
      lockfileVersion: 3,
      packages: {
        "packages/app": { name: "app", version: "1.0.0", dependencies: { a: "1.0.0", b: "1.0.0" } },
        "node_modules/a": { version: "1.0.0", integrity: "sha512-one", dependencies: { c: "1.0.0" } },
        "node_modules/b": { version: "1.0.0", integrity: "sha512-two", dependencies: { c: "1.0.0" } },
        "node_modules/c": { version: "1.0.0", integrity: "sha512-first" },
        "node_modules/b/node_modules/c": { version: "1.0.0", integrity: "sha512-second" },
      },
    };
    expect(() => closureOf(twice, "packages/app")).toThrow(/c@1\.0\.0 .* two different integrities/);
  });

  it("fails when what is vendored and what the list says is vendored differ", () => {
    const dropped = mutate((l) => {
      (l.packages["@antireverse/harden"] as Allowlist["packages"][string]).vendored = [];
    });
    expect(checkAllowlist(closures, dropped, noScripts)).toEqual([
      "@antireverse/harden: the vendored @antireverse/protocol is not on the allowlist",
    ]);
    const added = mutate((l) => {
      (l.packages["@antireverse/protocol"] as Allowlist["packages"][string]).vendored = ["@antireverse/guard"];
    });
    expect(checkAllowlist(closures, added, noScripts)).toEqual([
      "@antireverse/protocol: the allowlist names the vendored @antireverse/guard, which is not vendored",
    ]);
  });

  it("no package of today's closure has an install script on disk", () => {
    for (const pkg of SDK_PACKAGES)
      for (const entry of closure(pkg.short).entries) expect(installScripts(entry), entry.id).toEqual([]);
  });
});

describe("the bill of materials", () => {
  const tarballs = Object.fromEntries(SDK_PACKAGES.map((pkg, index) => [pkg.name, `${index}`.repeat(64)]));
  const sbom = (short: string) =>
    sbomOf(
      sdkPackage(short).name,
      version,
      closure(short),
      tarballs,
      short === "harden" ? [{ name: "@antireverse/protocol", dir: "dist/_protocol" }] : [],
    );

  it("is CycloneDX 1.5 with the packed package as its subject and its tarball's SHA-256", () => {
    const bom = sbom("harden");
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.5");
    expect(bom.version).toBe(1);
    expect(bom.metadata.component).toMatchObject({
      type: "library",
      "bom-ref": `pkg:npm/%40antireverse/harden@${version}`,
      group: "@antireverse",
      name: "harden",
      version,
      purl: `pkg:npm/%40antireverse/harden@${version}`,
      hashes: [{ alg: "SHA-256", content: tarballs["@antireverse/harden"] }],
    });
  });

  it("lists every closure package once with purl, licence and the lockfile's SHA-512; the protocol Harden carries, inside Harden", () => {
    const bom = sbom("harden");
    expect(bom.components.map((c) => c["bom-ref"])).toEqual([...bom.components.map((c) => c["bom-ref"])].sort());
    expect(bom.components.length).toBe(closure("harden").entries.length);
    const zod = bom.components.find((c) => c.name === "zod");
    const integrity = (lock.packages["node_modules/zod"] as { integrity: string }).integrity;
    expect(zod).toEqual({
      type: "library",
      "bom-ref": "pkg:npm/zod@4.6.7",
      name: "zod",
      version: "4.6.7",
      purl: "pkg:npm/zod@4.6.7",
      hashes: [{ alg: "SHA-512", content: Buffer.from(integrity.slice(7), "base64").toString("hex") }],
      licenses: [{ license: { id: "MIT" } }],
      externalReferences: [{ type: "distribution", url: "https://registry.npmjs.org/zod/-/zod-4.6.7.tgz" }],
    });
    const parser = bom.components.find((c) => c.purl === "pkg:npm/%40babel/parser@8.1.0");
    expect(parser).toMatchObject({ group: "@babel", name: "parser" });
    expect(bom.components.filter((c) => c.group === "@antireverse")).toEqual([]);
    expect(bom.metadata.component.components).toEqual([
      {
        type: "library",
        "bom-ref": `pkg:npm/%40antireverse/protocol@${version}`,
        group: "@antireverse",
        name: "protocol",
        version,
        purl: `pkg:npm/%40antireverse/protocol@${version}`,
        hashes: [{ alg: "SHA-256", content: tarballs["@antireverse/protocol"] }],
        licenses: [{ license: { id: "Apache-2.0" } }],
        properties: [{ name: "airverse:vendored", value: "compiled files copied into dist/_protocol" }],
      },
    ]);
    expect(sbom("protocol").metadata.component.components).toBeUndefined();
  });

  it("carries the dependency graph: Harden on Babel and zod, the protocol on zod", () => {
    const bom = sbom("harden");
    const of = (ref: string) => bom.dependencies.find((d) => d.ref === ref)?.dependsOn;
    expect(of(`pkg:npm/%40antireverse/harden@${version}`)).toEqual([
      "pkg:npm/%40babel/generator@8.1.0",
      "pkg:npm/%40babel/parser@8.1.0",
      "pkg:npm/%40babel/traverse@8.1.0",
      "pkg:npm/%40babel/types@8.1.0",
      "pkg:npm/zod@4.6.7",
    ]);
    const protocol = sbom("protocol");
    expect(protocol.dependencies).toEqual([
      { ref: `pkg:npm/%40antireverse/protocol@${version}`, dependsOn: ["pkg:npm/zod@4.6.7"] },
      { ref: "pkg:npm/zod@4.6.7", dependsOn: [] },
    ]);
    expect(bom.dependencies.length).toBe(bom.components.length + 1);
    const refs = new Set([bom.metadata.component["bom-ref"], ...bom.components.map((c) => c["bom-ref"])]);
    for (const d of bom.dependencies) for (const ref of [d.ref, ...d.dependsOn]) expect(refs.has(ref), ref).toBe(true);
  });

  it("has no time and no random part: the same bytes every time, and no dependency for Shield", () => {
    expect(serializeSbom(sbom("harden"))).toBe(serializeSbom(sbom("harden")));
    expect(serializeSbom(sbom("harden"))).not.toMatch(/timestamp|serialNumber|urn:uuid/);
    expect(serializeSbom(sbom("harden")).endsWith("}\n")).toBe(true);
    expect(sbom("shield-node").components).toEqual([]);
    expect(sbom("shield-node").dependencies).toEqual([
      { ref: `pkg:npm/%40antireverse/shield-node@${version}`, dependsOn: [] },
    ]);
    expect(serializeSbom(sbom("harden"))).not.toContain(REPO_ROOT);
  });

  it("the lockfile agrees with the source manifests on each package's dependencies", () => {
    for (const pkg of SDK_PACKAGES) {
      const manifest = JSON.parse(readFileSync(join(REPO_ROOT, "packages", pkg.short, "package.json"), "utf8"));
      expect(lock.packages[`packages/${pkg.short}`]?.dependencies ?? {}, pkg.short).toEqual(
        manifest.dependencies ?? {},
      );
    }
  });
});
