// Slice 19 — the lockfile reader: package-lock v1/v2/v3 to a de-duplicated, validated component list. Only
// names, versions and the dev flag come out; nothing else of the lockfile.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ComponentListSchema, EXPOSURE_LIMITS } from "@antireverse/protocol";
import { afterEach, describe, expect, it } from "vitest";
import { componentsFromLockfile, readComponents } from "../src/components.ts";

const temps: string[] = [];
afterEach(() => {
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function lockfile(content: unknown): string {
  const d = mkdtempSync(join(tmpdir(), "harden-lock-"));
  temps.push(d);
  const file = join(d, "package-lock.json");
  writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content), "utf8");
  return file;
}

const V3 = {
  name: "my-app",
  version: "1.0.0",
  lockfileVersion: 3,
  packages: {
    "": { name: "my-app", version: "1.0.0", dependencies: { "example-parser": "^1.2.0" } },
    "node_modules/example-parser": {
      version: "1.2.3",
      resolved: "https://registry.example/x.tgz",
      integrity: "sha512-x",
    },
    "node_modules/@example/ui": { version: "4.0.0-rc.1" },
    "node_modules/JSONStream": { version: "1.3.5" },
    "node_modules/example-test-runner": { version: "9.1.0", dev: true },
    "node_modules/example-maybe": { version: "2.0.0", devOptional: true },
    // A nested copy of a different version, and a nested duplicate of a top-level one.
    "node_modules/@example/ui/node_modules/example-parser": { version: "2.0.0" },
    "node_modules/example-test-runner/node_modules/@example/ui": { version: "4.0.0-rc.1", dev: true },
    // An alias: the key names the alias, the entry's `name` field the real package.
    "node_modules/parser-alias": { name: "example-parser", version: "1.0.1" },
    // A workspace link and its source (not a dependency).
    "node_modules/my-lib": { resolved: "packages/my-lib", link: true },
    "packages/my-lib": { name: "my-lib", version: "0.0.0" },
    // Non-semver: git and file dependencies.
    "node_modules/from-git": { version: "git+ssh://git@example.test/a/b.git#0123456789abcdef" },
    "node_modules/from-file": { version: "file:../vendor/from-file" },
    // Invalid name (leading dot) and a missing version.
    "node_modules/.hidden": { version: "1.0.0" },
    "node_modules/no-version": {},
  },
};

function names(list: { name: string; version: string; dev: boolean }[]) {
  return list.map((c) => `${c.name}@${c.version}${c.dev ? " dev" : ""}`);
}

describe("componentsFromLockfile — v2/v3 packages map", () => {
  it("reads names (scoped, legacy capitals, aliases via `name`), versions and dev, sorted, root skipped", () => {
    const result = componentsFromLockfile(V3);
    expect("error" in result).toBe(false);
    if ("error" in result) return;
    expect(names(result.components)).toEqual([
      "@example/ui@4.0.0-rc.1",
      "JSONStream@1.3.5",
      "example-maybe@2.0.0 dev",
      "example-parser@1.0.1",
      "example-parser@1.2.3",
      "example-parser@2.0.0",
      "example-test-runner@9.1.0 dev",
    ]);
    // git, file, ".hidden" and the missing version: four skipped. Links and the workspace source are not counted.
    expect(result.skipped).toBe(4);
    expect(ComponentListSchema.safeParse(result.components).success).toBe(true);
  });

  it("returns only name, version and dev for each component", () => {
    const result = componentsFromLockfile(V3);
    if ("error" in result) throw new Error(result.error);
    for (const c of result.components) expect(Object.keys(c).sort()).toEqual(["dev", "name", "version"]);
  });

  it("de-duplicates name@version: dev only when every occurrence is dev", () => {
    const result = componentsFromLockfile({
      lockfileVersion: 2,
      packages: {
        "": { name: "x" },
        "node_modules/a": { version: "1.0.0", dev: true },
        "node_modules/b/node_modules/a": { version: "1.0.0" },
        "node_modules/b": { version: "2.0.0", dev: true },
        "node_modules/c/node_modules/b": { version: "2.0.0", devOptional: true },
        "node_modules/c": { version: "3.0.0", dev: true },
      },
      dependencies: { ignored: { version: "9.9.9" } },
    });
    if ("error" in result) throw new Error(result.error);
    expect(names(result.components)).toEqual(["a@1.0.0", "b@2.0.0 dev", "c@3.0.0 dev"]);
    expect(result.skipped).toBe(0);
  });
});

describe("componentsFromLockfile — v1 dependencies tree", () => {
  it("walks the tree recursively, de-duplicates and skips non-semver", () => {
    const result = componentsFromLockfile({
      name: "old-app",
      lockfileVersion: 1,
      requires: true,
      dependencies: {
        "example-parser": { version: "1.2.3", resolved: "https://r/x.tgz" },
        "@example/ui": {
          version: "4.0.0",
          dependencies: {
            "example-parser": { version: "2.0.0" },
            deep: { version: "0.1.0", dependencies: { "example-parser": { version: "1.2.3" } } },
          },
        },
        JSONStream: { version: "1.3.5", dev: true },
        "from-git": { version: "github:a/b#abc" },
        alias: { version: "npm:example-parser@1.0.0" },
      },
    });
    if ("error" in result) throw new Error(result.error);
    expect(names(result.components)).toEqual([
      "@example/ui@4.0.0",
      "JSONStream@1.3.5 dev",
      "deep@0.1.0",
      "example-parser@1.2.3",
      "example-parser@2.0.0",
    ]);
    expect(result.skipped).toBe(2);
  });
});

describe("componentsFromLockfile — limits and shape", () => {
  it("errors when there are more than 5,000 distinct components", () => {
    const packages: Record<string, unknown> = { "": {} };
    for (let i = 0; i <= EXPOSURE_LIMITS.componentsMax; i++) packages[`node_modules/p${i}`] = { version: "1.0.0" };
    const result = componentsFromLockfile({ lockfileVersion: 3, packages });
    expect("error" in result).toBe(true);
    if ("error" in result) expect(result.error).toMatch(/5,?000/);
  });

  it("accepts exactly 5,000 components", () => {
    const packages: Record<string, unknown> = { "": {} };
    for (let i = 0; i < EXPOSURE_LIMITS.componentsMax; i++) packages[`node_modules/p${i}`] = { version: "1.0.0" };
    const result = componentsFromLockfile({ lockfileVersion: 3, packages });
    if ("error" in result) throw new Error(result.error);
    expect(result.components.length).toBe(EXPOSURE_LIMITS.componentsMax);
  });

  it("skips and counts names npm forbids (upper-case scope, too long, spaces)", () => {
    const result = componentsFromLockfile({
      lockfileVersion: 3,
      packages: {
        "node_modules/@Scope/x": { version: "1.0.0" },
        [`node_modules/${"a".repeat(EXPOSURE_LIMITS.nameMax + 1)}`]: { version: "1.0.0" },
        "node_modules/has space": { version: "1.0.0" },
        "node_modules/ok": { version: "1.0.0" },
      },
    });
    if ("error" in result) throw new Error(result.error);
    expect(names(result.components)).toEqual(["ok@1.0.0"]);
    expect(result.skipped).toBe(3);
  });

  it("errors on a JSON value that is not a lockfile", () => {
    for (const value of [null, [], 42, "x", { name: "no-packages" }, { packages: [] }]) {
      expect("error" in componentsFromLockfile(value)).toBe(true);
    }
  });

  it("skips entries that are not objects", () => {
    const result = componentsFromLockfile({
      lockfileVersion: 3,
      packages: { "node_modules/a": "1.0.0", "node_modules/b": { version: "1.0.0" } },
    });
    if ("error" in result) throw new Error(result.error);
    expect(names(result.components)).toEqual(["b@1.0.0"]);
    expect(result.skipped).toBe(1);
  });
});

describe("readComponents", () => {
  it("reads a lockfile from disk", () => {
    const result = readComponents(lockfile(V3));
    if ("error" in result) throw new Error(result.error);
    expect(result.components.length).toBe(7);
  });

  it("errors on a missing file", () => {
    const result = readComponents(join(tmpdir(), "harden-does-not-exist", "package-lock.json"));
    expect("error" in result).toBe(true);
  });

  it("errors on invalid JSON without echoing the file's content", () => {
    const result = readComponents(lockfile('{"secret-internal-name": oops'));
    expect("error" in result).toBe(true);
    if ("error" in result) {
      expect(result.error).toMatch(/JSON/);
      expect(result.error).not.toContain("secret-internal-name");
    }
  });
});
