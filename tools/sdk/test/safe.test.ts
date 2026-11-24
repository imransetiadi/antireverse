// Lesson L-009: the one function that removes a build folder can reach nothing else. Every case that names a folder
// outside a test's own temporary directory runs with a `remove` that only records, so a wrong answer deletes nothing.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { SDK_PACKAGES } from "../src/packages.ts";
import { BUILD_MARKER, cleanBuildDir, prepareBuildDir, repoLayout, tempLayout } from "../src/safe.ts";

const base = mkdtempSync(join(tmpdir(), "airverse-sdk-safe-"));
const elsewhere = mkdtempSync(join(tmpdir(), "not-ours-"));
afterAll(() => {
  rmSync(base, { recursive: true, force: true });
  rmSync(elsewhere, { recursive: true, force: true });
});

/** A `remove` that deletes nothing: it records what it was asked to remove. */
function recorder() {
  const asked: string[] = [];
  return { asked, remove: (path: string) => void asked.push(path) };
}

describe("cleanBuildDir refuses everything that is not a build folder", () => {
  const refused: Array<[string, string]> = [
    ["the repository root", REPO_ROOT],
    ["the API's data directory", join(REPO_ROOT, "apps/api/.data")],
    ["a package's source folder", join(REPO_ROOT, "packages/harden/src")],
    ["a package folder", join(REPO_ROOT, "packages/harden")],
    ["another package's dist", join(REPO_ROOT, "packages/prove/dist")],
    ["the repository's dist folder itself", join(REPO_ROOT, "dist")],
    ["a folder below a build folder", join(REPO_ROOT, "dist/sdk/x")],
    ["node_modules", join(REPO_ROOT, "node_modules")],
    ["the home directory", homedir()],
    ["the gate's key folder", join(homedir(), ".config/airverse")],
    ["the file system root", "/"],
    ["the temporary directory itself", tmpdir()],
    ["the real temporary directory", realpathSync(tmpdir())],
    ["a temporary folder that is not ours", elsewhere],
    ["a folder inside a temporary folder that is not ours", join(elsewhere, "build")],
    ["the test's own base folder (only build folders inside it)", base],
    ["a folder of ours that is not one of a layout's folders", join(base, "x/stage")],
    ["a folder below a layout's folder", join(base, "x/work/stage")],
    ["a build folder of a package that is not packed", join(base, "x/build/prove")],
    ["a relative path", "dist/sdk"],
    ["a path that is not normalised", `${join(base, "a")}/../../x`],
    ["a path that climbs out of the repository", join(REPO_ROOT, "dist/sdk/../../apps/api/.data")],
    ["an empty path", ""],
  ];
  it.each(refused)("%s", (_name, target) => {
    const { asked, remove } = recorder();
    expect(() => cleanBuildDir(target, { remove })).toThrow(/refus/i);
    expect(asked).toEqual([]);
  });

  it("names the folder it refuses", () => {
    const { remove } = recorder();
    expect(() => cleanBuildDir(join(REPO_ROOT, "apps/api/.data"), { remove })).toThrow("apps/api/.data");
  });
});

describe("cleanBuildDir inside a temporary folder of ours", () => {
  it("does nothing when the folder does not exist", () => {
    const { asked, remove } = recorder();
    cleanBuildDir(join(base, "absent/work"), { remove });
    expect(asked).toEqual([]);
  });

  it("removes an empty folder and a folder that carries the marker", () => {
    const empty = join(base, "empty/out");
    mkdirSync(empty, { recursive: true });
    cleanBuildDir(empty);
    expect(existsSync(empty)).toBe(false);
    const marked = join(base, "marked/work");
    mkdirSync(join(marked, "deep"), { recursive: true });
    writeFileSync(join(marked, BUILD_MARKER), "");
    writeFileSync(join(marked, "deep/file.js"), "x");
    cleanBuildDir(marked);
    expect(existsSync(marked)).toBe(false);
  });

  it("refuses a folder that holds files and no marker, and leaves it as it is", () => {
    const foreign = join(base, "foreign/out");
    mkdirSync(foreign, { recursive: true });
    writeFileSync(join(foreign, "thesis.txt"), "years of work");
    expect(() => cleanBuildDir(foreign)).toThrow(/refus.*marker/i);
    expect(readdirSync(foreign)).toEqual(["thesis.txt"]);
  });

  it("refuses a symbolic link, whatever it points at, and a file", () => {
    const real = join(base, "real/work");
    mkdirSync(real, { recursive: true });
    writeFileSync(join(real, BUILD_MARKER), "");
    mkdirSync(join(base, "link"));
    const link = join(base, "link/work");
    symlinkSync(real, link);
    expect(() => cleanBuildDir(link)).toThrow(/refus.*symbolic link/i);
    expect(existsSync(join(real, BUILD_MARKER))).toBe(true);
    mkdirSync(join(base, "link-out"));
    const out = join(base, "link-out/out");
    symlinkSync(elsewhere, out);
    expect(() => cleanBuildDir(out)).toThrow(/refus/i);
    mkdirSync(join(base, "file"));
    const file = join(base, "file/work");
    writeFileSync(file, "x");
    expect(() => cleanBuildDir(file)).toThrow(/refus.*not a folder/i);
    expect(existsSync(file)).toBe(true);
  });

  it("refuses a folder reached through a symbolic link that leaves the temporary folder", () => {
    const door = join(base, "door");
    symlinkSync(elsewhere, door);
    mkdirSync(join(elsewhere, "work"), { recursive: true });
    const { asked, remove } = recorder();
    expect(() => cleanBuildDir(join(door, "work"), { remove })).toThrow(/refus/i);
    expect(asked).toEqual([]);
  });

  it("prepareBuildDir empties a marked folder, creates it and writes the marker", () => {
    const dir = join(base, "prepared/build/harden");
    prepareBuildDir(dir);
    expect(readdirSync(dir)).toEqual([BUILD_MARKER]);
    writeFileSync(join(dir, "old.js"), "x");
    prepareBuildDir(dir);
    expect(readdirSync(dir)).toEqual([BUILD_MARKER]);
  });
});

describe("layouts", () => {
  it("the repository layout owns exactly the four dist folders, dist/sdk and dist/sdk-work", () => {
    const layout = repoLayout();
    expect(SDK_PACKAGES.map((pkg) => layout.dist(pkg))).toEqual(
      ["protocol", "shield-node", "guard", "harden"].map((name) => join(REPO_ROOT, "packages", name, "dist")),
    );
    expect(layout.out).toBe(join(REPO_ROOT, "dist/sdk"));
    expect(layout.work).toBe(join(REPO_ROOT, "dist/sdk-work"));
    // Each is a folder cleanBuildDir accepts: asked with a recorder, nothing is removed here.
    for (const target of [...SDK_PACKAGES.map((pkg) => layout.dist(pkg)), layout.out, layout.work]) {
      const { remove } = recorder();
      if (existsSync(target) && readdirSync(target).length > 0 && !existsSync(join(target, BUILD_MARKER))) continue;
      expect(() => cleanBuildDir(target, { remove })).not.toThrow();
    }
  });

  it("a temporary layout has the same three kinds of folder as the repository's, so a test meets the same refusals", () => {
    const layout = tempLayout(join(base, "shape"));
    for (const target of [...SDK_PACKAGES.map((pkg) => layout.dist(pkg)), layout.out, layout.work]) {
      const { remove } = recorder();
      expect(() => cleanBuildDir(target, { remove })).not.toThrow();
      expect(() => cleanBuildDir(join(target, "inner"), { remove })).toThrow(/refus/i);
    }
    const repo = repoLayout();
    for (const target of [...SDK_PACKAGES.map((pkg) => repo.dist(pkg)), repo.out, repo.work]) {
      const { asked, remove } = recorder();
      expect(() => cleanBuildDir(join(target, "inner"), { remove })).toThrow(/refus/i);
      expect(asked).toEqual([]);
    }
  });

  it("a temporary layout must lie in a temporary folder of ours", () => {
    const layout = tempLayout(join(base, "layout"));
    expect(layout.out).toBe(join(base, "layout/out"));
    expect(() => tempLayout(join(elsewhere, "layout"))).toThrow(/refus/i);
    expect(() => tempLayout(join(REPO_ROOT, "dist"))).toThrow(/refus/i);
    expect(() => tempLayout("relative")).toThrow(/refus/i);
  });
});
