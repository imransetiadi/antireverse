// Slice 23b: the release build. Three packages — Shield, Guard, Harden — packed so that the owner can publish them:
// no `private`, public metadata, a README for the npm page, a signed manifest of exactly those files. Nothing here
// publishes; the checks that talk to a registry talk to a loopback one. The ordinary pack stays private.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { type GateKey, loadOrCreateKey } from "../../gate/src/sign.ts";
import { exec } from "../src/exec.ts";
import { artifactFile, MANIFEST_FILE, type SdkManifest, verifyArtifacts, writeManifest } from "../src/manifest.ts";
import { npmPack } from "../src/pack.ts";
import { PUBLIC_REPOSITORY, RELEASED_PACKAGES, SDK_PACKAGES, sdkPackage } from "../src/packages.ts";
import { buildAndPack, type PackResult } from "../src/pipeline.ts";
import { publishedCheck, releaseCheck, shellQuote } from "../src/publish.ts";
import { startRegistry } from "../src/registry.ts";
import { normaliseRemote, type ReleaseInfo, releaseState } from "../src/release.ts";
import { BUILD_MARKER } from "../src/safe.ts";
import { sdkVersion } from "../src/stage.ts";
import { tarFile, tarNames } from "../src/tar.ts";
import { filesOf, layoutIn, tempBase } from "./helpers.ts";

const base = tempBase("release");
const layout = layoutIn(base, "pack");
const again = layoutIn(base, "again");
const ordinary = layoutIn(base, "ordinary");
/** The project's public repository: the one a release may name (pinned in packages.ts), whatever this checkout's origin is. */
const repository = PUBLIC_REPOSITORY;
const commit = "c".repeat(40);
let key: GateKey;
let info: ReleaseInfo;
let released: PackResult;
let private_: PackResult;

const git = (cwd: string, ...args: string[]) =>
  exec("git", ["-c", "user.name=Test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false", ...args], {
    cwd,
  });
/** The source files of the four packages as the working tree has them: what a release commit would track. */
function workingTreeSources(): string[] {
  return SDK_PACKAGES.flatMap((pkg) =>
    filesOf(join(REPO_ROOT, "packages", pkg.short, "src")).map((file) => `packages/${pkg.short}/src/${file}`),
  );
}
const packedManifest = (path: string) =>
  JSON.parse(tarFile(gunzipSync(readFileSync(path)), "package/package.json").toString("utf8")) as Record<
    string,
    unknown
  >;
const packedReadme = (result: PackResult, short: string) => {
  const tarball = result.tarballs.find((t) => t.name === sdkPackage(short).name);
  return tarFile(gunzipSync(readFileSync(tarball?.path as string)), "package/README.md").toString("utf8");
};

beforeAll(async () => {
  key = loadOrCreateKey(join(base, "keys/gate-key.json"));
  info = { repository, commit, tracked: workingTreeSources() };
  released = await buildAndPack(layout, { key, release: info });
  private_ = await buildAndPack(ordinary, { key });
});

describe("versions (D-144)", () => {
  it("the four packages are 0.1.0, Shield says so in what it sends, and the protocol stays private and is not released", () => {
    expect(sdkVersion()).toBe("0.1.0");
    for (const pkg of SDK_PACKAGES) {
      const manifest = JSON.parse(readFileSync(join(REPO_ROOT, "packages", pkg.short, "package.json"), "utf8"));
      expect(manifest.version, pkg.short).toBe("0.1.0");
      expect(manifest.private, pkg.short).toBe(true);
    }
    expect(readFileSync(join(REPO_ROOT, "packages/shield-node/src/types.ts"), "utf8")).toContain(
      'export const SDK_VERSION = "0.1.0";',
    );
    expect(RELEASED_PACKAGES.map((pkg) => pkg.name)).toEqual([
      "@antireverse/shield-node",
      "@antireverse/guard",
      "@antireverse/harden",
    ]);
    const lock = JSON.parse(readFileSync(join(REPO_ROOT, "package-lock.json"), "utf8")) as {
      packages: Record<string, { version?: string }>;
    };
    for (const pkg of SDK_PACKAGES) expect(lock.packages[`packages/${pkg.short}`]?.version, pkg.short).toBe("0.1.0");
  });
});

describe("the origin remote as a public URL", () => {
  it("normalises https and ssh forms to https without .git", () => {
    expect(normaliseRemote("https://github.com/acme/airverse.git")).toBe("https://github.com/acme/airverse");
    expect(normaliseRemote("https://github.com/acme/airverse")).toBe("https://github.com/acme/airverse");
    expect(normaliseRemote("git@github.com:acme/airverse.git")).toBe("https://github.com/acme/airverse");
    expect(normaliseRemote("ssh://git@github.com/acme/airverse.git")).toBe("https://github.com/acme/airverse");
    expect(normaliseRemote("https://github.com/acme/airverse.git\n")).toBe("https://github.com/acme/airverse");
  });

  it("refuses a remote that holds credentials, without repeating them, and anything that is not a repository URL", () => {
    for (const remote of [
      "https://alice:s3cr3t-token@github.com/acme/airverse.git",
      "https://ghp_abcdefghijklmnop@github.com/acme/airverse.git",
      "https://x-access-token:ghs_secretvalue@github.com/acme/airverse",
    ]) {
      let message = "";
      try {
        normaliseRemote(remote);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toMatch(/holds credentials/);
      expect(message).not.toMatch(/s3cr3t|ghp_|ghs_|alice/);
    }
    for (const remote of [
      "",
      "/local/path/repo.git",
      "file:///repo.git",
      "http://github.com/acme/airverse.git",
      "https://github.com/acme",
      "https://github.com/acme/airverse/extra/path",
    ]) {
      expect(() => normaliseRemote(remote), remote).toThrow(/not a repository URL|must be https/);
    }
  });
});

describe("what the release command refuses (on small repositories of its own)", () => {
  /** A repository with one commit, the packages' source folders, an origin remote and origin/main at that commit. */
  async function repo(name: string, remote = `${PUBLIC_REPOSITORY}.git`): Promise<string> {
    const dir = join(base, "repos", name);
    mkdirSync(dir, { recursive: true });
    await git(dir, "init", "-q", "-b", "main");
    writeFileSync(join(dir, "a.txt"), "one\n");
    writeFileSync(join(dir, ".gitignore"), "node_modules\n.env*\ndist/\n");
    for (const pkg of SDK_PACKAGES) {
      mkdirSync(join(dir, "packages", pkg.short, "src"), { recursive: true });
      writeFileSync(join(dir, "packages", pkg.short, "src/index.ts"), "export const one = 1;\n");
    }
    await git(dir, "add", ".");
    await git(dir, "commit", "-q", "-m", "one");
    await git(dir, "remote", "add", "origin", remote);
    await git(dir, "update-ref", "refs/remotes/origin/main", "HEAD");
    return dir;
  }

  it("accepts a clean tree whose HEAD is origin/main, and says which commit and repository", async () => {
    const dir = await repo("clean");
    const head = (await git(dir, "rev-parse", "HEAD")).stdout.trim();
    expect(await releaseState(dir)).toEqual({
      repository: PUBLIC_REPOSITORY,
      commit: head,
      tracked: SDK_PACKAGES.map((pkg) => `packages/${pkg.short}/src/index.ts`).sort(),
    });
  });

  it("refuses uncommitted changes: a changed file, a staged file, an untracked file", async () => {
    const changed = await repo("changed");
    appendFileSync(join(changed, "a.txt"), "two\n");
    await expect(releaseState(changed)).rejects.toThrow(/uncommitted changes[\s\S]*a\.txt/);
    const staged = await repo("staged");
    writeFileSync(join(staged, "b.txt"), "b\n");
    await git(staged, "add", "b.txt");
    await expect(releaseState(staged)).rejects.toThrow(/uncommitted changes[\s\S]*b\.txt/);
    const untracked = await repo("untracked");
    writeFileSync(join(untracked, "c.txt"), "c\n");
    await expect(releaseState(untracked)).rejects.toThrow(/uncommitted changes[\s\S]*c\.txt/);
  });

  it("refuses a HEAD that is not origin/main: ahead of it, behind it, or with no origin/main known", async () => {
    const ahead = await repo("ahead");
    writeFileSync(join(ahead, "a.txt"), "two\n");
    await git(ahead, "commit", "-q", "-am", "two");
    await expect(releaseState(ahead)).rejects.toThrow(/HEAD .* is not origin\/main/);
    const behind = await repo("behind");
    writeFileSync(join(behind, "a.txt"), "two\n");
    await git(behind, "commit", "-q", "-am", "two");
    await git(behind, "update-ref", "refs/remotes/origin/main", "HEAD");
    await git(behind, "reset", "-q", "--hard", "HEAD~1");
    await expect(releaseState(behind)).rejects.toThrow(/HEAD .* is not origin\/main/);
    const unknown = await repo("unknown");
    await git(unknown, "update-ref", "-d", "refs/remotes/origin/main");
    await expect(releaseState(unknown)).rejects.toThrow(/origin\/main is not known here.*git fetch origin/);
  });

  it("refuses a remote with credentials and a folder that is not a repository, and never fetches", async () => {
    const secret = await repo("secret", PUBLIC_REPOSITORY.replace("https://", "https://bob:hunter2token@"));
    await expect(releaseState(secret)).rejects.toThrow(/holds credentials/);
    await expect(releaseState(secret)).rejects.not.toThrow(/hunter2token/);
    mkdirSync(join(base, "repos/plain"), { recursive: true });
    await expect(releaseState(join(base, "repos/plain"))).rejects.toThrow(/not a git repository|no commit/);
    const source = readFileSync(join(REPO_ROOT, "tools/sdk/src/release.ts"), "utf8");
    expect(source).not.toMatch(/"(fetch|pull|push)"/);
  });
});

// Review S2: `git status` does not show an ignored file, and a tracked file can be hidden from it. Each would have
// been compiled or copied into a tarball while the tree read as clean.
describe("what a clean `git status` hides (on small repositories of its own)", () => {
  async function repo(name: string): Promise<string> {
    const dir = join(base, "hidden", name);
    mkdirSync(dir, { recursive: true });
    await git(dir, "init", "-q", "-b", "main");
    writeFileSync(join(dir, ".gitignore"), "node_modules\n.env*\ndist/\n");
    for (const pkg of SDK_PACKAGES) {
      mkdirSync(join(dir, "packages", pkg.short, "src"), { recursive: true });
      writeFileSync(join(dir, "packages", pkg.short, "src/index.ts"), "export const one = 1;\n");
    }
    await git(dir, "add", ".");
    await git(dir, "commit", "-q", "-m", "one");
    await git(dir, "remote", "add", "origin", `${PUBLIC_REPOSITORY}.git`);
    await git(dir, "update-ref", "refs/remotes/origin/main", "HEAD");
    return dir;
  }

  it("refuses an ignored file in a package's source folder: an .env file, a file under an ignored dist folder", async () => {
    const env = await repo("env");
    writeFileSync(join(env, "packages/guard/src/.env.local"), "SECRET=1\n");
    expect((await git(env, "status", "--porcelain")).stdout).toBe("");
    await expect(releaseState(env)).rejects.toThrow(/git ignores[\s\S]*packages\/guard\/src\/\.env\.local/);
    const nested = await repo("nested");
    mkdirSync(join(nested, "packages/shield-node/src/dist"));
    writeFileSync(join(nested, "packages/shield-node/src/dist/extra.ts"), "export const extra = 1;\n");
    expect((await git(nested, "status", "--porcelain")).stdout).toBe("");
    await expect(releaseState(nested)).rejects.toThrow(/git ignores[\s\S]*packages\/shield-node\/src\/dist\/extra\.ts/);
    // The protocol's folder counts too: Harden carries its compiled files.
    const vendored = await repo("vendored");
    writeFileSync(join(vendored, "packages/protocol/src/.env"), "x\n");
    await expect(releaseState(vendored)).rejects.toThrow(/packages\/protocol\/src\/\.env/);
  });

  it("refuses a tracked file that git was told not to look at: skip-worktree, assume-unchanged", async () => {
    const skip = await repo("skip");
    await git(skip, "update-index", "--skip-worktree", "packages/harden/src/index.ts");
    writeFileSync(join(skip, "packages/harden/src/index.ts"), "export const one = 2; // not what was committed\n");
    expect((await git(skip, "status", "--porcelain")).stdout).toBe("");
    await expect(releaseState(skip)).rejects.toThrow(
      /skip-worktree or assume-unchanged[\s\S]*packages\/harden\/src\/index\.ts/,
    );
    const assume = await repo("assume");
    await git(assume, "update-index", "--assume-unchanged", "packages/guard/src/index.ts");
    writeFileSync(join(assume, "packages/guard/src/index.ts"), "export const one = 3;\n");
    await expect(releaseState(assume)).rejects.toThrow(
      /skip-worktree or assume-unchanged[\s\S]*packages\/guard\/src\/index\.ts/,
    );
  });

  it("an ignored file elsewhere (node_modules, a dist folder at the root) does not stop a release", async () => {
    const dir = await repo("elsewhere");
    mkdirSync(join(dir, "node_modules/x"), { recursive: true });
    writeFileSync(join(dir, "node_modules/x/index.js"), "");
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist/old.tgz"), "");
    await expect(releaseState(dir)).resolves.toMatchObject({ repository: PUBLIC_REPOSITORY });
  });

  it("refuses an origin that is not the project's repository", async () => {
    const dir = await repo("other-origin");
    await git(dir, "remote", "set-url", "origin", "https://github.com/someone-else/antireverse.git");
    await expect(releaseState(dir)).rejects.toThrow(
      /origin is https:\/\/github\.com\/someone-else\/antireverse, not the project's repository/,
    );
  });
});

// Review S2, second half: what ships is what the release commit tracks, not what lies in the folder.
describe("a release ships only files of tracked sources", () => {
  it("a compiled file whose source the commit does not track stops the release: nothing is packed", async () => {
    const layoutStray = layoutIn(base, "stray");
    const tracked = workingTreeSources().filter((file) => file !== "packages/guard/src/signals.js");
    await expect(buildAndPack(layoutStray, { key, release: { repository, commit, tracked } })).rejects.toThrow(
      /@antireverse\/guard: dist\/signals\.js would ship, but packages\/guard\/src\/signals\.js is not tracked at the release commit/,
    );
    expect(existsSync(layoutStray.release)).toBe(false);
    const layoutTs = layoutIn(base, "stray-ts");
    const withoutTs = workingTreeSources().filter((file) => file !== "packages/shield-node/src/uuidv7.ts");
    await expect(buildAndPack(layoutTs, { key, release: { repository, commit, tracked: withoutTs } })).rejects.toThrow(
      /@antireverse\/shield-node: dist\/uuidv7\.js would ship, but packages\/shield-node\/src\/uuidv7\.ts is not tracked/,
    );
    // The protocol Harden carries is held to the same rule.
    const layoutVendored = layoutIn(base, "stray-vendored");
    const withoutProtocol = workingTreeSources().filter((file) => file !== "packages/protocol/src/slo.ts");
    await expect(
      buildAndPack(layoutVendored, { key, release: { repository, commit, tracked: withoutProtocol } }),
    ).rejects.toThrow(
      /@antireverse\/harden: dist\/_protocol\/slo\.(d\.ts|js) would ship, but packages\/protocol\/src\/slo\.ts is not tracked/,
    );
  });

  it("the release built from the full list has, in each tarball, a file for a tracked source and nothing else", () => {
    const tracked = new Set(info.tracked);
    for (const tarball of released.tarballs) {
      const pkg = sdkPackage(tarball.name);
      const entries = tarNames(gunzipSync(readFileSync(tarball.path))).filter((name) =>
        name.startsWith("package/dist/"),
      );
      expect(entries.length, pkg.short).toBeGreaterThan(5);
      for (const entry of entries) {
        const rel = entry.slice("package/dist/".length);
        const vendored = rel.startsWith("_protocol/");
        const short = vendored ? "protocol" : pkg.short;
        const file = vendored ? rel.slice("_protocol/".length) : rel;
        const source = pkg.kind === "copy" && !vendored ? file : file.replace(/\.d\.ts$|\.js$/, ".ts");
        expect(tracked.has(`packages/${short}/src/${source}`), `${pkg.short}: ${entry}`).toBe(true);
      }
    }
  });
});

describe("the release folder", () => {
  it("holds exactly three tarballs, their bills of materials, the manifest and the marker; the protocol is not there", () => {
    const version = sdkVersion();
    expect(released.tarballs.map((t) => t.file)).toEqual(
      ["shield-node", "guard", "harden"].map((n) => `antireverse-${n}-${version}.tgz`),
    );
    expect(filesOf(layout.release)).toEqual(
      [BUILD_MARKER, MANIFEST_FILE, ...released.manifest.packages.flatMap((p) => [p.tarball.file, p.sbom.file])].sort(),
    );
    expect(filesOf(layout.release).join(" ")).not.toMatch(/protocol/);
    // The ordinary folder of this layout was not written by the release, and the release wrote no ordinary folder.
    expect(existsSync(layout.out)).toBe(false);
    expect(existsSync(ordinary.release)).toBe(false);
  });

  it("each packed manifest can be published: no private, public access, and the public metadata of the project", () => {
    for (const tarball of released.tarballs) {
      const pkg = sdkPackage(tarball.name);
      const manifest = packedManifest(tarball.path);
      expect("private" in manifest, pkg.short).toBe(false);
      expect(manifest.publishConfig, pkg.short).toEqual({ access: "public" });
      expect(manifest.name).toBe(pkg.name);
      expect(manifest.version).toBe("0.1.0");
      expect(manifest.description).toBe(pkg.description);
      expect(manifest.license).toBe("Apache-2.0");
      expect(manifest.repository).toEqual({
        type: "git",
        url: `git+${repository}.git`,
        directory: `packages/${pkg.short}`,
      });
      expect(manifest.homepage).toBe(`${repository}/blob/main/${pkg.guide}`);
      expect(manifest.bugs).toEqual({ url: `${repository}/issues` });
      expect((manifest.keywords as string[]).length, pkg.short).toBeGreaterThanOrEqual(3);
      expect(manifest.keywords).toContain("airverse");
      expect(manifest.files).toEqual(["dist", "NOTICE"]);
      expect(manifest.type).toBe("module");
      expect(Object.keys(manifest.dependencies as object).filter((name) => name.startsWith("@antireverse/"))).toEqual(
        [],
      );
      expect(JSON.stringify(manifest)).not.toMatch(/devDependencies|"scripts"|src\/|workspace/);
    }
    const manifest = (short: string) =>
      packedManifest(released.tarballs.find((t) => t.name === sdkPackage(short).name)?.path as string);
    expect(manifest("shield-node").engines).toEqual({ node: ">=22.12" });
    expect(manifest("guard").engines).toEqual({ node: ">=22.12" });
    expect(manifest("harden").engines).toEqual({ node: "^22.18.0 || >=24.11.0" });
    expect(manifest("harden").bin).toEqual({ antireverse: "./dist/cli.js" });
    expect(manifest("shield-node").dependencies).toEqual({});
    expect(manifest("guard").dependencies).toEqual({});
  });

  it("the ordinary pack is as it was: four tarballs, every one private, none with release metadata", () => {
    expect(private_.tarballs.map((t) => t.name)).toEqual(SDK_PACKAGES.map((pkg) => pkg.name));
    for (const tarball of private_.tarballs) {
      const manifest = packedManifest(tarball.path);
      expect(manifest.private, tarball.name).toBe(true);
      for (const field of ["publishConfig", "repository", "homepage", "bugs", "keywords"])
        expect(field in manifest, `${tarball.name} ${field}`).toBe(false);
      expect(Object.keys(manifest)).toEqual([
        "name",
        "version",
        "private",
        "description",
        "license",
        "type",
        ...(tarball.name.endsWith("/guard") ? ["sideEffects"] : []),
        "engines",
        "exports",
        "types",
        ...(tarball.name.endsWith("/harden") ? ["bin"] : []),
        "files",
        "dependencies",
      ]);
      expect(tarFile(gunzipSync(readFileSync(tarball.path)), "package/README.md").toString("utf8")).toMatch(
        /not published to npm/,
      );
    }
    expect((private_.manifest as SdkManifest).kind).toBe("local");
  });

  it("the compiled files are the same in both: a release changes the manifest and the README, not the code", () => {
    for (const tarball of released.tarballs) {
      const other = private_.tarballs.find((t) => t.name === tarball.name);
      const a = gunzipSync(readFileSync(tarball.path));
      const b = gunzipSync(readFileSync(other?.path as string));
      for (const file of ["package/dist/index.js", "package/dist/index.d.ts", "package/LICENSE", "package/NOTICE"]) {
        expect(tarFile(a, file).equals(tarFile(b, file)), `${tarball.name} ${file}`).toBe(true);
      }
    }
  });

  it("a second release build of the same commit gives the same tarballs and bills of materials, byte for byte", async () => {
    const second = await buildAndPack(again, { key, release: info });
    expect(second.manifest.packages.map((p) => [p.tarball.sha256, p.sbom.sha256])).toEqual(
      released.manifest.packages.map((p) => [p.tarball.sha256, p.sbom.sha256]),
    );
  });
});

describe("the README for the npm page", () => {
  it("says what the package is, how to install it by name, and the honest status of the project", () => {
    for (const pkg of RELEASED_PACKAGES) {
      const readme = packedReadme(released, pkg.short);
      expect(readme.startsWith(`# ${pkg.name}\n\n${pkg.description}\n`), pkg.short).toBe(true);
      expect(readme, pkg.short).toContain(
        pkg.short === "harden" ? "npm install --save-dev @antireverse/harden" : `npm install ${pkg.name}`,
      );
      expect(readme, pkg.short).toMatch(/\*\*Early release \(0\.1\.0\)\.\*\*/);
      expect(readme, pkg.short).toMatch(/There is no hosted Airverse service/);
      expect(readme, pkg.short).toMatch(/you run them yourself, from the repository/);
      expect(readme, pkg.short).toMatch(/release gate is still blocked/);
      expect(readme, pkg.short).toMatch(/scripted stand-in/);
      expect(readme, pkg.short).toContain(`commit ${commit}`);
      expect(readme, pkg.short).toMatch(/## Honest limits/);
      expect(readme, pkg.short).toContain(repository);
    }
    expect(packedReadme(released, "harden")).toMatch(/obfuscation, not secrecy/);
    expect(packedReadme(released, "harden")).toMatch(/npx --no-install antireverse harden <bundle-dir>/);
    expect(packedReadme(released, "guard")).toMatch(
      /not that the client is genuine|not bot protection|does not prove/i,
    );
  });

  it("has nothing for a clone and nothing about tarballs, and every link is an absolute URL into the repository's docs", () => {
    for (const pkg of RELEASED_PACKAGES) {
      const readme = packedReadme(released, pkg.short);
      expect(readme, pkg.short).not.toMatch(
        /packages\/(shield-node|guard|harden|protocol)\/src|npx tsx|experimental-strip-types|sdk:pack|\.tgz|tarball|not published/,
      );
      const links = [...readme.matchAll(/\]\(([^)]+)\)/g)].map((m) => m[1] as string);
      for (const link of links)
        expect(link, pkg.short).toMatch(
          new RegExp(
            `^(#[a-z0-9-]+|${repository.replace(/[.]/g, "\\.")}(/blob/main/(docs/[a-z-]+\\.md|README\\.md)(#[a-z0-9-]+)?)?)$`,
          ),
        );
      expect(links.filter((link) => link.startsWith(repository)).length, pkg.short).toBeGreaterThan(0);
    }
    expect(packedReadme(released, "harden")).toContain(`](${repository}/blob/main/docs/reverse-assessment.md)`);
  });

  it("does not claim more than is true: no 'verified', no provenance, no hosted service, and it names what the signature is not", () => {
    for (const pkg of RELEASED_PACKAGES) {
      const readme = packedReadme(released, pkg.short);
      expect(readme, pkg.short).not.toMatch(/production-ready|battle-tested|guarantee/i);
      expect(readme, pkg.short).toMatch(/no provenance attestation/);
    }
  });
});

// Review B1: the unscoped npm name `antireverse` is not the project's. `npx antireverse` asks the registry for it
// whenever the command is not installed locally, so no text a user reads may show it (D-146).
describe("no documented command can fetch a package by a name the project does not hold", () => {
  const BARE = /npx (?!--no-install )(?:-\S+ )*antireverse\b/;
  const texts = (): Array<[string, string]> => [
    ...RELEASED_PACKAGES.map((pkg): [string, string] => [
      `release README of ${pkg.short}`,
      packedReadme(released, pkg.short),
    ]),
    ...SDK_PACKAGES.map((pkg): [string, string] => [
      `ordinary README of ${pkg.short}`,
      packedReadme(private_, pkg.short),
    ]),
    ...[
      "README.md",
      "docs/getting-started.md",
      "docs/shield.md",
      "docs/guard.md",
      "docs/harden.md",
      "docs/reverse-assessment.md",
      "skills/airverse-setup/SKILL.md",
      "skills/airverse-setup/scripts/preflight.mjs",
    ].map((file): [string, string] => [file, readFileSync(join(REPO_ROOT, file), "utf8")]),
  ];

  it("no text shows `npx antireverse` without --no-install, `npx @antireverse/…`, or an npx that says yes", () => {
    for (const [name, text] of texts()) {
      expect(text.match(BARE)?.[0], name).toBeUndefined();
      expect(text, name).not.toMatch(/npx (?:-\S+ )*@antireverse\//);
      expect(text, name).not.toMatch(/npx (--yes|-y)\b/);
      expect(text, name).not.toMatch(/"npx",\s*"antireverse"/);
    }
    // The pattern itself: it finds the bare form and passes the safe one. (Written with match: the gate takes a
    // string literal handed to a RegExp's test method for the name of a test.)
    expect("npx antireverse harden".match(BARE)).not.toBeNull();
    expect("npx --no-install antireverse harden".match(BARE)).toBeNull();
  });

  it("Harden's READMEs show the safe form in every command, and say in one sentence why", () => {
    for (const result of [released, private_]) {
      const readme = packedReadme(result, "harden");
      expect(readme.match(/npx --no-install antireverse/g)?.length).toBeGreaterThanOrEqual(9);
      expect(readme).toMatch(
        /`--no-install` makes npx run only the copy installed in your project: it never downloads or runs a package named `antireverse` from the registry/,
      );
    }
    expect(readFileSync(join(REPO_ROOT, "docs/harden.md"), "utf8")).toMatch(
      /never downloads or runs a package named `antireverse`/,
    );
  });

  it("nothing in a packed README is about the repository's own furniture", () => {
    for (const [name, text] of texts().slice(0, RELEASED_PACKAGES.length + SDK_PACKAGES.length)) {
      expect(text, name).not.toMatch(/reference target|this repository/);
    }
    expect(packedReadme(released, "shield-node")).toMatch(/\| `AR_SHIELD_KEY` \| your code \(as in the example\) \|/);
    expect(packedReadme(released, "shield-node")).not.toMatch(/AR_API_URL/);
    expect(packedReadme(released, "harden")).toMatch(/not a commit of the Airverse repository/);
  });
});

describe("the signed release manifest", () => {
  it("covers exactly the three tarballs and their bills of materials, with the version, the commit and the repository", () => {
    const manifest = JSON.parse(readFileSync(join(layout.release, MANIFEST_FILE), "utf8")) as SdkManifest;
    expect(manifest.kind).toBe("release");
    expect(manifest.packages.map((p) => [p.name, p.version])).toEqual(
      RELEASED_PACKAGES.map((pkg) => [pkg.name, "0.1.0"]),
    );
    expect(manifest.source).toEqual({ commit, dirty: false });
    expect(manifest.repository).toBe(repository);
    expect(manifest.statement).toMatch(/not provenance/);
    expect(manifest.statement).toMatch(/for publication/);
    expect(manifest.statement).not.toMatch(/not published and this is not a release/);
    expect(manifest.packages[2]?.vendored).toEqual(["@antireverse/protocol"]);
  });

  it("sdk:verify's check accepts it, and fails when a tarball changed", () => {
    expect(verifyArtifacts(layout.release, { localFingerprint: key.fingerprint }).ok).toBe(true);
    const copy = join(base, "tampered");
    cpSync(layout.release, copy, { recursive: true });
    appendFileSync(join(copy, released.tarballs[0]?.file as string), "x");
    expect(verifyArtifacts(copy, { localFingerprint: key.fingerprint }).ok).toBe(false);
  });

  it("Harden's bill of materials names the protocol it carries by version and by the digest of the carried files", () => {
    const sbom = JSON.parse(
      readFileSync(join(layout.release, released.manifest.packages[2]?.sbom.file as string), "utf8"),
    );
    const inside = sbom.metadata.component.components as Array<{
      name: string;
      version: string;
      hashes?: unknown;
      properties: Array<{ name: string; value: string }>;
    }>;
    expect(inside).toHaveLength(1);
    expect(inside[0]).toMatchObject({ group: "@antireverse", name: "protocol", version: "0.1.0" });
    expect(inside[0]?.properties.find((p) => p.name === "airverse:vendored-files-sha256")?.value).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(sbom.metadata.component.hashes).toEqual([
      { alg: "SHA-256", content: released.manifest.packages[2]?.tarball.sha256 },
    ]);
  });
});

describe("the owner's checks, against a loopback registry", () => {
  const work = join(base, "npm-checks");
  const options = (registry: string) => ({ registry, work, localFingerprint: key.fingerprint });
  const served = () =>
    released.tarballs.map((tarball) => ({
      manifest: packedManifest(tarball.path) as Record<string, unknown>,
      tarball,
    }));

  it("release-check: nothing is on the registry yet, so it lists every tarball and prints the commands to copy — and runs none", async () => {
    const registry = await startRegistry([]);
    try {
      const result = await releaseCheck(layout.release, options(registry.url));
      expect(result.problems).toEqual([]);
      expect(result.ok).toBe(true);
      expect(result.tarballs.map((t) => t.name)).toEqual(RELEASED_PACKAGES.map((pkg) => pkg.name));
      for (const tarball of result.tarballs) {
        const bytes = readFileSync(tarball.path);
        expect(tarball.size).toBe(bytes.length);
        expect(tarball.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
        expect(tarball.integrity).toBe(`sha512-${createHash("sha512").update(bytes).digest("base64")}`);
        expect(tarball.registry).toBe("absent");
      }
      expect(result.asked).toBe(true);
      expect(result.commands).toEqual([
        "npm login",
        ...released.tarballs.map((t) => `npm publish ${shellQuote(t.path)} --access public`),
      ]);
      // Read-only: three questions, each a GET for a name, and nothing else.
      expect(registry.requests.map((r) => r.path).sort()).toEqual(RELEASED_PACKAGES.map((pkg) => pkg.name).sort());
      expect(readFileSync(join(REPO_ROOT, "tools/sdk/src/publish.ts"), "utf8")).not.toMatch(
        /"(publish|login|adduser|token|access|link)"/,
      );
    } finally {
      await registry.close();
    }
  });

  it("release-check fails when a version is already on the registry: a published version can never be used again", async () => {
    const registry = await startRegistry(served().slice(0, 1));
    try {
      const result = await releaseCheck(layout.release, options(registry.url));
      expect(result.ok).toBe(false);
      expect(result.problems).toEqual([
        "@antireverse/shield-node@0.1.0 is already on the registry: that version can never be published again",
      ]);
      expect(result.commands).toEqual([]);
    } finally {
      await registry.close();
    }
  });

  it("release-check says so plainly when the registry cannot be reached, and prints no commands", async () => {
    const registry = await startRegistry([]);
    const url = registry.url;
    await registry.close();
    const result = await releaseCheck(layout.release, options(url));
    expect(result.ok).toBe(false);
    expect(result.problems.join(" ")).toMatch(/the registry could not be reached/);
    expect(result.problems.join(" ")).toMatch(/nothing was checked/i);
    expect(result.commands).toEqual([]);
  });

  it("release-check refuses the ordinary folder, a changed folder and an unknown signer before it asks any registry", async () => {
    const registry = await startRegistry([]);
    try {
      const local = await releaseCheck(ordinary.out, options(registry.url));
      expect(local.ok).toBe(false);
      expect(local.problems.join(" ")).toMatch(/not a release folder/);
      const unknown = await releaseCheck(layout.release, { registry: registry.url, work, localFingerprint: null });
      expect(unknown.ok).toBe(false);
      expect(unknown.problems.join(" ")).toMatch(/signer .* is not trusted/);
      const changed = await releaseCheck(join(base, "tampered"), options(registry.url));
      expect(changed.ok).toBe(false);
      expect(changed.problems.join(" ")).toMatch(/size|SHA-256/);
      expect(registry.requests).toEqual([]);
      for (const result of [local, unknown, changed]) {
        expect(result.commands).toEqual([]);
        expect(result.asked).toBe(false);
      }
    } finally {
      await registry.close();
    }
  });

  it("a signed release folder that holds a private tarball is refused by both checks before any registry is asked", async () => {
    // The ordinary pack's three tarballs (private) under a release manifest signed with the trusted key.
    const dir = join(base, "private-in-release");
    mkdirSync(dir, { recursive: true });
    const packages = private_.manifest.packages
      .filter((entry) => RELEASED_PACKAGES.some((pkg) => pkg.name === entry.name))
      .map((entry) => {
        for (const file of [entry.tarball.file, entry.sbom.file]) cpSync(join(ordinary.out, file), join(dir, file));
        return { ...entry, tarball: artifactFile(dir, entry.tarball.file), sbom: artifactFile(dir, entry.sbom.file) };
      });
    writeManifest(dir, { ...released.manifest, packages }, key);
    expect(verifyArtifacts(dir, { localFingerprint: key.fingerprint }).ok).toBe(true);
    const registry = await startRegistry([]);
    try {
      for (const check of [releaseCheck, publishedCheck]) {
        const result = await check(dir, options(registry.url));
        expect(result.ok).toBe(false);
        expect(
          result.problems.filter((p) => /its package\.json is private; it cannot be published/.test(p)),
        ).toHaveLength(3);
        expect(result.commands).toEqual([]);
        expect(result.asked).toBe(false);
      }
      expect(registry.requests).toEqual([]);
    } finally {
      await registry.close();
    }
  });

  it("the printed commands quote the path for a POSIX shell, whatever it holds", async () => {
    expect(shellQuote("/plain/path.tgz")).toBe("'/plain/path.tgz'");
    expect(shellQuote("it's")).toBe("'it'\\''s'");
    const awkward = join(base, "a dir with $HOME `id` !bang and 'quotes'");
    cpSync(layout.release, awkward, { recursive: true });
    const registry = await startRegistry([]);
    try {
      const result = await releaseCheck(awkward, options(registry.url));
      expect(result.ok).toBe(true);
      for (const [index, tarball] of result.tarballs.entries()) {
        const command = result.commands[index + 1] as string;
        expect(command.startsWith("npm publish '")).toBe(true);
        // A shell gives the program exactly the path: nothing is expanded, substituted or split.
        const echoed = await exec("/bin/sh", ["-c", command.replace(/^npm publish /, "printf '%s\\n' ")], {
          cwd: base,
        });
        expect(echoed.stdout).toBe(`${tarball.path}\n--access\npublic\n`);
      }
    } finally {
      await registry.close();
    }
  });

  it("published-check: passes when the registry has the same bytes for all three", async () => {
    const registry = await startRegistry(served());
    try {
      const result = await publishedCheck(layout.release, options(registry.url));
      expect(result.problems).toEqual([]);
      expect(result.ok).toBe(true);
      expect(result.tarballs.every((t) => t.registry === "same")).toBe(true);
    } finally {
      await registry.close();
    }
  });

  it("published-check: fails when a package is missing, and when the registry's bytes are others", async () => {
    // Guard is not there; Harden is there with other bytes under the same name and version.
    const other = join(base, "other-harden");
    mkdirSync(other, { recursive: true });
    writeFileSync(join(other, "package.json"), JSON.stringify({ name: "@antireverse/harden", version: "0.1.0" }));
    const [different] = await npmPack([other], join(base, "other-out"), work);
    const items = served();
    const registry = await startRegistry([
      items[0] as (typeof items)[number],
      {
        manifest: { name: "@antireverse/harden", version: "0.1.0" },
        tarball: different as (typeof items)[number]["tarball"],
      },
    ]);
    try {
      const result = await publishedCheck(layout.release, options(registry.url));
      expect(result.ok).toBe(false);
      expect(result.problems.sort()).toEqual([
        "@antireverse/guard@0.1.0 is not on the registry",
        "@antireverse/harden@0.1.0 on the registry has another integrity than the local tarball",
      ]);
      expect(result.tarballs.map((t) => t.registry)).toEqual(["same", "absent", "different"]);
    } finally {
      await registry.close();
    }
  });
});

describe("the commands", () => {
  const tsx = join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs");
  const run = (args: string[]) =>
    new Promise<{ code: number; stdout: string; stderr: string }>((done) => {
      execFile(
        process.execPath,
        [tsx, join(REPO_ROOT, "tools/sdk/src/cli.ts"), ...args],
        { cwd: REPO_ROOT, env: { ...process.env, AR_GATE_KEY_FILE: join(base, "keys/gate-key.json") } },
        (error, stdout, stderr) =>
          done({ code: error ? (typeof error.code === "number" ? error.code : -1) : 0, stdout, stderr }),
      );
    });

  it("release-check and published-check refuse the ordinary folder without asking a registry, and need a folder", async () => {
    for (const command of ["release-check", "published-check"]) {
      const refused = await run([command, ordinary.out]);
      expect(refused.code, command).toBe(1);
      expect(refused.stdout, command).toMatch(/not a release folder/);
      // No registry was asked, and the output does not say that one was.
      expect(refused.stdout, command).not.toMatch(/Registry asked/);
      expect(refused.stdout, command).not.toMatch(/npm publish/);
      expect((await run([command])).code, command).toBe(2);
    }
  });

  it("the usage names the release commands and says who publishes", async () => {
    const usage = await run([]);
    expect(usage.code).toBe(2);
    for (const name of ["sdk:release", "sdk:release-check", "sdk:published-check"])
      expect(usage.stderr).toContain(name);
    const root = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    expect(root.scripts["sdk:release"]).toBe("tsx tools/sdk/src/cli.ts release");
    expect(root.scripts["sdk:release-check"]).toBe("tsx tools/sdk/src/cli.ts release-check");
    expect(root.scripts["sdk:published-check"]).toBe("tsx tools/sdk/src/cli.ts published-check");
    // No script of the repository publishes.
    expect(Object.values(root.scripts).join("\n")).not.toMatch(/npm (publish|login|adduser|token)/);
    expect(
      readdirSync(join(REPO_ROOT, "tools/sdk/src"))
        .map((f) => readFileSync(join(REPO_ROOT, "tools/sdk/src", f), "utf8"))
        .join("\n"),
    ).not.toMatch(/\["(publish|login|adduser)"/);
  });
});
