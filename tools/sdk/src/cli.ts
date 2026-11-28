// The SDK commands (slice 23). Nothing here publishes anything.
//
//   npm run sdk:build                              compile into packages/<name>/dist
//   npm run sdk:pack                               build, check the allowlist, pack, bill of materials, signed manifest → dist/sdk
//   npm run sdk:verify -- <dir> [--expect <fingerprint>]
//   npm run sdk:allowlist                          print today's dependency closure in the allowlist's form
//
// Exit 0 done or valid, 1 failed or invalid or untrusted, 2 usage. `--dir <base>` (build, pack, allowlist) writes
// into a folder inside an airverse-sdk-* folder of the temporary directory instead of the repository's build folders;
// any other folder is refused. What each command empties and writes again, printed before it does:
//   build      the four packages/<name>/dist folders
//   allowlist  those four and dist/sdk-work (printed on the error stream: its output is the list)
//   pack       those five and dist/sdk; it also creates the local gate key on first use (outside the repository)
//   release    those five and dist/sdk-release; likewise the key (slice 23b, below)
//   verify, release-check, published-check   nothing; they never create a key
//
// Slice 23b, for the owner:
//   npm run sdk:release                              the three publishable tarballs → dist/sdk-release; refuses a
//                                                    dirty tree and a HEAD that is not origin/main (nothing is fetched)
//   npm run sdk:release-check -- <dir> [--expect <fingerprint>]     before publishing: verifies the folder, asks the
//                                                    registry (read-only) that no version exists yet, prints the commands
//   npm run sdk:published-check -- <dir> [--expect <fingerprint>]   after: the registry has the same bytes
// None of them publishes, logs in or changes npm's configuration. Publishing is done by the owner, by hand.
import { existsSync, mkdtempSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { defaultKeyFile, loadOrCreateKey } from "../../gate/src/sign.ts";
import { currentAllowlist } from "./allowlist.ts";
import { buildAll } from "./build.ts";
import { MANIFEST_FILE, verifyArtifacts } from "./manifest.ts";
import { SDK_PACKAGES } from "./packages.ts";
import { buildAndPack, stagedClosures } from "./pipeline.ts";
import { type CheckResult, NPM_REGISTRY, publishedCheck, releaseCheck, shellQuote } from "./publish.ts";
import { recordCheck } from "./record.ts";
import { releaseState } from "./release.ts";
import { cleanBuildDir, type Layout, prepareBuildDir, repoLayout, TEMP_PREFIX, tempLayout } from "./safe.ts";
import { stageAll } from "./stage.ts";

const USAGE = `usage:
  npm run sdk:build
  npm run sdk:pack
  npm run sdk:verify -- <dir> [--expect <fingerprint>]
  npm run sdk:allowlist
  npm run sdk:release                                            (owner: builds the publishable tarballs; publishes nothing)
  npm run sdk:release-check -- <dir> [--expect <fingerprint>]    (before publishing; read-only)
  npm run sdk:published-check -- <dir> [--expect <fingerprint>]  (after publishing; read-only)
  npm run sdk:record-check -- <releases/x.y.z> [--online] [--expect <fingerprint>]  (anyone; read-only)
`;

const out = (text: string) => void process.stdout.write(text);
const err = (text: string) => void process.stderr.write(text);
const cwd = () => process.env.INIT_CWD ?? process.cwd();

function layoutFrom(args: string[]): Layout | null {
  if (args.length === 0) return repoLayout();
  if (args.length === 2 && args[0] === "--dir") return tempLayout(resolve(cwd(), args[1] as string));
  return null;
}

/** Names the folders a command empties, before it does. `print`: where (the allowlist's own output is JSON). */
function announce(folders: string[], print: (text: string) => void = out): void {
  print("Removing and writing again (build folders of this tooling only):\n");
  for (const folder of folders) print(`  ${folder}\n`);
}

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  if (command === "verify") {
    let expect: string | undefined;
    const paths: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === "--expect") {
        expect = args[++i];
        if (expect === undefined || !/^[0-9a-f]{64}$/.test(expect)) {
          err(`--expect needs a 64-character hex fingerprint\n${USAGE}`);
          return 2;
        }
      } else if (arg.startsWith("--")) {
        err(USAGE);
        return 2;
      } else paths.push(arg);
    }
    if (paths.length !== 1) {
      err(USAGE);
      return 2;
    }
    const dir = resolve(cwd(), paths[0] as string);
    // The local gate key is read when there is one; it is never created here.
    const keyFile = defaultKeyFile(process.env);
    let local: string | null = null;
    let localNote = "no local gate key";
    if (existsSync(keyFile)) {
      try {
        local = loadOrCreateKey(keyFile).fingerprint;
      } catch (error) {
        localNote = `the local gate key could not be read (${error instanceof Error ? error.message : String(error)})`;
      }
    }
    const result = verifyArtifacts(dir, { localFingerprint: local, ...(expect === undefined ? {} : { expect }) });
    if (result.problems.length > 0) {
      out(`INVALID: ${dir}\n`);
      for (const problem of result.problems) out(`  ${problem}\n`);
      return 1;
    }
    if (!result.trusted) {
      const why =
        expect !== undefined
          ? "is not the fingerprint given with --expect"
          : local === null
            ? `is not known: ${localNote}, and no --expect was given`
            : "is not the local gate key, and no --expect was given";
      out(
        `UNTRUSTED KEY: every file matches ${MANIFEST_FILE} and its signature verifies, but the signer ${result.fingerprint} ${why}; ${dir}\n`,
      );
      return 1;
    }
    const by = expect !== undefined ? "the fingerprint given with --expect" : "the local gate key";
    out(
      `valid: ${result.packages.length} packages in ${dir} match ${MANIFEST_FILE}, signed by ${result.fingerprint} (${by}).\n` +
        "This is a local signature by whoever holds that key: it shows the files are the ones that were signed. It is not provenance from a trusted builder.\n",
    );
    for (const pkg of result.packages) out(`  ${pkg.name}@${pkg.version}  ${pkg.file}\n`);
    return 0;
  }

  if (command === "record-check") {
    // npm run sdk:record-check -- <releases/x.y.z> [--online] [--expect <fingerprint>]: a release record's signature
    // and files; with --online also the registry's integrity of each package, read-only.
    const online = args.includes("--online");
    const at = args.indexOf("--expect");
    const expect = at >= 0 ? args[at + 1] : undefined;
    const paths = args.filter((arg, index) => !arg.startsWith("--") && (at < 0 || index !== at + 1));
    if (paths.length !== 1 || (at >= 0 && !/^[0-9a-f]{64}$/.test(expect ?? ""))) {
      err(USAGE);
      return 2;
    }
    const dir = resolve(cwd(), paths[0] as string);
    let result: Awaited<ReturnType<typeof recordCheck>>;
    if (online) {
      const base = mkdtempSync(join(tmpdir(), `${TEMP_PREFIX}check-`));
      const work = tempLayout(base).work;
      prepareBuildDir(work);
      try {
        result = await recordCheck(dir, {
          ...(expect === undefined ? {} : { expect }),
          online: { registry: NPM_REGISTRY, work },
        });
      } finally {
        cleanBuildDir(work);
        rmdirSync(base);
      }
    } else result = await recordCheck(dir, expect === undefined ? {} : { expect });
    out(
      `record-check: ${dir}\n${result.asked ? `Registry asked (read-only): ${NPM_REGISTRY}` : "No registry was asked (pass --online to compare with it)."}\n\n`,
    );
    for (const pkg of result.packages) {
      out(
        `${pkg.name}@${pkg.version}\n  sha256     ${pkg.sha256}\n  integrity  ${pkg.integrity ?? "?"}\n  registry   ${pkg.registry}\n`,
      );
    }
    if (!result.ok) {
      out("\nNOT CONSISTENT:\n");
      for (const problem of result.problems) out(`  ${problem}\n`);
      return 1;
    }
    out(
      `\nconsistent: the manifest's signature verifies (signer ${result.fingerprint}; built from commit ${result.commit}) and the bills of materials match it${result.asked ? "; the registry has these integrities" : ""}.\n` +
        "The signature is a local one by the publisher, not provenance. The sha512 list is derived and unsigned.\n",
    );
    return 0;
  }

  if (command === "release-check" || command === "published-check") {
    let expect: string | undefined;
    const paths: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === "--expect") {
        expect = args[++i];
        if (expect === undefined || !/^[0-9a-f]{64}$/.test(expect)) {
          err(`--expect needs a 64-character hex fingerprint\n${USAGE}`);
          return 2;
        }
      } else if (arg.startsWith("--")) {
        err(USAGE);
        return 2;
      } else paths.push(arg);
    }
    if (paths.length !== 1) {
      err(USAGE);
      return 2;
    }
    const dir = resolve(cwd(), paths[0] as string);
    const keyFile = defaultKeyFile(process.env);
    let local: string | null = null;
    if (existsSync(keyFile)) {
      try {
        local = loadOrCreateKey(keyFile).fingerprint;
      } catch {}
    }
    // npm's cache and (empty) configuration for the read-only questions: a build folder of this run's own, in the
    // temporary directory, removed through the same function as every other.
    const base = mkdtempSync(join(tmpdir(), `${TEMP_PREFIX}check-`));
    const work = tempLayout(base).work;
    prepareBuildDir(work);
    let result: CheckResult;
    try {
      const options = {
        registry: NPM_REGISTRY,
        work,
        localFingerprint: local,
        ...(expect === undefined ? {} : { expect }),
      };
      result = command === "release-check" ? await releaseCheck(dir, options) : await publishedCheck(dir, options);
    } finally {
      cleanBuildDir(work);
      rmdirSync(base);
    }
    out(`${command}: ${dir}\n`);
    out(
      result.asked
        ? `Registry asked (read-only): ${NPM_REGISTRY}\n\n`
        : "No registry was asked: the folder itself was refused.\n\n",
    );
    for (const tarball of result.tarballs) {
      out(
        `${tarball.name}@${tarball.version}\n  file       ${tarball.file}\n  size       ${tarball.size} bytes\n  sha256     ${tarball.sha256}\n  integrity  ${tarball.integrity}\n  registry   ${tarball.registry}\n`,
      );
    }
    if (!result.ok) {
      out(`\nNOT READY:\n`);
      for (const problem of result.problems) out(`  ${problem}\n`);
      return 1;
    }
    if (command === "published-check") {
      out(
        `\npublished: the registry has ${result.tarballs.length} packages with exactly the bytes of the local tarballs (signed by ${result.fingerprint}).\n`,
      );
      return 0;
    }
    out(
      `\nready: the folder verifies (signed by ${result.fingerprint}, a local signature, not provenance) and none of these versions is on the registry.\n` +
        "This command published nothing. To publish, run these yourself, one by one, with your own npm login and one-time code:\n\n",
    );
    for (const line of result.commands) out(`${line}\n`);
    out("\n");
    for (const note of result.notes) out(`${note}\n`);
    out(
      "\nA published version can never be used again, and unpublishing is restricted: check the list above first.\n" +
        `Afterwards: npm run sdk:published-check -- ${shellQuote(dir)}\n`,
    );
    return 0;
  }

  if (command !== "build" && command !== "pack" && command !== "allowlist" && command !== "release") {
    err(USAGE);
    return 2;
  }
  let layout: Layout | null;
  try {
    layout = layoutFrom(args);
  } catch (error) {
    err(`${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
  if (layout === null) {
    err(USAGE);
    return 2;
  }
  const dists = SDK_PACKAGES.map((pkg) => (layout as Layout).dist(pkg));

  if (command === "build") {
    announce(dists);
    await buildAll(layout);
    out("Built. Nothing was packed or published.\n");
    return 0;
  }
  if (command === "allowlist") {
    // The closure needs the compiled code (what each package imports), so this builds and stages first. The list
    // is the command's output; what it empties is named on the error stream.
    announce([...dists, layout.work], err);
    await buildAll(layout);
    out(`${JSON.stringify(currentAllowlist(stagedClosures(stageAll(layout))), null, 2)}\n`);
    return 0;
  }
  if (command === "release") {
    // Refused before anything is built or removed: a dirty tree, a HEAD that is not origin/main, a remote with
    // credentials. The remote-tracking ref is read as it is; nothing is fetched.
    let release: Awaited<ReturnType<typeof releaseState>>;
    try {
      release = await releaseState(REPO_ROOT);
    } catch (error) {
      err(`sdk:release refused: ${error instanceof Error ? error.message : String(error)}\n`);
      return 1;
    }
    announce([...dists, layout.work, layout.release]);
    const releaseKey = loadOrCreateKey(defaultKeyFile(process.env));
    if (releaseKey.created)
      out(`Created a gate key at ${releaseKey.file} (outside the repository; keep it private).\n`);
    const built = await buildAndPack(layout, { key: releaseKey, release });
    out(`\nRelease tarballs in ${layout.release}:\n`);
    for (const pkg of built.manifest.packages) {
      out(
        `  ${pkg.name}@${pkg.version}  ${pkg.tarball.file}  ${pkg.tarball.size} bytes  sha256 ${pkg.tarball.sha256}\n`,
      );
    }
    out(
      `\nBuilt from commit ${release.commit} of ${release.repository} (clean tree, HEAD is origin/main as last fetched).\n` +
        `${MANIFEST_FILE} is signed by the gate key ${releaseKey.fingerprint}: a local signature, not provenance.\n` +
        "Nothing was published. Next, the owner runs:\n" +
        `  npm run sdk:release-check -- ${shellQuote(layout.release)}\n`,
    );
    return 0;
  }
  announce([...dists, layout.work, layout.out]);
  const key = loadOrCreateKey(defaultKeyFile(process.env));
  if (key.created) out(`Created a gate key at ${key.file} (outside the repository; keep it private).\n`);
  const result = await buildAndPack(layout, { key });
  out(`\nPacked into ${layout.out}:\n`);
  for (const pkg of result.manifest.packages) {
    out(`  ${pkg.tarball.file}  ${pkg.tarball.size} bytes  sha256 ${pkg.tarball.sha256}\n`);
    out(`  ${pkg.sbom.file}  ${pkg.sbom.size} bytes  sha256 ${pkg.sbom.sha256}\n`);
  }
  for (const entry of result.staged) {
    if (entry.unusedDependencies.length > 0) {
      out(
        `Note: ${entry.pkg.name} declares ${entry.unusedDependencies.join(", ")}, which its compiled code does not import.\n`,
      );
    }
  }
  const source = result.manifest.source;
  out(
    `\n${MANIFEST_FILE} is signed by the gate key ${key.fingerprint}: a local signature by whoever holds that key, not provenance from a trusted builder.\n` +
      `Source: commit ${source.commit ?? "unknown"}${source.dirty ? " with uncommitted changes" : ""}. Version ${result.manifest.packages[0]?.version}; the packed manifests are private.\n` +
      "Nothing was published.\n" +
      "Check the folder with: npm run sdk:verify -- <dir>\n",
  );
  return 0;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    err(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  },
);
