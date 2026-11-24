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
//   verify     nothing; it never creates a key
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { defaultKeyFile, loadOrCreateKey } from "../../gate/src/sign.ts";
import { currentAllowlist } from "./allowlist.ts";
import { buildAll } from "./build.ts";
import { MANIFEST_FILE, verifyArtifacts } from "./manifest.ts";
import { SDK_PACKAGES } from "./packages.ts";
import { buildAndPack, stagedClosures } from "./pipeline.ts";
import { type Layout, repoLayout, tempLayout } from "./safe.ts";
import { stageAll } from "./stage.ts";

const USAGE = `usage:
  npm run sdk:build
  npm run sdk:pack
  npm run sdk:verify -- <dir> [--expect <fingerprint>]
  npm run sdk:allowlist
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

  if (command !== "build" && command !== "pack" && command !== "allowlist") {
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
