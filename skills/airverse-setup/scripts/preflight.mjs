#!/usr/bin/env node
// Preflight for the airverse-setup skill. Reads only; changes nothing.
//
//   node preflight.mjs                                          (the npm path: no clone needed)
//   node preflight.mjs [--repo <path to the Airverse clone>]
//                      [--tarballs <folder> (--signer <fingerprint> | --integrity-only)]
//   (--repo=<path> and --tarballs=<path> work too; AIRVERSE_REPO and AIRVERSE_SDK_DIR name them as well)
//
// Prints one JSON object: where the clone is, whether it is installed, what this Node can do,
// and the exact command that runs Harden from any folder. With --tarballs it checks a folder
// written by `npm run sdk:pack` — every file the manifest lists, with its size and SHA-256, no
// other file, and the manifest's signature — and says where each tarball is and who signed. A
// folder is trusted only when its signer is the fingerprint given with --signer; without one the
// preflight fails, unless the user chose --integrity-only (the files match; the signer is unknown).
// Exit 0 when everything needed is there, 1 otherwise (the reasons are in "problems").

import { createHash, createPublicKey, verify } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const MIN = [22, 12];
// From this version on, Node loads TypeScript files itself (the repository's guides were tested on 22.23.4).
const STRIPS_TYPES = [22, 23];
const PACKAGES = ["packages/shield-node", "packages/guard", "packages/harden"];

const atLeast = (version, [major, minor]) => version[0] > major || (version[0] === major && version[1] >= minor);

function isAirverse(dir) {
  try {
    const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    return manifest.name === "antireverse" && PACKAGES.every((path) => existsSync(join(dir, path, "package.json")));
  } catch {
    return false;
  }
}

function findUp(start) {
  for (let dir = resolve(start); ; dir = dirname(dir)) {
    if (isAirverse(dir)) return dir;
    if (dirname(dir) === dir) return null;
  }
}

// The version of @antireverse/shield-node, guard and harden on npm that this skill installs. A test in the
// repository keeps it equal to the packages' own version.
const RELEASED_VERSION = "0.1.0";
const MANIFEST = "sdk-manifest.json";
const SCHEMA = "airverse.sdk-artifacts/1";
// The marker `npm run sdk:pack` leaves in the folder it writes: the one file that may be there unlisted.
const MARKER = ".airverse-sdk-build";
const MARKER_TEXT =
  "Build output of Airverse's SDK tooling (npm run sdk:build, npm run sdk:pack). This folder is removed and written again by those commands.\n";
const TARBALLS = {
  protocol: "@antireverse/protocol",
  shield: "@antireverse/shield-node",
  guard: "@antireverse/guard",
  harden: "@antireverse/harden",
};

/** JSON with keys sorted at every depth: the bytes the manifest's signature covers. */
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

/** The signer's fingerprint when the manifest's Ed25519 signature verifies against the key it embeds, else null. */
function signerOf(manifest) {
  const { signature, ...body } = manifest;
  if (signature?.algorithm !== "Ed25519") return null;
  if (typeof signature.public_key !== "string" || typeof signature.value !== "string") return null;
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: signature.public_key }, format: "jwk" });
    const fingerprint = createHash("sha256").update(Buffer.from(signature.public_key, "base64url")).digest("hex");
    if (fingerprint !== signature.fingerprint) return null;
    const valid = verify(null, Buffer.from(canonicalJson(body)), key, Buffer.from(signature.value, "base64url"));
    return valid ? fingerprint : null;
  } catch {
    return null;
  }
}

/** A manifest larger than this is not read: a real one is a few kilobytes. */
const MANIFEST_MAX_BYTES = 1024 * 1024;

/**
 * Checks a folder of tarballs against its manifest. Reads only.
 *   intact:  every listed file is there with its size and SHA-256, nothing else is, and the signature verifies
 *            against the key the manifest embeds. Anyone can make a folder intact by signing it themselves.
 *   trusted: intact, and signed by the key whose fingerprint the user gave with --signer.
 */
function checkTarballs(dir, expectedSigner) {
  const problems = [];
  const result = {
    path: dir,
    intact: false,
    trusted: false,
    signer: null,
    version: null,
    // Never npx without --no-install: when the command is not installed, npx would fetch an unscoped package of
    // that name from the registry, where it is only a placeholder and not Harden.
    command: ["npx", "--no-install", "antireverse"],
  };
  for (const name of Object.keys(TARBALLS)) result[name] = null;
  const done = () => {
    const intact = problems.length === 0;
    return {
      ...result,
      intact,
      trusted: intact && expectedSigner !== undefined && result.signer === expectedSigner,
      problems,
    };
  };
  if (!existsSync(dir)) {
    problems.push(`${dir} does not exist.`);
    return done();
  }
  const file = join(dir, MANIFEST);
  if (!existsSync(file)) {
    problems.push(`${MANIFEST} is missing in ${dir}: this is not a folder written by \`npm run sdk:pack\`.`);
    return done();
  }
  if (!lstatSync(file).isFile() || lstatSync(file).size > MANIFEST_MAX_BYTES) {
    problems.push(`${MANIFEST} is not a regular file or is larger than ${MANIFEST_MAX_BYTES} bytes.`);
    return done();
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    problems.push(`${MANIFEST} is not JSON.`);
    return done();
  }
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest) || manifest.schema !== SCHEMA) {
    problems.push(`${MANIFEST} is not an SDK artifact manifest.`);
    return done();
  }
  result.signer = signerOf(manifest);
  if (result.signer === null) problems.push(`${MANIFEST}: its signature does not verify.`);
  if (!Array.isArray(manifest.packages) || manifest.packages.length === 0) {
    problems.push(`${MANIFEST} lists no package.`);
    return done();
  }
  const listed = new Set([MANIFEST]);
  for (const entry of manifest.packages) {
    if (
      entry === null ||
      typeof entry !== "object" ||
      typeof entry.name !== "string" ||
      typeof entry.version !== "string"
    ) {
      problems.push(`${MANIFEST}: a package entry is malformed.`);
      continue;
    }
    for (const item of [entry.tarball, entry.sbom]) {
      const name = item?.file;
      const plain = typeof name === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) && !listed.has(name);
      if (!plain || typeof item.size !== "number" || typeof item.sha256 !== "string") {
        problems.push(
          `${MANIFEST}: a package entry is malformed (a file needs a plain, single name, a size and a SHA-256).`,
        );
        continue;
      }
      listed.add(name);
      let stat;
      try {
        stat = lstatSync(join(dir, name));
      } catch {
        problems.push(`${name} is missing.`);
        continue;
      }
      if (!stat.isFile()) problems.push(`${name} is not a regular file.`);
      else if (stat.size !== item.size) problems.push(`${name} has size ${stat.size}, the manifest says ${item.size}.`);
      else if (
        createHash("sha256")
          .update(readFileSync(join(dir, name)))
          .digest("hex") !== item.sha256
      )
        problems.push(`${name} does not have the SHA-256 the manifest lists.`);
    }
    const key = Object.keys(TARBALLS).find((k) => TARBALLS[k] === entry.name);
    if (key && typeof entry.tarball?.file === "string") result[key] = join(dir, entry.tarball.file);
    result.version = entry.version;
  }
  for (const name of readdirSync(dir).sort()) {
    if (listed.has(name)) continue;
    if (name === MARKER && lstatSync(join(dir, name)).isFile() && readFileSync(join(dir, name), "utf8") === MARKER_TEXT)
      continue;
    problems.push(`${name} is in the folder but not listed in the manifest.`);
  }
  for (const [key, name] of Object.entries(TARBALLS))
    if (result[key] === null) problems.push(`The manifest lists no ${name}.`);
  return done();
}

/** The value of `--name <value>` or `--name=<value>`: { given, value }. A following flag is not a value. */
function option(args, name) {
  const inline = args.find((arg) => arg.startsWith(`--${name}=`));
  const flag = inline ? args.indexOf(inline) : args.indexOf(`--${name}`);
  const value = inline ? inline.slice(name.length + 3) : args[flag + 1];
  return { given: flag >= 0, value: value && !value.startsWith("--") ? value : undefined };
}

function main() {
  const problems = [];
  const args = process.argv.slice(2);
  const repoOption = option(args, "repo");
  const flag = repoOption.given ? 0 : -1;
  const named = repoOption.given ? repoOption.value : process.env.AIRVERSE_REPO || undefined;

  // A folder of tarballs, when the user named one. With it the clone is optional.
  const tarballsOption = option(args, "tarballs");
  const signerOption = option(args, "signer");
  const tarballsDir = tarballsOption.given ? tarballsOption.value : process.env.AIRVERSE_SDK_DIR || undefined;
  let tarballs = null;
  // Only the user can decide to go on without knowing the signer; the flag says so in the report.
  const integrityOnly = args.includes("--integrity-only");
  if (tarballsOption.given && !tarballsDir) problems.push("--tarballs needs a path.");
  if (signerOption.given && !/^[0-9a-f]{64}$/.test(signerOption.value ?? ""))
    problems.push("--signer needs a 64-character hex fingerprint.");
  else if (tarballsDir) {
    tarballs = checkTarballs(resolve(tarballsDir), signerOption.value);
    for (const problem of tarballs.problems) problems.push(`Tarballs: ${problem}`);
    if (tarballs.intact && !tarballs.trusted) {
      if (signerOption.value !== undefined)
        problems.push(
          `Tarballs: the folder is signed by ${tarballs.signer}, not by the expected ${signerOption.value}.`,
        );
      else if (!integrityOnly)
        problems.push(
          `Tarballs: the signer ${tarballs.signer} is not checked. Anyone can sign a folder, so this says nothing about who built it. Ask the user for the fingerprint of the key they trust (their own \`npm run sdk:pack\` prints it) and pass --signer <fingerprint>. Only if the user decides to go on without it, pass --integrity-only.`,
        );
    }
  }

  const version = process.versions.node.split(".").map(Number);
  const node = {
    version: process.versions.node,
    supported: atLeast(version, MIN),
    stripsTypes: atLeast(version, STRIPS_TYPES),
  };
  if (!node.supported) problems.push(`Node ${node.version} is too old: Airverse needs ${MIN.join(".")} or newer.`);

  let repo = null;
  if (flag >= 0 && !named) {
    problems.push("--repo needs a path.");
  } else if (named) {
    const path = resolve(named);
    if (!existsSync(path)) problems.push(`${path} does not exist.`);
    else if (!isAirverse(path))
      problems.push(`${path} is not the Airverse repository (no root package named "antireverse").`);
    else repo = realpathSync(path);
  } else {
    // No clone was named. One that is found is reported (for the guides, and for running the API and Console), but
    // nothing depends on it: the packages are on npm.
    repo = findUp(process.cwd());
  }
  // A clone the user named is the way they chose; otherwise a tarball folder they named; otherwise npm.
  const mode = tarballs ? "tarballs" : named && repo ? "clone" : "npm";

  // The npm path: exact versions, never a range or "latest". Nothing is asked of a registry here.
  const spec = (name) => `@antireverse/${name}@${RELEASED_VERSION}`;
  const npm = {
    version: RELEASED_VERSION,
    shield: spec("shield-node"),
    guard: spec("guard"),
    harden: spec("harden"),
    installShield: ["npm", "install", "--save-exact", spec("shield-node")],
    installGuard: ["npm", "install", "--save-exact", spec("guard")],
    installHarden: ["npm", "install", "--save-dev", "--save-exact", spec("harden")],
    // Never npx without --no-install: it would fetch an unscoped package named "antireverse".
    command: ["npx", "--no-install", "antireverse"],
    guardFiles: "node_modules/@antireverse/guard/dist",
  };

  let harden = null;
  let packages = null;
  if (repo) {
    const tsx = join(repo, "node_modules/tsx/dist/cli.mjs");
    const installed = existsSync(tsx);
    if (!installed && mode === "clone")
      problems.push(`The clone at ${repo} is not installed: run \`npm install\` there.`);
    packages = {
      shield: join(repo, "packages/shield-node"),
      guard: join(repo, "packages/guard"),
      guardFiles: join(repo, "packages/guard/src"),
      tsx,
      docs: join(repo, "docs"),
    };
    // tsx runs the TypeScript entry on every supported Node, from any working directory.
    // "command" runs here and now; "portable" is the same without this machine's Node path, for scripts and CI.
    if (installed) {
      const cli = join(repo, "packages/harden/src/cli.ts");
      harden = { command: [process.execPath, tsx, cli], portable: ["node", tsx, cli] };
    }
    repo = { path: repo, installed };
  }

  const notes = [];
  if (tarballs?.trusted) {
    notes.push(
      `The tarballs are signed by ${tarballs.signer}, the key the user named. That is a local signature by whoever holds that key, not provenance from a trusted builder.`,
    );
  } else if (tarballs?.intact && integrityOnly) {
    notes.push(
      `Integrity only: the files match their manifest, signed by ${tarballs.signer}, and that signer is NOT trusted: nobody checked whose key it is. Say so in your report.`,
    );
  }
  if (mode === "clone" && !node.stripsTypes) {
    notes.push(
      `Node ${node.version} cannot load Shield's TypeScript entry by itself: run the server through tsx, or use Node ${STRIPS_TYPES.join(".")} or newer.`,
    );
  }
  const report = {
    ok: problems.length === 0,
    // "npm" (the default): install the packages by name at the exact version below. "tarballs" when a tarball
    // folder was named; "clone" when a clone was named with --repo or AIRVERSE_REPO.
    mode,
    node,
    npm,
    repo,
    packages,
    harden,
    tarballs,
    notes,
    problems,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
}

main();
