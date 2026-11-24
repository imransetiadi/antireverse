#!/usr/bin/env node
// Preflight for the airverse-setup skill. Reads only; changes nothing.
//
//   node preflight.mjs [--repo <path to the Airverse clone>]   (--repo=<path> works too)
//
// Prints one JSON object: where the clone is, whether it is installed, what this Node can do,
// and the exact command that runs Harden from any folder. Exit 0 when everything needed is
// there, 1 otherwise (the reasons are in "problems").

import { existsSync, readFileSync, realpathSync } from "node:fs";
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

function main() {
  const problems = [];
  const args = process.argv.slice(2);
  const inline = args.find((arg) => arg.startsWith("--repo="));
  const flag = inline ? args.indexOf(inline) : args.indexOf("--repo");
  const value = inline ? inline.slice("--repo=".length) : args[flag + 1];
  // A following flag is not a path.
  const given = value && !value.startsWith("--") ? value : undefined;
  const named = flag >= 0 ? given : process.env.AIRVERSE_REPO || undefined;

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
    repo = findUp(process.cwd());
    if (!repo)
      problems.push(
        "No Airverse clone found. The packages are not on npm: clone the repository, run `npm install` in it, then pass --repo <path> or set AIRVERSE_REPO.",
      );
  }

  let harden = null;
  let packages = null;
  if (repo) {
    const tsx = join(repo, "node_modules/tsx/dist/cli.mjs");
    const installed = existsSync(tsx);
    if (!installed) problems.push(`The clone at ${repo} is not installed: run \`npm install\` there.`);
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

  const report = {
    ok: problems.length === 0,
    node,
    repo,
    packages,
    harden,
    notes: node.stripsTypes
      ? []
      : [
          `Node ${node.version} cannot load Shield's TypeScript entry by itself: run the server through tsx, or use Node ${STRIPS_TYPES.join(".")} or newer.`,
        ],
    problems,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
}

main();
