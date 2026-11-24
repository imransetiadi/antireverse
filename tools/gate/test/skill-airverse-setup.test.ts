import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MANIFEST_FILE } from "../../sdk/src/manifest.ts";
import { buildAndPack } from "../../sdk/src/pipeline.ts";
import { MARKER_TEXT, tempLayout } from "../../sdk/src/safe.ts";
import { loadOrCreateKey, signReport } from "../src/sign.ts";

// The skill `skills/airverse-setup` tells Claude how to add Airverse to someone's own project.
// It names flags, variables, files and guides of this repository. These tests keep it in step:
// when a flag is renamed or a guide moves, the skill fails here, not in a user's session.

const root = fileURLToPath(new URL("../../../", import.meta.url));
const skillDir = join(root, "skills/airverse-setup");
const skillFile = join(skillDir, "SKILL.md");
const preflight = join(skillDir, "scripts/preflight.mjs");

const read = (path: string): string => readFileSync(path, "utf8");

function sources(dir: string): string {
  let text = "";
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) text += sources(path);
    else if (/\.(ts|js|mjs)$/.test(entry.name)) text += read(path);
  }
  return text;
}

function everyFile(dir: string): string {
  let text = "";
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    text += entry.isDirectory() ? everyFile(path) : read(path);
  }
  return text;
}

function frontmatter(text: string): { name: string; description: string; body: string } {
  const match = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  if (!match) throw new Error("SKILL.md has no front matter");
  const field = (key: string): string => new RegExp(`^${key}:\\s*(.+)$`, "m").exec(match[1] ?? "")?.[1]?.trim() ?? "";
  return { name: field("name"), description: field("description"), body: match[2] ?? "" };
}

describe("skill airverse-setup", () => {
  it("has a name, a description that says when to use it, and a body under 500 lines", () => {
    const skill = frontmatter(read(skillFile));
    expect(skill.name).toBe("airverse-setup");
    expect(skill.description.length).toBeGreaterThan(120);
    expect(skill.description.length).toBeLessThanOrEqual(1024);
    expect(skill.description).toMatch(/Shield/);
    expect(skill.description).toMatch(/Guard/);
    expect(skill.description).toMatch(/Harden/);
    expect(skill.body.split("\n").length).toBeLessThan(500);
  });

  it("names only guides and folders that exist in the repository", () => {
    const body = read(skillFile);
    const paths = new Set(
      [...body.matchAll(/(?:docs|packages)\/[A-Za-z0-9_./-]+/g)].map((m) => m[0].replace(/[.,)]+$/, "")),
    );
    expect(paths.size).toBeGreaterThanOrEqual(4);
    for (const path of paths) expect(existsSync(join(root, path)), path).toBe(true);
    for (const guide of [
      "docs/getting-started.md",
      "docs/shield.md",
      "docs/guard.md",
      "docs/harden.md",
      "docs/reverse-assessment.md",
    ])
      expect(paths.has(guide), guide).toBe(true);
  });

  it("names only Harden flags the command line knows", () => {
    const body = read(skillFile);
    const harden = sources(join(root, "packages/harden/src"));
    const flags = new Set([...body.matchAll(/(?<![A-Za-z0-9-])--[a-z][a-z-]+/g)].map((m) => m[0]));
    // Flags of other tools the skill may show.
    for (const other of [
      "--experimental-strip-types",
      "--repo",
      "--help",
      "--save",
      "--tarballs",
      "--signer",
      "--integrity-only",
      "--ignore-scripts",
      "--save-dev",
    ])
      flags.delete(other);
    expect(flags.size).toBeGreaterThan(8);
    for (const flag of flags) expect(harden.includes(`"${flag}"`), flag).toBe(true);
  });

  it("names only variables and Shield or Guard calls that exist", () => {
    const body = read(skillFile);
    const documented =
      read(join(root, "README.md")) + read(join(root, "docs/shield.md")) + read(join(root, "docs/harden.md"));
    const variables = new Set([...body.matchAll(/\bAR_[A-Z0-9_]+/g)].map((m) => m[0]));
    variables.delete("AR_ADMIN_KEY"); // the name the guides use for --key-env; the user may choose another
    for (const variable of variables) expect(documented.includes(variable), variable).toBe(true);
    // Every call the skill shows on a shield or a guard must be a member of the real object.
    const members = (object: string): Set<string> =>
      new Set([...body.matchAll(new RegExp(`(?<![/\\w.])${object}\\.([A-Za-z]+)\\(`, "g"))].map((m) => m[1] as string));
    const shield = sources(join(root, "packages/shield-node/src"));
    const shieldMembers = members("shield");
    expect(shieldMembers.size).toBeGreaterThan(3);
    for (const member of shieldMembers)
      expect(new RegExp(`\\b${member}\\s*[(:]`).test(shield), `shield.${member}`).toBe(true);
    const guard = read(join(root, "packages/guard/src/index.d.ts"));
    const guardMembers = members("guard");
    expect(guardMembers.size).toBeGreaterThan(2);
    for (const member of guardMembers)
      expect(new RegExp(`\\b${member}\\s*[(:]`).test(guard), `guard.${member}`).toBe(true);
    expect(shield).toMatch(/export function createShield\b|createShield\s*[=(]/);
    for (const option of ["key", "endpoint", "policyPublicKey", "bodyVerified"])
      if (new RegExp(`\\b${option}\\b`).test(body))
        expect(new RegExp(`\\b${option}\\??:`).test(shield), option).toBe(true);
    for (const pkg of [...body.matchAll(/@antireverse\/[a-z-]+/g)].map((m) => m[0]))
      expect(existsSync(join(root, "packages", pkg.replace("@antireverse/", ""), "package.json")), pkg).toBe(true);
  });

  it("holds no key, and tells the reader how keys are handled", () => {
    const everything = everyFile(skillDir);
    expect(everything).not.toMatch(/ark_(prod|stg|dev)_[A-Za-z0-9_-]{20,}/);
    expect(everything).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
    const body = read(skillFile);
    expect(body).toMatch(/environment variable/i);
    expect(body).toMatch(/never (write|paste|print|put)/i);
    expect(body).toMatch(/obfuscation, not secrecy/i);
  });
});

describe("skill airverse-setup: preflight", () => {
  const scratch = mkdtempSync(join(tmpdir(), "airverse-skill-"));
  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  const run = (
    args: string[],
    cwd: string,
    env: NodeJS.ProcessEnv = {},
  ): { status: number | null; report: Record<string, unknown> } => {
    const result = spawnSync(process.execPath, [preflight, ...args], {
      cwd,
      encoding: "utf8",
      env: { ...process.env, AIRVERSE_REPO: "", ...env },
    });
    return { status: result.status, report: JSON.parse(result.stdout) as Record<string, unknown> };
  };

  it("finds the clone from --repo and prints a Harden command that runs from another folder", () => {
    const { status, report } = run(["--repo", root], scratch);
    expect(status).toBe(0);
    expect(report.ok).toBe(true);
    expect(report.repo).toMatchObject({ path: root.replace(/\/$/, ""), installed: true });
    const command = (report.harden as { command: string[] }).command;
    expect(Array.isArray(command)).toBe(true);
    const [bin, ...rest] = command;
    const help = execFileSync(bin as string, [...rest, "--help"], { cwd: scratch, encoding: "utf8" });
    expect(help).toContain("antireverse harden <dir>");
  });

  it("finds the clone from AIRVERSE_REPO", () => {
    const { status, report } = run([], scratch, { AIRVERSE_REPO: root });
    expect(status).toBe(0);
    expect((report.repo as { path: string }).path).toBe(root.replace(/\/$/, ""));
  });

  it("says what is wrong, and exits 1, when there is no clone", () => {
    const { status, report } = run([], scratch);
    expect(status).toBe(1);
    expect(report.ok).toBe(false);
    expect(report.repo).toBeNull();
    expect((report.problems as string[]).join(" ")).toMatch(/clone/i);
  });

  it("refuses a folder that is not the Airverse repository", () => {
    const { status, report } = run(["--repo", scratch], scratch);
    expect(status).toBe(1);
    expect((report.problems as string[]).join(" ")).toMatch(/not the Airverse repository/i);
  });

  it("prints every field the skill tells the reader to use", () => {
    const { report } = run(["--repo", root], scratch);
    const body = read(skillFile);
    const named = new Set(
      [...body.matchAll(/`((?:repo|packages|harden|node)\.[A-Za-z]+)`/g)].map((m) => m[1] as string),
    );
    expect(named.size).toBeGreaterThan(4);
    expect(report.tarballs).toBeNull();
    for (const path of named) {
      const [group, key] = path.split(".") as [string, string];
      expect((report[group] as Record<string, unknown>)[key], path).toBeDefined();
    }
  });

  it("takes --repo=<path> too, and does not take another flag for the path", () => {
    expect(run([`--repo=${root}`], scratch).status).toBe(0);
    const { status, report } = run(["--repo", "--json"], scratch);
    expect(status).toBe(1);
    expect((report.problems as string[]).join(" ")).toMatch(/--repo needs a path/);
  });

  it("gives a Harden command without this machine's Node path, for scripts and CI", () => {
    const { report } = run(["--repo", root], scratch);
    const portable = (report.harden as { portable: string[] }).portable;
    expect(portable[0]).toBe("node");
    expect(portable.join(" ")).not.toContain(process.execPath);
  });

  it("reports the Node version and whether this Node can load Shield's TypeScript entry", () => {
    const { report } = run(["--repo", root], scratch);
    const node = report.node as { version: string; supported: boolean; stripsTypes: boolean };
    expect(node.version).toBe(process.versions.node);
    expect(node.supported).toBe(true);
    const [major, minor] = process.versions.node.split(".").map(Number) as [number, number];
    expect(node.stripsTypes).toBe(major > 22 || (major === 22 && minor >= 23));
  });
});

// Slice 23: the skill prefers a folder of tarballs when the user names one. The preflight checks it without the
// clone, reading only: every listed file with its size and SHA-256, no other file, and the manifest's signature.
describe("skill airverse-setup: preflight with tarballs", () => {
  const scratch = mkdtempSync(join(tmpdir(), "airverse-sdk-skill-"));
  afterAll(() => rmSync(scratch, { recursive: true, force: true }));
  const layout = tempLayout(join(scratch, "pack"));
  const key = loadOrCreateKey(join(scratch, "keys/gate-key.json"));
  let copies = 0;
  const copy = (): string => {
    const dir = join(scratch, `copy-${++copies}`);
    cpSync(layout.out, dir, { recursive: true });
    return dir;
  };
  type Tarballs = {
    path: string;
    intact: boolean;
    trusted: boolean;
    signer: string | null;
    version: string;
    shield: string;
    guard: string;
    harden: string;
    protocol: string;
    command: string[];
    problems: string[];
  };
  const run = (args: string[], env: NodeJS.ProcessEnv = {}) => {
    const result = spawnSync(process.execPath, [preflight, ...args], {
      cwd: scratch,
      encoding: "utf8",
      env: { ...process.env, AIRVERSE_REPO: "", AIRVERSE_SDK_DIR: "", ...env },
    });
    const report = JSON.parse(result.stdout) as {
      ok: boolean;
      mode: string;
      repo: unknown;
      notes: string[];
      problems: string[];
      tarballs: Tarballs | null;
    };
    return { status: result.status, stderr: result.stderr, report, tarballs: report.tarballs as Tarballs };
  };

  beforeAll(async () => {
    await buildAndPack(layout, { key });
  }, 120_000);

  it("accepts a packed folder signed by the key the user named, without a clone, and says where each tarball is", () => {
    const { status, report, tarballs } = run(["--tarballs", layout.out, "--signer", key.fingerprint]);
    expect(report.problems).toEqual([]);
    expect(status).toBe(0);
    expect(report).toMatchObject({ ok: true, mode: "tarballs", repo: null });
    expect(tarballs).toMatchObject({ intact: true, trusted: true, signer: key.fingerprint, problems: [] });
    expect(tarballs.version).toMatch(/^\d+\.\d+\.\d+/);
    for (const name of ["shield", "guard", "harden", "protocol"] as const) {
      expect(tarballs[name]).toMatch(/\.tgz$/);
      expect(existsSync(tarballs[name]), name).toBe(true);
    }
    expect(tarballs.shield).toContain("antireverse-shield-node-");
    expect(tarballs.command).toEqual(["npx", "antireverse"]);
    // AIRVERSE_SDK_DIR works like the flag; with a clone too, both are reported and the tarballs lead.
    expect(run(["--signer", key.fingerprint], { AIRVERSE_SDK_DIR: layout.out }).report).toMatchObject({
      ok: true,
      mode: "tarballs",
    });
    const both = run(["--tarballs", layout.out, "--signer", key.fingerprint, "--repo", root]);
    expect(both.report).toMatchObject({ ok: true, mode: "tarballs" });
    expect(both.report.repo).toMatchObject({ installed: true });
  });

  // Review M2: a signature only says that somebody signed. Without the fingerprint of the key the user trusts, a
  // folder is intact at most, never trusted, and the preflight does not say ok.
  it("without --signer a folder is intact but not trusted: not ok, exit 1, and the problem says what to ask the user", () => {
    const { status, report, tarballs } = run(["--tarballs", layout.out]);
    expect(status).toBe(1);
    expect(report.ok).toBe(false);
    expect(tarballs).toMatchObject({ intact: true, trusted: false, signer: key.fingerprint });
    expect(report.problems.join(" ")).toMatch(/signer .* is not checked/);
    expect(report.problems.join(" ")).toMatch(/--signer <fingerprint>/);
    expect(report.problems.join(" ")).toMatch(/--integrity-only/);
  });

  it("a tampered folder signed again by someone else is never ok on its own: the review's case", () => {
    const dir = copy();
    const other = loadOrCreateKey(join(scratch, "keys/other.json"));
    const harden = readdirSync(dir).find((file) => file.includes("harden") && file.endsWith(".tgz")) as string;
    appendFileSync(join(dir, harden), "tampered");
    const { signature: _signature, ...body } = JSON.parse(readFileSync(join(dir, MANIFEST_FILE), "utf8"));
    const entry = body.packages.find((p: { tarball: { file: string } }) => p.tarball.file === harden);
    const bytes = readFileSync(join(dir, harden));
    entry.tarball.size = bytes.length;
    entry.tarball.sha256 = createHash("sha256").update(bytes).digest("hex");
    writeFileSync(join(dir, MANIFEST_FILE), JSON.stringify(signReport(body, other)));
    const plain = run(["--tarballs", dir]);
    expect(plain.status).toBe(1);
    expect(plain.report.ok).toBe(false);
    expect(plain.tarballs).toMatchObject({ intact: true, trusted: false, signer: other.fingerprint });
    const expected = run(["--tarballs", dir, "--signer", key.fingerprint]);
    expect(expected.status).toBe(1);
    expect(expected.tarballs).toMatchObject({ intact: true, trusted: false });
    expect(expected.report.problems.join(" ")).toMatch(/signed by .* not by the expected/);
    // Only the user can wave the signer through, and the result still does not say trusted.
    const waved = run(["--tarballs", dir, "--integrity-only"]);
    expect(waved.status).toBe(0);
    expect(waved.report.ok).toBe(true);
    expect(waved.tarballs).toMatchObject({ intact: true, trusted: false, signer: other.fingerprint });
    expect(waved.report.notes.join(" ")).toMatch(/NOT trusted/);
    expect(waved.report.notes.join(" ")).toMatch(/integrity only/i);
  });

  it("checks the signer's form, and --integrity-only never covers a wrong --signer or a damaged folder", () => {
    expect(run(["--tarballs", layout.out, "--signer", "nothex"]).report.problems.join(" ")).toMatch(/--signer needs/);
    const wrong = run(["--tarballs", layout.out, "--signer", "0".repeat(64), "--integrity-only"]);
    expect(wrong.status).toBe(1);
    expect(wrong.tarballs.trusted).toBe(false);
    const damaged = copy();
    appendFileSync(join(damaged, readdirSync(damaged).find((file) => file.endsWith(".cdx.json")) as string), " ");
    const waved = run(["--tarballs", damaged, "--integrity-only"]);
    expect(waved.status).toBe(1);
    expect(waved.tarballs).toMatchObject({ intact: false, trusted: false });
  });

  it("reports a changed, missing or extra file and a changed manifest as problems, and exits 1", () => {
    const changed = copy();
    appendFileSync(
      join(changed, readdirSync(changed).find((file) => file.includes("harden") && file.endsWith(".tgz")) as string),
      "x",
    );
    const missing = copy();
    rmSync(
      join(missing, readdirSync(missing).find((file) => file.includes("guard") && file.endsWith(".tgz")) as string),
    );
    const extra = copy();
    writeFileSync(join(extra, "antireverse-extra-9.9.9.tgz"), "x");
    const edited = copy();
    const manifest = JSON.parse(readFileSync(join(edited, MANIFEST_FILE), "utf8")) as { statement: string };
    manifest.statement = "Built by a trusted pipeline.";
    writeFileSync(join(edited, MANIFEST_FILE), JSON.stringify(manifest));
    const none = copy();
    rmSync(join(none, MANIFEST_FILE));
    const cases: Array<[string, RegExp]> = [
      [changed, /harden.*size/],
      [missing, /guard.*missing/],
      [extra, /antireverse-extra-9\.9\.9\.tgz.*not listed/],
      [edited, /signature does not verify/],
      [none, /sdk-manifest\.json.*missing/],
      [join(scratch, "absent"), /does not exist/],
    ];
    for (const [dir, problem] of cases) {
      const { status, report, tarballs } = run(["--tarballs", dir, "--signer", key.fingerprint]);
      expect(status, dir).toBe(1);
      expect(report.ok, dir).toBe(false);
      expect(report.problems.join(" "), dir).toMatch(problem);
      expect(tarballs?.intact ?? false, dir).toBe(false);
      expect(tarballs?.trusted ?? false, dir).toBe(false);
    }
    expect(run(["--tarballs"]).report.problems.join(" ")).toMatch(/--tarballs needs a path/);
  });

  // Review L3: whatever the manifest holds, the answer is the documented JSON, never a crash.
  it("answers with its JSON for a manifest that is null, an array, a list of nulls, or too large", () => {
    const shapes: Array<[string, RegExp]> = [
      ["null", /not an SDK artifact manifest/],
      ["[]", /not an SDK artifact manifest/],
      ['"text"', /not an SDK artifact manifest/],
      [
        JSON.stringify({ schema: "airverse.sdk-artifacts/1", packages: [null, 5, { name: 1 }] }),
        /signature does not verify|malformed/,
      ],
      [`{"schema":"airverse.sdk-artifacts/1","pad":"${"x".repeat(1024 * 1024 + 10)}"}`, /larger than/],
    ];
    for (const [content, problem] of shapes) {
      const dir = copy();
      writeFileSync(join(dir, MANIFEST_FILE), content);
      const { status, stderr, report, tarballs } = run(["--tarballs", dir, "--signer", key.fingerprint]);
      expect(stderr, content.slice(0, 40)).toBe("");
      expect(status, content.slice(0, 40)).toBe(1);
      expect(report.problems.join(" "), content.slice(0, 40)).toMatch(problem);
      expect(tarballs.intact).toBe(false);
    }
  });

  it("agrees with sdk:verify's rules: the same marker text, the same manifest name, and it changes nothing", () => {
    const source = read(preflight);
    expect(source).toContain(JSON.stringify(MARKER_TEXT));
    expect(source).toContain(`"${MANIFEST_FILE}"`);
    expect(source).not.toMatch(/writeFile|appendFile|mkdir|rmSync|unlink|rename|child_process|fetch\(|https?:\/\//);
    const before = readdirSync(layout.out).sort();
    run(["--tarballs", layout.out, "--signer", key.fingerprint]);
    expect(readdirSync(layout.out).sort()).toEqual(before);
  });

  it("prints every tarballs field the skill tells the reader to use, and the skill keeps its rules for them", () => {
    const { tarballs } = run(["--tarballs", layout.out, "--signer", key.fingerprint]);
    const body = read(skillFile);
    const named = new Set(
      [...body.matchAll(/`(tarballs\.[A-Za-z]+)`/g)].map((m) => (m[1] as string).slice("tarballs.".length)),
    );
    expect(named.size).toBeGreaterThan(4);
    for (const field of named) expect((tarballs as unknown as Record<string, unknown>)[field], field).toBeDefined();
    expect(body).toMatch(/--tarballs/);
    expect(body).toMatch(/--ignore-scripts/);
    expect(body).toMatch(/not provenance/);
    expect(body).toMatch(/do not install/i);
    expect(body).toMatch(/never download/i);
    // Review M2: the fingerprint comes from the user, and the model never waves the signer through on its own.
    expect(body).toMatch(/ask the user for the fingerprint/i);
    expect(body).toMatch(/`tarballs\.trusted`/);
    expect(body).toMatch(/`tarballs\.intact`/);
    expect(body).toMatch(/--integrity-only/);
    expect(body).toMatch(/never (pass|add|use) `--integrity-only` on your own/i);
    expect(body).not.toMatch(/tarballs\.verified|signerChecked/);
    expect(existsSync(join(skillDir, "evals/express-tarballs-resigned-folder/case.yaml"))).toBe(true);
    // The clone path is still there.
    expect(body).toMatch(/--repo/);
    expect(body).toMatch(/AIRVERSE_REPO/);
  });
});
