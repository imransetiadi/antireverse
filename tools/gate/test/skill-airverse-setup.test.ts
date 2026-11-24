import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

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
    for (const other of ["--experimental-strip-types", "--repo", "--help", "--save"]) flags.delete(other);
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
