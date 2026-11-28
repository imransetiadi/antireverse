// Slice 16 — the docs in docs/ stay true to the code: every `harden` and `gate` command in a fenced bash block
// uses only flags the CLI's usage text lists, and every relative link between the docs (and from the README into
// docs/) resolves, anchors included. The Harden commands of Getting started that need no API — the `--help` form and
// a `harden` run without `--register` — are run for real, on a fixture bundle with `--out` in a temporary folder.
// Commands with `--register` or `gate` need a running API and an admin key, so they are flag-checked only (above);
// the HTTP e2e tests (harden, ci-gate, reverse-assessment) run those paths against a real API.
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { main } from "../../packages/harden/src/cli.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const docsDir = join(root, "docs");
const docFiles = readdirSync(docsDir)
  .filter((name) => name.endsWith(".md"))
  .sort()
  .map((name) => join(docsDir, name));
const readme = join(root, "README.md");

const EXPECTED_DOCS = ["getting-started.md", "guard.md", "harden.md", "reverse-assessment.md", "shield.md"];

/** The `bash` fenced blocks of a Markdown text, with backslash-continued lines joined. */
function bashBlocks(markdown: string): string[] {
  const blocks: string[] = [];
  for (const match of markdown.matchAll(/^```bash\n([\s\S]*?)^```$/gm)) {
    blocks.push((match[1] ?? "").replace(/\\\n\s*/g, " "));
  }
  return blocks;
}

/** One CLI command found in the docs: the subcommand, the file it is in, and the whole line. */
interface DocCommand {
  file: string;
  subcommand: "harden" | "gate";
  line: string;
}

/**
 * The `antireverse harden …` and `antireverse gate …` commands of the docs. In this repository the command is run
 * as `npx tsx packages/harden/src/cli.ts <subcommand>`; both spellings count.
 */
function cliCommands(file: string): DocCommand[] {
  const commands: DocCommand[] = [];
  for (const block of bashBlocks(readFileSync(file, "utf8"))) {
    for (const line of block.split("\n")) {
      const match = /(?:\bantireverse|packages\/harden\/src\/cli\.ts)\s+(harden|gate)\b/.exec(line);
      if (match) commands.push({ file, subcommand: match[1] as "harden" | "gate", line: line.trim() });
    }
  }
  return commands;
}

/**
 * The `--flags` the command line gives to the CLI, ignoring anything inside quotes (such as a `--test "npm test"`
 * value) and anything before the command itself: in `npx --no-install antireverse …` the first flag is npx's.
 */
function flagsOf(line: string): string[] {
  const own = line.replace(/^.*?(?:\bantireverse|packages\/harden\/src\/cli\.ts)(?=\s)/, "");
  const unquoted = own.replace(/"[^"]*"|'[^']*'/g, "");
  return [...unquoted.matchAll(/(?:^|\s)(--[a-z][a-z0-9-]*)/g)].map((m) => m[1] as string);
}

/** GitHub's heading anchor: lower case, punctuation dropped except hyphens, spaces to hyphens. */
function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/`/g, "")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .replace(/\s/g, "-");
}

function anchorsOf(file: string): Set<string> {
  const text = readFileSync(file, "utf8").replace(/^```[\s\S]*?^```$/gm, "");
  return new Set([...text.matchAll(/^#{1,6}\s+(.+)$/gm)].map((m) => slug(m[1] as string)));
}

/** Relative Markdown links of a file (outside code blocks and inline code): target path and optional anchor. */
function relativeLinks(file: string): Array<{ target: string; anchor: string | null }> {
  const text = readFileSync(file, "utf8")
    .replace(/^```[\s\S]*?^```$/gm, "")
    .replace(/`[^`\n]*`/g, "");
  const links: Array<{ target: string; anchor: string | null }> = [];
  for (const match of text.matchAll(/\]\(([^)\s]+)\)/g)) {
    const href = match[1] as string;
    if (/^[a-z][a-z0-9+.-]*:/i.test(href)) continue; // http:, https:, mailto:
    const [path, anchor] = href.split("#", 2) as [string, string | undefined];
    links.push({ target: path === "" ? file : resolve(dirname(file), path), anchor: anchor ?? null });
  }
  return links;
}

let usage = "";

beforeAll(async () => {
  let out = "";
  const code = await main(["--help"], { env: {}, stdout: (s) => (out += s), stderr: () => {} });
  expect(code).toBe(0);
  usage = out;
});

describe("docs/", () => {
  it("has the five pages", () => {
    expect(docFiles.map((f) => f.slice(docsDir.length + 1))).toEqual(EXPECTED_DOCS);
  });

  const commands = docFiles.flatMap(cliCommands);

  it("documents both harden and gate commands", () => {
    expect(commands.filter((c) => c.subcommand === "harden").length).toBeGreaterThanOrEqual(5);
    expect(commands.filter((c) => c.subcommand === "gate").length).toBeGreaterThanOrEqual(1);
  });

  it.each(commands.map((c) => [`${c.file.slice(root.length + 1)}: ${c.line}`, c] as const))(
    "uses only flags the CLI's usage text lists — %s",
    (_name, command) => {
      const flags = flagsOf(command.line);
      expect(flags.length).toBeGreaterThan(0);
      const unknown = flags.filter((flag) => !new RegExp(`${flag}(?![a-z0-9-])`).test(usage));
      expect(unknown, `flags missing from \`antireverse --help\` in ${command.line}`).toEqual([]);
    },
  );

  it("documents no gate flag that gate does not take", () => {
    const gateLine = usage.split("\n").find((line) => line.trim().startsWith("antireverse gate --assessment"));
    expect(gateLine).toBeDefined();
    for (const command of commands.filter((c) => c.subcommand === "gate")) {
      const unknown = flagsOf(command.line).filter((flag) => !new RegExp(`${flag}(?![a-z0-9-])`).test(gateLine ?? ""));
      expect(unknown, command.line).toEqual([]);
    }
  });

  it.each([...docFiles, readme].map((file) => [file.slice(root.length + 1), file] as const))(
    "has relative links that resolve — %s",
    (_name, file) => {
      const links = relativeLinks(file).filter((link) => file !== readme || link.target.startsWith(docsDir));
      const broken: string[] = [];
      for (const link of links) {
        if (!existsSync(link.target)) {
          broken.push(link.target.slice(root.length + 1));
        } else if (link.anchor !== null && link.target.endsWith(".md") && !anchorsOf(link.target).has(link.anchor)) {
          broken.push(`${link.target.slice(root.length + 1)}#${link.anchor}`);
        }
      }
      expect(broken).toEqual([]);
    },
  );

  it("links from the README to every page", () => {
    const targets = new Set(relativeLinks(readme).map((link) => link.target));
    for (const file of docFiles) expect(targets.has(file), file).toBe(true);
  });
});

/** Splits a shell command line into words: whitespace-separated, with "…" and '…' quoting. No expansion. */
function shellWords(line: string): string[] {
  return [...line.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map((m) => (m[1] ?? m[2] ?? m[3]) as string);
}

/** Runs a command from the repository root; never rejects. */
function run(words: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  const [file, ...args] = words as [string, ...string[]];
  return new Promise((done) => {
    execFile(
      file,
      args,
      { cwd: root, env: { ...process.env, AR_ADMIN_KEY: "" }, timeout: 60_000 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : 1;
        done({ code, stdout, stderr });
      },
    );
  });
}

describe("docs/getting-started.md, run offline", () => {
  const guide = join(docsDir, "getting-started.md");
  // Every Harden command line of the guide, in the order it gives them.
  const lines = bashBlocks(readFileSync(guide, "utf8"))
    .flatMap((block) => block.split("\n"))
    .map((line) => line.trim())
    .filter((line) => /^npx tsx packages\/harden\/src\/cli\.ts\b/.test(line));
  // Offline: no --register (that needs a running API and an admin key; flag-checked above only).
  const offline = lines.filter((line) => !line.includes("--register"));
  const fixture = join(root, "tests/e2e/fixtures/storefront");
  const temp = mkdtempSync(join(tmpdir(), "ar-docs-"));
  afterAll(() => rmSync(temp, { recursive: true, force: true }));

  it("has a --help command, a harden run without --register, and a registering command", () => {
    expect(offline.some((line) => line.endsWith("--help"))).toBe(true);
    expect(offline.some((line) => / harden /.test(line))).toBe(true);
    expect(lines.some((line) => line.includes("--register"))).toBe(true);
  });

  it.each(offline.map((line) => [line] as const))("runs: %s", async (line) => {
    const out = join(temp, `out-${offline.indexOf(line)}`);
    // Placeholders are filled word by word, after splitting, so paths with spaces stay one argument.
    const fill: Record<string, string> = { "<bundle-dir>": fixture, "<out-dir>": out };
    const words = shellWords(line).map((word) => fill[word] ?? word);
    // A placeholder this test cannot fill means the command is not runnable as written.
    expect(
      words.filter((word) => /<[a-z-]+>/.test(word)),
      "unfilled placeholders",
    ).toEqual([]);
    const result = await run(words);
    expect(result.code, result.stderr).toBe(0);
    if (line.endsWith("--help")) {
      expect(result.stdout).toContain("antireverse harden <dir>");
    } else {
      expect(result.stdout).toContain("✓ leak scan clean");
      expect(readdirSync(out, { recursive: true }).length).toBeGreaterThan(0);
    }
  });
});
