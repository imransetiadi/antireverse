// The entry check of cli.ts (slice 13 review): started through the npm bin (`npx antireverse …`), process.argv[1] is
// the symlink in node_modules/.bin, not the file itself. The CLI must still run — a silent exit 0 would pass every CI
// gate. Importing cli.ts as a module must not run it. Each case runs a real Node child process (type stripping).
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const CLI = realpathSync(fileURLToPath(new URL("../src/cli.ts", import.meta.url)));
const NPM_BIN = fileURLToPath(new URL("../../../node_modules/.bin/antireverse", import.meta.url));
/** Accepted by every Node 22 with type stripping (default-on from 22.18, behind the flag before). */
const NODE_ARGS = ["--experimental-strip-types", "--no-warnings"];

const temp = mkdtempSync(join(tmpdir(), "harden-bin-"));
afterAll(() => rmSync(temp, { recursive: true, force: true }));

function node(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done) => {
    execFile(process.execPath, [...NODE_ARGS, ...args], { env: { ...process.env } }, (error, stdout, stderr) => {
      const code = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
      done({ code, stdout, stderr });
    });
  });
}

const link = join(temp, "antireverse");
symlinkSync(CLI, link);

const bins: Array<[string, string]> = [["a symlink in a temp folder", link]];
if (existsSync(NPM_BIN)) bins.push(["the npm bin in node_modules/.bin", NPM_BIN]);

describe.each(bins)("the CLI started through %s", (_name, bin) => {
  it("prints the usage text for --help and exits 0", async () => {
    const r = await node([bin, "--help"]);
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("antireverse gate --assessment <asm_id> --min-rrs <0-100>");
    // Slice 23b review: equivalence is checked only when a test command is given; the help does not say more.
    expect(r.stdout).not.toContain("the equivalence gate proves it");
    expect(r.stdout).toContain(
      "with --test, the equivalence gate checks that the protected bundle still passes your tests",
    );
    expect(r.stdout).toContain("antireverse -v ");
  }, 30_000);

  it("prints the package's version for --version and -v, read from its own manifest", async () => {
    const manifest = JSON.parse(readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"));
    for (const flag of ["--version", "-v"]) {
      const r = await node([bin, flag]);
      expect(r.stderr).toBe("");
      expect(r.code).toBe(0);
      expect(r.stdout).toBe(`${manifest.version}\n`);
    }
  }, 30_000);

  it("exits 2 on a usage error (it never passes silently)", async () => {
    const r = await node([bin, "gate", "--min-rrs", "5"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("gate: missing --assessment");
  }, 30_000);
});

describe("cli.ts imported as a module", () => {
  it("does not run main", async () => {
    const importer = join(temp, "importer.mjs");
    writeFileSync(
      importer,
      `const cli = await import(${JSON.stringify(pathToFileURL(CLI).href)});\nconsole.log(typeof cli.main);\n`,
    );
    // Arguments that would make main print and exit 2 if it ran.
    const r = await node([importer, "gate", "--min-rrs", "5"]);
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("function\n");
  }, 30_000);
});
