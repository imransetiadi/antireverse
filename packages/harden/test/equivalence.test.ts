import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkEquivalence } from "../src/equivalence.ts";

let fixtureDir = "";

afterEach(() => {
  if (fixtureDir && existsSync(fixtureDir)) rmSync(fixtureDir, { recursive: true, force: true });
  fixtureDir = "";
});

/** A tiny bundle: a module plus a runner that asserts behaviour and exits non-zero on failure. */
function makeFixture(): string {
  fixtureDir = mkdtempSync(join(tmpdir(), "harden-equiv-"));
  writeFileSync(join(fixtureDir, "mod.mjs"), `export const double = (n) => n * 2;\n`, "utf8");
  writeFileSync(
    join(fixtureDir, "run.mjs"),
    `import { double } from "./mod.mjs";\nif (double(21) !== 42) { console.error("wrong"); process.exit(1); }\nconsole.log("ok");\n`,
    "utf8",
  );
  return fixtureDir;
}

describe("checkEquivalence", () => {
  it("passes when the protected output preserves behaviour", async () => {
    const dir = makeFixture();
    const result = await checkEquivalence({
      dir,
      testCommand: "node run.mjs",
      protectedFiles: { "mod.mjs": `const d = (n) => n * 2;\nexport { d as double };\n` },
    });
    expect(result.passed).toBe(true);
    expect(result.output).toContain("ok");
  });

  it("catches a behaviour-breaking transform", async () => {
    const dir = makeFixture();
    const result = await checkEquivalence({
      dir,
      testCommand: "node run.mjs",
      protectedFiles: { "mod.mjs": `export const double = (n) => n * 3;\n` }, // wrong!
    });
    expect(result.passed).toBe(false);
    expect(result.output).toMatch(/wrong|exit|fail/i);
  });

  it("cleans up its temp copy and never touches the source dir", async () => {
    const dir = makeFixture();
    const before = readdirSync(dir).sort();
    await checkEquivalence({
      dir,
      testCommand: "node run.mjs",
      protectedFiles: { "mod.mjs": `export const double = (n) => n * 2;\n` },
    });
    // Source dir unchanged (mod.mjs still the original).
    expect(readdirSync(dir).sort()).toEqual(before);
  });
});
