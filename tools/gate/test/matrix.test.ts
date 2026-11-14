// Slice 18e: the matrix criteria run whole test files, selected by the names of the tests they hold (a -t filter would
// skip the setup tests that later tests of the same file depend on).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { MATRICES, selectMatrixFiles, testNames } from "../src/matrix.ts";
import { REPO_ROOT } from "../src/paths.ts";

const root = mkdtempSync(join(tmpdir(), "gate-matrix-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("testNames", () => {
  it("reads it, test and describe names in every quote style", () => {
    const source = [
      'describe("tenancy and keys", () => {',
      "  it('answers 404 to another Organization', async () => {});",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: the fixture is source text with a template literal
      "  it.each([1])(`counts ${'x'} per tenant`, () => {});",
      '  test.skip("a skipped one", () => {});',
      '  helper("not a test");',
      "});",
    ].join("\n");
    expect(testNames(source)).toEqual([
      "tenancy and keys",
      "answers 404 to another Organization",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: the name as written in the source
      "counts ${'x'} per tenant",
      "a skipped one",
    ]);
  });
});

describe("selectMatrixFiles", () => {
  mkdirSync(join(root, "apps/api/test"), { recursive: true });
  mkdirSync(join(root, "packages/protocol/test"), { recursive: true });
  writeFileSync(join(root, "apps/api/test/a.test.ts"), 'it("answers 404 to another Organization", () => {});');
  writeFileSync(join(root, "apps/api/test/b.test.ts"), 'it("nothing relevant", () => {});');
  writeFileSync(join(root, "apps/api/test/helpers.ts"), 'it("another Organization in a helper", () => {});');
  writeFileSync(join(root, "packages/protocol/test/c.test.ts"), 'describe("row-level security", () => {});');

  it("selects the test files holding a matching name, per project, with the matching names", () => {
    const selected = selectMatrixFiles(
      { id: "matrix-tenant", pattern: /another Organization|row-level security/, projects: ["api", "protocol"] },
      root,
    );
    expect(selected).toEqual([
      { project: "api", file: "apps/api/test/a.test.ts", names: ["answers 404 to another Organization"] },
      { project: "protocol", file: "packages/protocol/test/c.test.ts", names: ["row-level security"] },
    ]);
  });

  it("finds files for every matrix in the real repository", () => {
    for (const matrix of MATRICES) {
      const selected = selectMatrixFiles(matrix, REPO_ROOT);
      expect(selected.length, matrix.id).toBeGreaterThan(0);
      for (const entry of selected) expect(entry.file.startsWith("tools/"), entry.file).toBe(false);
    }
    const audit = selectMatrixFiles(
      MATRICES.find((m) => m.id === "matrix-audit") as (typeof MATRICES)[number],
      REPO_ROOT,
    );
    expect(audit.map((e) => e.file)).toContain("apps/api/test/audit-coverage.test.ts");
  });
});
