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
      // Never the gate's own tests. The SDK tooling's tests (tools/sdk, slice 23) are checks of their own.
      for (const entry of selected) expect(entry.file.startsWith("tools/gate/"), entry.file).toBe(false);
    }
    const audit = selectMatrixFiles(
      MATRICES.find((m) => m.id === "matrix-audit") as (typeof MATRICES)[number],
      REPO_ROOT,
    );
    expect(audit.map((e) => e.file)).toContain("apps/api/test/audit-coverage.test.ts");
  });

  it("slice 18h: the upgrade, rollback and kill-switch checks select exactly their files, each in its project", () => {
    const selected = (id: string) =>
      selectMatrixFiles(MATRICES.find((m) => m.id === id) as (typeof MATRICES)[number], REPO_ROOT).map(
        (entry) => `${entry.project}:${entry.file}`,
      );
    expect(selected("upgrade-local")).toEqual(["api:apps/api/test/upgrade.test.ts"]);
    expect(selected("rollback-local")).toEqual([
      "api:apps/api/test/backup.test.ts",
      "api:apps/api/test/rollback-rehearsal.test.ts",
    ]);
    expect(selected("kill-switch-drill")).toEqual(["e2e:tests/e2e/kill-switch-drill.http.test.ts"]);
    // Every test of these files counts: the names the gate will demand a passed result for.
    const names = selectMatrixFiles(
      MATRICES.find((m) => m.id === "kill-switch-drill") as (typeof MATRICES)[number],
      REPO_ROOT,
    )[0]?.names;
    expect(
      names?.filter((name) =>
        /monitor|roll back|AR_SHIELD_DISABLED|kill switch|suspending|AR_PROVE_CAMPAIGNS/.test(name),
      ),
    ).toHaveLength(6);
  });

  it("slice 23: the SDK checks select exactly their files, in the sdk project, with the tests the gate will demand", () => {
    const selected = (id: string) =>
      selectMatrixFiles(MATRICES.find((m) => m.id === id) as (typeof MATRICES)[number], REPO_ROOT).map(
        (entry) => `${entry.project}:${entry.file}`,
      );
    expect(selected("sdk-reproducible")).toEqual([
      "sdk:tools/sdk/test/build.test.ts",
      "sdk:tools/sdk/test/reproducible.test.ts",
      "sdk:tools/sdk/test/safe.test.ts",
    ]);
    expect(selected("sdk-install-smoke")).toEqual(["sdk:tools/sdk/test/install-smoke.test.ts"]);
    expect(selected("sdk-equivalence")).toEqual(["sdk:tools/sdk/test/equivalence.test.ts"]);
    expect(selected("sdk-sbom-allowlist")).toEqual(["sdk:tools/sdk/test/sbom-allowlist.test.ts"]);
    expect(selected("sdk-signed-manifest")).toEqual([
      "sdk:tools/sdk/test/manifest.test.ts",
      "sdk:tools/sdk/test/release.test.ts",
    ]);
    for (const id of [
      "sdk-reproducible",
      "sdk-install-smoke",
      "sdk-equivalence",
      "sdk-sbom-allowlist",
      "sdk-signed-manifest",
    ]) {
      const files = selectMatrixFiles(MATRICES.find((m) => m.id === id) as (typeof MATRICES)[number], REPO_ROOT);
      for (const file of files) expect(file.names.length, file.file).toBeGreaterThan(3);
    }
  });
});
