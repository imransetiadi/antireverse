// Slice 18e: the criteria catalog has exactly one entry per checklist line of QASUITE §16 and SECURITY §12, read from
// the documents themselves, so a new line in either fails here until it is mapped.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CHECKS, CRITERIA, SOURCES, validateCatalog } from "../src/catalog.ts";
import { checklist, section } from "../src/docs.ts";
import { MATRICES } from "../src/matrix.ts";
import { REPO_ROOT } from "../src/paths.ts";

const read = (doc: string) => readFileSync(`${REPO_ROOT}/${doc}`, "utf8");

describe("checklist parsing", () => {
  const doc = [
    "# Title",
    "## 11. Other",
    "- [ ] not this one",
    "## 12. Release security gate",
    "",
    "A release ships only when every line is true:",
    "",
    "- [ ] First line.",
    "- [x] Second line, ticked.",
    "  - [ ] a nested line is not a criterion",
    "## 13. Next",
    "- [ ] nor this one",
  ].join("\n");

  it("reads the lines of one section only, with their line numbers", () => {
    expect(checklist(doc, "12")).toEqual([
      { line: 8, text: "First line." },
      { line: 9, text: "Second line, ticked." },
    ]);
  });

  it("returns the section text between its heading and the next one", () => {
    expect(section(doc, "11")).toBe("- [ ] not this one");
  });

  it("throws when the section is missing or holds no checklist line", () => {
    expect(() => checklist(doc, "14")).toThrow(/§14/);
    expect(() => checklist("## 14. Empty\ntext\n", "14")).toThrow(/no checklist line/);
  });
});

describe("the catalog", () => {
  for (const source of SOURCES) {
    it(`maps every line of ${source.doc} §${source.section} to exactly one entry`, () => {
      const lines = checklist(read(source.doc), source.section);
      expect(lines.length).toBeGreaterThan(0);
      for (const line of lines) {
        const entries = CRITERIA.filter((c) => c.source.doc === source.doc && c.source.text === line.text);
        expect(entries, `unmapped: ${source.doc} §${source.section}: "${line.text}"`).toHaveLength(1);
      }
      // And no stale entry: every entry of this source is a line of the document.
      const texts = new Set(lines.map((l) => l.text));
      for (const entry of CRITERIA.filter((c) => c.source.doc === source.doc)) {
        expect(texts.has(entry.source.text), `stale entry ${entry.id}`).toBe(true);
      }
    });
  }

  it("is valid: unique ids, known checks, every entry checkable or with a reason and a slice", () => {
    expect(validateCatalog(CRITERIA, CHECKS)).toEqual([]);
    for (const entry of CRITERIA) {
      expect(entry.checks.length + entry.gaps.length + entry.requires.length, entry.id).toBeGreaterThan(0);
      for (const gap of entry.gaps) {
        expect(gap.reason.length, entry.id).toBeGreaterThan(10);
        expect(gap.slice, entry.id).toMatch(/^(\d{2}[a-z]?|unplanned)$/);
      }
    }
  });

  it("reports catalog errors: duplicate id, unknown check, unknown or cyclic requirement, empty entry", () => {
    const base = { source: { doc: "QASUITE.md", section: "16", text: "x" }, title: "x" } as const;
    const errors = validateCatalog(
      [
        { ...base, id: "a", checks: ["nope"], gaps: [], requires: [] },
        { ...base, id: "a", checks: [], gaps: [], requires: [] },
        { ...base, id: "b", checks: [], gaps: [], requires: ["c"] },
        { ...base, id: "c", checks: [], gaps: [], requires: ["b"] },
        { ...base, id: "d", checks: [], gaps: [], requires: ["zz"] },
      ],
      CHECKS,
    );
    expect(errors.join("\n")).toMatch(/duplicate id a/);
    expect(errors.join("\n")).toMatch(/unknown check nope/);
    expect(errors.join("\n")).toMatch(/a: no check, gap or requirement/);
    expect(errors.join("\n")).toMatch(/cycle/);
    expect(errors.join("\n")).toMatch(/unknown requirement zz/);
  });

  it("runs the checks the ticket names, the matrices as separate checks", () => {
    expect(Object.keys(CHECKS).sort()).toEqual(
      [
        "verify",
        "e2e-browser",
        "matrix-audit",
        "matrix-tenant",
        "matrix-authz",
        "matrix-privacy",
        "rrs-stand-in",
        "campaign-safety",
        "upgrade-local",
        "rollback-local",
        "kill-switch-drill",
        "sdk-reproducible",
        "sdk-install-smoke",
        "sdk-equivalence",
        "sdk-sbom-allowlist",
        "sdk-signed-manifest",
        "bench-shield",
        "load-smoke",
        "npm-audit",
      ].sort(),
    );
    expect(CHECKS["npm-audit"].online).toBe(true);
    for (const id of ["verify", "e2e-browser", "bench-shield"] as const) expect(CHECKS[id].slow).toBe(true);
    for (const id of [
      "matrix-audit",
      "matrix-tenant",
      "matrix-authz",
      "matrix-privacy",
      "rrs-stand-in",
      "campaign-safety",
      "upgrade-local",
      "rollback-local",
      "kill-switch-drill",
      "sdk-reproducible",
      "sdk-install-smoke",
      "sdk-equivalence",
      "sdk-sbom-allowlist",
      "sdk-signed-manifest",
      "load-smoke",
    ] as const) {
      expect(CHECKS[id].slow, id).toBe(false);
    }
    const security = CRITERIA.find((c) => c.source.text.startsWith("Cross-tenant matrix"));
    expect(security?.checks).toEqual(["matrix-tenant", "matrix-authz", "matrix-privacy"]);
  });

  it("slice 15a: the Campaign safety criterion runs the scope-escape and kill-switch tests; real-engine lines stay open", () => {
    const safety = CRITERIA.find((c) => c.id === "gate-campaign-safety");
    expect(safety).toMatchObject({ checks: ["campaign-safety"], gaps: [], requires: [], source: { doc: "gate" } });
    expect(safety?.source.text).toMatch(/scope/i);
    expect(safety?.source.text).toMatch(/kill switch/i);
    expect(safety?.notes?.join(" ")).toMatch(/not a penetration test/);
    const files = MATRICES.find((m) => m.id === "campaign-safety")?.files ?? [];
    expect(files).toEqual(
      expect.arrayContaining([
        "tests/e2e/campaign-scope.http.test.ts",
        "tests/e2e/campaign-never-destructive.http.test.ts",
        "apps/api/test/campaign-gate.test.ts",
      ]),
    );
    for (const file of files) expect(existsSync(join(REPO_ROOT, file)), file).toBe(true);
    // The lines that need a real engine and a staging target are still not checkable, and say why.
    for (const id of ["qa16-defects", "sec12-rrs-pentest"]) {
      const entry = CRITERIA.find((c) => c.id === id);
      expect(entry?.checks, id).toEqual([]);
      const gap = entry?.gaps.find((g) => /Campaign/.test(g.reason));
      expect(gap?.slice, id).toBe("15b");
      expect(gap?.reason, id).toMatch(/real engine/);
      expect(gap?.reason, id).toMatch(/staging/);
      expect(gap?.reason, id).not.toMatch(/does not exist yet/);
    }
    expect(CRITERIA.find((c) => c.id === "sec12-kill-switches")?.gaps[0]?.reason).toMatch(/gate-campaign-safety/);
  });
});

// Slice 18h: the upgrade check, the rollback rehearsal and the kill-switch drill run locally, as criteria of the
// gate's own. The checklist lines speak of released SDK minors and of staging: no local run turns them green.
describe("slice 18h: upgrade, rollback and kill switches", () => {
  const criterion = (id: string) => CRITERIA.find((c) => c.id === id);
  const filesOf = (id: string) => MATRICES.find((m) => m.id === id)?.files ?? [];

  it("the three checklist lines stay not checkable, without a check, and say what is proven locally and what is not", () => {
    const upgrade = criterion("qa16-upgrade");
    expect(upgrade).toMatchObject({ checks: [], requires: [] });
    expect(upgrade?.gaps).toHaveLength(1);
    expect(upgrade?.gaps[0]?.reason).toMatch(/no SDK minor has been released/);
    expect(upgrade?.gaps[0]?.reason).toMatch(/gate-upgrade-local/);
    expect(upgrade?.gaps[0]?.reason).toMatch(/database schema/);

    const rollback = criterion("qa16-rollback");
    expect(rollback).toMatchObject({ checks: [], requires: [] });
    expect(rollback?.gaps).toHaveLength(1);
    expect(rollback?.gaps[0]?.reason).toMatch(/no staging deployment/);
    expect(rollback?.gaps[0]?.reason).toMatch(/gate-rollback-local/);
    expect(rollback?.gaps[0]?.reason).toMatch(/previous version's code/);

    const switches = criterion("sec12-kill-switches");
    expect(switches).toMatchObject({ checks: [], requires: [] });
    expect(switches?.gaps).toHaveLength(1);
    expect(switches?.gaps[0]?.reason).toMatch(/no staging environment/);
    expect(switches?.gaps[0]?.reason).toMatch(/gate-kill-switch-drill/);
    expect(switches?.gaps[0]?.reason).toMatch(/gate-rollback-local/);
    // The security gate still includes the kill-switch line, so it cannot complete from a local run either.
    expect(criterion("qa16-security-gate")?.requires).toContain("sec12-kill-switches");
  });

  it("gate-upgrade-local: every migration prefix with seeded data, upgraded to the head", () => {
    const entry = criterion("gate-upgrade-local");
    expect(entry).toMatchObject({ checks: ["upgrade-local"], gaps: [], requires: [], source: { doc: "gate" } });
    expect(entry?.source.text).toMatch(/migration prefix/);
    expect(entry?.source.text).toMatch(/audit chain/);
    expect(entry?.source.text).toMatch(/second migration run applies nothing/);
    const notes = entry?.notes?.join(" ") ?? "";
    expect(notes).toMatch(/No version has been released/);
    expect(notes).toMatch(/not an SDK upgrade/);
    expect(notes).toMatch(/today's shape/);
    expect(entry?.source.text).toMatch(/can still be written/);
    expect(filesOf("upgrade-local")).toEqual(["apps/api/test/upgrade.test.ts"]);
  });

  it("gate-rollback-local: the backup taken before an upgrade, restored, served", () => {
    const entry = criterion("gate-rollback-local");
    expect(entry).toMatchObject({ checks: ["rollback-local"], gaps: [], requires: [], source: { doc: "gate" } });
    expect(entry?.source.text).toMatch(/backup/);
    expect(entry?.source.text).toMatch(/key files/);
    const notes = entry?.notes?.join(" ") ?? "";
    expect(notes).toMatch(/data rollback/);
    expect(notes).toMatch(/previous version's code on the upgraded schema is not rehearsed/);
    expect(notes).toMatch(/Everything written after the backup is lost/);
    expect(notes).toMatch(/Only a data directory is ever replaced/);
    expect(filesOf("rollback-local")).toEqual([
      "apps/api/test/backup.test.ts",
      "apps/api/test/rollback-rehearsal.test.ts",
    ]);
  });

  it("gate-kill-switch-drill: the drill, plus the Campaign safety suite that cuts running Campaigns", () => {
    const entry = criterion("gate-kill-switch-drill");
    expect(entry).toMatchObject({
      checks: ["kill-switch-drill", "campaign-safety"],
      gaps: [],
      requires: [],
      source: { doc: "gate" },
    });
    for (const name of [
      /monitor/,
      /roll back/i,
      /AR_SHIELD_DISABLED/,
      /kill switch/,
      /suspension/,
      /AR_PROVE_CAMPAIGNS/,
    ]) {
      expect(entry?.source.text).toMatch(name);
    }
    const notes = entry?.notes?.join(" ") ?? "";
    expect(notes).toMatch(/App safe mode, global safe mode and the Guard kill switch do not exist/);
    expect(notes).toMatch(/not a drill in staging/);
    // Review M3: not every switch writes an audit entry, and the catalog must not say that it does.
    expect(notes).toMatch(/Lifting the Campaign kill switch writes no audit entry/);
    expect(`${entry?.source.text} ${CHECKS["kill-switch-drill"].title}`).not.toMatch(/with (its|the) audit entries/);
    expect(entry?.source.text).toMatch(/what the API records/);
    expect(entry?.source.text).toMatch(/disabled option/);
    expect(filesOf("kill-switch-drill")).toEqual(["tests/e2e/kill-switch-drill.http.test.ts"]);
  });

  it("every file of the three checks exists, and none of the checks is skipped by --skip-slow", () => {
    for (const id of ["upgrade-local", "rollback-local", "kill-switch-drill"] as const) {
      expect(filesOf(id).length, id).toBeGreaterThan(0);
      for (const file of filesOf(id)) expect(existsSync(join(REPO_ROOT, file)), file).toBe(true);
      expect(CHECKS[id]).toMatchObject({ slow: false, online: false });
    }
  });
});

// Slice 23: the SDK packages are built, packed and checked locally, as a criterion of the gate's own. The checklist
// line asks for provenance and speaks of releases: no local run turns it green.
describe("slice 23: SDK artifacts", () => {
  const criterion = (id: string) => CRITERIA.find((c) => c.id === id);
  const filesOf = (id: string) => MATRICES.find((m) => m.id === id)?.files ?? [];
  const SDK_CHECKS = [
    "sdk-reproducible",
    "sdk-install-smoke",
    "sdk-equivalence",
    "sdk-sbom-allowlist",
    "sdk-signed-manifest",
  ] as const;

  it("the checklist line stays not checkable, without a check, and says what is proven locally and what is still missing", () => {
    const line = criterion("sec12-sdk-artifacts");
    expect(line).toMatchObject({ checks: [], requires: [] });
    expect(line?.gaps).toHaveLength(1);
    const reason = line?.gaps[0]?.reason ?? "";
    expect(reason).toMatch(/gate-sdk-artifacts-local/);
    expect(reason).toMatch(/provenance/);
    expect(reason).toMatch(/two people/);
    expect(reason).toMatch(/published by the owner by hand/);
    expect(reason).toMatch(/no protected pipeline/);
    expect(reason).not.toMatch(/no package is published|there is no release:/);
    expect(reason).toMatch(/local key/);
    expect(reason).not.toMatch(
      /no SDK release pipeline exists \(no published artifacts, signatures, provenance or SBOM\)/,
    );
    expect(criterion("qa16-security-gate")?.requires).toContain("sec12-sdk-artifacts");
  });

  it("gate-sdk-artifacts-local: five checks, one per property, and notes that say what they do not prove", () => {
    const entry = criterion("gate-sdk-artifacts-local");
    expect(entry).toMatchObject({
      checks: [...SDK_CHECKS],
      gaps: [],
      requires: [],
      source: { doc: "gate", section: "D-127" },
    });
    for (const part of [
      /byte-identical/,
      /npm install/,
      /plain Node/,
      /compiled output/,
      /bill of materials/,
      /allowlist/,
      /signed manifest/,
    ]) {
      expect(entry?.source.text).toMatch(part);
    }
    const notes = entry?.notes?.join(" ") ?? "";
    expect(notes).toMatch(/No command here publishes/);
    expect(notes).toMatch(/release build/);
    expect(notes).toMatch(/owner/);
    expect(notes).toMatch(/no network and no npm login/);
    expect(notes).toMatch(/not provenance/);
    expect(notes).toMatch(/whoever holds/);
    expect(notes).toMatch(/loopback registry/);
    expect(notes).toMatch(/same Node and npm/);
    expect(notes).toMatch(/private/);
    // The titles say "local" or name the limit: none reads as a release check.
    for (const id of SDK_CHECKS) expect(CHECKS[id].title, id).toMatch(/slice 23/);
    expect(CHECKS["sdk-signed-manifest"].title).toMatch(/local key/);
    expect(CHECKS["sdk-signed-manifest"].title).toMatch(/not provenance/);
  });

  it("each check names its test files, every file exists, and none is slow or online", () => {
    expect(filesOf("sdk-reproducible")).toEqual([
      "tools/sdk/test/safe.test.ts",
      "tools/sdk/test/build.test.ts",
      "tools/sdk/test/reproducible.test.ts",
    ]);
    expect(filesOf("sdk-install-smoke")).toEqual(["tools/sdk/test/install-smoke.test.ts"]);
    expect(filesOf("sdk-equivalence")).toEqual(["tools/sdk/test/equivalence.test.ts"]);
    expect(filesOf("sdk-sbom-allowlist")).toEqual(["tools/sdk/test/sbom-allowlist.test.ts"]);
    // Slice 23b: the release shape is part of the same check — the publishable tarballs, their manifest and the
    // owner's two checks, against a loopback registry.
    expect(filesOf("sdk-signed-manifest")).toEqual([
      "tools/sdk/test/manifest.test.ts",
      "tools/sdk/test/release.test.ts",
    ]);
    for (const id of SDK_CHECKS) {
      for (const file of filesOf(id)) expect(existsSync(join(REPO_ROOT, file)), file).toBe(true);
      expect(CHECKS[id]).toMatchObject({ slow: false, online: false });
    }
    // Every test file of the SDK tooling belongs to a check: none can be added and forgotten.
    const listed = SDK_CHECKS.flatMap((id) => filesOf(id)).sort();
    const present = readdirSync(join(REPO_ROOT, "tools/sdk/test"))
      .filter((file) => file.endsWith(".test.ts"))
      .map((file) => `tools/sdk/test/${file}`)
      .sort();
    expect(listed).toEqual(present);
  });
});

// Slice 18g: the synthetic probes time PB-13 and PB-15 inside one running API instance against one local Shield. That
// shows the mechanism; it is not the budget's measurement, so the criterion stays not checkable and says exactly why.
describe("the performance criterion and the synthetic probes", () => {
  it("stays not checkable: no check is added for the probes, and its gap names PB-13 and PB-15 as in-process only", () => {
    const performance = CRITERIA.find((criterion) => criterion.id === "qa16-performance");
    expect(performance?.checks).toEqual(["bench-shield", "load-smoke"]);
    expect(performance?.gaps).toHaveLength(1);
    const reason = performance?.gaps[0]?.reason ?? "";
    expect(reason).toMatch(/PB-13 and PB-15/);
    expect(reason).toMatch(/AR_PROBES=1/);
    expect(reason).toMatch(/one running instance/);
    expect(reason).toMatch(/not run by this gate/);
    expect(Object.keys(CHECKS).some((id) => /probe/i.test(id))).toBe(false);
  });
});
