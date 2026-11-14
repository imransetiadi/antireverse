// Slice 18e: the criteria catalog has exactly one entry per checklist line of QASUITE §16 and SECURITY §12, read from
// the documents themselves, so a new line in either fails here until it is mapped.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CHECKS, CRITERIA, SOURCES, validateCatalog } from "../src/catalog.ts";
import { checklist, section } from "../src/docs.ts";
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
      "load-smoke",
    ] as const) {
      expect(CHECKS[id].slow, id).toBe(false);
    }
    const security = CRITERIA.find((c) => c.source.text.startsWith("Cross-tenant matrix"));
    expect(security?.checks).toEqual(["matrix-tenant", "matrix-authz", "matrix-privacy"]);
  });
});
