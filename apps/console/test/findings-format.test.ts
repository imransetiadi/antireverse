// @vitest-environment node
import { type Advisory, EXAMPLE_ADVISORY, EXAMPLE_FINDING, type Finding } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  affectedRanges,
  cveSummary,
  ignoreWindow,
  osvUrl,
  packageLabel,
  suggestedFix,
  untilFromDate,
} from "@/features/findings/format.ts";
import { confirmIgnoreFrom, findingFilterFrom, findingQueryFrom } from "@/features/findings/query.ts";
import { ROUTES } from "@/lib/routes.ts";

const advisory = (affected: Advisory["affected"]): Advisory => ({ ...EXAMPLE_ADVISORY, affected });
const npm = (name: string, ranges: Advisory["affected"][number]["ranges"], versions?: string[]) => ({
  package: { ecosystem: "npm", name },
  ranges,
  ...(versions === undefined ? {} : { versions }),
});
const finding = (overrides: Partial<Finding>): Finding => ({ ...EXAMPLE_FINDING, ...overrides });

describe("affectedRanges", () => {
  it("renders each interval readably: introduced 0 has no lower bound", () => {
    expect(affectedRanges(EXAMPLE_ADVISORY, "example-parser")).toEqual({
      ranges: ["< 1.2.4", ">= 2.0.0, < 2.1.1"],
      versions: [],
    });
  });

  it("renders last_affected as an inclusive bound, an open interval and every version", () => {
    const ranges = affectedRanges(
      advisory([
        npm("pkg", [
          { type: "SEMVER", events: [{ introduced: "1.0.0" }, { last_affected: "1.4.2" }] },
          { type: "ECOSYSTEM", events: [{ introduced: "3.0.0-rc.1" }] },
          { type: "SEMVER", events: [{ introduced: "0" }] },
        ]),
      ]),
      "pkg",
    );
    expect(ranges.ranges).toEqual([">= 1.0.0, <= 1.4.2", ">= 3.0.0-rc.1", null]);
  });

  it("sorts the events by version, drops versions that are not semver and repeats no range", () => {
    const ranges = affectedRanges(
      advisory([
        npm("pkg", [
          { type: "SEMVER", events: [{ fixed: "1.2.3" }, { introduced: "1.0.0" }, { introduced: "not-a-version" }] },
          { type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.3" }] },
        ]),
      ]),
      "pkg",
    );
    expect(ranges.ranges).toEqual([">= 1.0.0, < 1.2.3"]);
  });

  it("keeps to the Finding's npm package and lists explicit versions", () => {
    const ranges = affectedRanges(
      advisory([
        npm("other", [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }]),
        { package: { ecosystem: "PyPI", name: "pkg" }, ranges: [] },
        npm("pkg", [], ["1.0.1", "1.0.0", "1.0.1"]),
      ]),
      "pkg",
    );
    expect(ranges).toEqual({ ranges: [], versions: ["1.0.0", "1.0.1"] });
  });
});

describe("suggestedFix", () => {
  it("is the first fixed version above the installed one", () => {
    expect(suggestedFix(EXAMPLE_FINDING)).toBe("1.2.4");
    expect(suggestedFix(finding({ version: "2.0.5" }))).toBe("2.1.1");
  });

  it("is null when no fixed version lies above the installed one", () => {
    expect(suggestedFix(finding({ fixed_versions: [] }))).toBeNull();
    expect(suggestedFix(finding({ version: "3.0.0" }))).toBeNull();
  });
});

describe("cveSummary", () => {
  it("shows the first CVE alias and counts the rest; other aliases do not count", () => {
    expect(cveSummary(["GHSA-aaaa-bbbb-cccc", "CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])).toEqual({
      first: "CVE-2026-1",
      more: 2,
    });
    expect(cveSummary(["GHSA-aaaa-bbbb-cccc"])).toEqual({ first: null, more: 0 });
  });
});

describe("labels and links", () => {
  it("names a package at its version", () => {
    expect(packageLabel(finding({ package: "@scope/ui", version: "4.0.0-rc.1" }))).toBe("@scope/ui@4.0.0-rc.1");
  });

  it("links an advisory on osv.dev with the id encoded", () => {
    expect(osvUrl("GHSA-2c3m-4p5q-6r7v")).toBe("https://osv.dev/vulnerability/GHSA-2c3m-4p5q-6r7v");
    expect(osvUrl("GHSA-a/b?c")).toBe("https://osv.dev/vulnerability/GHSA-a%2Fb%3Fc");
  });
});

describe("the ignore window", () => {
  // 2026-11-11 15:30 UTC.
  const NOW = Date.UTC(2026, 10, 11, 15, 30);

  it("offers dates from tomorrow up to 90 days ahead, 30 days by default (UTC)", () => {
    expect(ignoreWindow(NOW)).toEqual({ min: "2026-11-12", max: "2027-02-09", initial: "2026-12-11" });
  });

  it("turns a date inside the window into the start of that day in UTC", () => {
    expect(untilFromDate("2026-12-11", NOW)).toBe("2026-12-11T00:00:00.000Z");
    expect(untilFromDate("2026-11-12", NOW)).toBe("2026-11-12T00:00:00.000Z");
    expect(untilFromDate("2027-02-09", NOW)).toBe("2027-02-09T00:00:00.000Z");
  });

  it("refuses today, the past, more than 90 days ahead and anything that is not a date", () => {
    for (const value of ["2026-11-11", "2025-01-01", "2027-02-10", "", "2026-02-30", "12/11/2026", "2026-12-11T00:00"])
      expect([value, untilFromDate(value, NOW)]).toEqual([value, null]);
  });
});

describe("the Finding list address", () => {
  it("reads the filters it knows and drops anything else", () => {
    expect(
      findingQueryFrom({
        severity: "critical",
        status: "ignored",
        source: "runtime",
        advisory: "GHSA-2c3m-4p5q-6r7v",
        build: "bld_0123456789abcdef01234567",
      }),
    ).toEqual({
      severity: "critical",
      status: "ignored",
      source: "runtime",
      advisory: "GHSA-2c3m-4p5q-6r7v",
      build: "bld_0123456789abcdef01234567",
    });
    expect(
      findingQueryFrom({ severity: "severe", status: ["open", "fixed"], source: "ci", advisory: "<x>", build: "b" }),
    ).toEqual({});
  });

  it("builds the list addresses with the filters in a fixed order", () => {
    expect(ROUTES.findings()).toBe("/findings");
    expect(ROUTES.findings({ source: "build", severity: "high" })).toBe("/findings?severity=high&source=build");
    expect(ROUTES.findings({ advisory: "GHSA-2c3m-4p5q-6r7v" })).toBe("/findings?advisory=GHSA-2c3m-4p5q-6r7v");
    expect(ROUTES.appFindings(EXAMPLE_FINDING.app_id)).toBe(`/apps/${EXAMPLE_FINDING.app_id}/findings`);
    expect(ROUTES.appFindings(EXAMPLE_FINDING.app_id, { build: "bld_0123456789abcdef01234567", status: "open" })).toBe(
      `/apps/${EXAMPLE_FINDING.app_id}/findings?status=open&build=bld_0123456789abcdef01234567`,
    );
    expect(ROUTES.finding(EXAMPLE_FINDING.id)).toBe(`/findings/${EXAMPLE_FINDING.id}`);
    expect(ROUTES.finding(EXAMPLE_FINDING.id, { confirm: "ignore" })).toBe(
      `/findings/${EXAMPLE_FINDING.id}?confirm=ignore`,
    );
  });

  it("opens the ignore step only for exactly ?confirm=ignore", () => {
    expect(confirmIgnoreFrom("ignore")).toBe(true);
    expect(confirmIgnoreFrom(undefined)).toBe(false);
    expect(confirmIgnoreFrom(["ignore"])).toBe(false);
  });

  it("turns every filter of the address into an API filter: the advisory and the Build are filtered by the server", () => {
    expect(findingFilterFrom({})).toEqual({});
    expect(
      findingFilterFrom({
        severity: "high",
        status: "open",
        source: "build",
        advisory: "CVE-2026-10001",
        build: "bld_0123456789abcdef01234567",
      }),
    ).toEqual({
      severity: "high",
      status: "open",
      source: "build",
      advisoryId: "CVE-2026-10001",
      buildId: "bld_0123456789abcdef01234567",
    });
    expect(findingFilterFrom({ advisory: "GHSA-2c3m-4p5q-6r7v" }, EXAMPLE_FINDING.app_id)).toEqual({
      appId: EXAMPLE_FINDING.app_id,
      advisoryId: "GHSA-2c3m-4p5q-6r7v",
    });
  });
});
