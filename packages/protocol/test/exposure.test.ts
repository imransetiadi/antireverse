import { describe, expect, it } from "vitest";
import {
  type Advisory,
  AdvisorySchema,
  type Component,
  ComponentSchema,
  compareSemver,
  cvss3BaseScore,
  EXAMPLE_ADVISORY,
  EXAMPLE_FINDING,
  EXAMPLE_FINDINGS_SUMMARY,
  EXAMPLE_INVENTORY,
  EXPOSURE_LIMITS,
  FINDING_SEVERITIES,
  FINDING_SOURCES,
  FINDING_STATUSES,
  type Finding,
  FindingDetailResponseSchema,
  FindingResponseSchema,
  FindingSchema,
  type FindingSeverity,
  type FindingsSummary,
  FindingsSummarySchema,
  fixedVersions,
  type IgnoreFindingRequest,
  IgnoreFindingRequestSchema,
  type Inventory,
  InventorySchema,
  isAffected,
  ListFindingsResponseSchema,
  parseSemver,
  SemverSchema,
  severityOf,
} from "../src/index.ts";

const ok = (schema: { safeParse: (value: unknown) => { success: boolean } }, value: unknown): boolean =>
  schema.safeParse(value).success;

/** An advisory for `pkg` with the given ranges and extras, valid against the schema. */
function advisory(
  patch: Partial<Record<keyof Advisory, unknown>> & { ranges?: unknown[]; versions?: string[] },
): Advisory {
  const { ranges = [], versions, ...rest } = patch;
  return AdvisorySchema.parse({
    id: "GHSA-aaaa-bbbb-cccc",
    aliases: [],
    summary: "test",
    severity: [],
    affected: [
      {
        package: { ecosystem: "npm", name: "pkg" },
        ranges,
        ...(versions === undefined ? {} : { versions }),
      },
    ],
    published: "2026-01-01T00:00:00Z",
    modified: "2026-01-02T00:00:00Z",
    ...rest,
  });
}
const semverRange = (...events: (Record<string, string> | undefined)[]) => ({ type: "SEMVER", events });

describe("exposure constants", () => {
  it("has the limits of plan 19", () => {
    expect(EXPOSURE_LIMITS).toEqual({
      componentsMax: 5000,
      componentsBytesMax: 2_097_152,
      nameMax: 214,
      versionMax: 256,
      summaryMax: 500,
      aliasesMax: 50,
      affectedMax: 100,
      rangesMax: 50,
      eventsMax: 200,
      versionsMax: 10_000,
      findingsListed: 200,
      summaryItemsMax: 50,
      ignoreReasonMax: 200,
      ignoreDaysMax: 90,
    });
  });

  it("lists Finding severities, sources and statuses", () => {
    const severity: FindingSeverity = "critical";
    expect(FINDING_SEVERITIES).toEqual([severity, "high", "medium", "low", "unknown"]);
    expect(FINDING_SOURCES).toEqual(["build", "runtime"]);
    expect(FINDING_STATUSES).toEqual(["open", "fixed", "ignored", "withdrawn"]);
  });
});

describe("ComponentSchema", () => {
  const component = (patch: Partial<Component>) => ({ name: "express", version: "4.18.2", dev: false, ...patch });

  it("accepts an npm name, a semver version and the dev flag", () => {
    expect(ComponentSchema.parse(component({}))).toEqual(component({}));
    expect(ok(ComponentSchema, component({ name: "@types/node", dev: true }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: "lodash.merge" }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: "a-b_c.d" }))).toBe(true);
    expect(ok(ComponentSchema, component({ version: "1.0.0-rc.1+build.5" }))).toBe(true);
  });

  it("applies the npm naming rules", () => {
    expect(ok(ComponentSchema, component({ name: "" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: ".hidden" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "_private" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "has space" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "a/b" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "@scope" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "@scope/" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "@/name" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "@a/b/c" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "@scope/.name" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "../evil" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "na%20me" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "ünicode" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "x".repeat(214) }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: "x".repeat(215) }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: `@s/${"x".repeat(211)}` }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: `@s/${"x".repeat(212)}` }))).toBe(false);
  });

  it("accepts legacy names with capitals and npm's legacy special characters, but only lower-case scopes", () => {
    expect(ok(ComponentSchema, component({ name: "JSONStream" }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: "Express" }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: "@scope/LegacyName" }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: "fn(x)" }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: "it's~ok!*" }))).toBe(true);
    expect(ok(ComponentSchema, component({ name: "@Babel/core" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "@SCOPE/pkg" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "_Private" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: ".Hidden" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "Has Space" }))).toBe(false);
    expect(ok(ComponentSchema, component({ name: "A".repeat(215) }))).toBe(false);
  });

  it("keeps names case-sensitive: JSONStream and jsonstream are two components", () => {
    const components = [component({ name: "JSONStream" }), component({ name: "jsonstream" })];
    expect(ok(InventorySchema, { components })).toBe(true);
  });

  it("requires a semver 2.0 version: no git URL, no file: path, no range", () => {
    for (const version of ["git+https://github.com/a/b.git", "file:../x", "^1.2.3", "1.2", "v1.2.3", "01.2.3", ""]) {
      expect(ok(ComponentSchema, component({ version }))).toBe(false);
    }
  });

  it("requires dev as a boolean and strips unknown keys", () => {
    expect(ok(ComponentSchema, { name: "express", version: "4.18.2" })).toBe(false);
    expect(ok(ComponentSchema, component({ dev: "yes" as unknown as boolean }))).toBe(false);
    const parsed = ComponentSchema.parse({ ...component({}), resolved: "https://registry.example/x.tgz" });
    expect(parsed).not.toHaveProperty("resolved");
  });
});

describe("InventorySchema", () => {
  const entry = (index: number) => ({ name: `p${index}`, version: "1.0.0", dev: false });

  it("parses the documented example unchanged", () => {
    const parsed: Inventory = InventorySchema.parse(EXAMPLE_INVENTORY);
    expect(parsed).toEqual(EXAMPLE_INVENTORY);
    expect(Object.isFrozen(EXAMPLE_INVENTORY)).toBe(true);
  });

  it("carries an optional instance id: random per Shield process, 32 lowercase hex (A7)", () => {
    const instance_id = "0123456789abcdef0123456789abcdef";
    expect(InventorySchema.parse({ components: [], instance_id })).toEqual({ components: [], instance_id });
    // An older Shield sends none: one shared legacy instance.
    expect(InventorySchema.parse({ components: [] })).toEqual({ components: [] });
    for (const bad of ["", "xyz", "0123456789ABCDEF0123456789ABCDEF", "0".repeat(33), 42]) {
      expect(ok(InventorySchema, { components: [], instance_id: bad })).toBe(false);
    }
  });

  it("accepts an empty list and at most 5,000 components", () => {
    expect(ok(InventorySchema, { components: [] })).toBe(true);
    const many = (count: number) => ({ components: Array.from({ length: count }, (_, index) => entry(index)) });
    expect(ok(InventorySchema, many(EXPOSURE_LIMITS.componentsMax))).toBe(true);
    expect(ok(InventorySchema, many(EXPOSURE_LIMITS.componentsMax + 1))).toBe(false);
  });

  it("rejects a name@version listed twice, even with a different dev flag", () => {
    expect(ok(InventorySchema, { components: [entry(1), entry(1)] })).toBe(false);
    expect(ok(InventorySchema, { components: [entry(1), { ...entry(1), dev: true }] })).toBe(false);
    expect(ok(InventorySchema, { components: [entry(1), { ...entry(1), version: "1.0.1" }] })).toBe(true);
  });
});

describe("parseSemver", () => {
  it("parses the core, pre-release identifiers (numeric as numbers) and build metadata", () => {
    expect(parseSemver("1.2.3")).toEqual({ major: 1, minor: 2, patch: 3, prerelease: [], build: [] });
    expect(parseSemver("1.0.0-alpha.1")).toEqual({ major: 1, minor: 0, patch: 0, prerelease: ["alpha", 1], build: [] });
    expect(parseSemver("1.0.0-0.3.7")).toEqual({ major: 1, minor: 0, patch: 0, prerelease: [0, 3, 7], build: [] });
    expect(parseSemver("1.0.0-x.7.z.92")?.prerelease).toEqual(["x", 7, "z", 92]);
    expect(parseSemver("1.0.0-x-y-z.--")?.prerelease).toEqual(["x-y-z", "--"]);
    expect(parseSemver("1.0.0+20130313144700")?.build).toEqual(["20130313144700"]);
    expect(parseSemver("1.0.0-beta+exp.sha.5114f85")).toEqual({
      major: 1,
      minor: 0,
      patch: 0,
      prerelease: ["beta"],
      build: ["exp", "sha", "5114f85"],
    });
    expect(parseSemver("1.0.0+21AF26D3----117B344092BD")?.build).toEqual(["21AF26D3----117B344092BD"]);
    expect(parseSemver("1.0.0-0A.is.legal")?.prerelease).toEqual(["0A", "is", "legal"]);
    expect(parseSemver("1.0.0+0.build.1-rc.10000aaa-kk-0.1")?.build).toEqual([
      "0",
      "build",
      "1-rc",
      "10000aaa-kk-0",
      "1",
    ]);
    expect(parseSemver("0.0.0")).not.toBeNull();
  });

  it("rejects leading zeros in numeric identifiers, but not in build metadata", () => {
    for (const version of ["01.1.1", "1.01.1", "1.1.01", "1.2.3-0123", "1.2.3-0123.0123", "1.0.0-alpha.01", "00.0.0"]) {
      expect(parseSemver(version)).toBeNull();
    }
    expect(parseSemver("1.0.0+001")?.build).toEqual(["001"]);
  });

  it("rejects everything that is not a full semver 2.0 version", () => {
    const invalid = [
      "",
      "1",
      "1.2",
      "1.2.3.4",
      "v1.2.3",
      "=1.2.3",
      " 1.2.3",
      "1.2.3 ",
      "1.2.3-",
      "1.2.3+",
      "1.2.3-+",
      "1.2.3-.alpha",
      "1.2.3-alpha.",
      "1.2.3-alpha..1",
      "1.2.3+build..1",
      "1.2.3-alpha_beta",
      "+invalid",
      "-invalid",
      "alpha",
      "1.2.-3",
      "1.2.3-ünï",
      "^1.2.3",
      "1.x.0",
      "git+https://example.com/x.git",
      "file:../x",
      "latest",
    ];
    for (const version of invalid) expect(parseSemver(version), version).toBeNull();
  });

  it("rejects numbers beyond Number.MAX_SAFE_INTEGER and versions over 256 characters", () => {
    expect(parseSemver(`${Number.MAX_SAFE_INTEGER}.0.0`)?.major).toBe(Number.MAX_SAFE_INTEGER);
    expect(parseSemver("9007199254740992.0.0")).toBeNull();
    expect(parseSemver("1.99999999999999999999999.0")).toBeNull();
    expect(parseSemver("1.0.0-99999999999999999999")).toBeNull();
    expect(parseSemver(`1.0.0-${Number.MAX_SAFE_INTEGER}`)?.prerelease).toEqual([Number.MAX_SAFE_INTEGER]);
    expect(parseSemver(`1.0.0-${"a".repeat(250)}`)).not.toBeNull();
    expect(parseSemver(`1.0.0-${"a".repeat(251)}`)).toBeNull();
  });

  it("returns a frozen result", () => {
    const parsed = parseSemver("1.0.0-a+b");
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed?.prerelease)).toBe(true);
  });
});

describe("compareSemver", () => {
  it("orders the SemVer 2.0.0 §11 example chain", () => {
    const chain = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];
    for (let i = 0; i < chain.length; i++) {
      for (let j = 0; j < chain.length; j++) {
        const expected = i < j ? -1 : i > j ? 1 : 0;
        expect(compareSemver(chain[i] as string, chain[j] as string), `${chain[i]} vs ${chain[j]}`).toBe(expected);
      }
    }
  });

  it("compares major, minor and patch numerically", () => {
    const chain = [
      "0.0.0",
      "0.0.1",
      "0.1.0",
      "0.9.0",
      "0.10.0",
      "1.0.0",
      "1.9.9",
      "1.10.0",
      "2.0.0",
      "2.1.0",
      "2.1.1",
      "10.0.0",
    ];
    for (let i = 0; i + 1 < chain.length; i++) {
      expect(compareSemver(chain[i] as string, chain[i + 1] as string)).toBe(-1);
      expect(compareSemver(chain[i + 1] as string, chain[i] as string)).toBe(1);
    }
    expect(compareSemver(`${Number.MAX_SAFE_INTEGER}.0.0`, `${Number.MAX_SAFE_INTEGER - 1}.0.0`)).toBe(1);
  });

  it("ranks a pre-release below its release and numeric identifiers below alphanumeric ones", () => {
    expect(compareSemver("1.0.0-0", "1.0.0")).toBe(-1);
    expect(compareSemver("1.0.0-rc.1", "0.9.9")).toBe(1);
    expect(compareSemver("1.0.0-1", "1.0.0-a")).toBe(-1);
    expect(compareSemver("1.0.0-999", "1.0.0-a")).toBe(-1);
    expect(compareSemver("1.0.0-a.1", "1.0.0-a.a")).toBe(-1);
    expect(compareSemver("1.0.0-B", "1.0.0-a")).toBe(-1); // ASCII order: uppercase before lowercase
    expect(compareSemver("1.0.0-alpha", "1.0.0-alpha.0")).toBe(-1);
    expect(compareSemver("1.0.0-2", "1.0.0-10")).toBe(-1);
    expect(compareSemver("1.0.0-a10", "1.0.0-a2")).toBe(-1); // alphanumeric: lexical
  });

  it("ignores build metadata", () => {
    expect(compareSemver("1.0.0+a", "1.0.0+b")).toBe(0);
    expect(compareSemver("1.0.0", "1.0.0+build.1")).toBe(0);
    expect(compareSemver("1.0.0-rc.1+x", "1.0.0-rc.1")).toBe(0);
    expect(compareSemver("1.0.0-rc.1+x", "1.0.0-rc.2")).toBe(-1);
  });

  it("throws a RangeError on an invalid version", () => {
    expect(() => compareSemver("1.0", "1.0.0")).toThrow(RangeError);
    expect(() => compareSemver("1.0.0", "01.0.0")).toThrow(RangeError);
  });
});

describe("SemverSchema", () => {
  it("accepts a semver 2.0 string only", () => {
    expect(SemverSchema.parse("1.0.0-rc.1")).toBe("1.0.0-rc.1");
    expect(ok(SemverSchema, "1.0")).toBe(false);
    expect(ok(SemverSchema, 1)).toBe(false);
  });
});

describe("AdvisorySchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: Advisory = AdvisorySchema.parse(EXAMPLE_ADVISORY);
    expect(parsed).toEqual(EXAMPLE_ADVISORY);
    expect(Object.isFrozen(EXAMPLE_ADVISORY)).toBe(true);
  });

  it("parses a full OSV record and strips everything outside the subset", () => {
    const osv = {
      schema_version: "1.6.0",
      id: "GHSA-c2qf-rxjj-qqgw",
      aliases: ["CVE-2022-25883"],
      summary: "semver vulnerable to Regular Expression Denial of Service",
      details: "Long markdown text that is never stored.",
      severity: [
        { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
        { type: "CVSS_V2", score: "AV:N/AC:L/Au:N/C:N/I:N/A:P" },
        { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N" },
        { type: "Ubuntu", score: "medium" },
      ],
      affected: [
        {
          package: { ecosystem: "npm", name: "semver", purl: "pkg:npm/semver" },
          ranges: [
            { type: "ECOSYSTEM", events: [{ introduced: "7.0.0" }, { fixed: "7.5.2" }] },
            {
              type: "GIT",
              repo: "https://github.com/npm/node-semver",
              events: [{ introduced: "0" }, { fixed: "abc" }],
            },
          ],
          database_specific: { source: "https://example" },
          ecosystem_specific: { x: 1 },
        },
      ],
      references: [{ type: "WEB", url: "https://example" }],
      database_specific: { severity: "MODERATE", cwe_ids: ["CWE-1333"], github_reviewed: true },
      published: "2023-06-21T06:30:28Z",
      modified: "2024-02-12T17:42:48.123Z",
    };
    const parsed = AdvisorySchema.parse(osv);
    expect(parsed).toEqual({
      id: "GHSA-c2qf-rxjj-qqgw",
      aliases: ["CVE-2022-25883"],
      summary: "semver vulnerable to Regular Expression Denial of Service",
      severity: [
        { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
        { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N" },
      ],
      database_specific: { severity: "MODERATE" },
      affected: [
        {
          package: { ecosystem: "npm", name: "semver" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "7.0.0" }, { fixed: "7.5.2" }] }],
        },
      ],
      published: "2023-06-21T06:30:28Z",
      modified: "2024-02-12T17:42:48.123Z",
    });
    expect(JSON.stringify(parsed)).not.toContain("details");
  });

  it("defaults missing aliases, summary and severity, and drops an unknown GHSA label", () => {
    const parsed = AdvisorySchema.parse({
      id: "MAL-2026-1",
      affected: [{ package: { ecosystem: "npm", name: "evil" }, versions: ["1.0.0"] }],
      database_specific: { severity: "EXTREME" },
      published: "2026-01-01T00:00:00Z",
      modified: "2026-01-01T00:00:00Z",
    });
    expect(parsed.aliases).toEqual([]);
    expect(parsed.summary).toBe("");
    expect(parsed.severity).toEqual([]);
    expect(parsed.database_specific).toEqual({});
    expect(parsed.affected[0]?.ranges).toEqual([]);
  });

  it("validates ids, bounds and dates", () => {
    const base = { ...EXAMPLE_ADVISORY };
    expect(ok(AdvisorySchema, { ...base, id: "" })).toBe(false);
    expect(ok(AdvisorySchema, { ...base, id: "ghsa-lower" })).toBe(false);
    expect(ok(AdvisorySchema, { ...base, id: "GHSA-a\u0000b" })).toBe(false);
    expect(ok(AdvisorySchema, { ...base, aliases: ["not an id"] })).toBe(false);
    expect(ok(AdvisorySchema, { ...base, summary: "x".repeat(500) })).toBe(true);
    expect(ok(AdvisorySchema, { ...base, summary: "x".repeat(501) })).toBe(false);
    expect(ok(AdvisorySchema, { ...base, aliases: Array.from({ length: 51 }, (_, i) => `CVE-2026-${1000 + i}`) })).toBe(
      false,
    );
    expect(ok(AdvisorySchema, { ...base, modified: "yesterday" })).toBe(false);
    expect(ok(AdvisorySchema, { ...base, published: undefined })).toBe(false);
    expect(ok(AdvisorySchema, { ...base, withdrawn: "2026-05-01T00:00:00Z" })).toBe(true);
    expect(ok(AdvisorySchema, { ...base, modified: "2026-05-01T00:00:00+02:00" })).toBe(true);
    expect(ok(AdvisorySchema, { ...base, affected: [] })).toBe(false);
  });

  it("requires a CVSS vector of the declared version", () => {
    const withSeverity = (type: string, score: string) => ({ ...EXAMPLE_ADVISORY, severity: [{ type, score }] });
    expect(ok(AdvisorySchema, withSeverity("CVSS_V3", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))).toBe(true);
    expect(ok(AdvisorySchema, withSeverity("CVSS_V3", "CVSS:4.0/AV:N"))).toBe(false);
    expect(ok(AdvisorySchema, withSeverity("CVSS_V4", "CVSS:3.1/AV:N"))).toBe(false);
    expect(ok(AdvisorySchema, withSeverity("CVSS_V3", "9.8"))).toBe(false);
  });

  it("requires each range event to carry exactly one of introduced, fixed, last_affected and limit", () => {
    const withEvents = (events: unknown[]) => ({
      ...EXAMPLE_ADVISORY,
      affected: [{ package: { ecosystem: "npm", name: "pkg" }, ranges: [{ type: "SEMVER", events }] }],
    });
    expect(ok(AdvisorySchema, withEvents([{ introduced: "0" }, { last_affected: "1.0.0" }, { limit: "2.0.0" }]))).toBe(
      true,
    );
    expect(ok(AdvisorySchema, withEvents([{ introduced: "0", fixed: "1.0.0" }]))).toBe(false);
    expect(ok(AdvisorySchema, withEvents([{ other: "1.0.0" }]))).toBe(false);
    expect(ok(AdvisorySchema, withEvents([]))).toBe(false);
  });

  it("keeps affected entries of other ecosystems (matching ignores them)", () => {
    const parsed = AdvisorySchema.parse({
      ...EXAMPLE_ADVISORY,
      affected: [{ package: { ecosystem: "PyPI", name: "Django" }, ranges: [] }],
    });
    expect(parsed.affected[0]?.package).toEqual({ ecosystem: "PyPI", name: "Django" });
  });
});

describe("isAffected", () => {
  it("matches from introduced up to, not including, fixed", () => {
    const adv = advisory({ ranges: [semverRange({ introduced: "1.2.0" }, { fixed: "1.4.1" })] });
    expect(isAffected(adv, "pkg", "1.1.9")).toBe(false);
    expect(isAffected(adv, "pkg", "1.2.0")).toBe(true);
    expect(isAffected(adv, "pkg", "1.4.0")).toBe(true);
    expect(isAffected(adv, "pkg", "1.4.1-rc.1")).toBe(true);
    expect(isAffected(adv, "pkg", "1.4.1")).toBe(false);
    expect(isAffected(adv, "pkg", "2.0.0")).toBe(false);
    expect(isAffected(adv, "pkg", "1.2.0-beta")).toBe(false);
  });

  it('treats introduced "0" as the start of time, including pre-releases', () => {
    const adv = advisory({ ranges: [semverRange({ introduced: "0" }, { fixed: "1.0.0" })] });
    expect(isAffected(adv, "pkg", "0.0.0")).toBe(true);
    expect(isAffected(adv, "pkg", "0.0.0-alpha")).toBe(true);
    expect(isAffected(adv, "pkg", "0.9.9")).toBe(true);
    expect(isAffected(adv, "pkg", "1.0.0-rc.1")).toBe(true);
    expect(isAffected(adv, "pkg", "1.0.0")).toBe(false);
  });

  it("includes last_affected", () => {
    const adv = advisory({ ranges: [semverRange({ introduced: "2.0.0" }, { last_affected: "2.3.4" })] });
    expect(isAffected(adv, "pkg", "2.3.4")).toBe(true);
    expect(isAffected(adv, "pkg", "2.3.4+build")).toBe(true);
    expect(isAffected(adv, "pkg", "2.3.5-alpha")).toBe(false);
    expect(isAffected(adv, "pkg", "2.3.5")).toBe(false);
    expect(isAffected(adv, "pkg", "1.9.9")).toBe(false);
  });

  it("leaves a range open when nothing follows introduced", () => {
    const adv = advisory({ ranges: [semverRange({ introduced: "3.0.0" })] });
    expect(isAffected(adv, "pkg", "2.9.9")).toBe(false);
    expect(isAffected(adv, "pkg", "3.0.0")).toBe(true);
    expect(isAffected(adv, "pkg", "999.0.0")).toBe(true);
  });

  it("handles several introduced/fixed pairs in one range and evaluates them in version order", () => {
    const events = [{ introduced: "0" }, { fixed: "1.0.5" }, { introduced: "2.0.0" }, { fixed: "2.0.3" }];
    const adv = advisory({ ranges: [semverRange(...events)] });
    const shuffled = advisory({ ranges: [semverRange(events[3], events[1], events[2], events[0])] });
    for (const candidate of [adv, shuffled]) {
      expect(isAffected(candidate, "pkg", "1.0.4")).toBe(true);
      expect(isAffected(candidate, "pkg", "1.0.5")).toBe(false);
      expect(isAffected(candidate, "pkg", "1.9.0")).toBe(false);
      expect(isAffected(candidate, "pkg", "2.0.0")).toBe(true);
      expect(isAffected(candidate, "pkg", "2.0.2")).toBe(true);
      expect(isAffected(candidate, "pkg", "2.0.3")).toBe(false);
    }
  });

  it("is the union of several ranges and several affected entries", () => {
    const adv = advisory({
      ranges: [
        semverRange({ introduced: "1.0.0" }, { fixed: "1.1.0" }),
        semverRange({ introduced: "3.0.0" }, { fixed: "3.0.1" }),
      ],
    });
    expect(isAffected(adv, "pkg", "1.0.5")).toBe(true);
    expect(isAffected(adv, "pkg", "2.0.0")).toBe(false);
    expect(isAffected(adv, "pkg", "3.0.0")).toBe(true);
    const twoEntries = AdvisorySchema.parse({
      ...adv,
      affected: [
        {
          package: { ecosystem: "npm", name: "pkg" },
          ranges: [semverRange({ introduced: "1.0.0" }, { fixed: "1.1.0" })],
        },
        {
          package: { ecosystem: "npm", name: "pkg" },
          ranges: [semverRange({ introduced: "5.0.0" }, { fixed: "5.1.0" })],
        },
      ],
    });
    expect(isAffected(twoEntries, "pkg", "5.0.1")).toBe(true);
    expect(isAffected(twoEntries, "pkg", "4.0.0")).toBe(false);
  });

  it("treats ECOSYSTEM ranges like SEMVER ranges", () => {
    const adv = advisory({ ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] });
    expect(isAffected(adv, "pkg", "4.17.20")).toBe(true);
    expect(isAffected(adv, "pkg", "4.17.21")).toBe(false);
  });

  it("matches the explicit versions list exactly", () => {
    const adv = advisory({ versions: ["1.3.0", "2.0.0-beta.1"] });
    expect(isAffected(adv, "pkg", "1.3.0")).toBe(true);
    expect(isAffected(adv, "pkg", "2.0.0-beta.1")).toBe(true);
    expect(isAffected(adv, "pkg", "1.3.1")).toBe(false);
    expect(isAffected(adv, "pkg", "2.0.0")).toBe(false);
  });

  it("excludes versions at or above a limit", () => {
    const adv = advisory({ ranges: [semverRange({ introduced: "0" }, { limit: "2.0.0" })] });
    expect(isAffected(adv, "pkg", "1.9.9")).toBe(true);
    expect(isAffected(adv, "pkg", "2.0.0")).toBe(false);
    expect(isAffected(adv, "pkg", "3.0.0")).toBe(false);
  });

  it("ignores a withdrawn advisory", () => {
    const adv = advisory({ ranges: [semverRange({ introduced: "0" })], versions: ["1.0.0"] });
    expect(isAffected(adv, "pkg", "1.0.0")).toBe(true);
    const withdrawn = AdvisorySchema.parse({ ...adv, withdrawn: "2026-03-01T00:00:00Z" });
    expect(isAffected(withdrawn, "pkg", "1.0.0")).toBe(false);
  });

  it("ignores other packages and other ecosystems, and matches scoped names exactly", () => {
    const adv = AdvisorySchema.parse({
      ...EXAMPLE_ADVISORY,
      affected: [
        { package: { ecosystem: "PyPI", name: "pkg" }, ranges: [semverRange({ introduced: "0" })] },
        { package: { ecosystem: "npm", name: "@scope/pkg" }, ranges: [semverRange({ introduced: "0" })] },
      ],
    });
    expect(isAffected(adv, "pkg", "1.0.0")).toBe(false);
    expect(isAffected(adv, "@scope/pkg", "1.0.0")).toBe(true);
    expect(isAffected(adv, "@other/pkg", "1.0.0")).toBe(false);
    expect(isAffected(adv, "@SCOPE/pkg", "1.0.0")).toBe(false);
    const legacy = advisory({ ranges: [semverRange({ introduced: "0" })] });
    const named = AdvisorySchema.parse({
      ...legacy,
      affected: [{ package: { ecosystem: "npm", name: "JSONStream" }, ranges: [semverRange({ introduced: "0" })] }],
    });
    expect(isAffected(named, "JSONStream", "1.0.0")).toBe(true);
    expect(isAffected(named, "jsonstream", "1.0.0")).toBe(false);
  });

  it("returns false for a version that is not semver, and skips events that are not semver", () => {
    const adv = advisory({ ranges: [semverRange({ introduced: "0" })], versions: ["git+https://x"] });
    expect(isAffected(adv, "pkg", "git+https://x")).toBe(false);
    expect(isAffected(adv, "pkg", "file:../pkg")).toBe(false);
    expect(isAffected(adv, "pkg", "^1.0.0")).toBe(false);
    const odd = advisory({ ranges: [semverRange({ introduced: "1.0.0" }, { fixed: "abcdef" })] });
    expect(isAffected(odd, "pkg", "5.0.0")).toBe(true);
    expect(isAffected(odd, "pkg", "0.5.0")).toBe(false);
  });

  it("matches the documented example", () => {
    expect(isAffected(EXAMPLE_ADVISORY, "example-parser", "1.2.3")).toBe(true);
    expect(isAffected(EXAMPLE_ADVISORY, "example-parser", "1.2.4")).toBe(false);
    expect(isAffected(EXAMPLE_ADVISORY, "example-parser", "2.1.0")).toBe(true);
    expect(isAffected(EXAMPLE_ADVISORY, "example-parser", "2.1.1")).toBe(false);
  });
});

describe("fixedVersions", () => {
  it("lists every fixed event of the package's npm entries, de-duplicated and in version order", () => {
    const adv = AdvisorySchema.parse({
      ...EXAMPLE_ADVISORY,
      affected: [
        {
          package: { ecosystem: "npm", name: "pkg" },
          ranges: [
            semverRange({ introduced: "2.0.0" }, { fixed: "2.0.3" }),
            semverRange({ introduced: "0" }, { fixed: "1.0.10" }, { introduced: "1.1.0" }, { fixed: "1.1.2" }),
          ],
        },
        { package: { ecosystem: "npm", name: "pkg" }, ranges: [semverRange({ introduced: "0" }, { fixed: "1.0.10" })] },
        {
          package: { ecosystem: "npm", name: "other" },
          ranges: [semverRange({ introduced: "0" }, { fixed: "9.9.9" })],
        },
        { package: { ecosystem: "PyPI", name: "pkg" }, ranges: [semverRange({ introduced: "0" }, { fixed: "8.8.8" })] },
      ],
    });
    expect(fixedVersions(adv, "pkg")).toEqual(["1.0.10", "1.1.2", "2.0.3"]);
    expect(fixedVersions(adv, "absent")).toEqual([]);
  });

  it("returns none when only last_affected or no upper bound is known, and drops non-semver values", () => {
    expect(
      fixedVersions(advisory({ ranges: [semverRange({ introduced: "0" }, { last_affected: "1.0.0" })] }), "pkg"),
    ).toEqual([]);
    expect(fixedVersions(advisory({ ranges: [semverRange({ introduced: "0" }, { fixed: "abc" })] }), "pkg")).toEqual(
      [],
    );
  });

  it("returns the documented example's fixes", () => {
    expect(fixedVersions(EXAMPLE_ADVISORY, "example-parser")).toEqual(["1.2.4", "2.1.1"]);
  });
});

describe("cvss3BaseScore", () => {
  // Scores computed by hand from the CVSS v3.1 specification §7 (FIRST.org) and checked with an independent
  // script over all 2,592 base vectors.
  const known: [string, number][] = [
    ["AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
    ["AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5],
    ["AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7],
    ["AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5],
    ["AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10],
    ["AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4],
    ["AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1],
    ["AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6],
    ["AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 6.5],
    ["AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N", 2.3],
    ["AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0],
  ];

  it.each(known)("scores CVSS:3.1/%s as %d", (vector, score) => {
    expect(cvss3BaseScore(`CVSS:3.1/${vector}`)).toBe(score);
    expect(cvss3BaseScore(`CVSS:3.0/${vector}`)).toBe(score);
  });

  it("accepts the base metrics in any order and ignores temporal and environmental metrics", () => {
    expect(cvss3BaseScore("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N")).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C/CR:H/MAV:L")).toBe(9.8);
  });

  it("returns null for anything that is not a complete v3 base vector", () => {
    const invalid = [
      "",
      "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:L",
      "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Q",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/E:H",
      "CVSS:3.1//AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ];
    for (const vector of invalid) expect(cvss3BaseScore(vector), vector).toBeNull();
  });
});

describe("severityOf", () => {
  const v3 = (vector: string) => ({ type: "CVSS_V3", score: `CVSS:3.1/${vector}` });
  const withSeverity = (severity: unknown[], label?: string) =>
    AdvisorySchema.parse({
      ...EXAMPLE_ADVISORY,
      severity,
      database_specific: label === undefined ? {} : { severity: label },
    });

  it("takes the GHSA label first", () => {
    const critical = v3("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(severityOf(withSeverity([critical], "LOW"))).toBe("low");
    expect(severityOf(withSeverity([], "MODERATE"))).toBe("medium");
    expect(severityOf(withSeverity([], "HIGH"))).toBe("high");
    expect(severityOf(withSeverity([], "CRITICAL"))).toBe("critical");
  });

  it("else bands the CVSS v3 base score: 0.1–3.9 low, 4.0–6.9 medium, 7.0–8.9 high, 9.0–10 critical", () => {
    expect(severityOf(withSeverity([v3("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]))).toBe("critical"); // 9.8
    expect(severityOf(withSeverity([v3("AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")]))).toBe("critical"); // 9.1
    expect(severityOf(withSeverity([v3("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")]))).toBe("high"); // 7.5
    expect(severityOf(withSeverity([v3("AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")]))).toBe("medium"); // 6.5
    expect(severityOf(withSeverity([v3("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")]))).toBe("medium"); // 5.5
    expect(severityOf(withSeverity([v3("AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L")]))).toBe("low"); // 3.7
    expect(severityOf(withSeverity([v3("AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")]))).toBe("low"); // 1.6
  });

  it("takes the highest of several v3 scores, ignores v4 and unscorable vectors, else unknown", () => {
    const low = v3("AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
    const high = v3("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
    expect(severityOf(withSeverity([low, high]))).toBe("high");
    expect(severityOf(withSeverity([high, low]))).toBe("high");
    const v4 = { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" };
    expect(severityOf(withSeverity([v4]))).toBe("unknown");
    expect(severityOf(withSeverity([{ type: "CVSS_V3", score: "CVSS:3.1/AV:N" }]))).toBe("unknown");
    expect(severityOf(withSeverity([]))).toBe("unknown");
  });

  it("returns unknown for a 0.0 score, which lies in no band of the plan", () => {
    expect(severityOf(withSeverity([v3("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")]))).toBe("unknown");
  });

  it("rates the documented example by its GHSA label", () => {
    expect(severityOf(EXAMPLE_ADVISORY)).toBe("high");
  });
});

describe("FindingSchema", () => {
  const finding = (patch: Record<string, unknown>) => ({ ...EXAMPLE_FINDING, ...patch });
  const IGNORE = { reason: "Not reachable", until: "2026-12-01T00:00:00.000Z", by: "key_0123456789abcdef01234567" };

  it("parses the documented example unchanged", () => {
    const parsed: Finding = FindingSchema.parse(EXAMPLE_FINDING);
    expect(parsed).toEqual(EXAMPLE_FINDING);
    expect(Object.isFrozen(EXAMPLE_FINDING)).toBe(true);
  });

  it("describes the example advisory on the example Build", () => {
    expect(EXAMPLE_FINDING.advisory_id).toBe(EXAMPLE_ADVISORY.id);
    expect(EXAMPLE_FINDING.aliases).toEqual(EXAMPLE_ADVISORY.aliases);
    expect(EXAMPLE_FINDING.severity).toBe(severityOf(EXAMPLE_ADVISORY));
    expect(EXAMPLE_FINDING.fixed_versions).toEqual(fixedVersions(EXAMPLE_ADVISORY, EXAMPLE_FINDING.package));
    expect(isAffected(EXAMPLE_ADVISORY, EXAMPLE_FINDING.package, EXAMPLE_FINDING.version)).toBe(true);
  });

  it("requires a fnd id, an App id, an Environment, and npm package and version rules", () => {
    expect(ok(FindingSchema, finding({ id: "inc_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(FindingSchema, finding({ id: "fnd_0123" }))).toBe(false);
    expect(ok(FindingSchema, finding({ app_id: "org_89abcdef0123456789abcdef" }))).toBe(false);
    expect(ok(FindingSchema, finding({ environment: "qa" }))).toBe(false);
    expect(ok(FindingSchema, finding({ package: "Bad Name" }))).toBe(false);
    expect(ok(FindingSchema, finding({ version: "^1.0.0" }))).toBe(false);
    expect(ok(FindingSchema, finding({ severity: "info" }))).toBe(false);
    expect(ok(FindingSchema, finding({ fixed_versions: ["abc"] }))).toBe(false);
  });

  it("names a Build exactly when the source is build", () => {
    expect(ok(FindingSchema, finding({ source: "runtime", build_id: null }))).toBe(true);
    expect(ok(FindingSchema, finding({ source: "runtime" }))).toBe(false);
    expect(ok(FindingSchema, finding({ source: "build", build_id: null }))).toBe(false);
    expect(ok(FindingSchema, finding({ build_id: "bld_0123" }))).toBe(false);
    expect(ok(FindingSchema, finding({ source: "ci" }))).toBe(false);
  });

  it("carries an ignore exactly when the status is ignored", () => {
    expect(ok(FindingSchema, finding({ status: "ignored", ignore: IGNORE }))).toBe(true);
    expect(ok(FindingSchema, finding({ status: "ignored", ignore: null }))).toBe(false);
    expect(ok(FindingSchema, finding({ status: "open", ignore: IGNORE }))).toBe(false);
    expect(ok(FindingSchema, finding({ status: "fixed" }))).toBe(true);
    // D-060: the advisory no longer covers the version (withdrawn or narrowed); never ignored.
    expect(ok(FindingSchema, finding({ status: "withdrawn" }))).toBe(true);
    expect(ok(FindingSchema, finding({ status: "withdrawn", ignore: IGNORE }))).toBe(false);
    expect(ok(FindingSchema, finding({ status: "ignored", ignore: { ...IGNORE, by: "aro_x" } }))).toBe(false);
    expect(ok(FindingSchema, finding({ status: "ignored", ignore: { ...IGNORE, reason: "" } }))).toBe(false);
    const { ignore: _ignore, ...withoutIgnore } = EXAMPLE_FINDING;
    expect(ok(FindingSchema, withoutIgnore)).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = FindingSchema.parse(finding({ organization_id: "org_0123456789abcdef01234567" }));
    expect(parsed).toEqual(EXAMPLE_FINDING);
    expect(parsed).not.toHaveProperty("organization_id");
  });
});

describe("Finding responses and the ignore request", () => {
  it("wraps a list of at most 200 Findings", () => {
    expect(ListFindingsResponseSchema.parse({ findings: [EXAMPLE_FINDING] }).findings).toEqual([EXAMPLE_FINDING]);
    const many = (count: number) => ({ findings: Array.from({ length: count }, () => EXAMPLE_FINDING) });
    expect(ok(ListFindingsResponseSchema, many(EXPOSURE_LIMITS.findingsListed))).toBe(true);
    expect(ok(ListFindingsResponseSchema, many(EXPOSURE_LIMITS.findingsListed + 1))).toBe(false);
  });

  it("returns a Finding with its advisory on the detail, and alone after ignore or reopen", () => {
    const detail = FindingDetailResponseSchema.parse({ finding: EXAMPLE_FINDING, advisory: EXAMPLE_ADVISORY });
    expect(detail).toEqual({ finding: EXAMPLE_FINDING, advisory: EXAMPLE_ADVISORY });
    expect(ok(FindingDetailResponseSchema, { finding: EXAMPLE_FINDING })).toBe(false);
    expect(FindingResponseSchema.parse({ finding: EXAMPLE_FINDING }).finding).toEqual(EXAMPLE_FINDING);
  });

  it("takes a trimmed reason of 1..200 characters and an ISO until", () => {
    const parsed: IgnoreFindingRequest = IgnoreFindingRequestSchema.parse({
      reason: "  Not reachable  ",
      until: "2026-12-01T00:00:00.000Z",
    });
    expect(parsed).toEqual({ reason: "Not reachable", until: "2026-12-01T00:00:00.000Z" });
    expect(ok(IgnoreFindingRequestSchema, { reason: "   ", until: "2026-12-01T00:00:00.000Z" })).toBe(false);
    expect(ok(IgnoreFindingRequestSchema, { reason: "x".repeat(200), until: "2026-12-01T00:00:00.000Z" })).toBe(true);
    expect(ok(IgnoreFindingRequestSchema, { reason: "x".repeat(201), until: "2026-12-01T00:00:00.000Z" })).toBe(false);
    expect(ok(IgnoreFindingRequestSchema, { reason: "a\u0000b", until: "2026-12-01T00:00:00.000Z" })).toBe(false);
    expect(ok(IgnoreFindingRequestSchema, { reason: "ok", until: "next week" })).toBe(false);
    expect(ok(IgnoreFindingRequestSchema, { reason: "ok" })).toBe(false);
  });
});

describe("FindingsSummarySchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: FindingsSummary = FindingsSummarySchema.parse(EXAMPLE_FINDINGS_SUMMARY);
    expect(parsed).toEqual(EXAMPLE_FINDINGS_SUMMARY);
    expect(Object.isFrozen(EXAMPLE_FINDINGS_SUMMARY)).toBe(true);
  });

  it("counts open Findings per severity and lists at most 50 items", () => {
    const item = EXAMPLE_FINDINGS_SUMMARY.items[0];
    const summary = (count: number) => ({
      ...EXAMPLE_FINDINGS_SUMMARY,
      items: Array.from({ length: count }, () => item),
    });
    expect(ok(FindingsSummarySchema, summary(EXPOSURE_LIMITS.summaryItemsMax))).toBe(true);
    expect(ok(FindingsSummarySchema, summary(EXPOSURE_LIMITS.summaryItemsMax + 1))).toBe(false);
    const { unknown: _unknown, ...missing } = EXAMPLE_FINDINGS_SUMMARY.open;
    expect(ok(FindingsSummarySchema, { ...EXAMPLE_FINDINGS_SUMMARY, open: missing })).toBe(false);
    expect(
      ok(FindingsSummarySchema, { ...EXAMPLE_FINDINGS_SUMMARY, open: { ...EXAMPLE_FINDINGS_SUMMARY.open, low: -1 } }),
    ).toBe(false);
    expect(ok(FindingsSummarySchema, { ...EXAMPLE_FINDINGS_SUMMARY, items: [{ ...item, severity: "info" }] })).toBe(
      false,
    );
  });
});
