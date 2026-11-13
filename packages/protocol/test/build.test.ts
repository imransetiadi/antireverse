import { describe, expect, it } from "vitest";
import {
  ArtifactDigestSchema,
  BUILD_LIMITS,
  type Build,
  BuildCanarySummarySchema,
  type BuildCosts,
  BuildCostsSchema,
  type BuildManifest,
  BuildManifestSchema,
  BuildResponseSchema,
  BuildSchema,
  CANARY_LIMITS,
  EXAMPLE_BUILD,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_CANARIES,
  EXAMPLE_FINDINGS_SUMMARY,
  EXAMPLE_INVENTORY,
  EXAMPLE_LOGIC,
  EXAMPLE_ROUTE_INVENTORY,
  EXPOSURE_LIMITS,
  ListBuildsResponseSchema,
  LOGIC_LIMITS,
  PROFILES,
  type Profile,
  RegisterBuildRequestSchema,
  ROUTE_LIMITS,
  type TransformSummary,
  TransformSummarySchema,
} from "../src/index.ts";

const manifest = (patch: Record<string, unknown>) => ({ ...EXAMPLE_BUILD_MANIFEST, ...patch });
const accepts = (value: unknown): boolean => BuildManifestSchema.safeParse(value).success;
const digest = { path: "dist/index.js", sha256: "a".repeat(64), bytes: 10 };
const digestsOf = (count: number) => Array.from({ length: count }, () => digest);

describe("build constants", () => {
  it("has the limits of contract P1", () => {
    expect(BUILD_LIMITS).toEqual({ artifactsMax: 1000, manifestBytesMax: 262_144, versionMax: 64, listed: 50 });
  });

  it("lists the profiles from lightest to heaviest", () => {
    const profile: Profile = "balanced";
    expect(PROFILES).toEqual(["light", profile, "maximum"]);
  });
});

describe("ArtifactDigestSchema", () => {
  it("parses a documented artifact unchanged", () => {
    expect(ArtifactDigestSchema.parse(digest)).toEqual(digest);
  });

  it("limits path to 1..256 storable characters", () => {
    expect(ArtifactDigestSchema.safeParse({ ...digest, path: "a".repeat(256) }).success).toBe(true);
    expect(ArtifactDigestSchema.safeParse({ ...digest, path: "a".repeat(257) }).success).toBe(false);
    expect(ArtifactDigestSchema.safeParse({ ...digest, path: "" }).success).toBe(false);
    expect(ArtifactDigestSchema.safeParse({ ...digest, path: "dist/\u0000.js" }).success).toBe(false);
  });

  it("requires sha256 to be 64 lowercase hex characters", () => {
    expect(ArtifactDigestSchema.safeParse({ ...digest, sha256: "A".repeat(64) }).success).toBe(false);
    expect(ArtifactDigestSchema.safeParse({ ...digest, sha256: "a".repeat(63) }).success).toBe(false);
    expect(ArtifactDigestSchema.safeParse({ ...digest, sha256: "a".repeat(65) }).success).toBe(false);
  });

  it("requires bytes to be an integer of at least 0", () => {
    expect(ArtifactDigestSchema.safeParse({ ...digest, bytes: 0 }).success).toBe(true);
    expect(ArtifactDigestSchema.safeParse({ ...digest, bytes: -1 }).success).toBe(false);
    expect(ArtifactDigestSchema.safeParse({ ...digest, bytes: 1.5 }).success).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = ArtifactDigestSchema.parse({ ...digest, content: "synthetic" });
    expect(parsed).toEqual(digest);
    expect(parsed).not.toHaveProperty("content");
  });
});

describe("TransformSummarySchema", () => {
  it("parses the documented summary unchanged", () => {
    const summary: TransformSummary = EXAMPLE_BUILD_MANIFEST.transform;
    expect(TransformSummarySchema.parse(summary)).toEqual(summary);
  });

  it("requires non-negative integer counts and a boolean integrity flag", () => {
    const base = { mangled: 1, strings_encrypted: 1, files_mangle_only: 0, integrity: false };
    expect(TransformSummarySchema.safeParse(base).success).toBe(true);
    expect(TransformSummarySchema.safeParse({ ...base, mangled: -1 }).success).toBe(false);
    expect(TransformSummarySchema.safeParse({ ...base, strings_encrypted: 1.5 }).success).toBe(false);
    expect(TransformSummarySchema.safeParse({ ...base, integrity: "no" }).success).toBe(false);
  });
});

describe("BuildCostsSchema", () => {
  it("allows a measured or an unmeasured run overhead", () => {
    const measured: BuildCosts = { size_overhead_pct: 12.5, run_overhead_pct: 3.2 };
    expect(BuildCostsSchema.parse(measured)).toEqual(measured);
    expect(BuildCostsSchema.parse({ size_overhead_pct: 0, run_overhead_pct: null })).toEqual({
      size_overhead_pct: 0,
      run_overhead_pct: null,
    });
  });

  it("requires a size overhead number", () => {
    expect(BuildCostsSchema.safeParse({ size_overhead_pct: "x", run_overhead_pct: null }).success).toBe(false);
    expect(BuildCostsSchema.safeParse({ run_overhead_pct: null }).success).toBe(false);
  });
});

describe("BuildManifestSchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: BuildManifest = BuildManifestSchema.parse(EXAMPLE_BUILD_MANIFEST);
    expect(parsed).toEqual(EXAMPLE_BUILD_MANIFEST);
  });

  it("requires format to be the literal 1", () => {
    expect(accepts(manifest({ format: 2 }))).toBe(false);
    expect(accepts(manifest({ format: "1" }))).toBe(false);
  });

  it("requires build_id to match bld_<24 hex>", () => {
    expect(accepts(manifest({ build_id: "bld_0123456789abcdef01234567" }))).toBe(true);
    expect(accepts(manifest({ build_id: "app_0123456789abcdef01234567" }))).toBe(false);
    expect(accepts(manifest({ build_id: "bld_0123" }))).toBe(false);
    expect(accepts(manifest({ build_id: "bld_0123456789ABCDEF01234567" }))).toBe(false);
  });

  it("requires a known App id and Environment", () => {
    expect(accepts(manifest({ app_id: "acme" }))).toBe(false);
    expect(accepts(manifest({ app_id: "org_89abcdef0123456789abcdef" }))).toBe(false);
    expect(accepts(manifest({ environment: "qa" }))).toBe(false);
  });

  it("limits version to 1..64 storable characters", () => {
    expect(accepts(manifest({ version: "a".repeat(64) }))).toBe(true);
    expect(accepts(manifest({ version: "a".repeat(65) }))).toBe(false);
    expect(accepts(manifest({ version: "" }))).toBe(false);
  });

  it("requires a known profile", () => {
    for (const profile of PROFILES) expect(accepts(manifest({ profile }))).toBe(true);
    expect(accepts(manifest({ profile: "paranoid" }))).toBe(false);
  });

  it("requires seed_id to be 16 lowercase hex characters", () => {
    expect(accepts(manifest({ seed_id: "0123456789abcdef" }))).toBe(true);
    expect(accepts(manifest({ seed_id: "0123456789ABCDEF" }))).toBe(false);
    expect(accepts(manifest({ seed_id: "0123" }))).toBe(false);
  });

  it("accepts 1..1000 artifacts and rejects 0 and 1001", () => {
    expect(accepts(manifest({ artifacts: digestsOf(1) }))).toBe(true);
    expect(accepts(manifest({ artifacts: digestsOf(1000) }))).toBe(true);
    expect(accepts(manifest({ artifacts: digestsOf(0) }))).toBe(false);
    expect(accepts(manifest({ artifacts: digestsOf(1001) }))).toBe(false);
  });

  it("limits equivalence to passed or skipped", () => {
    expect(accepts(manifest({ equivalence: "passed" }))).toBe(true);
    expect(accepts(manifest({ equivalence: "skipped" }))).toBe(true);
    expect(accepts(manifest({ equivalence: "failed" }))).toBe(false);
  });

  it("requires created_at to be a bounded ISO-8601 UTC datetime", () => {
    expect(accepts(manifest({ created_at: new Date(Date.UTC(2026, 0, 1)).toISOString() }))).toBe(true);
    expect(accepts(manifest({ created_at: "soon" }))).toBe(false);
    expect(accepts(manifest({ created_at: "2026-11-10T08:30:00+07:00" }))).toBe(false);
    expect(accepts(manifest({ created_at: new Date(Date.UTC(1999, 0, 1)).toISOString() }))).toBe(false);
  });

  it("does not add a byte check (the API enforces Manifest size)", () => {
    const big = manifest({ artifacts: digestsOf(1000) });
    expect(JSON.stringify(big).length).toBeGreaterThan(BUILD_LIMITS.manifestBytesMax / 10);
    expect(accepts(big)).toBe(true);
  });

  it("strips unknown keys", () => {
    const parsed = BuildManifestSchema.parse(manifest({ seed: "synthetic", source: "synthetic" }));
    expect(parsed).toEqual(EXAMPLE_BUILD_MANIFEST);
    expect(parsed).not.toHaveProperty("seed");
    expect(parsed).not.toHaveProperty("source");
  });
});

describe("Build, request and response schemas", () => {
  it("parses the documented Build unchanged and carries a registered_at", () => {
    const parsed: Build = BuildSchema.parse(EXAMPLE_BUILD);
    expect(parsed).toEqual(EXAMPLE_BUILD);
    expect(parsed.registered_at).toBe(EXAMPLE_BUILD.registered_at);
  });

  it("the Build is the Manifest plus registered_at", () => {
    const { registered_at: _stamp, ...manifestPart } = EXAMPLE_BUILD;
    expect(manifestPart).toEqual(EXAMPLE_BUILD_MANIFEST);
  });

  it("wraps the Manifest for registration", () => {
    const parsed = RegisterBuildRequestSchema.parse({ manifest: EXAMPLE_BUILD_MANIFEST });
    expect(parsed.manifest).toEqual(EXAMPLE_BUILD_MANIFEST);
    expect(RegisterBuildRequestSchema.safeParse({ manifest: manifest({ build_id: "nope" }) }).success).toBe(false);
  });

  it("wraps a Build and a list of Builds", () => {
    expect(BuildResponseSchema.parse({ build: EXAMPLE_BUILD }).build).toEqual(EXAMPLE_BUILD);
    expect(ListBuildsResponseSchema.parse({ builds: [EXAMPLE_BUILD] }).builds).toEqual([EXAMPLE_BUILD]);
    expect(ListBuildsResponseSchema.parse({ builds: [] }).builds).toEqual([]);
  });
});

describe("leak_scan and canaries on the Manifest and the Build", () => {
  const leak_scan = { status: "suppressed", suppressed: 2 } as const;
  const canaries = EXAMPLE_CANARIES;
  const routeCanary = (n: number) => ({
    id: `cny_${n.toString(16).padStart(24, "0")}`,
    kind: "route",
    value: `/api/internal/${n.toString(36).padStart(8, "0")}/sync`,
  });

  it("leaves an older Manifest without them valid, and absent stays absent", () => {
    const parsed = BuildManifestSchema.parse(EXAMPLE_BUILD_MANIFEST);
    expect(parsed).not.toHaveProperty("leak_scan");
    expect(parsed).not.toHaveProperty("canaries");
    const build = BuildSchema.parse(EXAMPLE_BUILD);
    expect(build).not.toHaveProperty("leak_scan");
    expect(build).not.toHaveProperty("canaries");
  });

  it("round-trips a Manifest and a Build that carry them", () => {
    const withBoth: BuildManifest = { ...EXAMPLE_BUILD_MANIFEST, leak_scan, canaries: [...canaries] };
    const parsed = BuildManifestSchema.parse(JSON.parse(JSON.stringify(withBoth)));
    expect(parsed).toEqual(withBoth);
    const summaries = canaries.map(({ id, kind }) => ({ id, kind }));
    const build: Build = { ...EXAMPLE_BUILD, leak_scan, canaries: summaries };
    expect(BuildSchema.parse(JSON.parse(JSON.stringify(build)))).toEqual(build);
    expect(BuildResponseSchema.parse({ build }).build).toEqual(build);
  });

  it("returns a Build's Canaries as id and kind only: the decoy values never leave in a response", () => {
    const parsed = BuildSchema.parse({ ...EXAMPLE_BUILD, canaries: [...canaries] });
    expect(parsed.canaries).toEqual(canaries.map(({ id, kind }) => ({ id, kind })));
    expect(JSON.stringify(parsed)).not.toContain("/api/internal/");
    expect(BuildCanarySummarySchema.safeParse({ id: "cny_x", kind: "key" }).success).toBe(false);
    expect(BuildCanarySummarySchema.safeParse({ id: canaries[0]?.id, kind: "other" }).success).toBe(false);
    const first = { id: canaries[0]?.id, kind: canaries[0]?.kind };
    expect(BuildSchema.safeParse({ ...EXAMPLE_BUILD, canaries: [first, first] }).success).toBe(false);
  });

  it("validates leak_scan with the summary rules", () => {
    expect(accepts(manifest({ leak_scan: { status: "clean", suppressed: 0 } }))).toBe(true);
    expect(accepts(manifest({ leak_scan: { status: "clean", suppressed: 1 } }))).toBe(false);
    expect(accepts(manifest({ leak_scan: { status: "failed", suppressed: 0 } }))).toBe(false);
    expect(accepts(manifest({ leak_scan: null }))).toBe(false);
  });

  it("accepts 0..10 Canaries and rejects 11", () => {
    const of = (count: number) => Array.from({ length: count }, (_, n) => routeCanary(n));
    expect(accepts(manifest({ canaries: of(0) }))).toBe(true);
    expect(accepts(manifest({ canaries: of(CANARY_LIMITS.perBuild) }))).toBe(true);
    expect(accepts(manifest({ canaries: of(CANARY_LIMITS.perBuild + 1) }))).toBe(false);
  });

  it("rejects a Canary id listed twice and an invalid Canary", () => {
    const [first] = canaries;
    expect(accepts(manifest({ canaries: [first, first] }))).toBe(false);
    expect(accepts(manifest({ canaries: [{ ...first, value: "ak_live_short" }] }))).toBe(false);
    expect(accepts(manifest({ canaries: null }))).toBe(false);
  });

  it("strips unknown keys inside leak_scan and each Canary", () => {
    const parsed = BuildManifestSchema.parse(
      manifest({
        leak_scan: { ...leak_scan, findings: [{ value: "synthetic" }] },
        canaries: canaries.map((canary) => ({ ...canary, seed: 1 })),
      }),
    );
    expect(parsed.leak_scan).toEqual(leak_scan);
    expect(parsed.canaries).toEqual(canaries);
  });
});

describe("beacon on the Manifest and the Build (slice 10)", () => {
  const beacon = { token: "bcn_a5dd35b17f47a81a0532f99e", origins: ["https://shop.example.com"] };

  it("leaves a Manifest and a Build without a beacon valid, and absent stays absent", () => {
    expect(BuildManifestSchema.parse(EXAMPLE_BUILD_MANIFEST)).not.toHaveProperty("beacon");
    expect(BuildSchema.parse(EXAMPLE_BUILD)).not.toHaveProperty("beacon");
  });

  it("round-trips a Manifest that carries the token and the allowed origins", () => {
    const withBeacon: BuildManifest = { ...EXAMPLE_BUILD_MANIFEST, beacon };
    expect(BuildManifestSchema.parse(JSON.parse(JSON.stringify(withBeacon)))).toEqual(withBeacon);
    expect(RegisterBuildRequestSchema.parse({ manifest: withBeacon }).manifest.beacon).toEqual(beacon);
  });

  it("returns a Build's beacon as its origins only: the token is stripped", () => {
    const parsed = BuildSchema.parse({ ...EXAMPLE_BUILD, beacon });
    expect(parsed.beacon).toEqual({ origins: beacon.origins });
    expect(JSON.stringify(parsed)).not.toContain("bcn_");
    const build: Build = { ...EXAMPLE_BUILD, beacon: { origins: beacon.origins } };
    expect(BuildResponseSchema.parse({ build }).build).toEqual(build);
  });

  it("validates the Manifest beacon: token, 1..20 canonical non-local unique origins", () => {
    expect(accepts(manifest({ beacon: { ...beacon, token: "bcn_x" } }))).toBe(false);
    expect(accepts(manifest({ beacon: { origins: beacon.origins } }))).toBe(false);
    expect(accepts(manifest({ beacon: { ...beacon, origins: [] } }))).toBe(false);
    expect(accepts(manifest({ beacon: { ...beacon, origins: ["https://Shop.example.com"] } }))).toBe(false);
    expect(accepts(manifest({ beacon: { ...beacon, origins: ["http://localhost:3000"] } }))).toBe(false);
    expect(accepts(manifest({ beacon: null }))).toBe(false);
  });
});

describe("components beside the Manifest and findings on the registration response (slice 19)", () => {
  const components = EXAMPLE_INVENTORY.components;
  const DIGEST = "a".repeat(64);
  const withSummary = { ...EXAMPLE_BUILD_MANIFEST, components_digest: DIGEST, component_count: components.length };

  it("keeps a Manifest without a component digest valid, and absent stays absent", () => {
    const parsed = BuildManifestSchema.parse(EXAMPLE_BUILD_MANIFEST);
    expect(parsed).not.toHaveProperty("components_digest");
    expect(parsed).not.toHaveProperty("component_count");
  });

  it("carries the components' digest and count in the Manifest, never the list", () => {
    const parsed: BuildManifest = BuildManifestSchema.parse({ ...withSummary, components: [...components] });
    expect(parsed.components_digest).toBe(DIGEST);
    expect(parsed.component_count).toBe(3);
    expect(parsed).not.toHaveProperty("components");
    expect(accepts(manifest({ components_digest: "A".repeat(64) }))).toBe(false);
    expect(accepts(manifest({ components_digest: "a".repeat(63) }))).toBe(false);
    expect(accepts(manifest({ component_count: -1 }))).toBe(false);
    expect(accepts(manifest({ component_count: 1.5 }))).toBe(false);
    expect(accepts(manifest({ component_count: EXPOSURE_LIMITS.componentsMax }))).toBe(true);
    expect(accepts(manifest({ component_count: EXPOSURE_LIMITS.componentsMax + 1 }))).toBe(false);
  });

  it("sends the components beside the Manifest in the registration request: npm names, semver, dev flag", () => {
    const request = RegisterBuildRequestSchema.parse({ manifest: withSummary, components: [...components] });
    expect(request.components).toEqual(components);
    expect(request.manifest).toEqual(withSummary);
    expect(RegisterBuildRequestSchema.parse({ manifest: EXAMPLE_BUILD_MANIFEST })).not.toHaveProperty("components");
    const bad = (list: unknown[]) =>
      RegisterBuildRequestSchema.safeParse({ manifest: EXAMPLE_BUILD_MANIFEST, components: list });
    expect(bad([{ name: "Bad Name", version: "1.0.0", dev: false }]).success).toBe(false);
    expect(bad([{ name: "x", version: "file:../x", dev: false }]).success).toBe(false);
    expect(bad([components[0], components[0]]).success).toBe(false);
  });

  it("caps components at 5,000 (the 2 MB byte cap is the API's)", () => {
    const many = (count: number) =>
      Array.from({ length: count }, (_, index) => ({ name: `p${index}`, version: "1.0.0", dev: false }));
    const request = (count: number) => ({ manifest: EXAMPLE_BUILD_MANIFEST, components: many(count) });
    expect(RegisterBuildRequestSchema.safeParse(request(EXPOSURE_LIMITS.componentsMax)).success).toBe(true);
    expect(RegisterBuildRequestSchema.safeParse(request(EXPOSURE_LIMITS.componentsMax + 1)).success).toBe(false);
    expect(EXPOSURE_LIMITS.componentsBytesMax).toBe(2_097_152);
  });

  it("requires the Manifest's component_count to equal the components sent, when both are present", () => {
    const parse = (count: number | undefined, list: unknown[] | undefined) =>
      RegisterBuildRequestSchema.safeParse({
        manifest: count === undefined ? EXAMPLE_BUILD_MANIFEST : { ...withSummary, component_count: count },
        ...(list === undefined ? {} : { components: list }),
      });
    expect(parse(3, [...components]).success).toBe(true);
    expect(parse(2, [...components]).success).toBe(false);
    expect(parse(4, [...components]).success).toBe(false);
    expect(parse(undefined, [...components]).success).toBe(true);
    expect(parse(3, undefined).success).toBe(true);
    const mismatch = parse(2, [...components]);
    expect(mismatch.error?.issues.map((issue) => issue.path)).toEqual([["components"]]);
  });

  it("returns the count and digest with the Build, never the list, and an optional findings summary", () => {
    const build = BuildSchema.parse({ ...EXAMPLE_BUILD, ...withSummary, components: [...components] });
    expect(build.component_count).toBe(3);
    expect(build.components_digest).toBe(DIGEST);
    expect(build).not.toHaveProperty("components");
    expect(BuildResponseSchema.parse({ build: EXAMPLE_BUILD })).toEqual({ build: EXAMPLE_BUILD });
    const response = BuildResponseSchema.parse({ build: EXAMPLE_BUILD, findings: EXAMPLE_FINDINGS_SUMMARY });
    expect(response.findings).toEqual(EXAMPLE_FINDINGS_SUMMARY);
    expect(BuildResponseSchema.safeParse({ build: EXAMPLE_BUILD, findings: { open: {} } }).success).toBe(false);
    expect(
      ListBuildsResponseSchema.parse({ builds: [{ ...build, components: [...components] }] }).builds[0],
    ).not.toHaveProperty("components");
  });
});

describe("route inventory beside the Manifest (slice 12a)", () => {
  const routes = [...EXAMPLE_ROUTE_INVENTORY];
  const DIGEST = "b".repeat(64);
  const withRoutes = { ...EXAMPLE_BUILD_MANIFEST, routes_digest: DIGEST, route_count: routes.length };

  it("keeps a Manifest without a route digest valid, and absent stays absent", () => {
    const parsed = BuildManifestSchema.parse(EXAMPLE_BUILD_MANIFEST);
    expect(parsed).not.toHaveProperty("routes_digest");
    expect(parsed).not.toHaveProperty("route_count");
  });

  it("carries the routes' digest and count in the Manifest, never the list", () => {
    const parsed: BuildManifest = BuildManifestSchema.parse({ ...withRoutes, routes });
    expect(parsed.routes_digest).toBe(DIGEST);
    expect(parsed.route_count).toBe(routes.length);
    expect(parsed).not.toHaveProperty("routes");
    expect(accepts(manifest({ routes_digest: "B".repeat(64) }))).toBe(false);
    expect(accepts(manifest({ routes_digest: "b".repeat(63) }))).toBe(false);
    expect(accepts(manifest({ route_count: -1 }))).toBe(false);
    expect(accepts(manifest({ route_count: 1.5 }))).toBe(false);
    expect(accepts(manifest({ route_count: ROUTE_LIMITS.routesMax }))).toBe(true);
    expect(accepts(manifest({ route_count: ROUTE_LIMITS.routesMax + 1 }))).toBe(false);
  });

  it("sends the routes beside the Manifest in the registration request, optional", () => {
    const request = RegisterBuildRequestSchema.parse({ manifest: withRoutes, routes });
    expect(request.routes).toEqual(routes);
    expect(RegisterBuildRequestSchema.parse({ manifest: EXAMPLE_BUILD_MANIFEST })).not.toHaveProperty("routes");
    expect(RegisterBuildRequestSchema.safeParse({ manifest: withRoutes, routes: ["GET /a/"] }).success).toBe(false);
    expect(RegisterBuildRequestSchema.safeParse({ manifest: withRoutes, routes: ["GET /a", "get /a"] }).success).toBe(
      false,
    );
  });

  it("requires the Manifest's route_count to equal the routes sent, when both are present", () => {
    const parse = (count: number | undefined, list: string[] | undefined) =>
      RegisterBuildRequestSchema.safeParse({
        manifest: count === undefined ? EXAMPLE_BUILD_MANIFEST : { ...withRoutes, route_count: count },
        ...(list === undefined ? {} : { routes: list }),
      });
    expect(parse(routes.length, routes).success).toBe(true);
    expect(parse(routes.length + 1, routes).success).toBe(false);
    expect(parse(undefined, routes).success).toBe(true);
    expect(parse(routes.length, undefined).success).toBe(true);
    expect(parse(routes.length - 1, routes).error?.issues.map((issue) => issue.path)).toEqual([["routes"]]);
  });

  it("returns the count and digest with the Build, never the list", () => {
    const build = BuildSchema.parse({ ...EXAMPLE_BUILD, ...withRoutes, routes });
    expect(build.route_count).toBe(routes.length);
    expect(build).not.toHaveProperty("routes");
  });
});

describe("logic beside the Manifest (slice 12b)", () => {
  const logic = structuredClone(EXAMPLE_LOGIC);
  const DIGEST = "c".repeat(64);
  const count = logic.functions.length;
  const withLogic = { ...EXAMPLE_BUILD_MANIFEST, logic_digest: DIGEST, logic_count: count };

  it("keeps a Manifest without a logic digest valid, and absent stays absent", () => {
    const parsed = BuildManifestSchema.parse(EXAMPLE_BUILD_MANIFEST);
    expect(parsed).not.toHaveProperty("logic_digest");
    expect(parsed).not.toHaveProperty("logic_count");
  });

  it("carries the logic's digest and function count in the Manifest, never the functions", () => {
    const parsed: BuildManifest = BuildManifestSchema.parse({ ...withLogic, logic });
    expect(parsed.logic_digest).toBe(DIGEST);
    expect(parsed.logic_count).toBe(count);
    expect(parsed).not.toHaveProperty("logic");
    expect(accepts(manifest({ logic_digest: "C".repeat(64) }))).toBe(false);
    expect(accepts(manifest({ logic_digest: "c".repeat(63) }))).toBe(false);
    expect(accepts(manifest({ logic_count: 0 }))).toBe(false);
    expect(accepts(manifest({ logic_count: 1.5 }))).toBe(false);
    expect(accepts(manifest({ logic_count: 1 }))).toBe(true);
    expect(accepts(manifest({ logic_count: LOGIC_LIMITS.functionsMax }))).toBe(true);
    expect(accepts(manifest({ logic_count: LOGIC_LIMITS.functionsMax + 1 }))).toBe(false);
  });

  it("sends the logic file beside the Manifest in the registration request, optional and validated", () => {
    const request = RegisterBuildRequestSchema.parse({ manifest: withLogic, logic });
    expect(request.logic).toEqual(logic);
    expect(RegisterBuildRequestSchema.parse({ manifest: EXAMPLE_BUILD_MANIFEST })).not.toHaveProperty("logic");
    expect(RegisterBuildRequestSchema.safeParse({ manifest: withLogic, logic: { functions: [] } }).success).toBe(false);
    const short = { functions: [{ ...logic.functions[0], vectors: logic.functions[0]?.vectors.slice(0, 9) }] };
    expect(RegisterBuildRequestSchema.safeParse({ manifest: withLogic, logic: short }).success).toBe(false);
  });

  it("requires the Manifest's logic_count to equal the functions sent, when both are present", () => {
    const two = { functions: [logic.functions[0], { ...logic.functions[0], id: "other" }] };
    const parse = (manifestCount: number | undefined, file: unknown) =>
      RegisterBuildRequestSchema.safeParse({
        manifest: manifestCount === undefined ? EXAMPLE_BUILD_MANIFEST : { ...withLogic, logic_count: manifestCount },
        ...(file === undefined ? {} : { logic: file }),
      });
    expect(parse(1, logic).success).toBe(true);
    expect(parse(2, two).success).toBe(true);
    expect(parse(2, logic).success).toBe(false);
    expect(parse(undefined, logic).success).toBe(true);
    expect(parse(1, undefined).success).toBe(true);
    expect(parse(1, two).error?.issues.map((issue) => issue.path)).toEqual([["logic"]]);
  });

  it("returns the count and digest with the Build, never the functions", () => {
    const build = BuildSchema.parse({ ...EXAMPLE_BUILD, ...withLogic, logic });
    expect(build.logic_count).toBe(count);
    expect(build.logic_digest).toBe(DIGEST);
    expect(build).not.toHaveProperty("logic");
    expect(ListBuildsResponseSchema.parse({ builds: [{ ...build, logic }] }).builds[0]).not.toHaveProperty("logic");
  });
});
