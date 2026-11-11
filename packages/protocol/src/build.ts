// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { BuildBeaconSchema, ManifestBeaconSchema } from "./beacon.ts";
import { BuildCanarySummarySchema, CANARY_LIMITS, CanarySchema, LeakScanSummarySchema } from "./canaries.ts";
import { ENVIRONMENTS, ID_PATTERNS } from "./constants.ts";
import { ComponentListSchema, EXPOSURE_LIMITS, FindingsSummarySchema } from "./exposure.ts";
import { deepFreeze, isoDateTime, text } from "./shared.ts";

// The Build contract: a Manifest the harden CLI produces and sends with `--register`, and the Build the API
// stores and returns. Every object schema is a plain `z.object`, which strips unknown keys. The Manifest
// carries no source and no secret: only per-artifact digests, transform counts, costs and the seed's
// fingerprint (`seed_id`, not the seed value), plus, from slice 07, the leak-scan summary and the Build's
// Canaries (decoy values, not secrets), and from slice 10 the Clone Beacon (token and allowed origins). The serialised Manifest is capped at 256 KB by the API, not
// here: a byte bound belongs where the body is read.

export const BUILD_LIMITS = {
  /** Artifacts a Manifest may list. */
  artifactsMax: 1000,
  /** Bytes of a serialised Manifest. Enforced by the API, not by `BuildManifestSchema`. */
  manifestBytesMax: 262_144,
  /** Characters of a Build version. */
  versionMax: 64,
  /** Builds returned by the Build list. */
  listed: 50,
} as const;

/** The protection profiles, from lightest to heaviest. */
export const PROFILES = ["light", "balanced", "maximum"] as const;
export type Profile = (typeof PROFILES)[number];

const AppIdSchema = z.string().regex(ID_PATTERNS.app);
const BuildIdSchema = z.string().regex(ID_PATTERNS.bld);
const EnvironmentSchema = z.enum(ENVIRONMENTS);
/** The first 16 hex characters of the SHA-256 of the seed value (`seedId` of the server entry). */
const SeedIdSchema = z.string().regex(/^[0-9a-f]{16}$/);
const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const CountSchema = z.int().min(0);

/** One artifact of a Build: its path, the SHA-256 of its bytes, and its size. Never its content. */
export const ArtifactDigestSchema = z.object({
  path: text(256).min(1),
  sha256: Sha256Schema,
  bytes: CountSchema,
});
export type ArtifactDigest = z.infer<typeof ArtifactDigestSchema>;

/** Counts of what each pass did, and whether the opt-in integrity pass ran. */
export const TransformSummarySchema = z.object({
  mangled: CountSchema,
  strings_encrypted: CountSchema,
  files_mangle_only: CountSchema,
  integrity: z.boolean(),
});
export type TransformSummary = z.infer<typeof TransformSummarySchema>;

/** The measured cost of the protection. `run_overhead_pct` is null when runtime was not measured. */
export const BuildCostsSchema = z.object({
  size_overhead_pct: z.number(),
  run_overhead_pct: z.number().nullable(),
});
export type BuildCosts = z.infer<typeof BuildCostsSchema>;

/** The Manifest the harden CLI builds and sends with `--register`. It holds no source and no secret. */
export const BuildManifestSchema = z.object({
  format: z.literal(1),
  build_id: BuildIdSchema,
  app_id: AppIdSchema,
  environment: EnvironmentSchema,
  /** The developer's own version string, not a monotonic number. */
  version: text(BUILD_LIMITS.versionMax).min(1),
  profile: z.enum(PROFILES),
  /** The seed's fingerprint, not the seed: it names the seed without revealing it. */
  seed_id: SeedIdSchema,
  artifacts: z.array(ArtifactDigestSchema).min(1).max(BUILD_LIMITS.artifactsMax),
  transform: TransformSummarySchema,
  costs: BuildCostsSchema,
  /** Whether the equivalence gate passed, or was skipped (no test command). */
  equivalence: z.enum(["passed", "skipped"]),
  created_at: isoDateTime(),
  /** The leak scan's outcome. Optional: a Manifest from before slice 07 has none, and absent stays absent. */
  leak_scan: LeakScanSummarySchema.optional(),
  /** The Canaries planted in this Build, each id once. Optional, as `leak_scan`. */
  canaries: z
    .array(CanarySchema)
    .max(CANARY_LIMITS.perBuild)
    .refine((canaries) => new Set(canaries.map((canary) => canary.id)).size === canaries.length, {
      message: "Must not list a Canary id twice.",
    })
    .optional(),
  /** The Clone Beacon planted in this Build: its token and the allowed origins. Optional, as `leak_scan`. */
  beacon: ManifestBeaconSchema.optional(),
  /**
   * The project's lockfile packages in summary (slice 19): `componentsDigest` (server entry) of the list sent
   * beside the Manifest, and its length. The list itself never goes into the Manifest or a Build response.
   * Optional, as `leak_scan`.
   */
  components_digest: Sha256Schema.optional(),
  component_count: z.int().min(0).max(EXPOSURE_LIMITS.componentsMax).optional(),
});
export type BuildManifest = z.infer<typeof BuildManifestSchema>;

/**
 * Body of `POST /v1/apps/:appId/builds`: the Manifest the CLI built and, from slice 19, the lockfile's
 * components beside it (at most 5,000; at most `EXPOSURE_LIMITS.componentsBytesMax` serialised, checked by the
 * API). When both are present, the Manifest's `component_count` must equal the list's length. That
 * `components_digest` equals `componentsDigest(components)` is the API's check: hashing needs node:crypto,
 * which this isomorphic module must not import.
 */
export const RegisterBuildRequestSchema = z
  .object({ manifest: BuildManifestSchema, components: ComponentListSchema.optional() })
  .refine(
    (request) =>
      request.components === undefined ||
      request.manifest.component_count === undefined ||
      request.manifest.component_count === request.components.length,
    { message: "Must list as many components as the Manifest's component_count.", path: ["components"] },
  );
export type RegisterBuildRequest = z.infer<typeof RegisterBuildRequestSchema>;

/**
 * A Build as the API returns it: the Manifest plus the time the API stamped it, Canaries as id and kind, the
 * beacon as its origins only.
 */
export const BuildSchema = BuildManifestSchema.extend({
  registered_at: z.iso.datetime(),
  /** The Build's Canaries as id and kind: a value given here is stripped, never returned. */
  canaries: z
    .array(BuildCanarySummarySchema)
    .max(CANARY_LIMITS.perBuild)
    .refine((canaries) => new Set(canaries.map((canary) => canary.id)).size === canaries.length, {
      message: "Must not list a Canary id twice.",
    })
    .optional(),
  /** The Build's Clone Beacon as its allowed origins: a token given here is stripped, never returned. */
  beacon: BuildBeaconSchema.optional(),
});
export type Build = z.infer<typeof BuildSchema>;

/**
 * 201 of `POST` and 200 of `GET /v1/apps/:appId/builds/:buildId`. From slice 19 the 201 may carry the Build's
 * open Findings as a summary (`findings`), which the harden CLI's `--fail-on` gate reads; absent stays absent.
 */
export const BuildResponseSchema = z.object({ build: BuildSchema, findings: FindingsSummarySchema.optional() });
export type BuildResponse = z.infer<typeof BuildResponseSchema>;

/** 200 of `GET /v1/apps/:appId/builds`: newest first, at most `BUILD_LIMITS.listed`. */
export const ListBuildsResponseSchema = z.object({ builds: z.array(BuildSchema) });
export type ListBuildsResponse = z.infer<typeof ListBuildsResponseSchema>;

// Documented examples, reused by the tests of every workspace. They are synthetic and deeply frozen:
// build a variant by spreading, e.g. `{ ...EXAMPLE_BUILD_MANIFEST, profile: "light" }`.

/** A valid Manifest for the App of `EXAMPLE_POLICY`, balanced profile, one artifact over budget (mangle-only). */
export const EXAMPLE_BUILD_MANIFEST: BuildManifest = deepFreeze({
  format: 1,
  build_id: "bld_0123456789abcdef01234567",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  version: "1.4.0",
  profile: "balanced",
  seed_id: "0123456789abcdef",
  artifacts: [
    { path: "dist/index.js", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", bytes: 2048 },
  ],
  transform: { mangled: 42, strings_encrypted: 12, files_mangle_only: 1, integrity: false },
  costs: { size_overhead_pct: 12.5, run_overhead_pct: 3.2 },
  equivalence: "passed",
  created_at: "2026-11-10T08:30:00.000Z",
});

/** `EXAMPLE_BUILD_MANIFEST` as the API returns it after registration. */
export const EXAMPLE_BUILD: Build = deepFreeze({
  ...EXAMPLE_BUILD_MANIFEST,
  registered_at: "2026-11-10T08:30:01.000Z",
});
