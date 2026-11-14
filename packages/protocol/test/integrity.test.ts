import { describe, expect, it } from "vitest";
import {
  ATTESTATION_SIGNALS,
  AttestRequestSchema,
  BuildManifestSchema,
  BuildSchema,
  DETECTION_RULES,
  DetectionSchema,
  EXAMPLE_BUILD,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_CLONE_INCIDENT,
  EXAMPLE_DETECTION,
  EXAMPLE_INCIDENT,
  EXAMPLE_TAMPER_DETECTION,
  EXAMPLE_TAMPER_INCIDENT,
  INTEGRITY_LIMITS,
  INTEGRITY_SIGNAL,
  IncidentSchema,
  IntegrityReportSchema,
  RegisterBuildRequestSchema,
  verdictFor,
  WebhookAlertPayloadSchema,
} from "../src/index.ts";

// Slice 21a: the integrity marker's Manifest field, the report an attestation may carry, and the
// `tampered-build` rule with its two Detection fields.

const APP = "app_89abcdef0123456789abcdef";
const BUILD = "bld_0123456789abcdef01234567";
const HASH = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"; // sha256("") as base64url
const SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const base = {
  app_id: APP,
  nonce: "0123456789abcdef0123456789abcdef",
  device: "AAECAwQFBgcICQoLDA0ODw",
  signals: [],
  cnf: {
    jkt: "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s",
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    },
  },
};
const report = (patch: Record<string, unknown> = {}) => ({
  build: BUILD,
  files: [{ i: 0, h: HASH }],
  skipped: 0,
  ...patch,
});
const acceptsReport = (patch: Record<string, unknown>) => IntegrityReportSchema.safeParse(report(patch)).success;

describe("INTEGRITY_LIMITS and the signal id", () => {
  it("has the Clone Beacon numbers plus the daily cap per Build (D-100, review M1)", () => {
    expect(INTEGRITY_LIMITS).toEqual({
      filesMax: 32,
      reportsPerHour: 600,
      newHashesPerHour: 20,
      hashesPerDay: 50,
      recentBuilds: 20,
      recentDays: 30,
    });
    expect(Object.isFrozen(INTEGRITY_LIMITS)).toBe(true);
  });

  it("names the signal, which no client can assert", () => {
    expect(INTEGRITY_SIGNAL).toBe("tamper.integrity_mismatch");
    expect(ATTESTATION_SIGNALS as readonly string[]).not.toContain(INTEGRITY_SIGNAL);
    const parsed = AttestRequestSchema.parse({ ...base, signals: [INTEGRITY_SIGNAL, "automation.webdriver"] });
    expect(parsed.signals).toEqual(["automation.webdriver"]);
    expect(verdictFor([INTEGRITY_SIGNAL])).toEqual({ verdict: "trusted", risk: 5 });
  });
});

describe("the integrity report of an attestation", () => {
  it("is optional: a request of an older Guard parses as before", () => {
    const parsed = AttestRequestSchema.parse(base);
    expect(parsed).not.toHaveProperty("integrity");
  });

  it("carries the Build, up to 32 files by index with a base64url SHA-256, and the skipped count", () => {
    const parsed = AttestRequestSchema.parse({ ...base, integrity: report({ extra: 1 }) });
    expect(parsed.integrity).toEqual({ build: BUILD, files: [{ i: 0, h: HASH }], skipped: 0 });
  });

  it("bounds every member", () => {
    expect(acceptsReport({})).toBe(true);
    expect(acceptsReport({ files: [] })).toBe(true);
    expect(acceptsReport({ build: "bld_nope" })).toBe(false);
    expect(acceptsReport({ build: undefined })).toBe(false);
    expect(acceptsReport({ files: [{ i: -1, h: HASH }] })).toBe(false);
    expect(acceptsReport({ files: [{ i: 32, h: HASH }] })).toBe(false);
    expect(acceptsReport({ files: [{ i: 31, h: HASH }] })).toBe(true);
    expect(acceptsReport({ files: [{ i: 1.5, h: HASH }] })).toBe(false);
    expect(acceptsReport({ files: [{ i: 0, h: HASH.slice(1) }] })).toBe(false);
    expect(acceptsReport({ files: [{ i: 0, h: `${HASH}A` }] })).toBe(false);
    expect(acceptsReport({ files: [{ i: 0, h: SHA }] })).toBe(false);
    // 43 characters name 258 bits: the last one must leave the two spare bits zero (one spelling per hash).
    expect(acceptsReport({ files: [{ i: 0, h: `${HASH.slice(0, 42)}V` }] })).toBe(false);
    expect(acceptsReport({ files: [{ i: 0, h: `${HASH.slice(0, 42)}+` }] })).toBe(false);
    expect(acceptsReport({ skipped: -1 })).toBe(false);
    expect(acceptsReport({ skipped: 33 })).toBe(false);
    expect(acceptsReport({ skipped: 32 })).toBe(true);
    expect(acceptsReport({ skipped: undefined })).toBe(false);
  });

  it("takes at most 32 files, each index once", () => {
    const files = (n: number) => Array.from({ length: n }, (_, i) => ({ i: i % 32, h: HASH }));
    expect(acceptsReport({ files: files(32) })).toBe(true);
    expect(acceptsReport({ files: files(33) })).toBe(false);
    expect(
      acceptsReport({
        files: [
          { i: 3, h: HASH },
          { i: 3, h: HASH },
        ],
      }),
    ).toBe(false);
  });

  it("never fails the attestation: a malformed report is dropped, the request still parses", () => {
    for (const integrity of [report({ build: "nope" }), "x", 7, null, [], report({ files: [{ i: 99, h: HASH }] })]) {
      const parsed = AttestRequestSchema.safeParse({ ...base, integrity });
      expect(parsed.success).toBe(true);
      expect(parsed.data?.integrity).toBeUndefined();
    }
  });

  it("fits the 4 KB attestation body with 32 files", () => {
    const files = Array.from({ length: 32 }, (_, i) => ({ i, h: HASH }));
    const body = JSON.stringify({
      ...base,
      signals: [...ATTESTATION_SIGNALS],
      integrity: { build: BUILD, files, skipped: 32 },
    });
    expect(Buffer.byteLength(body)).toBeLessThanOrEqual(4096);
    expect(AttestRequestSchema.parse(JSON.parse(body)).integrity?.files).toHaveLength(32);
  });
});

describe("the Manifest's integrity field", () => {
  const manifest = (patch: Record<string, unknown>) => ({ ...EXAMPLE_BUILD_MANIFEST, ...patch });
  const paths = (n: number) => Array.from({ length: n }, (_, i) => `dist/f${i}.js`);
  const artifacts = (n: number) => paths(n).map((path) => ({ path, sha256: SHA, bytes: 1 }));

  it("is optional and absent stays absent", () => {
    expect(BuildManifestSchema.parse(EXAMPLE_BUILD_MANIFEST)).not.toHaveProperty("integrity");
    expect(BuildSchema.parse(EXAMPLE_BUILD)).not.toHaveProperty("integrity");
  });

  it("lists 0..32 distinct paths", () => {
    const accepts = (files: unknown) => BuildManifestSchema.safeParse(manifest({ integrity: { files } })).success;
    expect(accepts([])).toBe(true);
    expect(accepts(["dist/index.js"])).toBe(true);
    expect(accepts(paths(32))).toBe(true);
    expect(accepts(paths(33))).toBe(false);
    expect(accepts(["dist/index.js", "dist/index.js"])).toBe(false);
    expect(accepts([""])).toBe(false);
    expect(accepts(["a".repeat(257)])).toBe(false);
    expect(accepts("dist/index.js")).toBe(false);
    expect(BuildManifestSchema.safeParse(manifest({ integrity: {} })).success).toBe(false);
  });

  it("is returned with the Build", () => {
    const build = BuildSchema.parse({ ...EXAMPLE_BUILD, integrity: { files: ["dist/index.js"] } });
    expect(build.integrity).toEqual({ files: ["dist/index.js"] });
  });

  it("must name artifacts of the Manifest when a Build is registered", () => {
    const register = (files: string[], n = 3) =>
      RegisterBuildRequestSchema.safeParse({ manifest: manifest({ artifacts: artifacts(n), integrity: { files } }) });
    expect(register(["dist/f2.js", "dist/f0.js"]).success).toBe(true);
    expect(register([]).success).toBe(true);
    const refused = register(["dist/f0.js", "dist/other.js"]);
    expect(refused.success).toBe(false);
    expect(refused.error?.issues[0]?.path).toEqual(["manifest", "integrity", "files", 1]);
  });
});

describe("the tampered-build rule", () => {
  it("is High, threshold 1, window 3600 s", () => {
    expect(DETECTION_RULES.find((rule) => rule.key === "tampered-build")).toEqual({
      key: "tampered-build",
      title: "Tampered Build",
      severity: "high",
      threshold: 1,
      window_s: 3600,
    });
  });

  it("adds artifact_path and observed_sha256 to a Detection and an Incident, null for every other rule", () => {
    expect(EXAMPLE_DETECTION).toMatchObject({ artifact_path: null, observed_sha256: null });
    expect(EXAMPLE_INCIDENT).toMatchObject({ artifact_path: null, observed_sha256: null });
    expect(EXAMPLE_CLONE_INCIDENT).toMatchObject({ artifact_path: null, observed_sha256: null });
    expect(DetectionSchema.parse(EXAMPLE_TAMPER_DETECTION)).toEqual(EXAMPLE_TAMPER_DETECTION);
    expect(IncidentSchema.parse(EXAMPLE_TAMPER_INCIDENT)).toEqual(EXAMPLE_TAMPER_INCIDENT);
    expect(EXAMPLE_TAMPER_DETECTION).toMatchObject({
      rule: "tampered-build",
      artifact_path: "dist/index.js",
      origin: "https://shop.example",
      ip_prefix: "203.0.113.0/24",
    });
    expect(EXAMPLE_TAMPER_DETECTION.observed_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(EXAMPLE_TAMPER_INCIDENT).toMatchObject({
      rule: "tampered-build",
      title: "Tampered Build",
      severity: "high",
      build_id: BUILD,
      ip_prefix: null,
      origin: null,
      artifact_path: EXAMPLE_TAMPER_DETECTION.artifact_path,
      observed_sha256: EXAMPLE_TAMPER_DETECTION.observed_sha256,
    });
    expect(Object.isFrozen(EXAMPLE_TAMPER_INCIDENT)).toBe(true);
  });

  it("is additive: a Detection or Incident from before the slice parses, with null for both", () => {
    const { artifact_path: _a, observed_sha256: _b, ...oldDetection } = EXAMPLE_DETECTION;
    const { artifact_path: _c, observed_sha256: _d, ...oldIncident } = EXAMPLE_INCIDENT;
    expect(DetectionSchema.parse(oldDetection)).toEqual(EXAMPLE_DETECTION);
    expect(IncidentSchema.parse(oldIncident)).toEqual(EXAMPLE_INCIDENT);
    const payload = { type: "incident.opened", incident: oldIncident, console_url: "https://console.example/i" };
    expect(WebhookAlertPayloadSchema.parse(payload).incident).toEqual(EXAMPLE_INCIDENT);
  });

  it("says whether a cap hid distinct hashes: detections_capped, false when absent (additive)", () => {
    expect(EXAMPLE_INCIDENT.detections_capped).toBe(false);
    expect(EXAMPLE_TAMPER_INCIDENT.detections_capped).toBe(false);
    const { detections_capped: _capped, ...before } = EXAMPLE_TAMPER_INCIDENT;
    expect(IncidentSchema.parse(before)).toEqual(EXAMPLE_TAMPER_INCIDENT);
    expect(IncidentSchema.parse({ ...EXAMPLE_TAMPER_INCIDENT, detections_capped: true }).detections_capped).toBe(true);
    expect(IncidentSchema.safeParse({ ...EXAMPLE_TAMPER_INCIDENT, detections_capped: "yes" }).success).toBe(false);
  });

  it("a Build may say since when it is watched: integrity_first_match_at, null until armed, absent without a marker", () => {
    expect(BuildSchema.parse(EXAMPLE_BUILD)).not.toHaveProperty("integrity_first_match_at");
    const marked = { ...EXAMPLE_BUILD, integrity: { files: ["dist/index.js"] } };
    expect(BuildSchema.parse({ ...marked, integrity_first_match_at: null }).integrity_first_match_at).toBeNull();
    const at = "2026-11-14T12:00:00.000Z";
    expect(BuildSchema.parse({ ...marked, integrity_first_match_at: at }).integrity_first_match_at).toBe(at);
    expect(BuildSchema.safeParse({ ...marked, integrity_first_match_at: "soon" }).success).toBe(false);
    // The Manifest a CLI sends never carries it.
    expect(BuildManifestSchema.parse({ ...EXAMPLE_BUILD_MANIFEST, integrity_first_match_at: at })).not.toHaveProperty(
      "integrity_first_match_at",
    );
  });

  it("bounds the two fields", () => {
    const accepts = (patch: Record<string, unknown>) =>
      DetectionSchema.safeParse({ ...EXAMPLE_TAMPER_DETECTION, ...patch }).success;
    expect(accepts({ artifact_path: "a".repeat(256) })).toBe(true);
    expect(accepts({ artifact_path: "a".repeat(257) })).toBe(false);
    expect(accepts({ artifact_path: "" })).toBe(false);
    expect(accepts({ observed_sha256: SHA.toUpperCase() })).toBe(false);
    expect(accepts({ observed_sha256: HASH })).toBe(false);
  });

  it("travels in the webhook payload", () => {
    const payload = {
      type: "incident.opened",
      incident: EXAMPLE_TAMPER_INCIDENT,
      console_url: `https://console.example/incidents/${EXAMPLE_TAMPER_INCIDENT.id}`,
    };
    expect(WebhookAlertPayloadSchema.parse(payload).incident).toEqual(EXAMPLE_TAMPER_INCIDENT);
  });
});
