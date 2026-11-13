import { createHash } from "node:crypto";
import { BuildManifestSchema } from "@antireverse/protocol";
import { deriveCanaries, seedId } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { buildManifest } from "../src/manifest.ts";

const BASE = {
  buildId: "bld_0123456789abcdef01234567",
  appId: "app_89abcdef0123456789abcdef",
  environment: "development" as const,
  version: "1.4.0",
  profile: "balanced" as const,
  seed: 1,
  transform: { mangled: 10, strings_encrypted: 4, files_mangle_only: 1, integrity: false },
  equivalence: "passed" as const,
};

describe("buildManifest", () => {
  it("produces a manifest that parses against BuildManifestSchema", () => {
    const manifest = buildManifest({
      ...BASE,
      artifacts: [{ path: "index.mjs", code: "export const a = 1;" }],
      originals: { "index.mjs": "export const a = 1;" },
    });
    expect(() => BuildManifestSchema.parse(manifest)).not.toThrow();
  });

  it("computes sha256 and bytes per artifact from the protected code", () => {
    const code = "export const a = 1;\n";
    const manifest = buildManifest({
      ...BASE,
      artifacts: [{ path: "index.mjs", code }],
      originals: { "index.mjs": code },
    });
    const art = manifest.artifacts[0];
    expect(art?.path).toBe("index.mjs");
    expect(art?.bytes).toBe(Buffer.byteLength(code));
    expect(art?.sha256).toBe(createHash("sha256").update(code).digest("hex"));
  });

  it("uses the protocol seedId (fingerprint, never the seed value)", () => {
    const manifest = buildManifest({
      ...BASE,
      artifacts: [{ path: "a.mjs", code: "const a=1;" }],
      originals: { "a.mjs": "const a=1;" },
    });
    expect(manifest.seed_id).toBe(seedId(String(BASE.seed)));
    expect(manifest.seed_id).toMatch(/^[0-9a-f]{16}$/);
    // The fingerprint is not the seed value itself.
    expect(manifest.seed_id).not.toBe(String(BASE.seed));
    expect(seedId("1")).not.toBe(seedId("2"));
  });

  it("computes a gzip size overhead and leaves run overhead null when not measured", () => {
    const original = `export const s = "${"x".repeat(500)}";`;
    const bigger = `export const s = "${"x".repeat(1500)}";`;
    const manifest = buildManifest({
      ...BASE,
      artifacts: [{ path: "a.mjs", code: bigger }],
      originals: { "a.mjs": original },
    });
    expect(manifest.costs.size_overhead_pct).toBeGreaterThan(0);
    expect(manifest.costs.run_overhead_pct).toBeNull();
  });

  it("carries the equivalence result and created_at", () => {
    const manifest = buildManifest({
      ...BASE,
      equivalence: "skipped",
      artifacts: [{ path: "a.mjs", code: "const a=1;" }],
      originals: { "a.mjs": "const a=1;" },
    });
    expect(manifest.equivalence).toBe("skipped");
    expect(manifest.created_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("carries the leak-scan summary and the Canaries when given (slice 07), and parses", () => {
    const canaries = deriveCanaries(1);
    const manifest = buildManifest({
      ...BASE,
      artifacts: [{ path: "a.mjs", code: "const a=1;" }],
      originals: { "a.mjs": "const a=1;" },
      leakScan: { status: "suppressed", suppressed: 2 },
      canaries,
    });
    expect(manifest.leak_scan).toEqual({ status: "suppressed", suppressed: 2 });
    expect(manifest.canaries).toEqual(canaries);
    expect(BuildManifestSchema.parse(manifest)).toEqual(manifest);
  });

  it("omits leak_scan and canaries when not given (older shape)", () => {
    const manifest = buildManifest({
      ...BASE,
      artifacts: [{ path: "a.mjs", code: "const a=1;" }],
    });
    expect("leak_scan" in manifest).toBe(false);
    expect("canaries" in manifest).toBe(false);
  });

  it("carries route_count and routes_digest when given (slice 12a), never the routes, and parses", () => {
    const manifest = buildManifest({
      ...BASE,
      artifacts: [{ path: "a.mjs", code: "const a=1;" }],
      routes: { count: 5, digest: "a".repeat(64) },
    });
    expect(manifest.route_count).toBe(5);
    expect(manifest.routes_digest).toBe("a".repeat(64));
    expect("routes" in manifest).toBe(false);
    expect(BuildManifestSchema.parse(manifest)).toEqual(manifest);
  });

  it("carries logic_count and logic_digest when given (slice 12b), never the logic file, and parses", () => {
    const manifest = buildManifest({
      ...BASE,
      artifacts: [{ path: "a.mjs", code: "const a=1;" }],
      logic: { count: 2, digest: "b".repeat(64) },
    });
    expect(manifest.logic_count).toBe(2);
    expect(manifest.logic_digest).toBe("b".repeat(64));
    expect("logic" in manifest).toBe(false);
    expect(BuildManifestSchema.parse(manifest)).toEqual(manifest);
  });

  it("omits logic_count and logic_digest when no logic file is given", () => {
    const manifest = buildManifest({ ...BASE, artifacts: [{ path: "a.mjs", code: "const a=1;" }] });
    expect("logic_count" in manifest).toBe(false);
    expect("logic_digest" in manifest).toBe(false);
  });

  it("omits route_count and routes_digest when no inventory is given", () => {
    const manifest = buildManifest({ ...BASE, artifacts: [{ path: "a.mjs", code: "const a=1;" }] });
    expect("route_count" in manifest).toBe(false);
    expect("routes_digest" in manifest).toBe(false);
  });
});
