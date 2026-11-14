// @vitest-environment node
import { BuildSchema, EXAMPLE_BUILD, IncidentDetailResponseSchema } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { integrityFilesOf, makeTamperIncident } from "../scripts/stub-tamper.mjs";

// The stand-in API answers a "Tampered Build" Incident (slice 21a) in the shape of the protocol: the Console is
// looked at against the same contract the real API serves.

const app = { id: EXAMPLE_BUILD.app_id, environment: "development" };
const build = {
  ...EXAMPLE_BUILD,
  artifacts: [
    { path: "dist/index.js", sha256: "a".repeat(64), bytes: 10 },
    { path: "dist/vendor.js", sha256: "b".repeat(64), bytes: 20 },
  ],
};
let n = 0;
const newId = (prefix: string) => `${prefix}_${String(++n).padStart(24, "0")}`;
const END = Date.parse("2026-11-14T10:00:00.000Z");

describe("stub: a Tampered Build Incident", () => {
  it("is a valid Incident detail: one Incident of the Build, one Detection per report, no evidence and no Actors", () => {
    const entry = makeTamperIncident(app, {
      build,
      path: "dist/vendor.js",
      status: "open",
      reports: [
        { origin: "https://shop.example", prefix: "198.51.100.0/24" },
        { origin: "https://www.shop.example", prefix: null },
      ],
      endMs: END,
      gapMs: 60_000,
      newId,
    });
    const parsed = IncidentDetailResponseSchema.parse({ ...entry, containments: [] });
    expect(parsed).toEqual({ ...entry, containments: [] });
    expect(parsed.incident).toMatchObject({
      rule: "tampered-build",
      title: "Tampered Build",
      severity: "high",
      build_id: build.build_id,
      ip_prefix: null,
      origin: null,
      artifact_path: "dist/vendor.js",
      detection_count: 2,
      detections_capped: false,
    });
    expect(parsed.detections.map((d) => [d.artifact_path, d.origin, d.ip_prefix])).toEqual([
      ["dist/vendor.js", "https://shop.example", "198.51.100.0/24"],
      ["dist/vendor.js", "https://www.shop.example", null],
    ]);
    // The observed hash is the opening report's, and never the registered digest.
    expect(parsed.incident.observed_sha256).toBe(parsed.detections[0]?.observed_sha256);
    expect(parsed.incident.observed_sha256).not.toBe("b".repeat(64));
    expect(parsed.evidence).toEqual([]);
    expect(parsed.actors).toEqual([]);
  });

  it("lists a Build's artifact paths as its integrity marker's files, a valid Build", () => {
    expect(integrityFilesOf(build)).toEqual({ files: ["dist/index.js", "dist/vendor.js"] });
    expect(BuildSchema.parse({ ...build, integrity: integrityFilesOf(build) }).integrity?.files).toHaveLength(2);
  });
});
