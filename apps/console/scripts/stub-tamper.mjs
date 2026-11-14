// The stand-in API's "Tampered Build" Incident (slice 21a), apart from stub-api.mjs so that a test can check its
// shape against the protocol. Pure: the caller passes the id generator and the times.
import { createHash } from "node:crypto";

const RULE = { key: "tampered-build", title: "Tampered Build", severity: "high" };

/** The Manifest's `integrity` of a stub Build: its marker lists every artifact, in the artifacts' order. */
export function integrityFilesOf(build) {
  return { files: build.artifacts.map((artifact) => artifact.path) };
}

/**
 * A Tampered Build Incident: `reports` integrity reports of `path` of `build`, `gapMs` apart, the last at `endMs`.
 * Each report is one Detection with the page's origin, the reporter's network (null when unknown) and an observed
 * hash that is not the registered one; the Incident has no network, no origin, no evidence and no Actors, and names
 * the file and the observed hash of its first Detection; `capped` says a cap dropped distinct hashes.
 */
export function makeTamperIncident(app, { build, path, status, reports, endMs, gapMs, newId, capped = false }) {
  const detections = reports.map((report, index) => {
    const at = endMs - (reports.length - 1 - index) * gapMs;
    return {
      id: newId("dtc"),
      rule: RULE.key,
      app_id: app.id,
      environment: app.environment,
      ip_prefix: report.prefix,
      count: 1,
      window_start: new Date(at).toISOString(),
      window_end: new Date(at).toISOString(),
      detected_at: new Date(at).toISOString(),
      canary_id: null,
      origin: report.origin,
      artifact_path: path,
      observed_sha256: createHash("sha256").update(`tampered:${build.build_id}:${path}:${index}`).digest("hex"),
    };
  });
  const first = detections[0];
  const last = detections.at(-1);
  const incident = {
    id: newId("inc"),
    app_id: app.id,
    environment: app.environment,
    rule: RULE.key,
    severity: RULE.severity,
    title: RULE.title,
    status,
    ip_prefix: null,
    first_seen: first.window_start,
    last_seen: last.window_end,
    detection_count: detections.length,
    created_at: first.detected_at,
    updated_at: last.detected_at,
    canary_id: null,
    build_id: build.build_id,
    origin: null,
    advisory_id: null,
    artifact_path: first.artifact_path,
    observed_sha256: first.observed_sha256,
    detections_capped: capped,
  };
  return { incident, detections, evidence: [], actors: [] };
}
