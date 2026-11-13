import { createHash } from "node:crypto";
import {
  ASSESSMENT_LIMITS,
  type Assessment,
  type AssessmentResponse,
  CreateAssessmentRequestSchema,
  type CreateAssessmentResponse,
  ID_PATTERNS,
  type ListAssessmentsResponse,
  type ProblemError,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import type { Assessor } from "../assess/assessor.ts";
import type { AssessmentQueue } from "../assess/runner.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { findApp } from "../stores/apps.ts";
import {
  type ArtifactFileInput,
  findAssessmentDetail,
  insertArtifact,
  insertAssessment,
  latestKeptArtifact,
  listAssessments,
  newArtifactId,
} from "../stores/assessments.ts";
import { findManifest } from "../stores/builds.ts";
import { validateJson } from "../validate.ts";

/**
 * Bytes of an Assessment request at most: the artifact's 25 MB as padded base64, plus each file's path (JSON escapes
 * at most 6 bytes per character) and member names, plus the tier and the braces.
 */
export const ASSESSMENT_BODY_BYTES_MAX =
  Math.ceil(ASSESSMENT_LIMITS.artifactBytesMax / 3) * 4 + ASSESSMENT_LIMITS.filesMax * (256 * 6 + 32) + 1024;

/** Proof of Ownership of uploaded files against the Manifest's artifacts: the errors, or the files to store. */
function proveOwnership(
  manifestArtifacts: readonly { path: string; sha256: string }[],
  files: readonly { path: string; base64: string }[],
): { errors: ProblemError[] } | { files: ArtifactFileInput[] } {
  const expected = new Map(manifestArtifacts.map((artifact) => [artifact.path, artifact.sha256]));
  const errors: ProblemError[] = [];
  const stored: ArtifactFileInput[] = [];
  files.forEach((file, index) => {
    const sha = expected.get(file.path);
    if (sha === undefined) {
      errors.push({ path: `files.${index}.path`, message: "Must be an artifact of the Build's Manifest." });
      return;
    }
    const content = Buffer.from(file.base64, "base64");
    const actual = createHash("sha256").update(content).digest("hex");
    if (actual !== sha) {
      errors.push({ path: `files.${index}.base64`, message: "Its SHA-256 must equal the Manifest's for this path." });
      return;
    }
    stored.push({ path: file.path, sha256: actual, content });
  });
  const sent = new Set(files.map((file) => file.path));
  const missing = [...expected.keys()].filter((path) => !sent.has(path)).length;
  if (missing > 0) {
    errors.push({ path: "files", message: `Must include every artifact of the Manifest (${missing} missing).` });
  }
  return errors.length > 0 ? { errors } : { files: stored };
}

export function assessmentRoutes(deps: {
  db: Db;
  assessor: Assessor;
  queue: AssessmentQueue;
  now?: (() => Date) | undefined;
}): Hono<AppEnv> {
  const { db, assessor, queue } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  // Requests an Assessment of a registered Build of the caller's Organization (slice 12a). With files: Proof of
  // Ownership — every file's SHA-256 equals the Manifest's entry for its path and every Manifest artifact is present —
  // then the files are kept as the Build's artifact. Without files: the Build's most recent kept artifact, or 409
  // `artifact-required`. 202 with the queued Assessment; the runner takes it from there.
  routes.post(
    "/v1/apps/:appId/builds/:buildId/assessments",
    admin,
    limitBody(ASSESSMENT_BODY_BYTES_MAX, "assessment-payload-too-large"),
    validateJson(CreateAssessmentRequestSchema),
    async (c) => {
      const { organizationId } = c.var.principal;
      const appId = c.req.param("appId");
      const buildId = c.req.param("buildId");
      const { tier, files } = c.req.valid("json");
      if (!ID_PATTERNS.app.test(appId) || !ID_PATTERNS.bld.test(buildId)) return problem(c, "not-found");
      const target = { organizationId, appId };

      const result = await db.tx({ organizationId }, async (q) => {
        if ((await findApp(q, appId)) === null) return "not-found" as const;
        const manifest = await findManifest(q, target, buildId);
        if (manifest === null) return "not-found" as const;
        const at = now();
        let artifactId: string;
        if (files === undefined) {
          const kept = await latestKeptArtifact(q, target, buildId, at);
          if (kept === null) return "artifact-required" as const;
          artifactId = kept;
        } else {
          const proof = proveOwnership(manifest.artifacts, files);
          if ("errors" in proof) return proof;
          artifactId = newArtifactId();
          await insertArtifact(q, { ...target, id: artifactId, buildId, files: proof.files, createdAt: at });
        }
        return insertAssessment(q, {
          ...target,
          id: newId("asm"),
          buildId,
          environment: manifest.environment,
          tier,
          scope: assessor.scope(tier),
          artifactId,
          createdAt: at,
        });
      });
      if (result === "not-found") return problem(c, "not-found");
      if (result === "artifact-required") return problem(c, "conflict", undefined, "artifact-required");
      if ("errors" in result) return problem(c, "validation", result.errors);
      queue.wake();
      return c.json({ assessment: result } satisfies CreateAssessmentResponse, 202);
    },
  );

  routes.get("/v1/apps/:appId/builds/:buildId/assessments", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const appId = c.req.param("appId");
    const buildId = c.req.param("buildId");
    if (!ID_PATTERNS.app.test(appId) || !ID_PATTERNS.bld.test(buildId)) return problem(c, "not-found");
    const target = { organizationId, appId };
    const assessments = await db.tx({ organizationId }, async (q): Promise<Assessment[] | null> => {
      if ((await findApp(q, appId)) === null || (await findManifest(q, target, buildId)) === null) return null;
      return listAssessments(q, target, buildId, ASSESSMENT_LIMITS.listed);
    });
    if (assessments === null) return problem(c, "not-found");
    return c.json({ assessments } satisfies ListAssessmentsResponse);
  });

  routes.get("/v1/assessments/:id", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const id = c.req.param("id");
    const found = ID_PATTERNS.asm.test(id) ? await db.tx({ organizationId }, (q) => findAssessmentDetail(q, id)) : null;
    if (found === null) return problem(c, "not-found");
    // The referenced calls and their totals (fork 5): on this detail only, never in the list.
    const response: AssessmentResponse =
      found.log === null
        ? { assessment: found.assessment }
        : { assessment: found.assessment, calls: [...found.log.calls], call_totals: found.log.totals };
    return c.json(response);
  });

  return routes;
}
