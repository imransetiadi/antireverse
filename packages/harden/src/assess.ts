// The assessment client (slice 12a): after a successful registration, `--assess <tier>` uploads the protected
// output files — exactly the Manifest's artifacts, so the API can prove ownership by their hashes — to
// `POST /v1/apps/:appId/builds/:buildId/assessments`. The 25 MB / 1,000-file limits are checked before anything
// is sent. Like the register client it carries the admin key only as a Bearer header, never logs or returns it,
// and never throws into the caller — failures come back as `{ error }`.
import {
  ASSESSMENT_LIMITS,
  type Assessment,
  type AssessmentTier,
  type CreateAssessmentRequest,
  CreateAssessmentRequestSchema,
  CreateAssessmentResponseSchema,
} from "@antireverse/protocol";

/** One protected output file: its path (as in the Manifest) and its final code. */
export interface AssessmentFile {
  path: string;
  code: string;
}

export interface AssessArgs {
  /** Base URL of the API. */
  endpoint: string;
  /** The admin key. Used only as a Bearer header; never logged or returned. */
  key: string;
  appId: string;
  buildId: string;
  tier: AssessmentTier;
  files: readonly AssessmentFile[];
}

export type AssessResult = { assessment: Assessment } | { error: string };

const count = (n: number) => n.toLocaleString("en-US");

/** The request body: each file's UTF-8 bytes as padded base64. */
function assessmentRequest(tier: AssessmentTier, files: readonly AssessmentFile[]): CreateAssessmentRequest {
  return {
    tier,
    files: files.map((file) => ({ path: file.path, base64: Buffer.from(file.code, "utf8").toString("base64") })),
  };
}

/**
 * Why these files cannot be uploaded for an Assessment, or null: more than 1,000 files, more than 25 MB of UTF-8
 * bytes in total, or anything else the protocol's request schema refuses (a path over 256 characters, a path
 * listed twice). Checked before anything is sent.
 */
export function assessmentUploadProblem(files: readonly AssessmentFile[]): string | null {
  if (files.length === 0) return "there are no protected files to upload";
  if (files.length > ASSESSMENT_LIMITS.filesMax) {
    return `the protected output has ${count(files.length)} files; an Assessment takes at most ${count(ASSESSMENT_LIMITS.filesMax)}`;
  }
  const bytes = files.reduce((total, file) => total + Buffer.byteLength(file.code, "utf8"), 0);
  if (bytes > ASSESSMENT_LIMITS.artifactBytesMax) {
    return `the protected output is ${count(bytes)} bytes; an Assessment takes at most 25 MB (${count(ASSESSMENT_LIMITS.artifactBytesMax)} bytes)`;
  }
  const parsed = CreateAssessmentRequestSchema.safeParse(assessmentRequest("T1", files));
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const where = issue?.path.includes("path") ? "a file path" : "the upload";
    return `${where} is not accepted (${issue?.message ?? "invalid"})`;
  }
  return null;
}

/** A short, secret-free description of a thrown value: its error code or name only. */
function describeError(error: unknown): string {
  const candidate = error as { code?: unknown; name?: unknown } | null | undefined;
  const label = typeof candidate?.code === "string" ? candidate.code : candidate?.name;
  return typeof label === "string" && /^[\w.-]{1,40}$/.test(label) ? label : "error";
}

/** Requests an Assessment of a registered Build, uploading its protected files. Never throws. */
export async function requestAssessment(args: AssessArgs): Promise<AssessResult> {
  const problem = assessmentUploadProblem(args.files);
  if (problem !== null) return { error: problem };
  const base = args.endpoint.replace(/\/+$/, "");
  const url = `${base}/v1/apps/${encodeURIComponent(args.appId)}/builds/${encodeURIComponent(args.buildId)}/assessments`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { authorization: `Bearer ${args.key}`, "content-type": "application/json" },
      body: JSON.stringify(assessmentRequest(args.tier, args.files)),
    });
  } catch (error) {
    return { error: `the API could not be reached (${describeError(error)})` };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }

  if (!response.ok) {
    const problemBody = body as { title?: unknown; detail?: unknown } | undefined;
    const title = typeof problemBody?.title === "string" ? problemBody.title : undefined;
    const detail = typeof problemBody?.detail === "string" ? problemBody.detail : undefined;
    return { error: detail ?? title ?? `the API responded ${response.status}` };
  }

  const parsed = CreateAssessmentResponseSchema.safeParse(body);
  if (!parsed.success) return { error: "the API returned a response that was not an Assessment" };
  return { assessment: parsed.data.assessment };
}

/** The Build page in the Console, where the Assessment's result appears. */
export function consoleBuildUrl(consoleBase: string, appId: string, buildId: string): string {
  return `${consoleBase.replace(/\/+$/, "")}/apps/${encodeURIComponent(appId)}/builds/${encodeURIComponent(buildId)}`;
}
