// The register client: one POST that sends the Build Manifest to the API. It sends ONLY the Manifest (no
// source, no unprotected bundle, no seed value) and, from slice 19, the lockfile's components beside it (name,
// version, dev — nothing else), carries the admin key in the Authorization header, never
// logs or returns the key, and never throws into the caller — failures come back as `{ error }`.
import type { Build, BuildManifest, Component, FindingsSummary } from "@antireverse/protocol";
import { BuildResponseSchema } from "@antireverse/protocol";

export interface RegisterArgs {
  /** Base URL of the API. The build goes to `{endpoint}/v1/apps/{appId}/builds`. */
  endpoint: string;
  /** The admin key. Used only as a Bearer header; never logged or returned. */
  key: string;
  appId: string;
  manifest: BuildManifest;
  /** The lockfile's components (slice 19), sent beside the Manifest. Omitted from the body when absent. */
  components?: readonly Component[];
}

/** `findings` is the Build's open-findings summary when the API returned one (slice 19). */
export type RegisterResult = { build: Build; findings?: FindingsSummary } | { error: string };

/** A short, secret-free description of a thrown value: its error code or name only. */
function describeError(error: unknown): string {
  const candidate = error as { code?: unknown; name?: unknown } | null | undefined;
  const label = typeof candidate?.code === "string" ? candidate.code : candidate?.name;
  return typeof label === "string" && /^[\w.-]{1,40}$/.test(label) ? label : "error";
}

export async function registerBuild(args: RegisterArgs): Promise<RegisterResult> {
  const url = `${args.endpoint.replace(/\/+$/, "")}/v1/apps/${args.appId}/builds`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { authorization: `Bearer ${args.key}`, "content-type": "application/json" },
      body: JSON.stringify(
        args.components ? { manifest: args.manifest, components: args.components } : { manifest: args.manifest },
      ),
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
    const problem = body as { title?: unknown; detail?: unknown } | undefined;
    const title = typeof problem?.title === "string" ? problem.title : undefined;
    const detail = typeof problem?.detail === "string" ? problem.detail : undefined;
    return { error: detail ?? title ?? `the API responded ${response.status}` };
  }

  const parsed = BuildResponseSchema.safeParse(body);
  if (!parsed.success) return { error: "the API returned a response that was not a Build" };
  return parsed.data.findings
    ? { build: parsed.data.build, findings: parsed.data.findings }
    : { build: parsed.data.build };
}
