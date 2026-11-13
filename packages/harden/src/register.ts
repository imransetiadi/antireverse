// The register client: one POST that sends the Build Manifest to the API. It sends ONLY the Manifest (no
// source, no unprotected bundle, no seed value) and, from slice 19, the lockfile's components beside it (name,
// version, dev — nothing else), from slice 12a, the route inventory (`METHOD /path` entries) and, from slice 12b,
// the logic file (the designated protected functions with their hidden vectors, for W3), carries the
// admin key in the Authorization header, never logs or returns the key, and never throws into the caller — failures come back as `{ error }`.
import type { Build, BuildManifest, Component, FindingsSummary, LogicFile } from "@antireverse/protocol";
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
  /** The route inventory (slice 12a), sent beside the Manifest for W1 Map. Omitted from the body when absent. */
  routes?: readonly string[];
  /** The logic file (slice 12b), sent beside the Manifest for W3 Logic. Omitted from the body when absent. */
  logic?: LogicFile;
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
      body: JSON.stringify({
        manifest: args.manifest,
        ...(args.components ? { components: args.components } : {}),
        ...(args.routes ? { routes: args.routes } : {}),
        ...(args.logic ? { logic: args.logic } : {}),
      }),
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
