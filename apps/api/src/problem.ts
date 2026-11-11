import {
  BUILD_LIMITS,
  CONTAINMENT_LIMITS,
  type ConflictReason,
  EXPOSURE_LIMITS,
  LIMITS,
  type Problem,
  type ProblemError,
  SIMULATION_LIMITS,
} from "@antireverse/protocol";
import type { Context } from "hono";

/** Bytes of a request body of the public attestation endpoints, at most. */
export const ATTEST_BODY_BYTES_MAX = 4_096;

const TYPE_BASE = "https://antireverse.dev/problems/";

// Every error the API can answer. One fixed text per kind: a response never says more than its kind,
// so it cannot reveal whether a key or a resource exists.
const PROBLEMS = {
  validation: { status: 400, title: "Invalid request" },
  "malformed-json": { status: 400, title: "Malformed JSON", detail: "The request body is not valid JSON." },
  unauthorized: {
    status: 401,
    title: "Unauthorized",
    detail: "A valid key is required. Send it as: Authorization: Bearer <key>.",
  },
  forbidden: { status: 403, title: "Forbidden", detail: "This kind of key cannot be used for this request." },
  "not-found": { status: 404, title: "Not found", detail: "The resource does not exist." },
  "method-not-allowed": { status: 405, title: "Method not allowed", detail: "This resource answers GET only." },
  // A write against a resource that moved on: a Policy published meanwhile, or a Build id already registered.
  // Names nothing specific, only that the resource changed.
  conflict: {
    status: 409,
    title: "Conflict",
    detail: "This resource was changed by someone else in the meantime. Reload it and try again.",
  },
  "payload-too-large": {
    status: 413,
    title: "Payload too large",
    detail: `The request body is larger than ${LIMITS.bodyBytesMax} bytes.`,
  },
  "too-many-streams": {
    status: 429,
    title: "Too many live streams",
    detail: `At most ${LIMITS.streamsPerOrganization} live streams can be open per Organization.`,
  },
  internal: { status: 500, title: "Internal server error" },
  // The public attestation endpoints (slice 03). One text for an unknown App and for any bad nonce: the answer
  // never says which it was.
  "attestation-refused": {
    status: 400,
    title: "Attestation refused",
    detail: "The App is unknown, or the nonce is unknown, used or expired. Request a new challenge.",
  },
  "attestation-payload-too-large": {
    status: 413,
    type: "payload-too-large",
    title: "Payload too large",
    detail: `The request body is larger than ${ATTEST_BODY_BYTES_MAX} bytes.`,
  },
  // Slice 19: the two bodies that may carry a component list.
  "inventory-payload-too-large": {
    status: 413,
    type: "payload-too-large",
    title: "Payload too large",
    detail: `The request body is larger than ${EXPOSURE_LIMITS.componentsBytesMax} bytes.`,
  },
  "build-payload-too-large": {
    status: 413,
    type: "payload-too-large",
    title: "Payload too large",
    detail: `The Manifest may be at most ${BUILD_LIMITS.manifestBytesMax} bytes and the component list at most ${EXPOSURE_LIMITS.componentsBytesMax} bytes.`,
  },
  // Slice 19 review (A7, M4): a Shield key sends at most 5 inventories at once, then 1 per minute.
  "too-many-inventories": {
    status: 429,
    type: "too-many-requests",
    title: "Too many requests",
    detail: "Too many inventories from this key. Try again after the time in Retry-After.",
  },
  // Slice 11: an Organization runs at most 6 Policy simulations a minute.
  "too-many-simulations": {
    status: 429,
    type: "too-many-requests",
    title: "Too many requests",
    detail: `At most ${SIMULATION_LIMITS.perMinute} simulations a minute per Organization. Try again after the time in Retry-After.`,
  },
  "too-many-attestations": {
    status: 429,
    title: "Too many requests",
    detail: "Too many attestation requests. Try again in a minute.",
  },
} as const satisfies Record<string, { status: number; title: string; detail?: string; type?: string }>;

export type ProblemKind = keyof typeof PROBLEMS;

/**
 * The 409s of containment and the allowlist: still type `conflict`, with the protocol's `reason` member for
 * clients and a fixed text per reason for people. The keys are exactly `CONFLICT_REASONS`: a reason added
 * there without a text here does not compile. No text names a hash, an address, a prefix or a range.
 */
export const CONFLICT_DETAILS: Readonly<Record<ConflictReason, string>> = {
  "incident-resolved": "The Incident is resolved. A resolved Incident cannot be contained.",
  "actor-unknown": "The Actor is not among the Events of this Incident.",
  "prefix-allowlisted":
    "The network overlaps a range on the allowlist, so it cannot be blocked. Block an Actor instead.",
  "containment-limit": `This App and Environment already has ${CONTAINMENT_LIMITS.activePerAppEnv} active blocks. Lift one first.`,
  "containment-ended": "The block has already expired or been lifted.",
  "allowlist-duplicate": "The range is already on the allowlist.",
  "allowlist-limit": `The allowlist already holds ${CONTAINMENT_LIMITS.allowlistMax} ranges. Remove one first.`,
  "beacon-token-taken":
    "This Build's beacon token is already registered. Harden it again with another seed or version.",
  "containment-not-applicable": "Containment does not apply to this Incident.",
};

/**
 * An `application/problem+json` response of the given kind. `errors` lists the invalid values of a 400. A
 * `conflict` may name its reason, whose fixed text replaces the generic one.
 */
export function problem(c: Context, kind: ProblemKind, errors?: ProblemError[], reason?: ConflictReason): Response {
  const definition: {
    status: (typeof PROBLEMS)[ProblemKind]["status"];
    title: string;
    detail?: string;
    type?: string;
  } = PROBLEMS[kind];
  const named = kind === "conflict" ? reason : undefined;
  const detail = named === undefined ? definition.detail : CONFLICT_DETAILS[named];
  const document: Problem = {
    type: TYPE_BASE + (definition.type ?? kind),
    title: definition.title,
    status: definition.status,
    ...(detail === undefined ? {} : { detail }),
    ...(errors === undefined ? {} : { errors }),
    ...(named === undefined ? {} : { reason: named }),
  };
  if (kind === "unauthorized") c.header("WWW-Authenticate", "Bearer");
  if (kind === "method-not-allowed") c.header("Allow", "GET");
  return c.body(JSON.stringify(document), definition.status, { "Content-Type": "application/problem+json" });
}
