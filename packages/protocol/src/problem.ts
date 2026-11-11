// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { deepFreeze } from "./shared.ts";

const ProblemErrorSchema = z.object({
  /** Where the value is, joined with dots: `events.1.request.status`. Empty for the document itself. */
  path: z.string(),
  message: z.string(),
});
export type ProblemError = z.infer<typeof ProblemErrorSchema>;

/**
 * Why a 409 `conflict` was refused, when the API can say so: a client acts on this member, never on the
 * `detail` text. A 409 without a reason (a Policy published meanwhile, a Build id taken) is still valid.
 */
export const CONFLICT_REASONS = deepFreeze([
  "incident-resolved",
  "actor-unknown",
  "prefix-allowlisted",
  "containment-limit",
  "containment-ended",
  "allowlist-duplicate",
  "allowlist-limit",
  "beacon-token-taken",
  "containment-not-applicable",
] as const);
export type ConflictReason = (typeof CONFLICT_REASONS)[number];

/** An `application/problem+json` document. */
export const ProblemSchema = z.object({
  type: z.string(),
  title: z.string(),
  status: z.int().min(100).max(599),
  detail: z.string().optional(),
  errors: z.array(ProblemErrorSchema).optional(),
  /** Only on some 409 `conflict` documents. */
  reason: z.enum(CONFLICT_REASONS).optional(),
});
export type Problem = z.infer<typeof ProblemSchema>;

/** The part of a zod error this module reads. Every `ZodError` fits. */
export interface ZodErrorLike {
  readonly issues: ReadonlyArray<{ readonly path: ReadonlyArray<PropertyKey>; readonly message: string }>;
}

/**
 * Maps a zod error to the `errors` member of a problem document: one entry per issue, in order.
 * zod messages name the expectation, never the rejected value, so a key cannot leak through them.
 */
export function toProblemErrors(error: ZodErrorLike): ProblemError[] {
  return error.issues.map((issue) => ({ path: issue.path.map(String).join("."), message: issue.message }));
}
