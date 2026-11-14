// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ID_PATTERNS } from "./constants.ts";
import { deepFreeze, text } from "./shared.ts";

// Tamper detection (slice 21a, D-100). Harden plants an integrity marker in a registered Build: the Build id and up
// to 32 artifact paths, identifiers only, never a hash. The Manifest records those paths (`integrity.files`), in the
// marker's order. An attestation may then carry an integrity report: the Build the page found in the marker and the
// SHA-256 a browser observed for some of its files, each named by its index into `integrity.files`. The API compares
// the report with the registered Build after the response and records a `tampered-build` Detection on a mismatch.
// The report changes nothing else: not the token, not the verdict, not what Shield does.

export const INTEGRITY_LIMITS = deepFreeze({
  /** Files an integrity marker, a Manifest's `integrity.files` and one report list at most. */
  filesMax: 32,
  /** Reports carrying a mismatch judged per Build per hour (per API process); a fully matching report is not counted. */
  reportsPerHour: 600,
  /** New observed hashes (a file and its hash) that become a Detection, per Build per hour (per API process). */
  newHashesPerHour: 20,
  /**
   * Distinct observed hashes (a file and its hash) recorded for one Build in any 24 hours, counted in the database:
   * it holds across API processes and restarts, and never blinds a Build for longer than a day.
   */
  hashesPerDay: 50,
  /** Recent Builds of the App Environment whose hash of the same path makes an observed hash stale, not tampered. */
  recentBuilds: 20,
  /** A Build registered longer ago than this many days is not one of the recent Builds. */
  recentDays: 30,
} as const);

/**
 * The signal id of an integrity mismatch. It is the API's own finding and is deliberately NOT one of
 * `ATTESTATION_SIGNALS`: a client that lists it in `signals` has it filtered out like any unknown id, and it never
 * reaches a verdict or a token.
 */
export const INTEGRITY_SIGNAL = "tamper.integrity_mismatch";

/** Characters of an artifact path (as `ArtifactDigestSchema`). */
const PATH_MAX = 256;

/** A SHA-256 as 43 canonical base64url characters: the last one leaves the two spare bits zero. */
export const INTEGRITY_HASH_PATTERN = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/**
 * The Manifest's `integrity`: the artifact paths the planted marker lists, in the marker's order, each once. Empty
 * when the marker was wanted but did not fit the size budget (nothing was planted). That each path is one of the
 * Manifest's artifacts is checked where a Build is registered (`RegisterBuildRequestSchema`).
 */
export const ManifestIntegritySchema = z.object({
  files: z
    .array(text(PATH_MAX).min(1))
    .max(INTEGRITY_LIMITS.filesMax)
    .refine((files) => new Set(files).size === files.length, { message: "Must not list a path twice." }),
});
export type ManifestIntegrity = z.infer<typeof ManifestIntegritySchema>;

/**
 * The integrity report of `POST /v1/attest`: the Build of the marker the page found, the files it hashed — `i` is
 * the index into that Build's `integrity.files`, `h` the SHA-256 of the bytes the browser received — and how many
 * listed files it could not hash (`skipped`). An index names each file once.
 */
export const IntegrityReportSchema = z.object({
  build: z.string().regex(ID_PATTERNS.bld),
  files: z
    .array(
      z.object({
        i: z
          .int()
          .min(0)
          .max(INTEGRITY_LIMITS.filesMax - 1),
        h: z.string().regex(INTEGRITY_HASH_PATTERN),
      }),
    )
    .max(INTEGRITY_LIMITS.filesMax)
    .refine((files) => new Set(files.map((file) => file.i)).size === files.length, {
      message: "Must not list a file twice.",
    }),
  skipped: z.int().min(0).max(INTEGRITY_LIMITS.filesMax),
});
export type IntegrityReport = z.infer<typeof IntegrityReportSchema>;
