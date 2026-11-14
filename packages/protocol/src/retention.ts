// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { deepFreeze, isoDateTime } from "./shared.ts";

// Retention (slice 18c, FR-CON-11, SECURITY §8, OPERATION §17). An Organization chooses how long its Events (request
// metadata) are kept; the other periods are fixed. A daily job removes what is older, per Organization, in batches: a
// run that is cut short continues at the next one. Builds and audit entries are not removed.

/** The choices of Event retention, in days. */
export const EVENT_RETENTION_DAYS = deepFreeze([7, 30, 90, 180, 395] as const);
export type EventRetentionDays = (typeof EVENT_RETENTION_DAYS)[number];

/** The Event retention of a new Organization. Organizations that existed when 18c shipped keep 395 days. */
export const DEFAULT_EVENT_RETENTION_DAYS: EventRetentionDays = 30;

/**
 * The fixed periods, in days. `guard_days`: Events carrying a Guard report (a verified Attestation Token) are kept at
 * most this long, whatever the Event retention. `evidence_days`: Incidents (from their last activity) with their
 * Detections and alert deliveries, alert deliveries, and finished Assessments. `artifact_days`: a protected artifact,
 * after its last Assessment.
 */
export const RETENTION_FIXED_DAYS = deepFreeze({ guard_days: 30, evidence_days: 395, artifact_days: 30 } as const);

const EventRetentionDaysSchema = z.union(EVENT_RETENTION_DAYS.map((days) => z.literal(days)));
const TableNameSchema = z.string().regex(/^[a-z_][a-z0-9_]{0,62}$/);

/** How long the Organization's data is kept. */
export const OrganizationRetentionSchema = z.object({
  event_retention_days: EventRetentionDaysSchema,
  guard_days: z.literal(RETENTION_FIXED_DAYS.guard_days),
  evidence_days: z.literal(RETENTION_FIXED_DAYS.evidence_days),
  artifact_days: z.literal(RETENTION_FIXED_DAYS.artifact_days),
});
export type OrganizationRetention = z.infer<typeof OrganizationRetentionSchema>;

/**
 * The last run of the retention job for the Organization: when, rows removed per table (tables with none left out),
 * and whether it finished (`complete: false`: the run was cut short; the rest goes at the next run).
 */
export const RetentionRunSchema = z.object({
  ran_at: isoDateTime(),
  complete: z.boolean(),
  counts: z.record(TableNameSchema, z.int().min(0)),
});
export type RetentionRun = z.infer<typeof RetentionRunSchema>;

/** `GET /v1/organization/retention`. */
export const RetentionResponseSchema = z.object({
  retention: OrganizationRetentionSchema,
  last_run: RetentionRunSchema.nullable(),
});
export type RetentionResponse = z.infer<typeof RetentionResponseSchema>;

/**
 * `PUT /v1/organization/retention` (admin key). Shortening is sensitive: it needs the reason header
 * (`X-Airverse-Reason`).
 */
export const UpdateRetentionRequestSchema = z.strictObject({ event_retention_days: EventRetentionDaysSchema });
export type UpdateRetentionRequest = z.infer<typeof UpdateRetentionRequestSchema>;

/**
 * The answer of `PUT /v1/organization/retention`: the new state, and `events_removed_before`, the instant before which
 * Events received are removed by the next run (the time of the change less the Event retention; it moves forward
 * with each run).
 */
export const UpdateRetentionResponseSchema = RetentionResponseSchema.extend({ events_removed_before: isoDateTime() });
export type UpdateRetentionResponse = z.infer<typeof UpdateRetentionResponseSchema>;
