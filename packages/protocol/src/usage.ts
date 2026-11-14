// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import type { Verdict } from "./attestation.ts";
import { ID_PATTERNS } from "./constants.ts";
import { OrganizationRetentionSchema } from "./retention.ts";
import { deepFreeze } from "./shared.ts";

// Usage metering (slice 17a, FR-CON-08, PRD §16). Per Organization, App and UTC month: protected requests (Events newly
// stored at ingest, counted in the same transaction, so a resent batch adds nothing), monthly active Guard devices (a
// distinct count of a keyed monthly reference of the per-App device subject, taken at `POST /v1/attest`) and Prove
// sandbox seconds (each Assessment's run time, recorded once when it finishes). No prices, plans or limits (17b).

/** Full UTC months kept before the current one; older months are removed and refused. */
export const USAGE_HISTORY_MONTHS = 13;

/**
 * The verdicts whose attestations count a device as monthly active (review M2, Jev cap_and_flag): `trusted` and
 * `suspect` (at most one automation signal). A `hostile` token (two or more signals) is issued but not counted.
 */
export const USAGE_COUNTED_VERDICTS = deepFreeze(["trusted", "suspect"] as const satisfies readonly Verdict[]);

/**
 * New device references recorded per App and UTC day at most (review M2). Beyond it the API stops recording for the
 * day and flags the App's month as capped (`guard_devices_capped`): the count is then a lower bound.
 */
export const USAGE_DEVICE_DAILY_CAP = 50_000;

/** What `seats` says while there are no member accounts. */
export const USAGE_SEATS_NOTE = "not applicable";

const MONTH_PATTERN = /^[0-9]{4}-(0[1-9]|1[0-2])$/;
const DAY_PATTERN = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$/;

/** The UTC month of an instant, as `YYYY-MM`. */
export function usageMonthOf(at: Date): string {
  return at.toISOString().slice(0, 7);
}

/** Months since year 0 of a `YYYY-MM`. */
function monthIndex(month: string): number {
  return Number(month.slice(0, 4)) * 12 + Number(month.slice(5, 7)) - 1;
}

/**
 * Why a month cannot be read at `now`, or null when it can: the current UTC month and the `USAGE_HISTORY_MONTHS`
 * before it can be read; later months are in the future, earlier ones are no longer kept.
 */
export function usageMonthRefusal(month: string, now: Date): string | null {
  const offset = monthIndex(usageMonthOf(now)) - monthIndex(month);
  if (offset < 0) return "The month is in the future.";
  if (offset > USAGE_HISTORY_MONTHS) return `The month is older than ${USAGE_HISTORY_MONTHS} months.`;
  return null;
}

/** Sandbox minutes: seconds / 60, rounded to the nearest hundredth (half up). */
export function sandboxMinutes(seconds: number): number {
  return Math.round((seconds * 100) / 60) / 100;
}

/** `GET /v1/usage` query: `month` as `YYYY-MM` (UTC); default the current month. */
export const UsageQuerySchema = z.object({
  month: z.string().regex(MONTH_PATTERN, "Expected a month as YYYY-MM.").optional(),
});
export type UsageQuery = z.infer<typeof UsageQuerySchema>;

const count = () => z.int().min(0);

/**
 * The usage of a month. `requests`: Events newly stored. `guard_devices`: distinct devices that received an Attestation
 * Token (per App; the total adds the Apps up, since a device subject is per App). `sandbox_seconds`: the run time of
 * Assessments that finished in the month, from start to finish (else the call log's seconds), rounded up to a whole
 * second per Assessment and capped at the tier's seconds plus the runner's grace; `sandbox_minutes` is
 * `sandboxMinutes(sandbox_seconds)` per App, and in the totals the sum of the Apps' minutes (so the parts add up).
 * `guard_devices_capped`: recording stopped at `USAGE_DEVICE_DAILY_CAP` on some day of the month (in the totals: for
 * some App), so `guard_devices` is a lower bound.
 */
export const UsageCountsSchema = z.object({
  requests: count(),
  guard_devices: count(),
  guard_devices_capped: z.boolean(),
  sandbox_seconds: count(),
  sandbox_minutes: z.number().min(0),
});
export type UsageCounts = z.infer<typeof UsageCountsSchema>;

export const UsageAppSchema = UsageCountsSchema.extend({
  app_id: z.string().regex(ID_PATTERNS.app),
  name: z.string().min(1),
});
export type UsageApp = z.infer<typeof UsageAppSchema>;

/** Requests of one UTC day. */
export const UsageDaySchema = z.object({ day: z.string().regex(DAY_PATTERN), requests: count() });
export type UsageDay = z.infer<typeof UsageDaySchema>;

/**
 * `GET /v1/usage`. `closed`: the month has ended (its Guard devices are a rolled-up total once the daily job closed
 * it). `apps`: every App of the Organization, zeros included. `daily`: every day of the month, in order, zeros
 * included. `apps_count` and `event_retention_days` are current values, whatever the month. `seats` is null while
 * there are no member accounts.
 */
export const UsageResponseSchema = z.object({
  month: z.string().regex(MONTH_PATTERN),
  closed: z.boolean(),
  totals: UsageCountsSchema,
  apps: z.array(UsageAppSchema),
  daily: z.array(UsageDaySchema),
  apps_count: count(),
  event_retention_days: OrganizationRetentionSchema.shape.event_retention_days,
  seats: z.null(),
  seats_note: z.literal(USAGE_SEATS_NOTE),
});
export type UsageResponse = z.infer<typeof UsageResponseSchema>;
