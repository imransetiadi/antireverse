import { createHmac } from "node:crypto";
import {
  type EventRetentionDays,
  sandboxMinutes,
  USAGE_SEATS_NOTE,
  type UsageApp,
  type UsageCounts,
  type UsageResponse,
  usageMonthOf,
} from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";
import type { EventOrigin } from "./events.ts";
import type { SweepCounts } from "./retention.ts";

// Usage metering (slice 17a, migration 0036). The request side adds requests through `usage_add_requests` (tenant
// transaction), records Guard devices through `usage_record_device` (no tenant: the attest route has none), and reads a
// month of its own Organization (row-level security). The owner side runs the monthly rollup and the 13-month sweep.

/** The UTC day of an instant, as `YYYY-MM-DD`. */
const dayOf = (at: Date): string => at.toISOString().slice(0, 10);

/**
 * Adds `n` newly stored Events to the origin's App, Environment and UTC day of receipt. Call it in the transaction of
 * the insert, with the number of rows the insert returned. Tenant transaction (the origin's Organization).
 */
export async function addRequests(q: Queryable, origin: EventOrigin, n: number): Promise<void> {
  if (n === 0) return;
  await q.query("SELECT usage_add_requests($1::text, $2::text, $3::date, $4::bigint)", [
    origin.appId,
    origin.environment,
    dayOf(origin.receivedAt),
    n,
  ]);
}

/**
 * The monthly reference of a device: HMAC-SHA-256 under the salt of its UTC month (review M3: computed here, the salt
 * never reaches the database) of the per-App device subject. 32 bytes.
 */
export function deviceRef(salt: Buffer, subject: string): Buffer {
  return createHmac("sha256", salt).update(subject, "utf8").digest();
}

/** What recording a device did: newly recorded, already recorded this month, stopped by the daily cap, or no App. */
export type DeviceRecord = "recorded" | "known" | "capped" | "unknown_app";

/**
 * Records a device's monthly reference for the App at `at`, once per UTC month, at most `cap` new references per App
 * and UTC day (beyond it the day is flagged as capped). Any transaction: the App names the Organization.
 */
export async function recordDevice(
  q: Queryable,
  appId: string,
  ref: Buffer,
  at: Date,
  cap: number,
): Promise<DeviceRecord> {
  const { rows } = await q.query<{ outcome: DeviceRecord }>(
    "SELECT usage_record_device($1::text, $2::bytea, $3::timestamptz, $4::integer) AS outcome",
    [appId, ref, at.toISOString(), cap],
  );
  const outcome = rows[0]?.outcome;
  if (outcome === undefined) throw new Error("The device recording answered nothing.");
  return outcome;
}

const zero = (): UsageCounts => ({
  requests: 0,
  guard_devices: 0,
  guard_devices_capped: false,
  sandbox_seconds: 0,
  sandbox_minutes: 0,
});

/**
 * The usage of the transaction's own Organization in `month` (`YYYY-MM`), read at `now`. Guard devices of a month that
 * the rollup closed are its totals; of any other month, the live distinct count of its references. Null when the
 * Organization is not visible.
 */
export async function usageOfMonth(
  q: Queryable,
  organizationId: string,
  month: string,
  now: Date,
): Promise<UsageResponse | null> {
  const organization = await q.query<{ event_retention_days: EventRetentionDays }>(
    "SELECT event_retention_days FROM organizations WHERE id = $1",
    [organizationId],
  );
  const retention = organization.rows[0];
  if (retention === undefined) return null;
  const first = `${month}-01`;
  const apps = await q.query<{ id: string; name: string }>(
    "SELECT id, name FROM apps WHERE organization_id = $1 ORDER BY created_at, id",
    [organizationId],
  );
  const days = await q.query<{ app_id: string; day: string; requests: string; sandbox_seconds: string }>(
    `SELECT app_id, to_char(day, 'YYYY-MM-DD') AS day, sum(requests)::text AS requests,
       sum(sandbox_seconds)::text AS sandbox_seconds
     FROM usage_daily
     WHERE organization_id = $1 AND day >= $2::date AND day < ($2::date + interval '1 month')
     GROUP BY app_id, day`,
    [organizationId, first],
  );
  // Rolled up: the month's total and flag; otherwise the live distinct count, and the flag of its days so far. A late
  // day row of a rolled-up month (an attestation in flight at its close) adds its flag.
  const devices = await q.query<{ app_id: string; devices: string; capped: boolean }>(
    `SELECT a.id AS app_id, COALESCE(
         (SELECT m.devices FROM usage_monthly_devices m
          WHERE m.organization_id = a.organization_id AND m.app_id = a.id AND m.month = $2::date),
         (SELECT count(*) FROM usage_devices d
          WHERE d.organization_id = a.organization_id AND d.app_id = a.id AND d.month = $2::date)
       )::text AS devices,
       COALESCE(
         (SELECT m.capped FROM usage_monthly_devices m
          WHERE m.organization_id = a.organization_id AND m.app_id = a.id AND m.month = $2::date), false)
       OR EXISTS (
         SELECT 1 FROM usage_device_days x
         WHERE x.organization_id = a.organization_id AND x.app_id = a.id AND x.capped
           AND x.day >= $2::date AND x.day < ($2::date + interval '1 month')) AS capped
     FROM apps a WHERE a.organization_id = $1`,
    [organizationId, first],
  );

  const perApp = new Map<string, UsageApp>(
    apps.rows.map((app) => [app.id, { app_id: app.id, name: app.name, ...zero() }]),
  );
  const perDay = new Map<string, number>();
  for (const row of days.rows) {
    const app = perApp.get(row.app_id);
    if (app !== undefined) {
      app.requests += Number(row.requests);
      app.sandbox_seconds += Number(row.sandbox_seconds);
    }
    perDay.set(row.day, (perDay.get(row.day) ?? 0) + Number(row.requests));
  }
  for (const row of devices.rows) {
    const app = perApp.get(row.app_id);
    if (app !== undefined) {
      app.guard_devices = Number(row.devices);
      app.guard_devices_capped = row.capped === true;
    }
  }
  const totals = zero();
  // Minutes in hundredths, summed as integers: the total is the sum of the Apps' rounded minutes (review L2).
  let hundredths = 0;
  for (const app of perApp.values()) {
    app.sandbox_minutes = sandboxMinutes(app.sandbox_seconds);
    hundredths += Math.round(app.sandbox_minutes * 100);
    totals.requests += app.requests;
    totals.guard_devices += app.guard_devices;
    totals.guard_devices_capped ||= app.guard_devices_capped;
    totals.sandbox_seconds += app.sandbox_seconds;
  }
  totals.sandbox_minutes = hundredths / 100;

  const daily: UsageResponse["daily"] = [];
  const year = Number(month.slice(0, 4));
  const monthIndex = Number(month.slice(5, 7)) - 1;
  const length = new Date(Date.UTC(year, monthIndex + 1, 0)).getUTCDate();
  for (let d = 1; d <= length; d++) {
    const day = `${month}-${String(d).padStart(2, "0")}`;
    daily.push({ day, requests: perDay.get(day) ?? 0 });
  }

  return {
    month,
    closed: month < usageMonthOf(now),
    totals,
    apps: [...perApp.values()],
    daily,
    apps_count: apps.rows.length,
    event_retention_days: retention.event_retention_days,
    seats: null,
    seats_note: USAGE_SEATS_NOTE,
  };
}

// --- The owner's side: the daily rollup -------------------------------------------------------------------------

export interface RollupCall {
  /** Rows removed per Organization id, per table (none: left out). */
  rows: SweepCounts;
  /** Some step used its whole batch: it may have more. */
  saturated: boolean;
}

/**
 * One call of `usage_rollup`: closes the months that ended at least an hour before `at` (distinct counts written,
 * salts deleted, at most `batch` references deleted) and removes at most `batch` rows each of usage older than 13
 * months. Owner transaction.
 */
export async function rollupUsage(q: Queryable, at: Date, batch: number): Promise<RollupCall> {
  const { rows } = await q.query<{
    result: { rows: Record<string, Record<string, number | string>>; saturated: boolean };
  }>("SELECT usage_rollup($1, $2) AS result", [at.toISOString(), batch]);
  const result = rows[0]?.result;
  if (result === undefined) throw new Error("The usage rollup answered nothing.");
  const counts: SweepCounts = {};
  for (const [organizationId, tables] of Object.entries(result.rows)) {
    counts[organizationId] = Object.fromEntries(Object.entries(tables).map(([table, n]) => [table, Number(n)]));
  }
  return { rows: counts, saturated: result.saturated === true };
}
