import type { UsageResponse } from "@antireverse/protocol";

/** Slice 17a: a month of usage as `GET /v1/usage` answers it, shared by the usage tests. */
const DAYS = 30;
const daily = Array.from({ length: DAYS }, (_, i) => ({
  day: `2026-11-${String(i + 1).padStart(2, "0")}`,
  // Requests on the 1st to the 14th only; the 3rd is the busiest day.
  requests: i < 14 ? (i === 2 ? 4200 : 100 * (i + 1)) : 0,
}));
const requests = daily.reduce((sum, day) => sum + day.requests, 0);

export const APP_A = "app_0123456789abcdef01234567";
export const APP_B = "app_89abcdef0123456789abcdef";

export const USAGE: UsageResponse = {
  month: "2026-11",
  closed: false,
  totals: { requests, guard_devices: 1250, guard_devices_capped: false, sandbox_seconds: 5430, sandbox_minutes: 90.5 },
  apps: [
    {
      app_id: APP_A,
      name: "Storefront",
      requests: requests - 1000,
      guard_devices: 1250,
      guard_devices_capped: false,
      sandbox_seconds: 5430,
      sandbox_minutes: 90.5,
    },
    {
      app_id: APP_B,
      name: "Back office",
      requests: 1000,
      guard_devices: 0,
      guard_devices_capped: false,
      sandbox_seconds: 0,
      sandbox_minutes: 0,
    },
  ],
  daily,
  apps_count: 2,
  event_retention_days: 30,
  seats: null,
  seats_note: "not applicable",
};

/** An earlier, closed month with nothing in it. */
export const EMPTY_USAGE: UsageResponse = {
  ...USAGE,
  month: "2026-02",
  closed: true,
  totals: { requests: 0, guard_devices: 0, guard_devices_capped: false, sandbox_seconds: 0, sandbox_minutes: 0 },
  apps: USAGE.apps.map((app) => ({ ...app, requests: 0, guard_devices: 0, sandbox_seconds: 0, sandbox_minutes: 0 })),
  daily: Array.from({ length: 28 }, (_, i) => ({ day: `2026-02-${String(i + 1).padStart(2, "0")}`, requests: 0 })),
};
