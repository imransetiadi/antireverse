import { describe, expect, it } from "vitest";
import {
  sandboxMinutes,
  USAGE_COUNTED_VERDICTS,
  USAGE_DEVICE_DAILY_CAP,
  USAGE_HISTORY_MONTHS,
  USAGE_SEATS_NOTE,
  UsageQuerySchema,
  UsageResponseSchema,
  usageMonthOf,
  usageMonthRefusal,
} from "../src/index.ts";

// Slice 17a: the usage contract (`GET /v1/usage?month=YYYY-MM`).

const APP = "app_0123456789abcdef01234567";
const counts = {
  requests: 1200,
  guard_devices: 3,
  guard_devices_capped: false,
  sandbox_seconds: 95,
  sandbox_minutes: 1.58,
};
const body = {
  month: "2026-11",
  closed: false,
  totals: counts,
  apps: [{ app_id: APP, name: "Shop", ...counts }],
  daily: [
    { day: "2026-11-01", requests: 0 },
    { day: "2026-11-02", requests: 1200 },
  ],
  apps_count: 1,
  event_retention_days: 30,
  seats: null,
  seats_note: USAGE_SEATS_NOTE,
};

describe("usage", () => {
  it("keeps 13 months of history before the current month", () => {
    expect(USAGE_HISTORY_MONTHS).toBe(13);
    expect(USAGE_SEATS_NOTE).toBe("not applicable");
  });

  it("counts the devices of trusted and suspect attestations, at most 50,000 new ones per App and UTC day", () => {
    expect(USAGE_COUNTED_VERDICTS).toEqual(["trusted", "suspect"]);
    expect(Object.isFrozen(USAGE_COUNTED_VERDICTS)).toBe(true);
    expect(USAGE_DEVICE_DAILY_CAP).toBe(50_000);
  });

  it("takes an optional month as YYYY-MM, nothing else", () => {
    expect(UsageQuerySchema.parse({})).toEqual({});
    expect(UsageQuerySchema.parse({ month: "2026-01" })).toEqual({ month: "2026-01" });
    for (const bad of ["2026-13", "2026-00", "2026-1", "26-01", "2026-01-01", "", "2026/01"]) {
      expect(UsageQuerySchema.safeParse({ month: bad }).success, bad).toBe(false);
    }
  });

  it("names the UTC month of an instant", () => {
    expect(usageMonthOf(new Date("2026-11-30T23:59:59.999Z"))).toBe("2026-11");
    expect(usageMonthOf(new Date("2026-12-01T00:00:00.000Z"))).toBe("2026-12");
    expect(usageMonthOf(new Date("2027-01-15T00:00:00.000Z"))).toBe("2027-01");
  });

  it("refuses months in the future and months older than 13 months", () => {
    const now = new Date("2026-11-14T09:00:00.000Z");
    expect(usageMonthRefusal("2026-11", now)).toBeNull();
    expect(usageMonthRefusal("2026-10", now)).toBeNull();
    // 13 months before the current one is the oldest that is kept.
    expect(usageMonthRefusal("2025-10", now)).toBeNull();
    expect(usageMonthRefusal("2025-09", now)).toMatch(/older than 13 months/);
    expect(usageMonthRefusal("2026-12", now)).toMatch(/future/);
    expect(usageMonthRefusal("2030-01", now)).toMatch(/future/);
  });

  it("gives sandbox minutes as seconds / 60 rounded to the nearest hundredth", () => {
    expect(sandboxMinutes(0)).toBe(0);
    expect(sandboxMinutes(60)).toBe(1);
    expect(sandboxMinutes(95)).toBe(1.58);
    expect(sandboxMinutes(1)).toBe(0.02);
    expect(sandboxMinutes(7200)).toBe(120);
  });

  it("states totals, Apps, every day's requests, the Apps count, the retention and seats as not applicable", () => {
    expect(UsageResponseSchema.parse(body)).toEqual(body);
    expect(UsageResponseSchema.safeParse({ ...body, seats: 2 }).success).toBe(false);
    expect(UsageResponseSchema.safeParse({ ...body, seats_note: "" }).success).toBe(false);
    expect(UsageResponseSchema.safeParse({ ...body, totals: { ...counts, requests: -1 } }).success).toBe(false);
    expect(UsageResponseSchema.safeParse({ ...body, totals: { ...counts, requests: 1.5 } }).success).toBe(false);
    expect(UsageResponseSchema.safeParse({ ...body, daily: [{ day: "2026-11-1", requests: 0 }] }).success).toBe(false);
    expect(UsageResponseSchema.safeParse({ ...body, event_retention_days: 31 }).success).toBe(false);
    // Whether recording stopped at the daily cap is stated, per App and in total.
    const { guard_devices_capped: _, ...uncapped } = counts;
    expect(UsageResponseSchema.safeParse({ ...body, totals: uncapped }).success).toBe(false);
    const capped = { ...body, totals: { ...counts, guard_devices_capped: true } };
    expect(UsageResponseSchema.parse(capped)).toEqual(capped);
    expect(UsageResponseSchema.safeParse({ ...body, apps: [{ ...body.apps[0], app_id: "x" }] }).success).toBe(false);
  });
});
