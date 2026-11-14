import { describe, expect, it } from "vitest";
import {
  AUDIT_ACTIONS,
  DEFAULT_EVENT_RETENTION_DAYS,
  EVENT_RETENTION_DAYS,
  RETENTION_FIXED_DAYS,
  RetentionResponseSchema,
  UpdateRetentionRequestSchema,
  UpdateRetentionResponseSchema,
} from "../src/index.ts";

// Slice 18c: the retention contract (`GET` and `PUT /v1/organization/retention`).

const RETENTION = {
  event_retention_days: 30,
  guard_days: 30,
  evidence_days: 395,
  artifact_days: 30,
};

describe("retention", () => {
  it("offers 7, 30, 90, 180 and 395 days of Events; new Organizations keep 30", () => {
    expect(EVENT_RETENTION_DAYS).toEqual([7, 30, 90, 180, 395]);
    expect(Object.isFrozen(EVENT_RETENTION_DAYS)).toBe(true);
    expect(DEFAULT_EVENT_RETENTION_DAYS).toBe(30);
    expect(RETENTION_FIXED_DAYS).toEqual({ guard_days: 30, evidence_days: 395, artifact_days: 30 });
    expect(Object.isFrozen(RETENTION_FIXED_DAYS)).toBe(true);
  });

  it("names the audit action of a change", () => {
    expect(AUDIT_ACTIONS).toContain("organization.retention.update");
  });

  it("takes one of the choices, nothing else", () => {
    for (const days of EVENT_RETENTION_DAYS) {
      expect(UpdateRetentionRequestSchema.parse({ event_retention_days: days })).toEqual({
        event_retention_days: days,
      });
    }
    for (const bad of [0, 1, 14, 31, 365, 396, 30.5, "30", null]) {
      expect(UpdateRetentionRequestSchema.safeParse({ event_retention_days: bad }).success, String(bad)).toBe(false);
    }
    expect(UpdateRetentionRequestSchema.safeParse({}).success).toBe(false);
    expect(UpdateRetentionRequestSchema.safeParse({ event_retention_days: 30, guard_days: 7 }).success).toBe(false);
  });

  it("states the periods and the last run, or none", () => {
    const none = { retention: RETENTION, last_run: null };
    expect(RetentionResponseSchema.parse(none)).toEqual(none);
    const ran = {
      retention: { ...RETENTION, event_retention_days: 395 },
      last_run: { ran_at: "2026-11-14T03:00:00.000Z", complete: true, counts: { events: 120, containments: 2 } },
    };
    expect(RetentionResponseSchema.parse(ran)).toEqual(ran);
    // The fixed periods are fixed.
    expect(RetentionResponseSchema.safeParse({ ...none, retention: { ...RETENTION, guard_days: 7 } }).success).toBe(
      false,
    );
    expect(
      RetentionResponseSchema.safeParse({ ...ran, last_run: { ...ran.last_run, counts: { "bad table": 1 } } }).success,
    ).toBe(false);
    expect(
      RetentionResponseSchema.safeParse({ ...ran, last_run: { ...ran.last_run, counts: { events: -1 } } }).success,
    ).toBe(false);
  });

  it("says from when older Events go after a change", () => {
    const body = { retention: RETENTION, last_run: null, events_removed_before: "2026-10-15T09:00:00.000Z" };
    expect(UpdateRetentionResponseSchema.parse(body)).toEqual(body);
    expect(UpdateRetentionResponseSchema.safeParse({ retention: RETENTION, last_run: null }).success).toBe(false);
  });
});
