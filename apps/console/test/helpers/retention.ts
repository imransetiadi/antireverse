import type { OrganizationRetention, RetentionRun } from "@antireverse/protocol";

/** Slice 18c: the retention of an Organization and a run of the retention job, shared by the retention tests. */
export const RETENTION: OrganizationRetention = {
  event_retention_days: 30,
  guard_days: 30,
  evidence_days: 395,
  artifact_days: 30,
};

export const RETENTION_RUN: RetentionRun = {
  ran_at: "2026-11-14T03:00:00.000Z",
  complete: true,
  counts: { events: 1200, containments: 1, incidents: 3, detections: 9, alert_deliveries: 4, assessments: 2 },
};
