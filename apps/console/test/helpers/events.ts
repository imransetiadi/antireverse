import { EXAMPLE_STORED_EVENT, type StoredEvent } from "@antireverse/protocol";

/** 2026-11-10T08:00:00.000Z */
export const BASE_MS = Date.UTC(2026, 10, 10, 8, 0, 0);

/**
 * A valid stored Event that happened and was received `offsetMs` after `BASE_MS`. Its UUID version 7
 * carries the same instant, so identifiers sort like time. `n` keeps two Events of one instant apart.
 */
export function eventAt(offsetMs: number, overrides: Partial<StoredEvent> = {}, n = 0): StoredEvent {
  const ms = BASE_MS + offsetMs;
  const time = ms.toString(16).padStart(12, "0");
  const iso = new Date(ms).toISOString();
  return {
    ...EXAMPLE_STORED_EVENT,
    event_id: `${time.slice(0, 8)}-${time.slice(8)}-7000-8000-${n.toString(16).padStart(12, "0")}`,
    ts: iso,
    received_at: iso,
    ...overrides,
  };
}
