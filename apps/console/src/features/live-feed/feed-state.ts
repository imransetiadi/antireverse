import type { StoredEvent } from "@antireverse/protocol";

// The state of the live feed, as pure functions. Incoming Events are queued by `receive` and become
// visible in batches through `flushPending`, which the hook calls at most once per RENDER_INTERVAL_MS.

export type Connection = "connecting" | "live" | "reconnecting";

export interface FeedState {
  /** What is shown: newest first, at most FEED_CAP. */
  events: StoredEvent[];
  /** Received but not shown yet. */
  pending: StoredEvent[];
  connection: Connection;
}

export const FEED_CAP = 500;
export const RENDER_INTERVAL_MS = 250;

/** Newest first, in the order of the API's Event list: by arrival, then by identifier (UUID version 7 sorts by time). */
function newestFirst(a: StoredEvent, b: StoredEvent): number {
  if (a.received_at !== b.received_at) return a.received_at < b.received_at ? 1 : -1;
  if (a.event_id !== b.event_id) return a.event_id < b.event_id ? 1 : -1;
  return 0;
}

function arrange(events: readonly StoredEvent[]): StoredEvent[] {
  const seen = new Set<string>();
  const unique: StoredEvent[] = [];
  for (const event of events) {
    if (seen.has(event.event_id)) continue;
    seen.add(event.event_id);
    unique.push(event);
  }
  return unique.sort(newestFirst).slice(0, FEED_CAP);
}

export function initialFeed(events: StoredEvent[]): FeedState {
  return { events: arrange(events), pending: [], connection: "connecting" };
}

/** Queues an Event. An `event_id` that is already shown or queued is ignored and the same state is returned. */
export function receive(state: FeedState, event: StoredEvent): FeedState {
  const known = (candidate: StoredEvent): boolean => candidate.event_id === event.event_id;
  if (state.pending.some(known) || state.events.some(known)) return state;
  return { ...state, pending: [...state.pending, event] };
}

/** Merges what is pending into what is shown: newest first, capped at FEED_CAP. Nothing pending: the same state. */
export function flushPending(state: FeedState): FeedState {
  if (state.pending.length === 0) return state;
  return { ...state, events: arrange([...state.pending, ...state.events]), pending: [] };
}

export function setConnection(state: FeedState, connection: Connection): FeedState {
  return state.connection === connection ? state : { ...state, connection };
}
