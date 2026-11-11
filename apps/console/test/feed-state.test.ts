// @vitest-environment node
import { describe, expect, it } from "vitest";
import {
  FEED_CAP,
  type FeedState,
  flushPending,
  initialFeed,
  RENDER_INTERVAL_MS,
  receive,
  setConnection,
} from "@/features/live-feed/feed-state.ts";
import { eventAt } from "./helpers/events.ts";

const ids = (state: FeedState): string[] => state.events.map((event) => event.event_id);

describe("constants", () => {
  it("caps the feed at 500 Events and renders at most once per 250 ms", () => {
    expect(FEED_CAP).toBe(500);
    expect(RENDER_INTERVAL_MS).toBe(250);
  });
});

describe("initialFeed", () => {
  it("starts connecting, with nothing pending", () => {
    expect(initialFeed([])).toEqual({ events: [], pending: [], connection: "connecting" });
  });

  it("orders newest first, whatever order it was given", () => {
    const a = eventAt(1_000);
    const b = eventAt(2_000);
    const c = eventAt(3_000);
    expect(ids(initialFeed([b, a, c]))).toEqual([c.event_id, b.event_id, a.event_id]);
  });

  it("orders Events received at the same instant by identifier, newest first", () => {
    const received_at = eventAt(5_000).received_at;
    const first = eventAt(1_000, { received_at });
    const second = eventAt(2_000, { received_at });
    expect(ids(initialFeed([first, second]))).toEqual([second.event_id, first.event_id]);
  });

  it("orders by arrival, like the API's list, when an older Event arrives late", () => {
    const onTime = eventAt(2_000);
    const late = eventAt(1_000, { received_at: eventAt(9_000).received_at });
    expect(ids(initialFeed([onTime, late]))).toEqual([late.event_id, onTime.event_id]);
  });

  it("does not change the array it was given, keeps one of each Event and caps at 500", () => {
    const given = Object.freeze([eventAt(1), eventAt(2), eventAt(2)]) as ReturnType<typeof eventAt>[];
    expect(ids(initialFeed(given))).toEqual([eventAt(2).event_id, eventAt(1).event_id]);

    const many = Array.from({ length: 520 }, (_unused, index) => eventAt(index));
    const feed = initialFeed(many);
    expect(feed.events).toHaveLength(500);
    expect(feed.events[0]?.event_id).toBe(eventAt(519).event_id);
    expect(feed.events.at(-1)?.event_id).toBe(eventAt(20).event_id);
  });
});

describe("receive", () => {
  it("queues an Event without showing it yet", () => {
    const shown = eventAt(1_000);
    const state = initialFeed([shown]);
    const incoming = eventAt(2_000);
    const next = receive(state, incoming);
    expect(next.pending).toEqual([incoming]);
    expect(next.events).toBe(state.events);
    expect(next.connection).toBe("connecting");
    expect(state.pending).toEqual([]);
  });

  it("ignores an event_id that is already shown or already queued", () => {
    const shown = eventAt(1_000);
    const state = initialFeed([shown]);
    expect(receive(state, { ...shown })).toBe(state);

    const queued = receive(state, eventAt(2_000));
    expect(receive(queued, eventAt(2_000))).toBe(queued);
    expect(queued.pending).toHaveLength(1);
  });
});

describe("flushPending", () => {
  it("merges what is pending, newest first, and empties the queue", () => {
    const state = initialFeed([eventAt(1_000), eventAt(3_000)]);
    const queued = receive(receive(state, eventAt(4_000)), eventAt(2_000, { received_at: eventAt(5_000).received_at }));
    const flushed = flushPending(queued);
    expect(ids(flushed)).toEqual([
      eventAt(2_000).event_id,
      eventAt(4_000).event_id,
      eventAt(3_000).event_id,
      eventAt(1_000).event_id,
    ]);
    expect(flushed.pending).toEqual([]);
    expect(flushed.connection).toBe(queued.connection);
  });

  it("caps at 500 and drops the oldest", () => {
    let state = initialFeed(Array.from({ length: 500 }, (_unused, index) => eventAt(index)));
    for (let index = 500; index < 510; index++) state = receive(state, eventAt(index));
    const flushed = flushPending(state);
    expect(flushed.events).toHaveLength(500);
    expect(flushed.events[0]?.event_id).toBe(eventAt(509).event_id);
    expect(flushed.events.at(-1)?.event_id).toBe(eventAt(10).event_id);
  });

  it("returns the same state when nothing is pending", () => {
    const state = initialFeed([eventAt(1_000)]);
    expect(flushPending(state)).toBe(state);
  });
});

describe("setConnection", () => {
  it("changes only the connection", () => {
    const state = receive(initialFeed([eventAt(1_000)]), eventAt(2_000));
    const live = setConnection(state, "live");
    expect(live.connection).toBe("live");
    expect(live.events).toBe(state.events);
    expect(live.pending).toBe(state.pending);
    expect(setConnection(live, "reconnecting").connection).toBe("reconnecting");
  });

  it("returns the same state when the connection does not change", () => {
    const state = initialFeed([]);
    expect(setConnection(state, "connecting")).toBe(state);
  });
});
