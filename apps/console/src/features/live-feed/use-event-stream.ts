"use client";

import { ListEventsResponseSchema, type StoredEvent, StoredEventSchema } from "@antireverse/protocol";
import { useEffect, useRef, useState } from "react";
import {
  type Connection,
  type FeedState,
  flushPending,
  initialFeed,
  RENDER_INTERVAL_MS,
  receive,
  setConnection,
} from "./feed-state.ts";

/** The SSE event name of contract C2. */
const STREAM_EVENT = "security-event";

/** How long to wait before opening a new stream after the browser gave up on the old one. */
export const RECONNECT_DELAY_MS = 2_000;

/** EventSource.CLOSED. A literal, because the global does not exist during server rendering. */
const CLOSED = 2;

export interface EventStream {
  /** Newest first, at most FEED_CAP. */
  events: StoredEvent[];
  connection: Connection;
  /** When the stream last opened or delivered a message (ISO-8601); null until then. Refreshed on an error. */
  lastContact: string | null;
}

/** A message's data as a stored Event, or null when it is not one. Unknown keys are stripped by the schema. */
function parseEvent(data: unknown): StoredEvent | null {
  if (typeof data !== "string") return null;
  let value: unknown;
  try {
    value = JSON.parse(data);
  } catch {
    return null;
  }
  const parsed = StoredEventSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/**
 * The live feed of one App: the Events the server rendered, then everything the stream at `url` delivers.
 *
 * - Every message is validated; anything that is not a stored Event is ignored.
 * - Messages are queued and merged into the rendered list at most once per RENDER_INTERVAL_MS.
 * - Whenever the stream opens, the list at `listUrl` is read and merged: an Event ingested before the
 *   subscription, or while the feed was reconnecting, appears without a reload.
 * - When the list answers 401 the session is no longer accepted: `onSessionExpired` runs and the feed stops
 *   retrying. When it answers 404 the App is gone and the feed stops retrying.
 * - `connection` follows the stream: connecting → live on open → reconnecting on an error. The browser
 *   reconnects by itself after a dropped connection. It does not after an answer other than 200 — which is
 *   what the proxy gives while the API is down — so in that case a new stream is opened after
 *   RECONNECT_DELAY_MS, again and again, and the feed recovers without a reload.
 */
export function useEventStream(
  url: string,
  initialEvents: StoredEvent[],
  options: { listUrl: string; onSessionExpired: () => void },
): EventStream {
  const { listUrl } = options;
  const onSessionExpired = useRef(options.onSessionExpired);
  onSessionExpired.current = options.onSessionExpired;
  const [view, setView] = useState<FeedState>(() => initialFeed(initialEvents));
  const [lastContact, setLastContact] = useState<string | null>(null);
  // The whole state, including what is queued. Queuing does not render; `view` is what was last rendered.
  const state = useRef<FeedState>(view);

  useEffect(() => {
    let source: EventSource | undefined;
    let flushTimer: ReturnType<typeof setTimeout> | undefined;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let contactAt: number | undefined;
    /** The effect was cleaned up, or the feed gave up for good (session expired, App gone). */
    let ended = false;

    const render = (next: FeedState): void => {
      if (next === state.current) return;
      state.current = next;
      setView(next);
    };

    const flush = (): void => {
      flushTimer = undefined;
      render(flushPending(state.current));
    };

    /** Queues without rendering; the first queued Event schedules the one flush of this interval. */
    const queue = (event: StoredEvent): void => {
      state.current = receive(state.current, event);
      if (flushTimer === undefined && state.current.pending.length > 0) {
        flushTimer = setTimeout(flush, RENDER_INTERVAL_MS);
      }
    };

    const onMessage = (message: MessageEvent): void => {
      const event = parseEvent(message.data);
      if (!event) return;
      contactAt = Date.now();
      queue(event);
    };

    /** Reads the list and merges what the stream did not deliver. Resolves with the status; 0 when unreachable. */
    const catchUp = async (): Promise<number> => {
      try {
        const response = await fetch(listUrl, { cache: "no-store", headers: { accept: "application/json" } });
        if (response.ok) {
          const parsed = ListEventsResponseSchema.safeParse(await response.json());
          if (parsed.success && !ended) for (const event of parsed.data.events) queue(event);
        }
        return response.status;
      } catch {
        return 0;
      }
    };

    const disconnect = (): void => {
      if (!source) return;
      source.removeEventListener(STREAM_EVENT, onMessage);
      source.onopen = null;
      source.onerror = null;
      source.close();
      source = undefined;
    };

    const giveUp = (): void => {
      ended = true;
      clearTimeout(retryTimer);
      retryTimer = undefined;
      disconnect();
    };

    const connect = (): void => {
      retryTimer = undefined;
      if (ended) return;
      const current = new EventSource(url);
      source = current;
      current.addEventListener(STREAM_EVENT, onMessage);
      current.onopen = () => {
        contactAt = Date.now();
        render(setConnection(state.current, "live"));
        void catchUp();
      };
      current.onerror = () => {
        setLastContact(contactAt === undefined ? null : new Date(contactAt).toISOString());
        render(setConnection(state.current, "reconnecting"));
        if (current.readyState === CLOSED) {
          disconnect();
          retryTimer = setTimeout(connect, RECONNECT_DELAY_MS);
          // The stream was refused. The list says why: 401 and 404 will not get better by retrying.
          void catchUp().then((status) => {
            if (ended) return;
            if (status === 401) {
              giveUp();
              onSessionExpired.current();
            } else if (status === 404) {
              giveUp();
            }
          });
        }
      };
    };

    connect();
    return () => {
      ended = true;
      clearTimeout(flushTimer);
      clearTimeout(retryTimer);
      disconnect();
    };
  }, [url, listUrl]);

  return { events: view.events, connection: view.connection, lastContact };
}
