"use client";

import type { Environment } from "@antireverse/protocol";
import { useEffect } from "react";
import { useEventStream } from "@/features/live-feed/use-event-stream.ts";
import { ROUTES } from "@/lib/routes.ts";

interface ShieldWatcherProps {
  appId: string;
  environment: Environment;
  /** Runs with the received time of the earliest Event of `environment` the stream or its catch up delivered. */
  onFirstEvent: (at: string) => void;
  onSessionExpired: () => void;
}

/**
 * Follows the App's live event stream (the one the live feed uses) until Shield's first Event of the Environment
 * arrives. It renders nothing; the Set up page unmounts it once Shield is done, which closes the stream.
 */
export function ShieldWatcher({ appId, environment, onFirstEvent, onSessionExpired }: ShieldWatcherProps) {
  const { events } = useEventStream(ROUTES.stream(appId), [], { listUrl: ROUTES.events(appId), onSessionExpired });

  useEffect(() => {
    // Newest first: the last match is the earliest.
    const first = events.findLast((event) => event.environment === environment);
    if (first) onFirstEvent(first.received_at);
  }, [events, environment, onFirstEvent]);

  return null;
}
