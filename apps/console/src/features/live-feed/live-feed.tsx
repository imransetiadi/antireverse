"use client";

import type { StoredEvent } from "@antireverse/protocol";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { Icon } from "@/components/icons.tsx";
import { LiveIndicator } from "@/components/live-indicator.tsx";
import { formatTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { ClientNote, EVENT_COLUMNS as COLUMNS, EventRow, EventTableHead } from "./event-row.tsx";
import { useEventStream } from "./use-event-stream.ts";

interface LiveFeedProps {
  appId: string;
  appName: string;
  /** The latest Events, fetched by the server when the page was rendered. */
  initialEvents: StoredEvent[];
  /** Virtual patch titles by id (slice 20), to name the patch of a Decision. */
  patchTitles?: Readonly<Record<string, string>> | undefined;
  /** Runs when the API no longer accepts the session. Default: go to sign-in. */
  onSessionExpired?: () => void;
}

function goToSignIn(): void {
  window.location.assign(ROUTES.signInExpired);
}

/**
 * SCR-03 Live: the Events of one App, newest first, as they arrive. The connection indicator is the only
 * status region; the table is deliberately not a live region (UIUX.md §12).
 */
export function LiveFeed({ appId, appName, initialEvents, patchTitles, onSessionExpired = goToSignIn }: LiveFeedProps) {
  const { events, connection, lastContact } = useEventStream(ROUTES.stream(appId), initialEvents, {
    listUrl: ROUTES.events(appId),
    onSessionExpired,
  });
  const newest = events[0];
  const caption = t("live.caption", { app: appName });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex min-h-6 flex-wrap items-center gap-3">
        <LiveIndicator state={connection} />
        {newest ? <EnvironmentTag environment={newest.environment} /> : null}
        {connection === "reconnecting" && lastContact ? (
          <span data-testid="last-updated" className="body-5 text-fg-subtle">
            {t("live.updated", { time: formatTime(lastContact).text })}
          </span>
        ) : null}
      </div>
      <ClientNote />
      {/* The table scrolls sideways inside this region on a narrow screen; the keyboard can reach it. */}
      <section
        aria-label={caption}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="overflow-x-auto"
      >
        <table className="w-full border-collapse body-5">
          <caption className="sr-only">{caption}</caption>
          <EventTableHead />
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={COLUMNS.length} className="px-3 py-6 body-4 text-fg-muted">
                  <span className="inline-flex items-center gap-2">
                    <Icon name="circle-dashed" className="size-4 text-fg-subtle" />
                    <span data-testid="feed-waiting" className="break-words">
                      {t("live.waiting", { app: appName })}
                    </span>
                  </span>
                </td>
              </tr>
            ) : (
              events.map((event) => <EventRow key={event.event_id} event={event} patchTitles={patchTitles} />)
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
