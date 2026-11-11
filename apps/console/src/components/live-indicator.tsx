import { type MessageKey, t } from "@/lib/t.ts";

export type LiveState = "connecting" | "live" | "reconnecting";

const LABEL: Record<LiveState, MessageKey> = {
  connecting: "live.state.connecting",
  live: "live.state.live",
  reconnecting: "live.state.reconnecting",
};

// The state is carried by the word first, then by the dot's shape (filled, hollow, dashed), then by colour.
const DOT: Record<LiveState, string> = {
  live: "live-dot-pulse border-solid border-primary bg-primary",
  reconnecting: "border-solid border-sev-medium bg-transparent",
  connecting: "border-dashed border-fg-subtle bg-transparent",
};

const WORD: Record<LiveState, string> = {
  live: "text-primary",
  reconnecting: "text-sev-medium",
  connecting: "text-fg-muted",
};

/**
 * The one live indicator of a screen (UIUX.md §8): the connection state as a word with a dot. Connection
 * changes are rare, so it is a polite status region; the Event stream itself is never a live region.
 */
export function LiveIndicator({ state }: { state: LiveState }) {
  return (
    <span
      role="status"
      data-testid="live-indicator"
      data-state={state}
      className={`inline-flex h-6 items-center gap-2 caption-1 ${WORD[state]}`}
    >
      <span aria-hidden="true" className={`inline-block size-2 rounded-full border ${DOT[state]}`} />
      {t(LABEL[state])}
    </span>
  );
}
