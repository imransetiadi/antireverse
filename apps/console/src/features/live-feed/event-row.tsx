import type { StoredEvent } from "@antireverse/protocol";
import { memo } from "react";
import { AttestationChip } from "@/components/attestation-chip.tsx";
import { DecisionChip } from "@/components/decision-chip.tsx";
import { ModeTag } from "@/components/mode-tag.tsx";
import { SignatureChip } from "@/components/signature-chip.tsx";
import { formatLatency, formatTime, type StatusClass, statusClass } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";

// One Event as a table row, shared by the live feed (SCR-03) and the evidence of an Incident (SCR-05):
// fixed columns, monospace data, nothing hidden behind a hover (UIUX.md §8 Event row).

export const EVENT_COLUMNS = [
  "live.col.time",
  "live.col.decision",
  "live.col.client",
  "live.col.signature",
  "live.col.method",
  "live.col.route",
  "live.col.status",
  "live.col.latency",
  "live.col.network",
] as const;

// The status code is the information; the colour only helps to find 4xx and 5xx at a glance.
const STATUS_TONE: Record<StatusClass, string> = {
  ok: "text-fg",
  client: "text-sev-medium",
  server: "text-sev-critical-text",
};

const HEAD = "h-10 px-3 text-start caption-1 text-fg-muted whitespace-nowrap";
const CELL = "h-10 px-3 py-2 align-middle";
const DATA = `${CELL} code-3 whitespace-nowrap`;
// The first column stays in view while the table scrolls sideways inside its container (UIUX.md §13).
const STICKY = "sticky start-0 bg-bg";

/**
 * True when the Decision was only observed: Shield would have acted but did not, or no Policy is published
 * yet. An allowed request under a published Policy (`policy_version` 1 or higher) is a real outcome.
 */
function observedOnly({ action, mode, policy_version }: StoredEvent["decision"]): boolean {
  if (mode !== "monitor") return false;
  return action !== "allow" || policy_version === 0;
}

/**
 * What the Client column shows, said once above every Event table: the attestation is evidence about the
 * client, never proof that it is genuine (plan 03, Review Focus 5).
 */
export function ClientNote() {
  return (
    <p data-testid="client-note" className="body-5 text-fg-muted">
      {t("live.client.note")}
    </p>
  );
}

/** The header row of an Event table. */
export function EventTableHead() {
  return (
    <thead>
      <tr className="border-border border-b">
        {EVENT_COLUMNS.map((column, index) => (
          <th
            key={column}
            scope="col"
            className={`${HEAD} ${index === 0 ? STICKY : ""} ${column === "live.col.latency" ? "text-end" : ""}`}
          >
            {t(column)}
            {column === "live.col.time" ? <span className="text-fg-subtle"> {t("live.col.time.zone")}</span> : null}
          </th>
        ))}
      </tr>
    </thead>
  );
}

export const EventRow = memo(function EventRow({ event }: { event: StoredEvent }) {
  const time = formatTime(event.ts);
  const status = statusClass(event.request.status);
  // UIUX.md §4.2: observed is dashed and carries the Monitor mark; enforced is solid and carries none.
  const observed = observedOnly(event.decision);
  return (
    <tr data-testid="event-row" data-event-id={event.event_id} className="border-border border-b">
      <td className={`${DATA} ${STICKY} text-fg-subtle`}>
        <time dateTime={time.iso} title={time.iso}>
          {time.text}
        </time>
      </td>
      <td className={`${CELL} whitespace-nowrap`}>
        <span className="inline-flex items-center gap-2">
          <DecisionChip action={event.decision.action} mode={observed ? "monitor" : "enforce"} />
          {observed ? <ModeTag mode="monitor" /> : null}
        </span>
      </td>
      <td className={`${CELL} whitespace-nowrap`}>
        <AttestationChip attestation={event.attestation} />
      </td>
      <td className={`${CELL} whitespace-nowrap`}>
        <SignatureChip signature={event.signature} />
      </td>
      <td className={DATA}>{event.request.method}</td>
      {/* A route is never cut off: a long one wraps, so nothing is hidden behind a hover. For a blocked
          request the Event carries the Rule's path pattern, never the concrete path. */}
      <td className={`${CELL} min-w-48 break-all code-3`}>{event.request.route}</td>
      <td className={DATA}>
        <span data-status={status} className={STATUS_TONE[status]}>
          {event.request.status}
        </span>
      </td>
      <td className={`${DATA} text-end`}>{formatLatency(event.request.latency_ms)}</td>
      <td className={`${DATA} text-fg-muted`}>{event.actor.ip_prefix ?? t("live.network.unknown")}</td>
    </tr>
  );
});
