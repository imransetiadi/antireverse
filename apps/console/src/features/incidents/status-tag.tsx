import type { IncidentStatus } from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";

export const STATUS_LABEL: Record<IncidentStatus, MessageKey> = {
  open: "incident.status.open",
  acknowledged: "incident.status.acknowledged",
  resolved: "incident.status.resolved",
};

// The word carries the status; the outline only helps: solid while it needs someone, dashed while someone
// has it, faint once it is over. Readable in greyscale.
const SHAPE: Record<IncidentStatus, string> = {
  open: "border-solid border-fg text-fg",
  acknowledged: "border-dashed border-fg-muted text-fg-muted",
  resolved: "border-dotted border-border-strong text-fg-subtle",
};

/** The status of an Incident: Open, Acknowledged or Resolved. */
export function IncidentStatusTag({ status }: { status: IncidentStatus }) {
  return (
    <span
      data-testid="incident-status"
      data-status={status}
      className={`inline-flex h-6 items-center rounded-control border px-2 caption-1 ${SHAPE[status]}`}
    >
      {t(STATUS_LABEL[status])}
    </span>
  );
}
