import type { FindingSeverity, Severity } from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";
import { Icon, type IconName } from "./icons.tsx";

/** An Incident's severity, or a Finding's (slice 19), which adds Unknown: an advisory without a rating. */
export type BadgeSeverity = Severity | FindingSeverity;

const LABEL: Record<BadgeSeverity, MessageKey> = {
  critical: "severity.critical",
  high: "severity.high",
  medium: "severity.medium",
  low: "severity.low",
  info: "severity.info",
  unknown: "severity.unknown",
};

// UIUX.md §4.2: the text colour of each severity. Critical text uses the lighter text token for contrast.
const TONE: Record<BadgeSeverity, string> = {
  critical: "text-sev-critical-text",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-sev-info",
  // Unknown shares the neutral Info colour; its own shape and word tell the two apart.
  unknown: "text-sev-info",
};

// One Phosphor icon per severity (UIUX.md §4.2), each with its own silhouette so the severity reads in
// greyscale: octagon, triangle, circle with a bar, circle with an "i", an empty circle for Info and a circle
// with a question mark for Unknown.
const ICON: Record<BadgeSeverity, IconName> = {
  critical: "warning-octagon",
  high: "warning",
  medium: "warning-circle",
  low: "info",
  info: "circle",
  unknown: "question",
};

/**
 * The severity of an Incident or a Finding as an icon, a word and a colour — never the colour alone (UIUX.md §8).
 * One size in tables and headers: the colour at 16 % over the surface with coloured text.
 */
export function SeverityBadge({ severity, testId = "severity-badge" }: { severity: BadgeSeverity; testId?: string }) {
  return (
    <span
      data-testid={testId}
      data-severity={severity}
      className={`inline-flex h-6 items-center gap-1 rounded-control border border-current border-solid bg-current/16 px-2 caption-1 ${TONE[severity]}`}
    >
      <Icon name={ICON[severity]} />
      {t(LABEL[severity])}
    </span>
  );
}
