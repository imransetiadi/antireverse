import type { TargetStatus } from "@antireverse/protocol";
import { Icon, type IconName } from "@/components/icons.tsx";
import { t } from "@/lib/t.ts";
import { TARGET_STATUS_HELP, TARGET_STATUS_LABEL } from "./labels.ts";

// D-053: a glyph, a word and a colour per status — never the colour alone. Verified takes the accent and a tint,
// Lapsed a warning colour and a tint, Pending stays a hollow chip in the muted text colour. Each glyph has its own
// silhouette (a circled check, a circled exclamation mark, an hourglass), so the status reads in greyscale.
const TONE: Record<TargetStatus, string> = {
  pending: "bg-transparent text-fg-muted",
  verified: "bg-current/16 text-primary",
  lapsed: "bg-current/16 text-sev-high",
};

const ICON: Record<TargetStatus, IconName> = {
  pending: "hourglass-medium",
  verified: "check-circle",
  lapsed: "warning-circle",
};

/** The status of a Verified Target: Pending, Verified or Lapsed. The title says what it means. */
export function TargetStatusChip({ status }: { status: TargetStatus }) {
  return (
    <span
      data-testid="target-status"
      data-status={status}
      title={t(TARGET_STATUS_HELP[status])}
      className={`inline-flex h-6 items-center gap-1 rounded-control border border-current border-solid px-2 caption-1 whitespace-nowrap ${TONE[status]}`}
    >
      <Icon name={ICON[status]} />
      {t(TARGET_STATUS_LABEL[status])}
    </span>
  );
}
