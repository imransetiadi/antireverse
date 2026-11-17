import type { CampaignFindingState, CampaignStatus } from "@antireverse/protocol";
import { Icon, type IconName } from "@/components/icons.tsx";
import { t } from "@/lib/t.ts";
import { FINDING_STATE_HELP, FINDING_STATE_LABEL, STATUS_HELP, STATUS_LABEL } from "./labels.ts";

// D-053: a glyph, a word and a colour per status — never the colour alone. Each glyph has its own silhouette, so the
// status reads in greyscale. Completed is neutral on purpose: that every check ran says nothing about the target.
const TONE: Record<CampaignStatus, string> = {
  queued: "bg-transparent text-fg-muted",
  running: "bg-current/16 text-primary",
  completed: "bg-transparent text-fg",
  stopped: "bg-current/16 text-sev-medium",
  refused: "bg-current/16 text-sev-high",
  failed: "bg-current/16 text-sev-high",
  interrupted: "bg-current/16 text-sev-medium",
};

const ICON: Record<CampaignStatus, IconName> = {
  queued: "hourglass-medium",
  running: "arrows-clockwise",
  completed: "check-circle",
  stopped: "prohibit",
  refused: "shield-slash",
  failed: "warning-circle",
  interrupted: "file-x",
};

const CHIP =
  "inline-flex h-6 items-center gap-1 rounded-control border border-current border-solid px-2 caption-1 whitespace-nowrap";

/** The status of a Campaign. The title says what it means. */
export function CampaignStatusChip({ status }: { status: CampaignStatus }) {
  return (
    <span
      data-testid="campaign-status"
      data-status={status}
      title={t(STATUS_HELP[status])}
      className={`${CHIP} ${TONE[status]}`}
    >
      <Icon name={ICON[status]} />
      {t(STATUS_LABEL[status])}
    </span>
  );
}

const STATE_TONE: Record<CampaignFindingState, string> = {
  unverified: "bg-transparent text-fg-muted",
  confirmed: "bg-current/16 text-fg",
};

const STATE_ICON: Record<CampaignFindingState, IconName> = {
  unverified: "seal-question",
  confirmed: "check-circle",
};

/** Whether one automatic repeat showed a Finding again: Unverified or Confirmed. */
export function FindingStateChip({ state }: { state: CampaignFindingState }) {
  return (
    <span
      data-testid="finding-state"
      data-state={state}
      title={t(FINDING_STATE_HELP[state])}
      className={`${CHIP} ${STATE_TONE[state]}`}
    >
      <Icon name={STATE_ICON[state]} />
      {t(FINDING_STATE_LABEL[state])}
    </span>
  );
}
