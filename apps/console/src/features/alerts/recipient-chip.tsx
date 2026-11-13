import type { AlertRecipientStatus } from "@antireverse/protocol";
import { Icon, type IconName } from "@/components/icons.tsx";
import { type MessageKey, t } from "@/lib/t.ts";

const LABEL: Record<AlertRecipientStatus, MessageKey> = {
  confirmed: "alerts.recipient.confirmed",
  pending: "alerts.recipient.pending",
};
const HELP: Record<AlertRecipientStatus, MessageKey> = {
  confirmed: "alerts.recipient.help.confirmed",
  pending: "alerts.recipient.help.pending",
};
// The accent for Confirmed, the medium severity colour for Pending: it receives nothing until it confirms.
const TONE: Record<AlertRecipientStatus, string> = {
  confirmed: "text-primary bg-current/16",
  pending: "text-sev-medium bg-transparent",
};
// A circled check and an hourglass: each its own silhouette, so the status reads in greyscale.
const ICON: Record<AlertRecipientStatus, IconName> = {
  confirmed: "check-circle",
  pending: "hourglass-medium",
};

/**
 * Whether a recipient of an email channel confirmed its address, as an icon, a word and a colour — never the
 * colour alone (UIUX.md §8). Confirmed is tinted like a badge; Pending is a hollow chip. The title says what each
 * word means.
 */
export function RecipientChip({ status }: { status: AlertRecipientStatus }) {
  return (
    <span
      data-testid="recipient-status"
      data-status={status}
      title={t(HELP[status])}
      className={`inline-flex h-6 items-center gap-1 rounded-control border border-current border-solid px-2 caption-1 whitespace-nowrap ${TONE[status]}`}
    >
      <Icon name={ICON[status]} />
      {t(LABEL[status])}
    </span>
  );
}
