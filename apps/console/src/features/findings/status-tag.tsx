import type { FindingStatus } from "@antireverse/protocol";
import { Icon, type IconName } from "@/components/icons.tsx";
import { t } from "@/lib/t.ts";
import { STATUS_LABEL } from "./labels.ts";

// The word carries the status; the icon and the outline only help, so it reads in greyscale: a solid outline
// and a shield while it needs a fix, a dashed one while someone decided to ignore it, a faint one once fixed, and
// a voided document in its own colour once the advisory no longer covers the version (withdrawn, D-060).
const SHAPE: Record<FindingStatus, string> = {
  open: "border-solid border-fg text-fg",
  ignored: "border-dashed border-fg-muted text-fg-muted",
  fixed: "border-dotted border-border-strong text-fg-subtle",
  withdrawn: "border-solid border-finding-withdrawn text-finding-withdrawn",
};

const ICON: Record<FindingStatus, IconName> = {
  open: "shield-warning",
  ignored: "eye-slash",
  fixed: "check-circle",
  withdrawn: "file-x",
};

/** The status of a Finding: Open, Fixed, Ignored or Withdrawn, as an icon and a word. */
export function FindingStatusTag({ status }: { status: FindingStatus }) {
  return (
    <span
      data-testid="finding-status"
      data-status={status}
      className={`inline-flex h-6 items-center gap-1 rounded-control border px-2 caption-1 ${SHAPE[status]}`}
    >
      <Icon name={ICON[status]} />
      {t(STATUS_LABEL[status])}
    </span>
  );
}
