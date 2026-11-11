import type { ContainmentStatus } from "@antireverse/protocol";
import { Icon, type IconName } from "@/components/icons.tsx";
import { type MessageKey, t } from "@/lib/t.ts";

const STATUS_LABEL: Record<ContainmentStatus, MessageKey> = {
  active: "blocks.status.active",
  expired: "blocks.status.expired",
  lifted: "blocks.status.lifted",
};

// The word carries the status; outline and icon only help, and tell the three apart in greyscale: a solid
// outline and a closed padlock while it blocks, dotted with a clock once it expired, dashed with an open padlock
// once someone lifted it.
const OUTLINE: Record<ContainmentStatus, string> = {
  active: "border-solid border-fg text-fg",
  expired: "border-dotted border-border-strong text-fg-subtle",
  lifted: "border-dashed border-fg-muted text-fg-muted",
};

const ICON: Record<ContainmentStatus, IconName> = {
  active: "lock",
  expired: "clock",
  lifted: "lock-open",
};

const TAG = "inline-flex h-6 items-center gap-1 rounded-control border px-2 caption-1";

/** The status of a block: Active, Expired or Lifted — a word and an icon, never colour alone. */
export function ContainmentStatusTag({ status }: { status: ContainmentStatus }) {
  return (
    <span data-testid="block-status" data-status={status} className={`${TAG} ${OUTLINE[status]}`}>
      <Icon name={ICON[status]} />
      {t(STATUS_LABEL[status])}
    </span>
  );
}

/** "Contained": the Incident has an active block. A closed padlock and the word. */
export function ContainedTag() {
  return (
    <span data-testid="incident-contained" className={`${TAG} border-fg border-solid text-fg`}>
      <Icon name="lock" />
      {t("containment.contained")}
    </span>
  );
}
