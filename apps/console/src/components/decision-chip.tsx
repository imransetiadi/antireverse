import type { DecisionAction, DecisionMode } from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";
import { Icon, type IconName } from "./icons.tsx";

const LABEL: Record<DecisionAction, MessageKey> = {
  allow: "decision.allow",
  monitor: "decision.monitor",
  challenge: "decision.challenge",
  throttle: "decision.throttle",
  block: "decision.block",
  deceive: "decision.deceive",
};

const TONE: Record<DecisionAction, string> = {
  allow: "text-dec-allow",
  monitor: "text-dec-monitor",
  challenge: "text-dec-challenge",
  throttle: "text-dec-throttle",
  block: "text-dec-block",
  deceive: "text-dec-deceive",
};

// One Phosphor icon per Decision (UIUX.md §4.2): check, eye, seal with a question mark, hourglass, prohibit
// sign and mask.
const ICON: Record<DecisionAction, IconName> = {
  allow: "check",
  monitor: "eye",
  challenge: "seal-question",
  throttle: "hourglass-medium",
  block: "prohibit",
  deceive: "mask-happy",
};

/**
 * The outcome of a Decision as an icon, a word and a colour. In monitor mode the chip is dashed and
 * hollow — the outcome was observed, not enforced; in enforce mode it is solid (UIUX.md §8).
 */
export function DecisionChip({ action, mode }: { action: DecisionAction; mode: DecisionMode }) {
  const outline = mode === "monitor" ? "border-dashed bg-transparent" : "border-solid bg-current/16";
  return (
    <span
      data-testid="decision-chip"
      data-decision={action}
      data-mode={mode}
      className={`inline-flex h-6 items-center gap-1 rounded-control border border-current px-2 caption-1 ${outline} ${TONE[action]}`}
    >
      <Icon name={ICON[action]} />
      {t(LABEL[action])}
    </span>
  );
}
