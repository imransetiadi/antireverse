import type { DecisionMode } from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";

const LABEL: Record<DecisionMode, MessageKey> = { monitor: "mode.monitor", enforce: "mode.enforce" };

// UIUX.md §4.2: monitor is always dashed and hollow, enforce is always solid — readable in greyscale.
const SHAPE: Record<DecisionMode, string> = {
  monitor: "border-dashed border-dec-monitor bg-transparent text-dec-monitor",
  enforce: "border-solid border-fg bg-fg text-bg",
};

export function ModeTag({ mode }: { mode: DecisionMode }) {
  return (
    <span
      data-testid="mode-tag"
      data-mode={mode}
      className={`inline-flex h-6 items-center rounded-control border px-2 caption-1 ${SHAPE[mode]}`}
    >
      {t(LABEL[mode])}
    </span>
  );
}
