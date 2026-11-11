import type { DecisionMode } from "@antireverse/protocol";
import { Icon, type IconName } from "@/components/icons.tsx";
import { type MessageKey, t } from "@/lib/t.ts";

const LABEL: Record<DecisionMode, MessageKey> = { monitor: "mode.monitor", enforce: "mode.enforce" };

// D-053: each mode has its own glyph, word and colour, and stays readable in greyscale. Monitor is dashed and
// hollow with the eye (it records, never refuses); enforce is solid with the shield in the block colour (it
// refuses a matching request).
const SHAPE: Record<DecisionMode, string> = {
  monitor: "border-dashed bg-transparent text-dec-monitor",
  enforce: "border-solid bg-current/16 text-dec-block",
};
const ICON: Record<DecisionMode, IconName> = { monitor: "eye", enforce: "shield-check" };

/** The mode of a virtual patch: Monitor or Enforce, as a glyph, a word and a colour. */
export function PatchModeChip({ mode }: { mode: DecisionMode }) {
  return (
    <span
      data-testid="patch-mode"
      data-mode={mode}
      className={`inline-flex h-6 items-center gap-1 rounded-control border border-current px-2 caption-1 whitespace-nowrap ${SHAPE[mode]}`}
    >
      <Icon name={ICON[mode]} />
      {t(LABEL[mode])}
    </span>
  );
}

/** "Not shipped: bundle budget": an active patch the signed bundle had no room for. */
export function NotShippedTag() {
  return (
    <span
      data-testid="patch-not-shipped"
      className="inline-flex h-6 items-center gap-1 rounded-control border border-sev-medium border-dotted px-2 caption-1 whitespace-nowrap text-sev-medium"
    >
      <Icon name="warning" />
      {t("patch.notShipped")}
    </span>
  );
}
