import { Icon, type IconName } from "@/components/icons.tsx";
import { type MessageKey, t } from "@/lib/t.ts";
import type { ConfirmOutcome as Outcome } from "./confirm-result.ts";

const TEXT: Record<Outcome, MessageKey> = {
  confirmed: "confirm.confirmed",
  invalid: "confirm.invalid",
  busy: "confirm.busy",
  unavailable: "confirm.unavailable",
};

// The accent where it worked, a severity colour where it did not; an icon of its own for each, so that the outcome
// never rests on colour alone (UIUX.md §8).
const TONE: Record<Outcome, string> = {
  confirmed: "text-primary",
  invalid: "text-sev-critical-text",
  busy: "text-sev-medium",
  unavailable: "text-sev-medium",
};
const ICON: Record<Outcome, IconName> = {
  confirmed: "check-circle",
  invalid: "prohibit",
  busy: "hourglass-medium",
  unavailable: "warning-circle",
};

/** The outcome of a confirmation link, in one sentence. */
export function ConfirmOutcome({ outcome }: { outcome: Outcome }) {
  return (
    <p data-testid="confirm-outcome" data-outcome={outcome} className="flex items-start gap-2 body-3 text-fg">
      <span className={`mt-1 ${TONE[outcome]}`}>
        <Icon name={ICON[outcome]} />
      </span>
      <span>{t(TEXT[outcome])}</span>
    </p>
  );
}
