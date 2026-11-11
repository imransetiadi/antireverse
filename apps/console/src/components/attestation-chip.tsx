import type { EventAttestation } from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";
import { Icon, type IconName } from "./icons.tsx";

/**
 * What the Console shows for the attestation of one request: the verdict of a valid token, the status of any
 * other, or `unreported` when the Event comes from a Shield that does not report attestation (null).
 */
type AttestationState = "trusted" | "suspect" | "hostile" | "missing" | "invalid" | "expired" | "unreported";

const LABEL: Record<AttestationState, MessageKey> = {
  trusted: "attestation.trusted",
  suspect: "attestation.suspect",
  hostile: "attestation.hostile",
  missing: "attestation.missing",
  invalid: "attestation.invalid",
  expired: "attestation.expired",
  unreported: "attestation.unreported",
};

const HELP: Record<AttestationState, MessageKey> = {
  trusted: "attestation.help.trusted",
  suspect: "attestation.help.suspect",
  hostile: "attestation.help.hostile",
  missing: "attestation.help.missing",
  invalid: "attestation.help.invalid",
  expired: "attestation.help.expired",
  unreported: "attestation.help.unreported",
};

// Plan 03 Global Constraints (Console): the accent for Trusted, the severity colours for Suspect, Hostile
// and Invalid, the subtle text colour where Shield has no verdict to show.
const TONE: Record<AttestationState, string> = {
  trusted: "text-primary",
  suspect: "text-sev-medium",
  hostile: "text-sev-critical-text",
  missing: "text-fg-subtle",
  invalid: "text-sev-high",
  expired: "text-fg-subtle",
  unreported: "text-fg-subtle",
};

// One Phosphor icon per state, each with its own silhouette so the state reads in greyscale: three shields
// (check, exclamation mark, slashed), a dash, a prohibit sign, a clock counting down and a dashed circle.
const ICON: Record<AttestationState, IconName> = {
  trusted: "shield-check",
  suspect: "shield-warning",
  hostile: "shield-slash",
  missing: "minus",
  invalid: "prohibit",
  expired: "clock-countdown",
  unreported: "circle-dashed",
};

function stateOf(attestation: EventAttestation | null): AttestationState {
  if (attestation === null) return "unreported";
  if (attestation.status !== "valid") return attestation.status;
  // The protocol sets a verdict exactly when the token is valid; without one, claim nothing.
  return attestation.verdict ?? "unreported";
}

/**
 * The Guard attestation Shield verified for one request, as an icon, a word and a colour — never the colour
 * alone (UIUX.md §8). A verdict is evidence about the client, not proof: the title says what each word means.
 * A verdict is tinted like a severity badge; a request without one is a hollow chip. The risk of a verdict
 * follows the chip as a small number.
 */
export function AttestationChip({ attestation }: { attestation: EventAttestation | null }) {
  const state = stateOf(attestation);
  const verdict = state === "trusted" || state === "suspect" || state === "hostile" ? state : null;
  const fill = verdict ? "bg-current/16" : "bg-transparent";
  const risk = verdict ? attestation?.risk : null;
  return (
    <span className="inline-flex items-center gap-2">
      <span
        data-testid="attestation-chip"
        data-attestation={state}
        data-status={attestation?.status ?? "unreported"}
        data-verdict={verdict ?? undefined}
        title={t(HELP[state])}
        className={`inline-flex h-6 items-center gap-1 rounded-control border border-current border-solid px-2 caption-1 whitespace-nowrap ${fill} ${TONE[state]}`}
      >
        <Icon name={ICON[state]} />
        {t(LABEL[state])}
      </span>
      {risk === null || risk === undefined ? null : (
        <span data-testid="attestation-risk" className="code-3 text-fg-muted whitespace-nowrap">
          {t("attestation.risk", { risk: String(risk) })}
        </span>
      )}
    </span>
  );
}
