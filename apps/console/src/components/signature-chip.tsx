import type { EventSignature } from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";
import { Icon, type IconName } from "./icons.tsx";

/**
 * What the Console shows for the request signature of one request (slice 04). A valid signature counts only with
 * the body checked or absent; with a body nobody checked it is `unchecked`. A body that differs from the signed
 * one is `mismatch` (recorded as status invalid). `unreported` when the Event comes from a Shield that does not
 * report signatures (null).
 */
type SignatureState = "signed" | "unchecked" | "missing" | "invalid" | "mismatch" | "stale" | "replayed" | "unreported";

const LABEL: Record<SignatureState, MessageKey> = {
  signed: "signature.signed",
  unchecked: "signature.unchecked",
  missing: "signature.missing",
  invalid: "signature.invalid",
  mismatch: "signature.mismatch",
  stale: "signature.stale",
  replayed: "signature.replayed",
  unreported: "signature.unreported",
};

const HELP: Record<SignatureState, MessageKey> = {
  signed: "signature.help.signed",
  unchecked: "signature.help.unchecked",
  missing: "signature.help.missing",
  invalid: "signature.help.invalid",
  mismatch: "signature.help.mismatch",
  stale: "signature.help.stale",
  replayed: "signature.help.replayed",
  unreported: "signature.help.unreported",
};

// Plan 04 Global Constraints (Console): the accent for Signed, the severity colours where something is wrong, the
// subtle text colour where Shield has nothing to show.
const TONE: Record<SignatureState, string> = {
  signed: "text-primary",
  unchecked: "text-sev-medium",
  missing: "text-fg-subtle",
  invalid: "text-sev-high",
  mismatch: "text-sev-critical-text",
  stale: "text-sev-medium",
  replayed: "text-sev-critical-text",
  unreported: "text-fg-subtle",
};

// One Phosphor icon per state, each with its own silhouette so the state reads in greyscale: a signature, a pen
// nib, a dash, a prohibit sign, a crossed out file, a clock, two circling arrows and a dashed circle.
const ICON: Record<SignatureState, IconName> = {
  signed: "signature",
  unchecked: "pen-nib",
  missing: "minus",
  invalid: "prohibit",
  mismatch: "file-x",
  stale: "clock",
  replayed: "arrows-clockwise",
  unreported: "circle-dashed",
};

function stateOf(signature: EventSignature | null): SignatureState {
  if (signature === null) return "unreported";
  // A changed body is the strongest finding, whatever the status says.
  if (signature.body === "mismatch") return "mismatch";
  if (signature.status === "valid") return signature.body === "unchecked" ? "unchecked" : "signed";
  return signature.status;
}

/**
 * The request signature Shield verified for one request, as an icon, a word and a colour — never the colour
 * alone (UIUX.md §8). A request that carried a signature is tinted like a severity badge; one without is a hollow
 * chip. The title says what each word means.
 */
export function SignatureChip({ signature }: { signature: EventSignature | null }) {
  const state = stateOf(signature);
  const fill = state === "missing" || state === "unreported" ? "bg-transparent" : "bg-current/16";
  return (
    <span
      data-testid="signature-chip"
      data-signature={state}
      data-status={signature?.status ?? "unreported"}
      data-body={signature?.body ?? undefined}
      title={t(HELP[state])}
      className={`inline-flex h-6 items-center gap-1 rounded-control border border-current border-solid px-2 caption-1 whitespace-nowrap ${fill} ${TONE[state]}`}
    >
      <Icon name={ICON[state]} />
      {t(LABEL[state])}
    </span>
  );
}
