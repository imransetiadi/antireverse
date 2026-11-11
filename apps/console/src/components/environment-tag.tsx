import type { Environment } from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";

const LABEL: Record<Environment, MessageKey> = {
  production: "environment.production",
  staging: "environment.staging",
  development: "environment.development",
};

// Colour-coded and always worded (UIUX.md §5): the word carries the meaning, the colour only helps.
const TONE: Record<Environment, string> = {
  production: "border-sev-medium text-sev-medium",
  staging: "border-sev-low text-sev-low",
  development: "border-border-strong text-fg-muted",
};

export function EnvironmentTag({ environment }: { environment: Environment }) {
  return (
    <span
      data-testid="environment-tag"
      data-environment={environment}
      className={`inline-flex h-6 items-center rounded-control border border-solid px-2 caption-1 ${TONE[environment]}`}
    >
      {t(LABEL[environment])}
    </span>
  );
}
