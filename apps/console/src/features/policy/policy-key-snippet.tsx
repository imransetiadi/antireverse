"use client";

import { CopyButton } from "@/components/copy-button.tsx";
import { POLICY_KEY_LINE_END, POLICY_KEY_LINE_START, policyKeyLine } from "@/features/apps/shield-snippet.ts";
import { t } from "@/lib/t.ts";

/**
 * The policy public key as the line that hands it to the server, with a button that copies that line.
 * The key is public — Shield only verifies with it — so it is rendered like any other text.
 */
export function PolicyKeySnippet({ publicKey, label = t("policy.key.env") }: { publicKey: string; label?: string }) {
  return (
    <figure className="flex flex-col gap-1">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <figcaption className="caption-1 text-fg-muted">{label}</figcaption>
        <CopyButton value={policyKeyLine(publicKey)} />
      </div>
      <pre
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="overflow-x-auto rounded-control border border-border-strong bg-bg px-3 py-2 code-3"
      >
        <code>
          {POLICY_KEY_LINE_START}
          <span data-testid="policy-public-key">{publicKey}</span>
          {POLICY_KEY_LINE_END}
        </code>
      </pre>
    </figure>
  );
}
