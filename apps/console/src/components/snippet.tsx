"use client";

import { CopyButton } from "./copy-button.tsx";

/** A copyable block of code under a label. Long lines scroll inside the block, never the page. */
export function Snippet({ label, code }: { label: string; code: string }) {
  return (
    <figure className="flex flex-col gap-1">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <figcaption className="caption-1 text-fg-muted">{label}</figcaption>
        <CopyButton value={code} />
      </div>
      <pre
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="overflow-x-auto rounded-control border border-border-strong bg-bg px-3 py-2 code-3"
      >
        <code>{code}</code>
      </pre>
    </figure>
  );
}
