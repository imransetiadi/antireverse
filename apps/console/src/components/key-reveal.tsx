"use client";

import { useEffect, useId, useRef } from "react";
import { CopyButton } from "./copy-button.tsx";

interface KeyRevealProps {
  title: string;
  help: string;
  /** The key. It lives only in the action state that rendered this component. */
  value: string;
  /** `admin-key` or `shield-key`: the element that holds the key. */
  testId: string;
}

/**
 * A key, shown once. The value is rendered as text and can be copied; it is never written to a URL, to
 * browser storage or to a log. When it appears, focus moves to its title so that it is not missed.
 */
export function KeyReveal({ title, help, value, testId }: KeyRevealProps) {
  const titleId = useId();
  const titleRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    titleRef.current?.focus();
  }, []);

  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-2 rounded-card border border-border bg-surface p-3">
      <h2 id={titleId} ref={titleRef} tabIndex={-1} className="heading-4">
        {title}
      </h2>
      <p className="text-fg-muted">{help}</p>
      <div className="flex flex-wrap items-start gap-2">
        <code
          data-testid={testId}
          className="min-w-0 flex-1 basis-64 select-all break-all rounded-control border border-border-strong bg-bg px-2 py-2 code-3"
        >
          {value}
        </code>
        <CopyButton value={value} />
      </div>
    </section>
  );
}
