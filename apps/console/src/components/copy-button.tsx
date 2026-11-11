"use client";

import { useEffect, useRef, useState } from "react";
import { t } from "@/lib/t.ts";
import { Button } from "./button.tsx";

const COPIED_FOR_MS = 2_000;

type CopyState = "idle" | "copied" | "failed";

/** Copies `value` to the clipboard — and nowhere else — and answers "Copy" with "Copied" for two seconds. */
export function CopyButton({ value }: { value: string }) {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  async function copy(): Promise<void> {
    clearTimeout(timer.current);
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
      timer.current = setTimeout(() => setState("idle"), COPIED_FOR_MS);
    } catch {
      // No clipboard permission, or a page that is not a secure context.
      setState("failed");
    }
  }

  return (
    <span className="inline-flex flex-col items-end gap-1">
      {/* A fixed minimum width keeps the layout still when the label changes. */}
      <Button variant="secondary" className="min-w-20" onClick={copy}>
        {state === "copied" ? t("copied") : t("copy")}
      </Button>
      {state === "failed" ? (
        <span role="alert" className="body-5 text-sev-critical-text">
          {t("copy.failed")}
        </span>
      ) : null}
    </span>
  );
}
