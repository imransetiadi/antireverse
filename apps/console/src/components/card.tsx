import type { ComponentProps } from "react";

/** A panel: surface step and a decorative border instead of a shadow (UIUX.md §4.4). */
export function Card({ className, ...rest }: ComponentProps<"div">) {
  return <div className={`rounded-card border border-border bg-surface p-3 ${className ?? ""}`.trim()} {...rest} />;
}
