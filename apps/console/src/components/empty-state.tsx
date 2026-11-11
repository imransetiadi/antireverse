import type { ReactNode } from "react";
import { Icon, type IconName } from "./icons.tsx";

interface EmptyStateProps {
  /** What will appear here. */
  children: ReactNode;
  /** The one action that makes it appear. */
  action?: ReactNode;
  /** The decorative icon; the words carry the meaning. Default: a dashed circle, "nothing here yet". */
  icon?: IconName;
}

/**
 * A getting-started view: an icon, what will appear here and the one action that makes it appear (UIUX.md
 * §8, §11). Bordered all around, flat, no shadow.
 */
export function EmptyState({ children, action, icon = "circle-dashed" }: EmptyStateProps) {
  return (
    <div className="flex items-start gap-3 rounded-card border border-border-strong border-dashed p-6">
      <Icon name={icon} className="mt-0.5 size-4 text-fg-subtle" />
      <div className="flex min-w-0 flex-col items-start gap-3">
        <p className="text-fg-muted">{children}</p>
        {action}
      </div>
    </div>
  );
}
