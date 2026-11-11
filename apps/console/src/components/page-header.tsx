import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  /** A caption line above the title, e.g. the App a screen belongs to. */
  eyebrow?: ReactNode;
  /** Tags that belong to the title, e.g. the Environment. */
  tags?: ReactNode;
  /** The screen's actions, e.g. "New App". */
  actions?: ReactNode;
}

export function PageHeader({ title, eyebrow, tags, actions }: PageHeaderProps) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        {eyebrow ? <p className="break-words caption-1 text-fg-muted">{eyebrow}</p> : null}
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="break-words heading-2">{title}</h1>
          {tags}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
