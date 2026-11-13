"use client";

import { useEffect, useRef } from "react";
import { t } from "@/lib/t.ts";
import type { DataQuery } from "./query.ts";

/**
 * What Data controls says first (slice 18b): why another page sent the person here (the deletion is pending), or that
 * a deletion was just requested or cancelled — announced and focused, as the result of the person's own action. Each
 * is said only while it is true (`pending` is the state the API gave): an old, shared or bookmarked address that no
 * longer matches says nothing (review 18b, L1).
 */
export function DataNotices({ query, pending }: { query: DataQuery; pending: boolean }) {
  const done = useRef<HTMLParagraphElement>(null);
  const doneNow = query.done === (pending ? "requested" : "cancelled") ? query.done : undefined;
  const blocked = query.blocked && pending && doneNow === undefined;
  useEffect(() => {
    if (doneNow !== undefined) done.current?.focus();
  }, [doneNow]);

  return (
    <>
      {blocked ? (
        <p
          role="alert"
          data-testid="data-blocked"
          className="max-w-3xl rounded-card border border-destructive p-3 body-4 text-fg"
        >
          {t("data.blocked")}
        </p>
      ) : null}
      {doneNow !== undefined ? (
        <p
          ref={done}
          tabIndex={-1}
          role="status"
          data-testid="data-done"
          className="max-w-3xl rounded-card border border-border p-3 body-4 text-fg"
        >
          {t(doneNow === "requested" ? "data.done.requested" : "data.done.cancelled")}
        </p>
      ) : null}
    </>
  );
}
