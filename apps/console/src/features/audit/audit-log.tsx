"use client";

import type { App, AuditEntry } from "@antireverse/protocol";
import { Fragment, type ReactNode, useEffect, useId, useRef, useState, useTransition } from "react";
import { loadMoreAuditAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { ACTION_LABEL, TARGET_LABEL } from "./labels.ts";
import type { AuditQuery } from "./query.ts";

const HEAD = "h-10 px-3 text-start caption-1 text-fg-muted whitespace-nowrap";
const CELL = "px-3 py-2 align-top";
const MONO = "code-3 break-all";
const STICKY = "sticky start-0 bg-bg";
// Details comes right after the time, so that opening an entry never scrolls the table sideways.
const COLUMNS = [
  "audit.col.details",
  "audit.col.action",
  "audit.col.app",
  "audit.col.target",
  "audit.col.actor",
  "audit.col.reason",
  "audit.col.summary",
] as const;

interface AuditLogProps {
  /** The first page, newest first. */
  entries: readonly AuditEntry[];
  /** The `next_cursor` of the first page: null when it is the last. */
  nextCursor: string | null;
  /** The filters of the page's address, sent again with every "Load more". */
  query: AuditQuery;
  /** The Organization's Apps, to name an entry's App. */
  apps: ReadonlyArray<Pick<App, "id" | "name">>;
  /** True when the address narrows the log: the empty state then says so. */
  filtered: boolean;
}

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="caption-1 text-fg-muted">{term}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

/** What an entry holds beyond its row: its place in the chain and the ids that let anyone check it. */
function EntryDetails({ entry, id }: { entry: AuditEntry; id: string }) {
  const time = formatDateTime(entry.at);
  return (
    <section
      id={id}
      aria-labelledby={`${id}-title`}
      data-testid="audit-details"
      className="flex flex-col gap-3 rounded-card border border-border bg-surface p-3"
    >
      <h3 id={`${id}-title`} className="heading-6">
        {t("audit.details.title", { seq: entry.seq })}
      </h3>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
        <Fact term={t("audit.details.seq")}>
          <span data-testid="audit-detail-seq" className={MONO}>
            {entry.seq}
          </span>
        </Fact>
        <Fact term={t("audit.details.at")}>
          <time dateTime={time.iso} className={MONO}>
            {entry.at}
          </time>
        </Fact>
        <Fact term={t("audit.details.id")}>
          <span data-testid="audit-detail-id" className={MONO}>
            {entry.id}
          </span>
        </Fact>
        <Fact term={t("audit.details.actor")}>
          <span className={MONO}>{entry.actor.key_id}</span>
        </Fact>
        <Fact term={t("audit.details.target")}>
          <span className={MONO}>{`${entry.target.kind} ${entry.target.id}`}</span>
        </Fact>
        <Fact term={t("audit.details.request")}>
          <span data-testid="audit-detail-request" className={MONO}>
            {entry.request_id}
          </span>
        </Fact>
        <Fact term={t("audit.details.prev")}>
          <span data-testid="audit-detail-prev" className={MONO}>
            {entry.prev_hash}
          </span>
        </Fact>
        <Fact term={t("audit.details.hash")}>
          <span data-testid="audit-detail-hash" className={MONO}>
            {entry.hash}
          </span>
        </Fact>
      </dl>
    </section>
  );
}

/**
 * Settings → Audit log (slice 18a, SCR-13): every entry newest first — time, the action in words, App, target, the
 * actor's key id, reason and summary — with each entry's sequence and hashes behind a disclosure, and "Load more",
 * which reads the next page with the same filters and appends it.
 */
export function AuditLog({ entries: first, nextCursor: firstCursor, query, apps, filtered }: AuditLogProps) {
  const [entries, setEntries] = useState<readonly AuditEntry[]>(first);
  const [cursor, setCursor] = useState(firstCursor);
  const [failure, setFailure] = useState<string | null>(null);
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set());
  const [pending, startTransition] = useTransition();
  // After "Load more", the focus goes to the first new row (or to the end message when the page was empty), so that
  // it never falls back to the page when the button is disabled or goes away.
  const [focusTarget, setFocusTarget] = useState<string | null>(null);
  const endRef = useRef<HTMLParagraphElement>(null);
  const baseId = useId();
  useEffect(() => {
    if (focusTarget === null) return;
    const target = focusTarget === "end" ? endRef.current : document.getElementById(focusTarget);
    target?.focus();
  }, [focusTarget]);
  const names = new Map(apps.map((app) => [app.id, app.name]));

  if (entries.length === 0) {
    return (
      <div data-testid="audit-empty">
        <EmptyState>{t(filtered ? "audit.empty.filtered" : "audit.empty")}</EmptyState>
      </div>
    );
  }

  const toggle = (id: string) =>
    setOpen((current) => {
      const next = new Set(current);
      if (!next.delete(id)) next.add(id);
      return next;
    });

  const loadMore = () => {
    if (cursor === null) return;
    startTransition(async () => {
      const answer = await loadMoreAuditAction(query, cursor);
      if (answer.ok) {
        setFailure(null);
        setEntries((current) => [...current, ...answer.entries]);
        setCursor(answer.nextCursor);
        const first = answer.entries[0];
        setFocusTarget(first === undefined ? "end" : `${baseId}-${first.id}-row`);
      } else {
        setFailure(answer.message);
      }
    });
  };

  return (
    <div className="flex flex-col gap-3">
      <section
        aria-label={t("audit.caption")}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="overflow-x-auto"
      >
        <table className="w-full border-collapse body-5">
          <caption className="sr-only">{t("audit.caption")}</caption>
          <thead>
            <tr className="border-border border-b">
              <th scope="col" className={`${HEAD} ${STICKY}`}>
                {t("audit.col.time")}
                <span className="text-fg-subtle"> {t("live.col.time.zone")}</span>
              </th>
              {COLUMNS.map((column) => (
                <th key={column} scope="col" className={HEAD}>
                  {t(column)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => {
              const time = formatDateTime(entry.at);
              const detailsId = `${baseId}-${entry.id}`;
              const expanded = open.has(entry.id);
              const app = entry.app_id === undefined ? t("audit.app.none") : (names.get(entry.app_id) ?? entry.app_id);
              return (
                <Fragment key={entry.id}>
                  <tr
                    data-testid="audit-row"
                    data-seq={entry.seq}
                    data-action={entry.action}
                    className={expanded ? "" : "border-border border-b"}
                  >
                    <th
                      scope="row"
                      id={`${detailsId}-row`}
                      // Focusable by script only: "Load more" moves the focus here.
                      tabIndex={-1}
                      className={`${CELL} ${STICKY} text-start whitespace-nowrap`}
                    >
                      <time data-testid="audit-time" dateTime={time.iso} title={time.iso} className="code-3">
                        {time.text}
                      </time>
                    </th>
                    <td className={CELL}>
                      <Button
                        variant="quiet"
                        aria-expanded={expanded}
                        aria-controls={detailsId}
                        // Each button names its entry: the row's time and action are read with it.
                        aria-describedby={`${detailsId}-row ${detailsId}-action`}
                        onClick={() => toggle(entry.id)}
                        data-testid="audit-toggle"
                      >
                        {t(expanded ? "audit.details.hide" : "audit.details.show")}
                      </Button>
                    </td>
                    <td id={`${detailsId}-action`} data-testid="audit-action" className={`${CELL} min-w-32 body-4`}>
                      {t(ACTION_LABEL[entry.action])}
                    </td>
                    <td
                      data-testid="audit-app"
                      className={`${CELL} min-w-24 ${names.has(entry.app_id ?? "") || entry.app_id === undefined ? "break-words" : MONO}`}
                    >
                      {app}
                    </td>
                    <td data-testid="audit-target" className={`${CELL} min-w-40`}>
                      <span className="flex flex-col gap-0.5">
                        <span className="caption-1 text-fg-muted">{t(TARGET_LABEL[entry.target.kind])}</span>
                        <span className={MONO}>{entry.target.id}</span>
                      </span>
                    </td>
                    <td className={`${CELL} min-w-40`}>
                      <span className="sr-only">{t("audit.actor.key")} </span>
                      <span data-testid="audit-actor" className={MONO}>
                        {entry.actor.key_id}
                      </span>
                    </td>
                    <td
                      data-testid="audit-reason"
                      className={`${CELL} min-w-40 break-words ${entry.reason === undefined ? "text-fg-muted" : ""}`}
                    >
                      {entry.reason ?? t("audit.reason.none")}
                    </td>
                    <td data-testid="audit-summary" className={`${CELL} min-w-48 break-words`}>
                      {entry.summary}
                    </td>
                  </tr>
                  {expanded ? (
                    <tr className="border-border border-b">
                      <td colSpan={COLUMNS.length + 1} className="px-3 pb-3">
                        <EntryDetails entry={entry} id={detailsId} />
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </section>
      {failure ? (
        <p role="alert" className="body-5 text-sev-critical-text">
          {failure}
        </p>
      ) : null}
      {cursor === null ? (
        <p ref={endRef} tabIndex={-1} data-testid="audit-end" className="body-5 text-fg-muted">
          {t("audit.more.end")}
        </p>
      ) : (
        <div>
          <Button variant="secondary" onClick={loadMore} disabled={pending} data-testid="audit-more">
            {pending ? t("audit.more.loading") : t("audit.more")}
          </Button>
        </div>
      )}
    </div>
  );
}
