import type { IncidentDetailResponse } from "@antireverse/protocol";
import { EmptyState } from "@/components/empty-state.tsx";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { t } from "@/lib/t.ts";
import { shortHash } from "./format.ts";

export type IncidentActor = IncidentDetailResponse["actors"][number];

/** Most requests first; equal counts by hash, so the order never depends on the API's. */
export function byRequests(actors: readonly IncidentActor[]): IncidentActor[] {
  return [...actors].sort((a, b) => b.events - a.events || a.ip_hash.localeCompare(b.ip_hash));
}

/**
 * The Actors of an Incident: each keyed address hash in its evidence with its request count. The hash is
 * shortened on screen; the full value is its title and what assistive technology reads. Never an address.
 */
export function ActorList({ actors }: { actors: readonly IncidentActor[] }) {
  if (actors.length === 0) {
    return (
      <div data-testid="actors-empty">
        <EmptyState>{t("actors.empty")}</EmptyState>
      </div>
    );
  }
  const caption = t("actors.caption");
  return (
    <section
      aria-label={caption}
      data-testid="incident-actors"
      // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
      tabIndex={0}
      className="overflow-x-auto"
    >
      <table className="w-full max-w-xl border-collapse body-5">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-border border-b">
            <th scope="col" className={`${HEAD} ${STICKY}`}>
              {t("actors.col.actor")}
            </th>
            <th scope="col" className={`${HEAD} text-end`}>
              {t("actors.col.requests")}
            </th>
          </tr>
        </thead>
        <tbody>
          {byRequests(actors).map((actor) => (
            <tr
              key={actor.ip_hash}
              data-testid="actor-row"
              data-actor={actor.ip_hash}
              className="border-border border-b"
            >
              <th scope="row" className={`${CELL} ${STICKY} text-start body-5`}>
                <span data-testid="actor-hash" title={actor.ip_hash} aria-hidden="true" className="code-3">
                  {shortHash(actor.ip_hash)}
                </span>
                <span data-testid="actor-hash-full" className="sr-only">
                  {t("actors.full", { actor: actor.ip_hash })}
                </span>
              </th>
              <td data-testid="actor-requests" className={`${DATA} text-end`}>
                {actor.events}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
