"use client";

import { CONTAINMENT_DEFAULT_TTL, CONTAINMENT_TTLS, type Incident } from "@antireverse/protocol";
import { useActionState, useId } from "react";
import { createContainmentAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { ConfirmPanel, REASON_FIELD_ID, reasonLabel, TYPED_FIELD_ID } from "@/components/confirm-panel.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Select } from "@/components/input.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { byRequests, type IncidentActor } from "./actor-list.tsx";
import { shortHash, TTL_LABEL } from "./format.ts";
import type { BlockRequest } from "./query.ts";

const NO_ERRORS: readonly SummaryError[] = [];
const ACTOR_ID = "containment-actor";
const DURATION_ID = "containment-duration";

interface ContainmentBarProps {
  incident: Incident;
  appName: string;
  actors: readonly IncidentActor[];
  /** The block the address asks to confirm, if any. Ignored once the Incident is resolved. */
  block: BlockRequest | null;
  /** When that block would end, e.g. "14:05 UTC" — computed by the server render. */
  expiry: string | null;
}

/**
 * SCR-05 CONTAIN: the primary containment action first — Block actor (the Actor with the most requests,
 * 1 hour, both changeable) — then Block network. The bar itself changes nothing: its form is a GET of the
 * Incident's address that opens the confirmation step, which states the blast radius and the expiry and
 * alone can send the block. Alert → Incident → Block actor → confirm: three interactions.
 * An Incident without a network prefix (nullable since slice 10) offers no Block network and opens no network
 * confirmation.
 */
export function ContainmentBar({ incident, appName, actors, block, expiry }: ContainmentBarProps) {
  const [state, formAction, pending] = useActionState(createContainmentAction, null);
  const reasonId = useId();
  const errors = state?.errors ?? NO_ERRORS;

  if (incident.status === "resolved") {
    return (
      <p data-testid="containment-resolved-note" className="text-fg-muted">
        {t("containment.resolved")}
      </p>
    );
  }

  const ordered = byRequests(actors);
  const chosenActor = block?.kind === "actor" ? block.ipHash : ordered[0]?.ip_hash;
  const chosenTtl = block?.ttl ?? CONTAINMENT_DEFAULT_TTL;
  const where = { environment: incident.environment, app: appName };
  const network = incident.ip_prefix;
  // Without a prefix there is no network to block, and the typed field never shows.
  const typedLabel = t("containment.confirm.typed", { network: network ?? "" });
  const step = block?.kind === "prefix" && network === null ? null : block;

  return (
    <div data-testid="containment-bar" className="flex flex-col gap-3 rounded-card border border-border bg-surface p-3">
      <ErrorSummary
        errors={errors}
        fields={{
          typedPrefix: { id: TYPED_FIELD_ID, label: typedLabel },
          reason: { id: REASON_FIELD_ID, label: reasonLabel(true) },
        }}
      />
      <p className="body-5 text-fg-muted">{t("containment.scope", where)}</p>
      <form method="get" action={ROUTES.incident(incident.id)} className="flex flex-wrap items-end gap-2">
        {ordered.length > 0 ? (
          <div className="w-full max-w-64">
            <Select
              id={ACTOR_ID}
              name="actor"
              label={t("containment.actor")}
              defaultValue={chosenActor}
              mono
              data-testid="containment-actor"
            >
              {ordered.map((actor) => (
                <option key={actor.ip_hash} value={actor.ip_hash} title={actor.ip_hash}>
                  {actor.events === 1
                    ? t("containment.actor.option.one", { actor: shortHash(actor.ip_hash) })
                    : t("containment.actor.option", { actor: shortHash(actor.ip_hash), count: actor.events })}
                </option>
              ))}
            </Select>
          </div>
        ) : null}
        <div className="w-40">
          <Select
            id={DURATION_ID}
            name="ttl"
            label={t("containment.duration")}
            defaultValue={String(chosenTtl)}
            data-testid="containment-duration"
          >
            {CONTAINMENT_TTLS.map((ttl) => (
              <option key={ttl} value={String(ttl)}>
                {t(TTL_LABEL[ttl])}
              </option>
            ))}
          </Select>
        </div>
        <Button
          type="submit"
          name="contain"
          value="actor"
          disabled={ordered.length === 0}
          aria-describedby={ordered.length === 0 ? reasonId : undefined}
          data-testid="containment-block-actor"
        >
          {t("containment.blockActor")}
        </Button>
        {network === null ? null : (
          <Button
            type="submit"
            variant="secondary"
            name="contain"
            value="prefix"
            data-testid="containment-block-network"
          >
            {t("containment.blockNetwork")}
          </Button>
        )}
      </form>
      {ordered.length === 0 ? (
        <p id={reasonId} data-testid="containment-no-actor" className="body-5 text-fg-muted">
          {t(network === null ? "containment.noTarget" : "containment.noActor")}
        </p>
      ) : null}
      {step !== null && expiry !== null ? (
        <ConfirmPanel
          testId="containment-confirm"
          question={
            step.kind === "actor"
              ? t("containment.confirm.actor", {
                  ...where,
                  actor: shortHash(step.ipHash),
                  duration: t(TTL_LABEL[step.ttl]),
                  expiry,
                })
              : t("containment.confirm.network", {
                  ...where,
                  network: network ?? "",
                  duration: t(TTL_LABEL[step.ttl]),
                  expiry,
                })
          }
          note={t("containment.confirm.note")}
          confirmLabel={t(step.kind === "actor" ? "containment.blockActor" : "containment.blockNetwork")}
          pendingLabel={t("containment.blocking")}
          cancelHref={ROUTES.incident(incident.id)}
          action={formAction}
          busy={pending}
          // Slice 18a: a block is a sensitive change, recorded with its reason.
          reason={{ required: true, error: fieldError(errors, "reason"), value: state?.reason }}
          typed={
            step.kind === "prefix"
              ? {
                  warning: t("containment.confirm.network.warning", { network: network ?? "" }),
                  environment: network ?? "",
                  error: fieldError(errors, "typedPrefix"),
                  label: typedLabel,
                  name: "typedPrefix",
                }
              : undefined
          }
        >
          <input type="hidden" name="incidentId" value={incident.id} />
          {/* The Environment the question named: the cap message names it without reading again. */}
          <input type="hidden" name="environment" value={incident.environment} />
          <input type="hidden" name="kind" value={step.kind} />
          {step.kind === "actor" ? <input type="hidden" name="ipHash" value={step.ipHash} /> : null}
          <input type="hidden" name="ttl" value={String(step.ttl)} />
          {/* The confirmation: the Actor or the network named in the question. */}
          <input type="hidden" name="confirm" value={step.kind === "actor" ? step.ipHash : (network ?? "")} />
        </ConfirmPanel>
      ) : null}
    </div>
  );
}
