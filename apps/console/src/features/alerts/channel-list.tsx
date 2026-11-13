"use client";

import type { AlertChannel, AlertChannelKind, AlertRecipient } from "@antireverse/protocol";
import { useActionState, useId } from "react";
import {
  deleteAlertChannelAction,
  resendConfirmationAction,
  type TestAlertChannelState,
  testAlertChannelAction,
} from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel } from "@/components/confirm-panel.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { ErrorSummary, type SummaryError } from "@/components/error-summary.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";
import { RecipientChip } from "./recipient-chip.tsx";

const COLUMNS = [
  "alerts.col.name",
  "alerts.col.kind",
  "alerts.col.destination",
  "alerts.col.created",
  "alerts.col.actions",
] as const;
const NO_ERRORS: readonly SummaryError[] = [];

export const KIND_LABEL: Record<AlertChannelKind, MessageKey> = {
  webhook: "alerts.kind.webhook",
  slack: "alerts.kind.slack",
  email: "alerts.kind.email",
};

/**
 * Where a channel sends to, as far as it may be shown: the host and the URL's last 4 characters, or the addresses
 * of an email channel.
 */
export const destination = (channel: AlertChannel): string =>
  channel.kind === "email"
    ? channel.recipients.map((recipient) => recipient.address).join(", ")
    : t("alerts.destination", { host: channel.host, lastFour: channel.url_last4 });

function outcomeText(state: Exclude<TestAlertChannelState, null>): string {
  if (!state.ok) return state.message;
  if (state.outcome === "delivered") return t("alerts.test.delivered");
  return state.statusCode === null
    ? t("alerts.test.failed.none")
    : t("alerts.test.failed.status", { status: state.statusCode });
}

/** "Send test" for one channel, with the outcome of the last test next to it. */
function ChannelTest({ channel, describedBy }: { channel: AlertChannel; describedBy: string }) {
  const [state, formAction, pending] = useActionState(testAlertChannelAction, null);
  const tone = state?.ok && state.outcome === "delivered" ? "text-fg" : "text-sev-critical-text";
  return (
    <div className="flex flex-wrap items-center gap-2">
      <form action={formAction}>
        <input type="hidden" name="channelId" value={channel.id} />
        <SubmitButton
          variant="secondary"
          pendingLabel={t("alerts.testing")}
          aria-describedby={describedBy}
          data-testid="channel-test"
        >
          {t("alerts.test")}
        </SubmitButton>
      </form>
      {/* A polite live region that is always there, so that a new outcome is announced. */}
      <span
        role="status"
        data-testid={state && !pending ? "channel-test-outcome" : undefined}
        data-outcome={state?.ok ? state.outcome : state ? "error" : undefined}
        className={`body-5 ${tone}`}
      >
        {state && !pending ? outcomeText(state) : null}
      </span>
    </div>
  );
}

/** "Resend confirmation" for one pending recipient, with the outcome of the last resend next to it. */
function ResendConfirmation({
  channelId,
  recipientId,
  describedBy,
}: {
  channelId: string;
  recipientId: string;
  describedBy: string;
}) {
  const [state, formAction, pending] = useActionState(resendConfirmationAction, null);
  const tone = state?.ok ? "text-fg" : "text-sev-critical-text";
  return (
    <div className="flex flex-wrap items-center gap-2">
      <form action={formAction}>
        <input type="hidden" name="channelId" value={channelId} />
        <input type="hidden" name="recipientId" value={recipientId} />
        <SubmitButton
          variant="quiet"
          pendingLabel={t("alerts.recipient.resending")}
          aria-describedby={describedBy}
          data-testid="recipient-resend"
        >
          {t("alerts.recipient.resend")}
        </SubmitButton>
      </form>
      <span
        role="status"
        data-testid={state && !pending ? "recipient-resend-outcome" : undefined}
        className={`body-5 ${tone}`}
      >
        {state && !pending ? (state.ok ? t("alerts.recipient.resent") : state.message) : null}
      </span>
    </div>
  );
}

/** One recipient of an email channel: its address, whether it confirmed, when it was last sent to. */
function Recipient({ channelId, recipient }: { channelId: string; recipient: AlertRecipient }) {
  const addressId = useId();
  const lastSent = recipient.last_sent_at === null ? null : formatDateTime(recipient.last_sent_at);
  return (
    <li data-testid="recipient" data-recipient-id={recipient.id} className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <span id={addressId} data-testid="recipient-address" className="break-all code-3 text-fg">
          {recipient.address}
        </span>
        <RecipientChip status={recipient.status} />
      </div>
      <span data-testid="recipient-last-sent" className="body-5 text-fg-muted">
        {lastSent === null ? (
          t("alerts.recipient.unsent")
        ) : (
          <time dateTime={lastSent.iso} title={lastSent.iso}>
            {t("alerts.recipient.sent", { time: lastSent.text })}
          </time>
        )}
      </span>
      {recipient.status === "pending" ? (
        <ResendConfirmation channelId={channelId} recipientId={recipient.id} describedBy={addressId} />
      ) : null}
    </li>
  );
}

interface ChannelListProps {
  channels: readonly AlertChannel[];
  /** The channel whose removal the address asks to confirm, if any. */
  confirmRemoveId: string | undefined;
}

/**
 * The alert channels of the Organization. A URL is never shown — only its host and last 4 characters.
 * Removing is never one click: the control is a link to the confirmation step, and only that step holds a
 * form that can send it.
 */
export function ChannelList({ channels, confirmRemoveId }: ChannelListProps) {
  const [removeState, removeAction, removePending] = useActionState(deleteAlertChannelAction, null);
  const baseId = useId();
  const errors = removeState?.errors ?? NO_ERRORS;
  const caption = t("alerts.caption");

  if (channels.length === 0) {
    return (
      <div data-testid="channels-empty">
        <EmptyState>{t("alerts.empty")}</EmptyState>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <ErrorSummary errors={errors} fields={{}} />
      <section
        aria-label={caption}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="overflow-x-auto"
      >
        <table className="w-full border-collapse body-5">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr className="border-border border-b">
              {COLUMNS.map((column, index) => (
                <th key={column} scope="col" className={`${HEAD} ${index === 0 ? STICKY : ""}`}>
                  {t(column)}
                  {column === "alerts.col.created" ? (
                    <span className="text-fg-subtle"> {t("incidents.col.zone")}</span>
                  ) : null}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {channels.map((channel) => {
              const nameId = `${baseId}-${channel.id}`;
              const confirming = channel.id === confirmRemoveId;
              const created = formatDateTime(channel.created_at);
              return [
                <tr
                  key={channel.id}
                  data-testid="channel-row"
                  data-channel-id={channel.id}
                  data-kind={channel.kind}
                  className={confirming ? "" : "border-border border-b"}
                >
                  <th scope="row" id={nameId} className={`${CELL} ${STICKY} min-w-32 break-words text-start body-4`}>
                    {channel.name}
                  </th>
                  <td data-testid="channel-kind" className={`${CELL} whitespace-nowrap`}>
                    {t(KIND_LABEL[channel.kind])}
                  </td>
                  <td data-testid="channel-destination" className={`${DATA} min-w-40 break-all`}>
                    {channel.kind === "email" ? (
                      <ul
                        data-testid="channel-recipients"
                        aria-label={t("alerts.recipients", { name: channel.name })}
                        className="flex flex-col gap-3"
                      >
                        {channel.recipients.map((recipient) => (
                          <Recipient key={recipient.id} channelId={channel.id} recipient={recipient} />
                        ))}
                      </ul>
                    ) : (
                      destination(channel)
                    )}
                  </td>
                  <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                    <time data-testid="channel-created-at" dateTime={created.iso} title={created.iso}>
                      {created.text}
                    </time>
                  </td>
                  <td className={CELL}>
                    <div className="flex flex-wrap items-center gap-2">
                      <ChannelTest channel={channel} describedBy={nameId} />
                      {confirming ? null : (
                        <ButtonLink
                          variant="quiet"
                          href={ROUTES.alerts({ remove: channel.id })}
                          scroll={false}
                          prefetch={false}
                          aria-describedby={nameId}
                          data-testid="channel-remove"
                        >
                          {t("alerts.remove")}
                        </ButtonLink>
                      )}
                    </div>
                  </td>
                </tr>,
                confirming ? (
                  <tr key={`${channel.id}-confirm`} className="border-border border-b">
                    <td colSpan={COLUMNS.length} className="px-3 pt-1 pb-3">
                      <ConfirmPanel
                        testId="channel-confirm"
                        question={t("alerts.confirm.remove", { name: channel.name, destination: destination(channel) })}
                        note={t("alerts.confirm.note")}
                        confirmLabel={t("alerts.remove")}
                        pendingLabel={t("alerts.removing")}
                        cancelHref={ROUTES.alerts()}
                        action={removeAction}
                        busy={removePending}
                      >
                        <input type="hidden" name="channelId" value={channel.id} />
                        {/* The confirmation: the channel named in the question. */}
                        <input type="hidden" name="confirm" value={channel.id} />
                      </ConfirmPanel>
                    </td>
                  </tr>
                ) : null,
              ];
            })}
          </tbody>
        </table>
      </section>
    </div>
  );
}
