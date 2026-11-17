import { type Campaign, campaignChecksSentence, type ListCampaignsResponse } from "@antireverse/protocol";
import Link from "next/link";
import { EmptyState } from "@/components/empty-state.tsx";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { EngineTag } from "./campaign-notice.tsx";
import { CampaignStatusChip } from "./campaign-status.tsx";
import { isActive } from "./labels.ts";

const COLUMNS = [
  "campaigns.col.host",
  "campaigns.col.status",
  "campaigns.col.intensity",
  "campaigns.col.engine",
  "campaigns.col.requests",
  "campaigns.col.checks",
  "campaigns.col.created",
] as const;

const NOTICE = "max-w-3xl rounded-card border border-sev-medium p-3 body-4 text-fg";

/**
 * Why no Campaign can be created now, or nothing: Campaigns are switched off on this API, the operator stopped them
 * all, or suspended this Organization. Ended Campaigns stay readable below it.
 */
export function CampaignsAvailability({ enabled, blocked }: Pick<ListCampaignsResponse, "enabled" | "blocked">) {
  if (!enabled) {
    return (
      <p role="status" data-testid="campaigns-disabled" className={NOTICE}>
        {t("campaigns.disabled")}
      </p>
    );
  }
  if (blocked === null) return null;
  return (
    <p role="status" data-testid="campaigns-blocked" data-blocked={blocked} className={NOTICE}>
      {t(`campaigns.blocked.${blocked}`)}
    </p>
  );
}

/** What the list says about a Campaign's checks: the protocol's sentence once it ended. */
function checksText(campaign: Campaign): string {
  if (campaign.checks !== null) return campaignChecksSentence(campaign.checks);
  return t(isActive(campaign.status) ? "campaigns.checks.pending" : "campaigns.checks.none");
}

/** The Organization's Campaigns, newest first: status, target, intensity, engine, counts and when each was created. */
export function CampaignList({
  campaigns,
  canCreate = true,
}: {
  campaigns: readonly Campaign[];
  /** False when none can be created: the empty state then does not ask for one. */
  canCreate?: boolean;
}) {
  if (campaigns.length === 0) {
    return (
      <div data-testid="campaigns-empty">
        <EmptyState>{t(canCreate ? "campaigns.empty" : "campaigns.empty.disabled")}</EmptyState>
      </div>
    );
  }
  const caption = t("campaigns.caption");
  return (
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
                {column === "campaigns.col.created" ? (
                  <span className="text-fg-subtle"> {t("campaigns.zone")}</span>
                ) : null}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {campaigns.map((campaign) => {
            const created = formatDateTime(campaign.created_at);
            return (
              <tr
                key={campaign.id}
                data-testid="campaign-row"
                data-campaign-id={campaign.id}
                className="border-border border-b"
              >
                <th scope="row" className={`${DATA} ${STICKY} min-w-40 break-all text-start`}>
                  <Link href={ROUTES.campaign(campaign.id)} data-testid="campaign-host">
                    {campaign.host}
                  </Link>
                </th>
                <td className={`${CELL} whitespace-nowrap`}>
                  <CampaignStatusChip status={campaign.status} />
                </td>
                <td data-testid="campaign-intensity" className={`${DATA} whitespace-nowrap`}>
                  {campaign.intensity}
                </td>
                <td className={`${CELL} whitespace-nowrap`}>
                  <EngineTag engine={campaign.engine} />
                </td>
                <td data-testid="campaign-requests" className={`${DATA} whitespace-nowrap`}>
                  {t("campaigns.requests", { sent: campaign.requests_sent, refused: campaign.requests_refused })}
                </td>
                <td data-testid="campaign-checks" className={`${CELL} min-w-40 text-fg-muted`}>
                  {checksText(campaign)}
                </td>
                <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                  <time data-testid="campaign-created" dateTime={created.iso} title={created.iso}>
                    {created.text}
                  </time>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
