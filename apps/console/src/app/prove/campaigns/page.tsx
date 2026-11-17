import { CAMPAIGN_LIMITS, type ListCampaignsResponse, STAND_IN_ENGINE } from "@antireverse/protocol";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { ButtonLink } from "@/components/button.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { CampaignList, CampaignsAvailability } from "@/features/campaigns/campaign-list.tsx";
import { CampaignNotice } from "@/features/campaigns/campaign-notice.tsx";
import { DeletionPendingError, listCampaigns, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// `/prove/campaigns` (slice 15a) — the Organization's Pentest Campaigns, newest first, read from the API on every
// request. The notice says what the results of the scripted engine are and are not. "New Campaign" is offered only
// while one can be created: not while Campaigns are switched off on the API, stopped by the operator or suspended.
export default async function CampaignsPage() {
  const { key, organization } = await requireSession();
  let list: ListCampaignsResponse;
  try {
    list = await listCampaigns(key);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    // A deletion requested since the session was read (D-084): Data controls shows it, with why.
    if (error instanceof DeletionPendingError) redirect(ROUTES.dataControls({ blocked: true }));
    throw error;
  }
  const canCreate = list.enabled && list.blocked === null;

  return (
    <AppShell organization={organization} current="campaigns">
      <PageHeader
        title={t("campaigns.title")}
        actions={
          canCreate ? (
            <ButtonLink href={ROUTES.newCampaign} data-testid="campaign-new">
              {t("campaigns.new")}
            </ButtonLink>
          ) : null
        }
      />
      <p className="max-w-3xl text-fg-muted">{t("campaigns.lead")}</p>
      <CampaignNotice engine={STAND_IN_ENGINE} notice={list.notice} />
      <CampaignsAvailability enabled={list.enabled} blocked={list.blocked} />

      <section aria-labelledby="campaigns-list-title" className="flex flex-col gap-3">
        <h2 id="campaigns-list-title" className="heading-4">
          {t("campaigns.list.title")}
        </h2>
        <CampaignList campaigns={list.campaigns} canCreate={canCreate} />
        {list.campaigns.length >= CAMPAIGN_LIMITS.listed ? (
          <p className="body-5 text-fg-muted">{t("campaigns.shown", { count: CAMPAIGN_LIMITS.listed })}</p>
        ) : null}
      </section>
    </AppShell>
  );
}
