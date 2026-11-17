import { CAMPAIGN_LIMITS, VERIFICATION_FILE_PATH } from "@antireverse/protocol";
import Link from "next/link";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { ButtonLink } from "@/components/button.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { CampaignsAvailability } from "@/features/campaigns/campaign-list.tsx";
import { eligibility, type NotEligible } from "@/features/campaigns/labels.ts";
import { NewCampaignForm } from "@/features/campaigns/new-campaign-form.tsx";
import {
  DeletionPendingError,
  getCurrentRulesOfEngagement,
  listCampaigns,
  listTargets,
  UnauthorizedError,
} from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

/** Where each reason nothing qualifies is fixed: on Targets, or on Rules of Engagement. */
const FIX: Readonly<Record<NotEligible, "targets" | "rules">> = {
  "no-targets": "targets",
  "no-verified": "targets",
  "no-rules": "rules",
  "rules-too-old": "rules",
  "none-in-scope": "rules",
  "verification-path-excluded": "rules",
};

// `/prove/campaigns/new` (slice 15a) — launches a Campaign. Only verified targets in the scope of the current Rules of
// Engagement are offered; when none qualifies the page says why and where to fix it, and while Campaigns are switched
// off, stopped or suspended it says so instead of showing a form. The API checks everything again.
export default async function NewCampaignPage() {
  const { key, organization } = await requireSession();
  let loaded: [
    Awaited<ReturnType<typeof listTargets>>,
    Awaited<ReturnType<typeof getCurrentRulesOfEngagement>>,
    Awaited<ReturnType<typeof listCampaigns>>,
  ];
  try {
    loaded = await Promise.all([listTargets(key), getCurrentRulesOfEngagement(key), listCampaigns(key)]);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof DeletionPendingError) redirect(ROUTES.dataControls({ blocked: true }));
    throw error;
  }
  const [{ targets }, { version }, { enabled, blocked }] = loaded;
  const available = enabled && blocked === null;
  const offer = eligibility(targets, version, Date.now());

  return (
    <AppShell organization={organization} current="campaigns" width="narrow">
      <PageHeader eyebrow={<Link href={ROUTES.campaigns}>{t("campaign.back")}</Link>} title={t("campaign.new.title")} />
      <p className="text-fg-muted">{t("campaign.new.lead")}</p>
      {!available ? (
        <CampaignsAvailability enabled={enabled} blocked={blocked} />
      ) : offer.kind === "ok" && version !== null ? (
        <NewCampaignForm targets={offer.targets} rules={version} />
      ) : (
        <div data-testid="campaign-none" data-why={offer.kind === "none" ? offer.why : undefined}>
          {offer.kind === "none" ? (
            <EmptyState
              action={
                <ButtonLink
                  href={FIX[offer.why] === "targets" ? ROUTES.targets : ROUTES.rulesOfEngagement}
                  variant="secondary"
                >
                  {t(FIX[offer.why] === "targets" ? "campaign.new.toTargets" : "campaign.new.toRules")}
                </ButtonLink>
              }
            >
              {t(`campaign.new.none.${offer.why}`, {
                days: CAMPAIGN_LIMITS.roeMaxAgeDays,
                path: VERIFICATION_FILE_PATH,
              })}
            </EmptyState>
          ) : null}
        </div>
      )}
    </AppShell>
  );
}
