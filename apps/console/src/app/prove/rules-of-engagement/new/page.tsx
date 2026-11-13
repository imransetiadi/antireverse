import Link from "next/link";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { ButtonLink } from "@/components/button.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { RoeForm } from "@/features/prove/roe-form.tsx";
import { listTargets, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// `/prove/rules-of-engagement/new` — writes and signs a new version. Every host is listed; only verified ones can be
// chosen. Without a verified host there is nothing to sign, and the page says how to get one.
export default async function NewRulesOfEngagementPage() {
  const { key, organization } = await requireSession();
  let targets: Awaited<ReturnType<typeof listTargets>>["targets"];
  try {
    ({ targets } = await listTargets(key));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
  const anyVerified = targets.some((target) => target.status === "verified");

  return (
    <AppShell organization={organization} current="rules" width="narrow">
      <PageHeader eyebrow={<Link href={ROUTES.rulesOfEngagement}>{t("roe.back")}</Link>} title={t("roe.form.title")} />
      <p className="text-fg-muted">{t("roe.form.lead")}</p>
      {anyVerified ? (
        <RoeForm targets={targets} />
      ) : (
        <div data-testid="roe-no-targets">
          <EmptyState
            action={
              <ButtonLink href={ROUTES.targets} variant="secondary">
                {t("roe.form.toTargets")}
              </ButtonLink>
            }
          >
            {t("roe.form.noTargets")}
          </EmptyState>
        </div>
      )}
    </AppShell>
  );
}
