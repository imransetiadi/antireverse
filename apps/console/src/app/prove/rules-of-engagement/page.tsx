import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { ButtonLink } from "@/components/button.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { CheckTestForm } from "@/features/prove/check-test-form.tsx";
import { RoeHistory } from "@/features/prove/roe-history.tsx";
import { RoeVersionCard } from "@/features/prove/roe-version.tsx";
import { listRulesOfEngagement, listTargets, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";

/** Now in UTC as a `datetime-local` value: `YYYY-MM-DDTHH:MM`. */
const nowForInput = (): string => new Date().toISOString().slice(0, 16);

// `/prove/rules-of-engagement` — the current signed version, the dry "Check a test" form and the history. The newest
// version is the current one; versions are never changed, so the page has no action on them.
export default async function RulesOfEngagementPage() {
  const { key, organization } = await requireSession();
  let loaded: [Awaited<ReturnType<typeof listRulesOfEngagement>>, Awaited<ReturnType<typeof listTargets>>];
  try {
    loaded = await Promise.all([listRulesOfEngagement(key), listTargets(key)]);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
  const [{ versions }, { targets }] = loaded;
  const current = versions[0];
  const newVersion = (
    <ButtonLink href={ROUTES.newRulesOfEngagement} data-testid="roe-new">
      {t("roe.new")}
    </ButtonLink>
  );

  return (
    <AppShell organization={organization} current="rules">
      <PageHeader title={t("roe.title")} actions={current ? newVersion : undefined} />
      <p className="text-fg-muted">{t("roe.lead")}</p>

      <section aria-labelledby="roe-current-title" className={SECTION}>
        <h2 id="roe-current-title" className={SECTION_TITLE}>
          {t("roe.current.title")}
        </h2>
        {current ? (
          <RoeVersionCard version={current} targets={targets} />
        ) : (
          <div data-testid="roe-none">
            <EmptyState action={newVersion}>{t("roe.none")}</EmptyState>
          </div>
        )}
      </section>

      <section aria-labelledby="check-title" className={SECTION}>
        <h2 id="check-title" className={SECTION_TITLE}>
          {t("check.title")}
        </h2>
        <p className="text-fg-muted">{t("check.lead")}</p>
        <CheckTestForm defaultAt={nowForInput()} hosts={targets.map((target) => target.host)} />
      </section>

      <section aria-labelledby="roe-history-title" className={SECTION}>
        <h2 id="roe-history-title" className={SECTION_TITLE}>
          {t("roe.history.title")}
        </h2>
        <RoeHistory versions={versions} targets={targets} />
      </section>
    </AppShell>
  );
}
