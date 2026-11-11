import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { FindingFilters } from "@/features/findings/finding-filters.tsx";
import { FindingList } from "@/features/findings/finding-list.tsx";
import { findingFilterFrom, findingQueryFrom } from "@/features/findings/query.ts";
import { listApps, listFindings, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// `/findings?severity=&status=&source=&advisory=&build=` — the Organization's Findings, newest first, every
// filter applied by the API. App names come from the App list.
export default async function FindingsPage({ searchParams }: PageProps<"/findings">) {
  const { key, organization } = await requireSession();
  const query = findingQueryFrom(await searchParams);
  let loaded: [Awaited<ReturnType<typeof listFindings>>, Awaited<ReturnType<typeof listApps>>];
  try {
    loaded = await Promise.all([listFindings(key, findingFilterFrom(query)), listApps(key)]);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
  const [{ findings }, { apps }] = loaded;

  return (
    <AppShell organization={organization} current="findings">
      <PageHeader title={t("findings.title")} />
      <FindingFilters query={query} href={(next) => ROUTES.findings(next)} />
      <FindingList
        findings={findings}
        appNames={new Map(apps.map((app) => [app.id, app.name]))}
        query={query}
        clearHref={ROUTES.findings()}
        caption={t("findings.caption", { organization: organization.name })}
      />
    </AppShell>
  );
}
