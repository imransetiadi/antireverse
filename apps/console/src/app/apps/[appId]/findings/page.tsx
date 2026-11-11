import { ID_PATTERNS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { FindingFilters } from "@/features/findings/finding-filters.tsx";
import { FindingList } from "@/features/findings/finding-list.tsx";
import { type FindingQuery, findingFilterFrom, findingQueryFrom } from "@/features/findings/query.ts";
import { getApp, listFindings, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

async function load(key: string, appId: string, query: FindingQuery) {
  try {
    const [{ app }, { findings }] = await Promise.all([
      getApp(key, appId),
      listFindings(key, findingFilterFrom(query, appId)),
    ]);
    return { app, findings };
  } catch (error) {
    // Another Organization's App and an App that does not exist look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/apps/[appId]/findings?severity=&status=&source=&advisory=&build=` — the Findings of one App, newest first.
export default async function AppFindingsPage({ params, searchParams }: PageProps<"/apps/[appId]/findings">) {
  const { key, organization } = await requireSession();
  const { appId } = await params;
  if (!ID_PATTERNS.app.test(appId)) notFound();
  const query = findingQueryFrom(await searchParams);
  const { app, findings } = await load(key, appId, query);

  return (
    <AppShell organization={organization}>
      <PageHeader eyebrow={app.name} title={t("findings.title")} />
      <AppNav appId={app.id} current="findings" />
      <FindingFilters query={query} href={(next) => ROUTES.appFindings(app.id, next)} />
      <FindingList
        findings={findings}
        query={query}
        clearHref={ROUTES.appFindings(app.id)}
        caption={t("findings.caption.app", { app: app.name })}
      />
    </AppShell>
  );
}
