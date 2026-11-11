import { ID_PATTERNS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { BuildList } from "@/features/builds/build-list.tsx";
import { getApp, listBuilds, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

async function load(key: string, appId: string) {
  try {
    const [{ app }, { builds }] = await Promise.all([getApp(key, appId), listBuilds(key, appId)]);
    return { app, builds };
  } catch (error) {
    // Another Organization's App and an App that does not exist look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/apps/[appId]/builds` — the Builds of one App, newest first. Each row links to the Build.
export default async function BuildsPage({ params }: PageProps<"/apps/[appId]/builds">) {
  const { key, organization } = await requireSession();
  const { appId } = await params;
  if (!ID_PATTERNS.app.test(appId)) notFound();
  const { app, builds } = await load(key, appId);

  return (
    <AppShell organization={organization}>
      <PageHeader eyebrow={app.name} title={t("builds.title")} />
      <AppNav appId={app.id} current="builds" />
      <BuildList appId={app.id} appName={app.name} builds={builds} />
    </AppShell>
  );
}
