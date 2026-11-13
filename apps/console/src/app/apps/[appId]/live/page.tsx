import { ID_PATTERNS, LIMITS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { LiveFeed } from "@/features/live-feed/live-feed.tsx";
import { feedPatchTitles } from "@/features/patches/load.ts";
import { loadSetupDone } from "@/features/setup/load.ts";
import { getApp, listEvents, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

async function load(key: string, appId: string) {
  try {
    const [{ app }, { events }] = await Promise.all([getApp(key, appId), listEvents(key, appId, LIMITS.listDefault)]);
    // To name the patch of a Decision: the titles of each Environment the feed shows.
    return { app, events, titles: await feedPatchTitles(key, appId, events) };
  } catch (error) {
    // Another Organization's App and an App that does not exist look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/apps/[appId]/live` — the live feed of one App. The server renders the latest Events; the browser
// then follows the stream through the Console's proxy.
export default async function LivePage({ params }: PageProps<"/apps/[appId]/live">) {
  const { key, organization } = await requireSession();
  const { appId } = await params;
  if (!ID_PATTERNS.app.test(appId)) notFound();
  // The set-up progress is asked for beside the screen's own data (slice 16).
  const [{ app, events, titles }, setupDone] = await Promise.all([load(key, appId), loadSetupDone(key, appId)]);

  return (
    <AppShell organization={organization}>
      <PageHeader eyebrow={app.name} title={t("live.title")} />
      <AppNav appId={app.id} current="live" setupDone={setupDone} />
      <LiveFeed appId={app.id} appName={app.name} initialEvents={events} patchTitles={titles} />
    </AppShell>
  );
}
