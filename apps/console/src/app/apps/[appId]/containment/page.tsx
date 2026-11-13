import { ID_PATTERNS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { AppContainment } from "@/features/containment/app-containment.tsx";
import { liftFrom } from "@/features/containment/query.ts";
import { loadSetupDone } from "@/features/setup/load.ts";
import { getApp, listContainments, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

async function load(key: string, appId: string) {
  try {
    const [{ app }, { containments }] = await Promise.all([
      getApp(key, appId),
      listContainments(key, { appId, status: "active" }),
    ]);
    return { app, containments };
  } catch (error) {
    // Another Organization's App and an App that does not exist look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/apps/[appId]/containment?lift=` — the App's active blocks in each Environment, with Lift. `?lift=<id>`
// opens the step that asks before that block is lifted.
export default async function ContainmentPage({ params, searchParams }: PageProps<"/apps/[appId]/containment">) {
  const { key, organization } = await requireSession();
  const { appId } = await params;
  if (!ID_PATTERNS.app.test(appId)) notFound();
  // The set-up progress is asked for beside the screen's own data (slice 16).
  const [{ app, containments }, setupDone] = await Promise.all([load(key, appId), loadSetupDone(key, appId)]);
  const confirmLiftId = liftFrom((await searchParams).lift, containments);

  return (
    <AppShell organization={organization}>
      <PageHeader eyebrow={app.name} title={t("appContainment.title")} />
      <AppNav appId={app.id} current="containment" setupDone={setupDone} />
      <p className="text-fg-muted">{t("appContainment.lead", { app: app.name })}</p>
      <AppContainment
        // A confirmation step that opens or closes starts the Lift forms afresh.
        key={confirmLiftId ?? ""}
        appId={app.id}
        appName={app.name}
        containments={containments}
        confirmLiftId={confirmLiftId}
      />
    </AppShell>
  );
}
