import { ID_PATTERNS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { BuildDetail } from "@/features/builds/build-detail.tsx";
import { loadSetupDone } from "@/features/setup/load.ts";
import {
  ApiError,
  getApp,
  getBuild,
  listAssessments,
  listFindings,
  NotFoundError,
  UnauthorizedError,
} from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";

async function load(key: string, appId: string, buildId: string) {
  try {
    const [{ app }, { build }] = await Promise.all([getApp(key, appId), getBuild(key, appId, buildId)]);
    // Slice 19: this Build's Findings, filtered by the API; slice 12a: its Reverse Assessments. When either cannot
    // be read, the rest of the Build is still shown and the section says so.
    const unreadable = (error: unknown): null => {
      if (error instanceof ApiError && !(error instanceof UnauthorizedError)) return null;
      throw error;
    };
    const [findings, assessments] = await Promise.all([
      listFindings(key, { appId, buildId, source: "build" }).then((response) => response.findings, unreadable),
      listAssessments(key, appId, buildId).then((response) => response.assessments, unreadable),
    ]);
    return { app, build, findings, assessments };
  } catch (error) {
    // An unknown Build and a Build of another Organization look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/apps/[appId]/builds/[buildId]` — one Build: its Reverse resistance, costs against budget, transform summary,
// Findings and artifacts.
export default async function BuildPage({ params }: PageProps<"/apps/[appId]/builds/[buildId]">) {
  const { key, organization } = await requireSession();
  const { appId, buildId } = await params;
  if (!ID_PATTERNS.app.test(appId) || !ID_PATTERNS.bld.test(buildId)) notFound();
  // The set-up progress is asked for beside the screen's own data (slice 16).
  const [{ app, build, findings, assessments }, setupDone] = await Promise.all([
    load(key, appId, buildId),
    loadSetupDone(key, appId),
  ]);

  return (
    <AppShell organization={organization}>
      <AppNav appId={app.id} current="builds" setupDone={setupDone} />
      <BuildDetail build={build} appName={app.name} findings={findings} assessments={assessments} />
    </AppShell>
  );
}
