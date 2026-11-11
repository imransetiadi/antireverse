import { ID_PATTERNS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { BuildDetail } from "@/features/builds/build-detail.tsx";
import { ApiError, getApp, getBuild, listFindings, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";

async function load(key: string, appId: string, buildId: string) {
  try {
    const [{ app }, { build }] = await Promise.all([getApp(key, appId), getBuild(key, appId, buildId)]);
    // Slice 19: this Build's Findings, filtered by the API. When they cannot be read, the rest of the Build is
    // still shown and the section says so.
    const findings = await listFindings(key, { appId, buildId, source: "build" }).then(
      (response) => response.findings,
      (error: unknown) => {
        if (error instanceof ApiError && !(error instanceof UnauthorizedError)) return null;
        throw error;
      },
    );
    return { app, build, findings };
  } catch (error) {
    // An unknown Build and a Build of another Organization look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/apps/[appId]/builds/[buildId]` — one Build: its costs against budget, transform summary, Findings and artifacts.
export default async function BuildPage({ params }: PageProps<"/apps/[appId]/builds/[buildId]">) {
  const { key, organization } = await requireSession();
  const { appId, buildId } = await params;
  if (!ID_PATTERNS.app.test(appId) || !ID_PATTERNS.bld.test(buildId)) notFound();
  const { app, build, findings } = await load(key, appId, buildId);

  return (
    <AppShell organization={organization}>
      <AppNav appId={app.id} current="builds" />
      <BuildDetail build={build} appName={app.name} findings={findings} />
    </AppShell>
  );
}
