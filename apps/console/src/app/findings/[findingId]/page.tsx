import { ID_PATTERNS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { FindingDetail } from "@/features/findings/finding-detail.tsx";
import { confirmIgnoreFrom } from "@/features/findings/query.ts";
import { getApp, getBuild, getFinding, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";

/** A fallback for a lookup whose resource is gone (404); any other failure is passed on. */
function orIfGone<T>(fallback: T): (error: unknown) => T {
  return (error) => {
    if (error instanceof NotFoundError) return fallback;
    throw error;
  };
}

async function load(key: string, findingId: string) {
  try {
    const { finding, advisory } = await getFinding(key, findingId);
    const [appName, build] = await Promise.all([
      // The App is gone: the Finding stays readable and names the App by its id.
      getApp(key, finding.app_id).then((response) => response.app.name, orIfGone(finding.app_id)),
      // A build Finding names its Build by version when the Build can be read, by id otherwise.
      finding.build_id === null
        ? Promise.resolve(null)
        : getBuild(key, finding.app_id, finding.build_id).then((response) => response.build, orIfGone(null)),
    ]);
    return { finding, advisory, appName, build };
  } catch (error) {
    // An unknown Finding and a Finding of another Organization look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/findings/[findingId]?confirm=ignore` — one Finding. The ignore step is opened by the address and holds the
// only form that can ignore; everything is read from the API on every request.
export default async function FindingPage({ params, searchParams }: PageProps<"/findings/[findingId]">) {
  const { key, organization } = await requireSession();
  const { findingId } = await params;
  if (!ID_PATTERNS.fnd.test(findingId)) notFound();
  const { finding, advisory, appName, build } = await load(key, findingId);
  const confirmIgnore = finding.status === "open" && confirmIgnoreFrom((await searchParams).confirm);

  return (
    <AppShell organization={organization} current="findings">
      <FindingDetail
        // A new status or a step that opens or closes starts the actions afresh: no earlier refusal stays.
        key={`${finding.status}:${finding.last_seen}:${confirmIgnore}`}
        finding={finding}
        advisory={advisory}
        appName={appName}
        build={build}
        confirmIgnore={confirmIgnore}
        // The render time: the ignore window is counted from it.
        now={Date.now()}
      />
    </AppShell>
  );
}
