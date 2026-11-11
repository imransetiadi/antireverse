import { ID_PATTERNS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { FindingDetail } from "@/features/findings/finding-detail.tsx";
import { confirmIgnoreFrom } from "@/features/findings/query.ts";
import { patchesOrNull } from "@/features/patches/load.ts";
import { confirmEnforceFrom, patchForFinding } from "@/features/patches/query.ts";
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
    const [appName, build, patches] = await Promise.all([
      // The App is gone: the Finding stays readable and names the App by its id.
      getApp(key, finding.app_id).then((response) => response.app.name, orIfGone(finding.app_id)),
      // A build Finding names its Build by version when the Build can be read, by id otherwise.
      finding.build_id === null
        ? Promise.resolve(null)
        : getBuild(key, finding.app_id, finding.build_id).then((response) => response.build, orIfGone(null)),
      // The virtual patches of its App and Environment; null when they could not be read.
      patchesOrNull(key, finding.app_id, finding.environment),
    ]);
    return { finding, advisory, appName, build, patches };
  } catch (error) {
    // An unknown Finding and a Finding of another Organization look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/findings/[findingId]?confirm=ignore|enforce` — one Finding. The ignore step and the step that enforces its
// virtual patch are opened by the address and hold the only forms that can ignore or enforce; everything is read
// from the API on every request.
export default async function FindingPage({ params, searchParams }: PageProps<"/findings/[findingId]">) {
  const { key, organization } = await requireSession();
  const { findingId } = await params;
  if (!ID_PATTERNS.fnd.test(findingId)) notFound();
  const { finding, advisory, appName, build, patches } = await load(key, findingId);
  const { confirm } = await searchParams;
  const confirmIgnore = finding.status === "open" && confirmIgnoreFrom(confirm);
  // Only an active patch in monitor can be enforced, whatever the address says.
  const patch = patches === null ? null : patchForFinding(patches, finding);
  const confirmEnforce = patch?.active === true && patch.mode === "monitor" && confirmEnforceFrom(confirm);

  return (
    <AppShell organization={organization} current="findings">
      <FindingDetail
        // A new status or a step that opens or closes starts the actions afresh: no earlier refusal stays.
        key={`${finding.status}:${finding.last_seen}:${confirmIgnore}:${patch?.mode ?? ""}:${confirmEnforce}`}
        finding={finding}
        advisory={advisory}
        appName={appName}
        build={build}
        confirmIgnore={confirmIgnore}
        patches={patches}
        confirmEnforce={confirmEnforce}
        // The render time: the ignore window is counted from it.
        now={Date.now()}
      />
    </AppShell>
  );
}
