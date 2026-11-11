import { ID_PATTERNS } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { blockRequestFrom, liftFrom } from "@/features/containment/query.ts";
import { IncidentDetail } from "@/features/incidents/incident-detail.tsx";
import { confirmResolveFrom } from "@/features/incidents/query.ts";
import { getApp, getBuild, getIncident, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";

/** A fallback for a lookup whose resource is gone (404); any other failure is passed on. */
function orIfGone<T>(fallback: T): (error: unknown) => T {
  return (error) => {
    if (error instanceof NotFoundError) return fallback;
    throw error;
  };
}

async function load(key: string, incidentId: string) {
  try {
    const detail = await getIncident(key, incidentId);
    const { app_id: appId, build_id: buildId } = detail.incident;
    const [appName, canaryBuild] = await Promise.all([
      // The App is gone: the Incident stays readable and names the App by its id.
      getApp(key, appId).then((response) => response.app.name, orIfGone(appId)),
      // A Canary Incident names its Build: the Build gives the Canary's kind and the version. Without it
      // (gone, or not a Canary Incident) the facts show the ids alone.
      buildId === null
        ? Promise.resolve(null)
        : getBuild(key, appId, buildId).then((response) => response.build, orIfGone(null)),
    ]);
    return { ...detail, appName, canaryBuild };
  } catch (error) {
    // An unknown Incident and an Incident of another Organization look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

// `/incidents/[incidentId]?confirm=resolve` — SCR-05: one Incident. Everything is read from the address and
// the API on every request, including the confirmation steps: resolving (`?confirm=resolve`), blocking an
// Actor or the network (`?contain=actor&actor=&ttl=` or `?contain=prefix&ttl=`, what the containment bar's
// form sends) and lifting a block (`?lift=`). One step is open at a time.
export default async function IncidentPage({ params, searchParams }: PageProps<"/incidents/[incidentId]">) {
  const { key, organization } = await requireSession();
  const { incidentId } = await params;
  if (!ID_PATTERNS.inc.test(incidentId)) notFound();
  const { incident, detections, evidence, actors, containments, appName, canaryBuild } = await load(key, incidentId);
  const query = await searchParams;
  const open = incident.status !== "resolved";
  const confirmLiftId = liftFrom(query.lift, containments);
  const block = open && confirmLiftId === undefined ? blockRequestFrom(query, actors) : null;
  const confirmResolve = open && confirmLiftId === undefined && block === null && confirmResolveFrom(query.confirm);

  return (
    <AppShell organization={organization} current="incidents">
      <IncidentDetail
        // A new status or a confirmation step that opens or closes starts the actions afresh: no refusal
        // of an earlier change stays on the screen.
        key={`${incident.status}:${incident.updated_at}:${confirmResolve}:${confirmLiftId ?? ""}:${JSON.stringify(block)}:${containments.length}`}
        incident={incident}
        detections={detections}
        evidence={evidence}
        appName={appName}
        confirmResolve={confirmResolve}
        canaryBuild={canaryBuild}
        actors={actors}
        containments={containments}
        // The render time: the confirmation states the expiry of a block created now.
        now={Date.now()}
        block={block}
        confirmLiftId={confirmLiftId}
      />
    </AppShell>
  );
}
