import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { IncidentList } from "@/features/incidents/incident-list.tsx";
import { statusFrom } from "@/features/incidents/query.ts";
import { StatusFilter } from "@/features/incidents/status-filter.tsx";
import { ApiError, listApps, listContainments, listIncidents, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// `/incidents?status=` — SCR-04: the Organization's Incidents, most recently seen first, filtered by the
// status in the address (All when it names none). App names come from the App list. The Contained marker
// comes from one read of the active blocks per page, not one per row; when that read fails, the list is
// still shown and says that the marker is missing.
export default async function IncidentsPage({ searchParams }: PageProps<"/incidents">) {
  const { key, organization } = await requireSession();
  const status = statusFrom((await searchParams).status);
  let loaded: [
    Awaited<ReturnType<typeof listIncidents>>,
    Awaited<ReturnType<typeof listApps>>,
    Awaited<ReturnType<typeof listContainments>> | null,
  ];
  try {
    loaded = await Promise.all([
      listIncidents(key, { status }),
      listApps(key),
      listContainments(key, { status: "active" }).catch((error: unknown) => {
        if (error instanceof ApiError && !(error instanceof UnauthorizedError)) return null;
        throw error;
      }),
    ]);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
  const [{ incidents }, { apps }, active] = loaded;
  const appNames = new Map(apps.map((app) => [app.id, app.name]));
  const contained =
    active === null
      ? null
      : new Set(
          active.containments.flatMap((containment) =>
            containment.incident_id === null ? [] : [containment.incident_id],
          ),
        );

  return (
    <AppShell organization={organization} current="incidents">
      <PageHeader title={t("incidents.title")} />
      <StatusFilter current={status} />
      <IncidentList
        incidents={incidents}
        appNames={appNames}
        status={status}
        contained={contained}
        caption={t("incidents.caption", { organization: organization.name })}
      />
    </AppShell>
  );
}
