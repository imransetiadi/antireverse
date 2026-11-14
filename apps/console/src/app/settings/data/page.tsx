import { DELETION_GRACE_DAYS, type RetentionResponse } from "@antireverse/protocol";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { buttonClass } from "@/components/button.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { ExportNotice, exportNoticeFrom } from "@/features/audit/export-notice.tsx";
import { DataNotices } from "@/features/data-controls/data-notices.tsx";
import { DeleteOrganization } from "@/features/data-controls/delete-organization.tsx";
import { dataQueryFrom } from "@/features/data-controls/query.ts";
import { RetentionSettings } from "@/features/data-controls/retention-settings.tsx";
import { SubjectRequest } from "@/features/data-controls/subject-request.tsx";
import { ApiError, DeletionPendingError, getRetention, UnauthorizedError } from "@/lib/api.ts";
import { requireSessionDuringDeletion } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";
const DAY_MS = 86_400_000;

// `/settings/data?step=&done=&blocked=1&subject_export=` — Settings → Data controls (slice 18b, FR-CON-11): Export, an end
// user's request by actor hash, Retention (slice 18c) and Delete Organization. The one signed-in page that stays open while a deletion is
// pending: every other page sends the person here (`blocked=1`), and the shell shows the deletion banner.
// The route types of `.next/types` come from `next typegen`, which this slice does not run: the props are written out.
/** The Organization's retention, or null when the API could not give it (the section then says so). */
async function loadRetention(key: string): Promise<RetentionResponse | null> {
  try {
    return await getRetention(key);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    // A deletion requested since the session was read (D-084): the page shows it, with why.
    if (error instanceof DeletionPendingError) redirect(ROUTES.dataControls({ blocked: true }));
    if (error instanceof ApiError) return null;
    throw error;
  }
}

interface DataPageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function DataControlsPage({ searchParams }: DataPageProps) {
  const session = await requireSessionDuringDeletion();
  const params = await searchParams;
  const query = dataQueryFrom(params);
  const exportNotice = exportNoticeFrom(params);
  const { organization, deletion } = session;
  // Shown before the request, as "about": the time the data would be erased if the deletion were asked for now.
  const erasedIfNow = new Date(Date.now() + DELETION_GRACE_DAYS * DAY_MS).toISOString();
  // While pending, the API refuses subject requests and the retention: those sections are not offered.
  const step = query.step;
  const retention = deletion === null ? await loadRetention(session.key) : null;

  return (
    <AppShell organization={organization} deletion={deletion} current="data">
      <PageHeader title={t("data.title")} />
      <p className="max-w-3xl text-fg-muted">{t("data.lead")}</p>
      <DataNotices query={query} pending={deletion !== null} />

      <section aria-labelledby="data-export-title" className={SECTION}>
        <h2 id="data-export-title" className={SECTION_TITLE}>
          {t("data.export.title")}
        </h2>
        <p id="data-export-help" className="max-w-3xl body-4 text-fg-muted">
          {t("data.export.lead")}
        </p>
        <div className="flex flex-col items-start gap-1">
          {/* A plain link to the route handler: the download keeps the session cookie; a refusal comes back here. */}
          <a
            href={ROUTES.dataExport}
            className={buttonClass("secondary")}
            aria-describedby="data-export-help"
            data-testid="data-export"
          >
            {t("data.export")}
          </a>
          <ExportNotice notice={exportNotice} />
        </div>
      </section>

      {deletion === null ? (
        <section aria-labelledby="data-subject-title" className={SECTION}>
          <h2 id="data-subject-title" className={SECTION_TITLE}>
            {t("data.subject.title")}
          </h2>
          <SubjectRequest query={query} />
        </section>
      ) : null}

      {deletion === null ? (
        <section aria-labelledby="data-retention-title" className={SECTION}>
          <h2 id="data-retention-title" className={SECTION_TITLE}>
            {t("data.retention.title")}
          </h2>
          {retention ? (
            <RetentionSettings retention={retention.retention} lastRun={retention.last_run} />
          ) : (
            <p role="alert" data-testid="retention-unavailable" className="max-w-3xl body-4 text-fg">
              {t("data.retention.unavailable")}
            </p>
          )}
        </section>
      ) : null}

      <section aria-labelledby="data-delete-title" className={SECTION}>
        <h2 id="data-delete-title" className={`${SECTION_TITLE} text-sev-critical-text`}>
          {t("data.delete.title")}
        </h2>
        <DeleteOrganization
          key={step ?? ""}
          organization={organization}
          deletion={deletion}
          erasedIfNow={erasedIfNow}
          step={step}
        />
      </section>
    </AppShell>
  );
}
