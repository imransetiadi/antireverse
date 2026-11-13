import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { buttonClass } from "@/components/button.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { AuditFilters } from "@/features/audit/audit-filters.tsx";
import { AuditLog } from "@/features/audit/audit-log.tsx";
import { AuditPublicKey } from "@/features/audit/audit-public-key.tsx";
import { ChainCheck } from "@/features/audit/chain-check.tsx";
import { ChainStatus } from "@/features/audit/chain-status.tsx";
import { ExportNotice, exportNoticeFrom } from "@/features/audit/export-notice.tsx";
import { loadAuditPage } from "@/features/audit/load.ts";
import { auditQueryFrom, filtered } from "@/features/audit/query.ts";
import { ApiError, getAuditPublicKey, listApps, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";

/** The public half of the audit key, or null when it could not be read. */
async function publicKeyOf() {
  try {
    return await getAuditPublicKey();
  } catch (error) {
    if (error instanceof ApiError) return null;
    throw error;
  }
}

// `/settings/audit?action=&app=&from=&to=` — SCR-13 Audit log (slice 18a): who changed what, when and why. The chain
// status, Export, the filters (a GET form of this address) and the first page of entries, newest first; "Load more"
// appends the next pages in the browser.
// The route types of `.next/types` come from `next typegen`, which this slice does not run: the props are written out.
interface AuditPageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function AuditPage({ searchParams }: AuditPageProps) {
  const { key, organization } = await requireSession();
  const params = await searchParams;
  const query = auditQueryFrom(params);
  const notice = exportNoticeFrom(params);
  let loaded: Awaited<ReturnType<typeof loadAuditPage>>;
  let apps: Awaited<ReturnType<typeof listApps>>["apps"];
  let publicKey: Awaited<ReturnType<typeof publicKeyOf>>;
  try {
    // The chain is checked only on the unfiltered view, and not on the way back from a refused export: verify shares
    // the API's limit with Export. A filtered view offers "Verify chain" instead.
    [loaded, { apps }, publicKey] = await Promise.all([
      loadAuditPage(key, query, notice === null),
      listApps(key),
      publicKeyOf(),
    ]);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
  const { page, chain, filtersApplied } = loaded;
  // A new address starts the list afresh: no page appended for other filters stays on the screen.
  const revision = ROUTES.audit(query);

  return (
    <AppShell organization={organization} current="audit">
      <PageHeader title={t("audit.title")} />
      <p className="max-w-3xl text-fg-muted">{t("audit.lead")}</p>

      <div className={SECTION}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1 basis-64">
            {chain === null ? <ChainCheck /> : <ChainStatus result={chain.result} limited={chain.limited} />}
          </div>
          <div className="flex flex-col items-start gap-1">
            {/* A plain link to the route handler: the download keeps the session cookie; a refusal comes back here. */}
            <a
              href={ROUTES.auditExport}
              className={buttonClass("secondary")}
              aria-describedby="audit-export-help"
              data-testid="audit-export"
            >
              {t("audit.export")}
            </a>
            <p id="audit-export-help" className="max-w-xs body-5 text-fg-muted">
              {t("audit.export.help")}
            </p>
            <ExportNotice notice={notice} />
          </div>
        </div>
      </div>

      <section aria-labelledby="audit-filter-title" className={SECTION}>
        <h2 id="audit-filter-title" className={SECTION_TITLE}>
          {t("audit.filter.title")}
        </h2>
        <AuditFilters query={query} apps={apps} notApplied={!filtersApplied} />
      </section>

      <section aria-labelledby="audit-list-title" className={SECTION}>
        <h2 id="audit-list-title" className={SECTION_TITLE}>
          {t("audit.caption")}
        </h2>
        <AuditLog
          key={revision}
          entries={page.entries}
          nextCursor={page.next_cursor}
          query={filtersApplied ? query : {}}
          apps={apps}
          filtered={filtered(query) && filtersApplied}
        />
      </section>

      <AuditPublicKey publicKey={publicKey} />
    </AppShell>
  );
}
