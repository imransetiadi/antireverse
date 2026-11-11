import Link from "next/link";
import { AppShell } from "@/components/app-shell.tsx";
import { ButtonLink } from "@/components/button.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { listApps } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// `/apps` — the Organization's Apps, newest first.
export default async function AppsPage() {
  const { key, organization } = await requireSession();
  const { apps } = await listApps(key);
  const caption = t("apps.caption", { organization: organization.name });
  const newApp = <ButtonLink href={ROUTES.newApp}>{t("apps.new")}</ButtonLink>;

  return (
    <AppShell organization={organization} current="apps">
      {/* Exactly one "New App": inside the empty state while there is no App, in the header afterwards. */}
      <PageHeader title={t("apps.title")} actions={apps.length === 0 ? undefined : newApp} />
      {apps.length === 0 ? (
        <EmptyState action={newApp}>{t("apps.empty")}</EmptyState>
      ) : (
        <section aria-label={caption} className="overflow-x-auto">
          <table className="w-full border-collapse text-start body-5">
            <caption className="sr-only">{caption}</caption>
            <thead>
              <tr className="border-border border-b">
                {(["apps.col.name", "apps.col.id", "apps.col.feed", "apps.col.policy", "apps.col.builds"] as const).map(
                  (column) => (
                    <th key={column} scope="col" className="h-10 px-3 text-start caption-1 text-fg-muted">
                      {t(column)}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {apps.map((app) => (
                <tr key={app.id} data-testid="app-row" className="border-border border-b">
                  <th scope="row" className="h-10 break-words px-3 py-2 text-start body-4">
                    {app.name}
                  </th>
                  <td className="px-3 py-2 code-3 text-fg-muted">{app.id}</td>
                  <td className="px-3 py-2">
                    <Link href={ROUTES.live(app.id)} aria-label={t("apps.live.for", { app: app.name })}>
                      {t("apps.live")}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <Link
                      href={ROUTES.policy(app.id)}
                      aria-label={t("apps.policy.for", { app: app.name })}
                      data-testid="app-policy-link"
                    >
                      {t("nav.policy")}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <Link
                      href={ROUTES.builds(app.id)}
                      aria-label={t("apps.builds.for", { app: app.name })}
                      data-testid="app-builds-link"
                    >
                      {t("nav.builds")}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </AppShell>
  );
}
