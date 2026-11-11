import { ID_PATTERNS } from "@antireverse/protocol";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { AddRangeForm } from "@/features/allowlist/add-range-form.tsx";
import { AllowlistTable } from "@/features/allowlist/allowlist-table.tsx";
import { listAllowlist, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";

// `/settings/allowlist?remove=` — the Organization's never block list: the ranges with remove, and the form
// that adds one. `?remove=<entry id>` opens the step that asks before a range is removed.
export default async function AllowlistPage({ searchParams }: PageProps<"/settings/allowlist">) {
  const { key, organization } = await requireSession();
  const { remove } = await searchParams;
  let entries: Awaited<ReturnType<typeof listAllowlist>>["entries"];
  try {
    ({ entries } = await listAllowlist(key));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
  const confirmRemoveId =
    typeof remove === "string" && ID_PATTERNS.alw.test(remove) && entries.some((entry) => entry.id === remove)
      ? remove
      : undefined;

  return (
    <AppShell organization={organization} current="allowlist">
      <PageHeader title={t("allowlist.title")} />
      <p className="text-fg-muted">{t("allowlist.lead")}</p>

      <section aria-labelledby="allowlist-list-title" className={SECTION}>
        <h2 id="allowlist-list-title" className={SECTION_TITLE}>
          {t("nav.allowlist")}
        </h2>
        <AllowlistTable key={confirmRemoveId ?? ""} entries={entries} confirmRemoveId={confirmRemoveId} />
      </section>

      <section aria-labelledby="allowlist-add-title" className={SECTION}>
        <h2 id="allowlist-add-title" className={SECTION_TITLE}>
          {t("allowlist.add.title")}
        </h2>
        <AddRangeForm />
      </section>
    </AppShell>
  );
}
