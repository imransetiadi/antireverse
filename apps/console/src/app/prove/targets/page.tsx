import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { AddTargetForm } from "@/features/prove/add-target-form.tsx";
import { TargetList } from "@/features/prove/target-list.tsx";
import { listTargets, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";

// `/prove/targets` — the Organization's Verified Targets and the form that adds a host. Read from the API on
// every request.
export default async function TargetsPage() {
  const { key, organization } = await requireSession();
  let targets: Awaited<ReturnType<typeof listTargets>>["targets"];
  try {
    ({ targets } = await listTargets(key));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }

  return (
    <AppShell organization={organization} current="targets">
      <PageHeader title={t("targets.title")} />
      <p className="text-fg-muted">{t("targets.lead")}</p>

      <section aria-labelledby="targets-list-title" className={SECTION}>
        <h2 id="targets-list-title" className={SECTION_TITLE}>
          {t("targets.list.title")}
        </h2>
        <TargetList targets={targets} />
      </section>

      <section aria-labelledby="targets-add-title" className={SECTION}>
        <h2 id="targets-add-title" className={SECTION_TITLE}>
          {t("targets.add.title")}
        </h2>
        <AddTargetForm />
      </section>
    </AppShell>
  );
}
