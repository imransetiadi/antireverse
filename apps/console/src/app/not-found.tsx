import Link from "next/link";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// Also what a signed-in visitor sees for another Organization's App: the two cases look the same on purpose.
export default function NotFound() {
  return (
    <AppShell width="narrow">
      <PageHeader title={t("notfound.title")} />
      <p className="text-fg-muted">{t("notfound.body")}</p>
      <p>
        <Link href={ROUTES.apps}>{t("notfound.back")}</Link>
      </p>
    </AppShell>
  );
}
