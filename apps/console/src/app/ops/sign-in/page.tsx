import type { Metadata } from "next";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { OpsSignInForm } from "@/features/ops/ops-sign-in-form.tsx";
import { t } from "@/lib/t.ts";

// `/ops/sign-in` (slice 18d) — paste the operator token. Not linked from the tenant navigation, and a tenant session
// plays no part. It never redirects on its own: it is where a token the API stopped accepting ends up.
// The route types of `.next/types` come from `next typegen`, which this slice does not run: the props are written out.
export const metadata: Metadata = { robots: { index: false, follow: false } };

interface OpsSignInPageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function OpsSignInPage({ searchParams }: OpsSignInPageProps) {
  const expired = (await searchParams).reason === "expired";
  return (
    <AppShell width="narrow">
      <PageHeader title={t("ops.signin.title")} />
      <p className="text-fg-muted">{t("ops.signin.lead")}</p>
      {expired ? (
        <p role="status" data-testid="ops-signin-notice" className="rounded-card border border-sev-medium p-3">
          {t("ops.signin.expired")}
        </p>
      ) : null}
      <OpsSignInForm />
    </AppShell>
  );
}
