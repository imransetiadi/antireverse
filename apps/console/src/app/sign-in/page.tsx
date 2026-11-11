import Link from "next/link";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { SignInForm } from "@/features/onboarding/sign-in-form.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// `/sign-in` — paste an admin key. It never redirects on its own: it is where a session whose key the
// API stopped accepting ends up, so it must stay reachable with a stale cookie.
export default async function SignInPage({ searchParams }: PageProps<"/sign-in">) {
  const expired = (await searchParams).reason === "expired";

  return (
    <AppShell width="narrow">
      <PageHeader title={t("signin.title")} />
      {expired ? (
        <p data-testid="signin-notice" className="rounded-card border border-sev-medium p-3">
          {t("signin.expired")}
        </p>
      ) : null}
      <SignInForm />
      <p>
        <Link href={ROUTES.home}>{t("signin.create")}</Link>
      </p>
    </AppShell>
  );
}
