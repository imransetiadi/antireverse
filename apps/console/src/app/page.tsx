import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { CreateOrganizationForm } from "@/features/onboarding/create-organization-form.tsx";
import { currentOrganization, isActionRequest } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// `/` — create an Organization, or go to sign-in. A signed-in visitor goes to the Apps.
// createOrganizationAction sets the session cookie, which makes Next.js re-render this page inside the
// action's own POST. Redirecting during that render would discard the admin key before it was shown, so
// the redirect applies to ordinary requests only; the next GET of `/` redirects as usual.
export default async function OnboardingPage() {
  if (!(await isActionRequest()) && (await currentOrganization())) redirect(ROUTES.apps);

  return (
    <AppShell width="narrow">
      <PageHeader title={t("onboarding.title")} />
      <p className="text-fg-muted">{t("onboarding.lead")}</p>
      <CreateOrganizationForm />
    </AppShell>
  );
}
