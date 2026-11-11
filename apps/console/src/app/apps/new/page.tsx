import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { CreateAppForm } from "@/features/apps/create-app-form.tsx";
import { policyPublicKey } from "@/features/policy/signing-key.ts";
import { apiBaseUrl } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { t } from "@/lib/t.ts";

// `/apps/new` — create an App; its Shield key is shown once, with the set-up for Express and the policy
// public key Shield needs before it accepts a Policy.
export default async function NewAppPage() {
  const { organization } = await requireSession();
  const publicKey = await policyPublicKey();

  return (
    <AppShell organization={organization} width="narrow">
      <PageHeader title={t("app.new.title")} />
      <p className="text-fg-muted">{t("app.new.lead")}</p>
      {/* Neither the API's base URL nor the policy public key is a secret; the set-up snippet needs both. */}
      <CreateAppForm apiUrl={apiBaseUrl()} policyPublicKey={publicKey} />
    </AppShell>
  );
}
