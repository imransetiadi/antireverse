import { type Environment, ID_PATTERNS, type Policy } from "@antireverse/protocol";
import { notFound, redirect } from "next/navigation";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { patchesOrNull } from "@/features/patches/load.ts";
import { PolicyPatches } from "@/features/patches/policy-patches.tsx";
import { AddRuleForm } from "@/features/policy/add-rule-form.tsx";
import { newlyBroad, newlyEnforced } from "@/features/policy/broad.ts";
import { EnvironmentSwitch } from "@/features/policy/environment-switch.tsx";
import { PolicyKeySnippet } from "@/features/policy/policy-key-snippet.tsx";
import { confirmationFrom, environmentFrom } from "@/features/policy/query.ts";
import { RuleList } from "@/features/policy/rule-list.tsx";
import { policyPublicKey } from "@/features/policy/signing-key.ts";
import { PolicySimulation } from "@/features/policy/simulation-context.tsx";
import { SimulationPanel } from "@/features/policy/simulation-panel.tsx";
import { VersionHistory } from "@/features/policy/version-history.tsx";
import { loadSetupDone } from "@/features/setup/load.ts";
import {
  getApp,
  getPolicy,
  getPolicyVersion,
  listPolicyVersions,
  NotFoundError,
  UnauthorizedError,
} from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

async function load(key: string, appId: string, environment: ReturnType<typeof environmentFrom>) {
  try {
    const [{ app }, { policy }, { versions }, publicKey, patches] = await Promise.all([
      getApp(key, appId),
      getPolicy(key, appId, environment),
      listPolicyVersions(key, appId, environment),
      policyPublicKey(),
      patchesOrNull(key, appId, environment),
    ]);
    return { app, policy, versions, publicKey, patches };
  } catch (error) {
    // Another Organization's App and an App that does not exist look the same.
    if (error instanceof NotFoundError) notFound();
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

/**
 * What rolling back to `version` would do: `broad` when it would enforce a broad pattern that is not enforced now
 * (the confirmation step then asks for the typed Environment), `promotes` when it would enforce any Rule that is not
 * enforced now (slice 18a: the reason is then required). The Server Action decides the same way again.
 */
async function rollbackEffect(
  key: string,
  current: Policy,
  environment: Environment,
  version: number,
): Promise<{ broad: boolean; promotes: boolean }> {
  try {
    const { policy } = await getPolicyVersion(key, current.app_id, environment, version);
    return {
      broad: newlyBroad(current.rules, policy.rules).length > 0,
      promotes: newlyEnforced(current.rules, policy.rules).length > 0,
    };
  } catch (error) {
    // Gone since the list was read: the action will say that the Policy changed.
    if (error instanceof NotFoundError) return { broad: false, promotes: false };
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";

// `/apps/[appId]/policy?environment=` — SCR-08: the Policy of one App and Environment. Everything the
// screen shows is read from the address and the API on every request: the Environment, and the
// confirmation step (`?promote=<Rule id>` or `?rollback=<version>`) that precedes a wide-impact change.
export default async function PolicyPage({ params, searchParams }: PageProps<"/apps/[appId]/policy">) {
  const { key, organization } = await requireSession();
  const { appId } = await params;
  if (!ID_PATTERNS.app.test(appId)) notFound();
  const query = await searchParams;
  const environment = environmentFrom(query.environment);
  // The set-up progress is asked for beside the screen's own data (slice 16).
  const [{ app, policy, versions, publicKey, patches }, setupDone] = await Promise.all([
    load(key, appId, environment),
    loadSetupDone(key, appId),
  ]);
  const confirmation = confirmationFrom(query, policy, versions);
  const rollback =
    confirmation.rollback === undefined
      ? { broad: false, promotes: false }
      : await rollbackEffect(key, policy, environment, confirmation.rollback);
  // A new version, another Environment, or a confirmation step that opens or closes starts the client
  // components afresh: no refusal of an earlier change stays on the screen.
  const revision = `${environment}:${policy.version}`;

  return (
    <AppShell organization={organization}>
      <PageHeader eyebrow={app.name} title={t("policy.title")} tags={<EnvironmentTag environment={environment} />} />
      <AppNav appId={app.id} current="policy" setupDone={setupDone} />
      <div className="flex flex-col gap-2">
        <EnvironmentSwitch appId={app.id} current={environment} />
        <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span data-testid="policy-version" data-version={policy.version} className="code-3">
            {t("policy.version", { version: policy.version })}
          </span>
          <span className="text-fg-muted">{t("policy.applied")}</span>
        </p>
      </div>

      {/* Slice 11: the latest simulation lives in this view only. A confirmation step that opens keeps it (the
          address changes, the view stays); a new version or another Environment starts without one. */}
      <PolicySimulation key={revision}>
        <section aria-labelledby="policy-rules-title" className={SECTION}>
          <h2 id="policy-rules-title" className={SECTION_TITLE}>
            {t("policy.rules.title")}
          </h2>
          <RuleList
            key={`${revision}:${confirmation.promote ?? ""}`}
            appId={app.id}
            appName={app.name}
            environment={environment}
            version={policy.version}
            rules={policy.rules}
            confirmRuleId={confirmation.promote}
          />
          <SimulationPanel
            appId={app.id}
            environment={environment}
            version={policy.version}
            ruleCount={policy.rules.length}
          />
        </section>

        <section aria-labelledby="policy-add-title" className={SECTION}>
          <h2 id="policy-add-title" className={SECTION_TITLE}>
            {t("policy.rule.add.title")}
          </h2>
          <p className="text-fg-muted">{t("policy.rule.add.lead")}</p>
          <AddRuleForm key={revision} appId={app.id} environment={environment} version={policy.version} />
        </section>
      </PolicySimulation>

      <section aria-labelledby="policy-patches-title" data-testid="policy-patches" className={SECTION}>
        <h2 id="policy-patches-title" className={SECTION_TITLE}>
          {t("policy.patches.title")}
        </h2>
        <p className="text-fg-muted">{t("policy.patches.lead")}</p>
        <PolicyPatches environment={environment} patches={patches} />
      </section>

      <section aria-labelledby="policy-history-title" className={SECTION}>
        <h2 id="policy-history-title" className={SECTION_TITLE}>
          {t("policy.history")}
        </h2>
        <VersionHistory
          key={`${revision}:${confirmation.rollback ?? ""}`}
          appId={app.id}
          appName={app.name}
          environment={environment}
          currentVersion={policy.version}
          versions={versions}
          confirmVersion={confirmation.rollback}
          confirmBroad={rollback.broad}
          confirmPromotes={rollback.promotes}
        />
      </section>

      <section aria-labelledby="policy-key-title" className={`${SECTION} max-w-2xl`}>
        <h2 id="policy-key-title" className={SECTION_TITLE}>
          {t("policy.key.title")}
        </h2>
        <p className="text-fg-muted">{t("policy.key.help")}</p>
        {publicKey ? (
          <PolicyKeySnippet publicKey={publicKey} />
        ) : (
          <p data-testid="policy-key-unavailable">{t("policy.key.unavailable")}</p>
        )}
      </section>
    </AppShell>
  );
}
