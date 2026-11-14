import type { SloReport } from "@antireverse/protocol";
import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { opsSignOutAction } from "@/app/ops/actions.ts";
import { AppShell } from "@/components/app-shell.tsx";
import { Button, ButtonLink } from "@/components/button.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { OpsSummary } from "@/features/ops/ops-summary.tsx";
import { SloPanel } from "@/features/ops/slo-panel.tsx";
import { ApiError, getSloReport, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { readOpsSession } from "@/lib/ops-session.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

export const metadata: Metadata = { robots: { index: false, follow: false } };

type Loaded =
  | { kind: "report"; report: SloReport }
  | { kind: "disabled" }
  | { kind: "unexpected" }
  | { kind: "unavailable" };

/** The SLO report, or why it is not shown. A token the API no longer accepts is cleared through `/ops/expired`. */
async function loadReport(token: string): Promise<Loaded> {
  try {
    return { kind: "report", report: await getSloReport(token) };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.opsExpired);
    if (error instanceof NotFoundError) return { kind: "disabled" };
    // 502: the API client's verdict on an answer outside the contract.
    if (error instanceof ApiError) return { kind: error.status === 502 ? "unexpected" : "unavailable" };
    throw error;
  }
}

// `/ops` (slice 18d) — the operator SLO dashboard: one panel per SLO in catalog order, the summary above them. Signed
// in with the operator cookie only (a tenant session does not grant it), not linked from the tenant navigation, and
// server-rendered: it works without JavaScript, and Refresh is a plain link to this address.
export default async function OpsPage() {
  const token = await readOpsSession();
  if (token === undefined) redirect(ROUTES.opsSignIn);
  const loaded = await loadReport(token);

  return (
    <AppShell>
      <PageHeader
        title={t("ops.title")}
        actions={
          <>
            <ButtonLink href={ROUTES.ops} variant="secondary" data-testid="ops-refresh" prefetch={false}>
              {t("ops.refresh")}
            </ButtonLink>
            <form action={opsSignOutAction}>
              <Button type="submit" variant="quiet">
                {t("ops.signout")}
              </Button>
            </form>
          </>
        }
      />
      <p className="max-w-3xl text-fg-muted">{t("ops.lead")}</p>
      {loaded.kind === "disabled" ? (
        <p role="alert" data-testid="ops-disabled" className="max-w-3xl rounded-card border border-sev-medium p-3">
          {t("ops.disabled")}
        </p>
      ) : null}
      {loaded.kind === "unavailable" || loaded.kind === "unexpected" ? (
        <p role="alert" data-testid="ops-unavailable" className="max-w-3xl rounded-card border border-sev-medium p-3">
          {t(loaded.kind === "unexpected" ? "ops.unexpected" : "ops.unavailable")}
        </p>
      ) : null}
      {loaded.kind === "report" ? (
        <>
          <OpsSummary report={loaded.report} />
          {loaded.report.slos.map((slo) => (
            <SloPanel key={slo.id} slo={slo} />
          ))}
        </>
      ) : null}
    </AppShell>
  );
}
