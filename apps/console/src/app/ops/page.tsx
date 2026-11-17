import type { ProveOperatorState, SloReport } from "@antireverse/protocol";
import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { opsSignOutAction } from "@/app/ops/actions.ts";
import { AppShell } from "@/components/app-shell.tsx";
import { Button, ButtonLink } from "@/components/button.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { OpsSummary } from "@/features/ops/ops-summary.tsx";
import { ProveSwitch } from "@/features/ops/prove-switch.tsx";
import { SloPanel } from "@/features/ops/slo-panel.tsx";
import { ApiError, getProveOperatorState, getSloReport, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { readOpsSession } from "@/lib/ops-session.ts";
import { type OpsProveDone, ROUTES } from "@/lib/routes.ts";
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

type LoadedProve = { kind: "state"; state: ProveOperatorState } | { kind: "disabled" } | { kind: "unavailable" };

/**
 * The operator's Campaign switches (slice 15a), or why they are not shown: an API that does not have them answers
 * 404. A failure here never hides the SLO report.
 */
async function loadProve(token: string): Promise<LoadedProve> {
  try {
    return { kind: "state", state: await getProveOperatorState(token) };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.opsExpired);
    if (error instanceof NotFoundError) return { kind: "disabled" };
    if (error instanceof ApiError) return { kind: "unavailable" };
    throw error;
  }
}

const PROVE_CHANGES: readonly OpsProveDone[] = ["kill", "enable", "suspend", "resume"];
const COUNT = /^[0-9]{1,6}$/;

/** The change the address says was just made (`?prove=&stopped=`), or nothing for anything else. */
function proveDone(
  query: Record<string, string | string[] | undefined>,
): { change: OpsProveDone; stopped: number } | undefined {
  const change = PROVE_CHANGES.find((known) => known === query.prove);
  if (change === undefined) return undefined;
  const stopped = typeof query.stopped === "string" && COUNT.test(query.stopped) ? Number(query.stopped) : 0;
  return { change, stopped };
}

// The route types of `.next/types` come from `next typegen`, which this slice does not run: the props are written out.
interface OpsPageProps {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}

// `/ops` (slice 18d) — the operator SLO dashboard: one panel per SLO in catalog order, the summary above them. Signed
// in with the operator cookie only (a tenant session does not grant it), not linked from the tenant navigation, and
// server-rendered: it works without JavaScript, and Refresh is a plain link to this address.
// Slice 15a: above the SLOs, the operator's switches of Pentest Campaigns — the state, Stop all or Enable, and Suspend
// or Resume by Organization id, each with a required reason. `?prove=&stopped=` says what the last change did.
export default async function OpsPage({ searchParams }: OpsPageProps = {}) {
  const token = await readOpsSession();
  if (token === undefined) redirect(ROUTES.opsSignIn);
  const [loaded, prove] = await Promise.all([loadReport(token), loadProve(token)]);
  const done = proveDone((await searchParams) ?? {});

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
      <section aria-labelledby="ops-prove-title" data-testid="ops-prove" className="flex flex-col gap-3">
        <h2 id="ops-prove-title" className="heading-4">
          {t("ops.prove.title")}
        </h2>
        <p className="max-w-3xl body-5 text-fg-muted">{t("ops.prove.lead")}</p>
        {prove.kind === "state" ? <ProveSwitch state={prove.state} done={done} /> : null}
        {prove.kind === "disabled" ? (
          <p role="status" data-testid="ops-prove-disabled" className="max-w-3xl rounded-card border border-border p-3">
            {t("ops.prove.disabled")}
          </p>
        ) : null}
        {prove.kind === "unavailable" ? (
          <p
            role="alert"
            data-testid="ops-prove-unavailable"
            className="max-w-3xl rounded-card border border-sev-medium p-3"
          >
            {t("ops.prove.unavailable")}
          </p>
        ) : null}
      </section>
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
