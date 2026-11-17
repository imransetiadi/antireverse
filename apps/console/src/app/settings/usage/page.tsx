import { type UsageResponse, usageMonthOf } from "@antireverse/protocol";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { usageMonthOptions, usageMonthParam } from "@/features/usage/query.ts";
import { UsageMonthForm } from "@/features/usage/usage-month-form.tsx";
import { UsageReport } from "@/features/usage/usage-report.tsx";
import {
  ApiError,
  DeletionPendingError,
  getUsage,
  RateLimitedError,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

type Loaded =
  | { kind: "usage"; usage: UsageResponse }
  | { kind: "invalid"; reason: string }
  | { kind: "limited" }
  | { kind: "unavailable" };

/** The month's usage, or why it is not shown. A key no longer accepted and a pending deletion leave the page. */
async function loadUsage(key: string, month: string | undefined): Promise<Loaded> {
  try {
    return { kind: "usage", usage: await getUsage(key, month) };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    // A deletion requested since the session was read (D-084): Data controls shows it, with why.
    if (error instanceof DeletionPendingError) redirect(ROUTES.dataControls({ blocked: true }));
    if (error instanceof ValidationError) {
      return { kind: "invalid", reason: error.errors[0]?.message ?? t("usage.invalid.fallback") };
    }
    if (error instanceof RateLimitedError) return { kind: "limited" };
    if (error instanceof ApiError) return { kind: "unavailable" };
    throw error;
  }
}

// `/settings/usage?month=YYYY-MM` — Settings → Usage (slice 17a, FR-CON-08): a month's protected requests, monthly
// active Guard devices and Prove sandbox minutes, in total, per day and per App; the Apps count, the Event retention and
// seats. The month picker is a GET form of this address. The API validates the month: one it refuses is named in its
// words above the picker, which then offers the current month.
// The route types of `.next/types` come from `next typegen`, which this slice does not run: the props are written out.
interface UsagePageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function UsagePage({ searchParams }: UsagePageProps) {
  const { key, organization } = await requireSession();
  const params = await searchParams;
  const month = usageMonthParam(params);
  const now = new Date(Date.now());
  const loaded = await loadUsage(key, month);
  // The API's clock decides the month: around midnight on the 1st it may be a month the Console's clock has not
  // reached yet, which is then offered first, so the picker never shows another month than the report.
  const offered = usageMonthOptions(now);
  const months =
    loaded.kind === "usage" && !offered.includes(loaded.usage.month)
      ? [loaded.usage.month, ...offered].sort().reverse()
      : offered;
  const selected =
    loaded.kind === "usage"
      ? loaded.usage.month
      : month !== undefined && months.includes(month)
        ? month
        : usageMonthOf(now);

  return (
    <AppShell organization={organization} current="usage">
      <PageHeader title={t("usage.title")} />
      <p className="max-w-3xl text-fg-muted">{t("usage.lead")}</p>
      <UsageMonthForm months={months} selected={selected} />
      {loaded.kind === "invalid" ? (
        <p role="alert" data-testid="usage-invalid" className="max-w-3xl body-4 text-sev-medium">
          {t("usage.invalid", { reason: loaded.reason })}
        </p>
      ) : null}
      {loaded.kind === "limited" ? (
        <p role="status" data-testid="usage-limited" className="max-w-3xl body-4 text-fg">
          {t("usage.limited")}
        </p>
      ) : null}
      {loaded.kind === "unavailable" ? (
        <p role="alert" data-testid="usage-unavailable" className="max-w-3xl body-4 text-fg">
          {t("usage.unavailable")}
        </p>
      ) : null}
      {loaded.kind === "usage" ? <UsageReport usage={loaded.usage} /> : null}
      {/* Slice 15a (D-105): Pentest Campaigns are not metered yet, and the page says so rather than showing a zero. */}
      <p data-testid="usage-campaigns" className="max-w-3xl body-5 text-fg-muted">
        {t("usage.campaigns")}
      </p>
    </AppShell>
  );
}
