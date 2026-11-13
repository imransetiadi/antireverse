import type { Metadata } from "next";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { ConfirmOutcome } from "@/features/alerts/confirm-outcome.tsx";
import { outcomeFrom } from "@/features/alerts/confirm-result.ts";
import { t } from "@/lib/t.ts";

// Route props written out: `next typegen` is not run in this slice.
interface AlertConfirmDonePageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export const metadata: Metadata = { title: t("confirm.title"), referrer: "no-referrer" };

// `/alerts/confirm/done?result=…` — where "Confirm email" lands (slice 06b): the outcome in one sentence, never the
// token. Public and without a session, like the link page. An unknown result reads as invalid.
export default async function AlertConfirmDonePage({ searchParams }: AlertConfirmDonePageProps) {
  const { result } = await searchParams;
  return (
    <AppShell width="narrow">
      <PageHeader title={t("confirm.title")} />
      <ConfirmOutcome outcome={outcomeFrom(result)} />
    </AppShell>
  );
}
