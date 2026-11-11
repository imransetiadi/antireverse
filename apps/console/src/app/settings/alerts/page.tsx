import { ID_PATTERNS, INCIDENT_LIMITS } from "@antireverse/protocol";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { AddChannelForm } from "@/features/alerts/add-channel-form.tsx";
import { ChannelList } from "@/features/alerts/channel-list.tsx";
import { listAlertChannels, UnauthorizedError } from "@/lib/api.ts";
import { requireSession } from "@/lib/guard.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";

// `/settings/alerts?remove=` — the Organization's alert channels: the list with test and remove, and the
// form that adds one. `?remove=<channel id>` opens the step that asks before a channel is removed.
export default async function AlertSettingsPage({ searchParams }: PageProps<"/settings/alerts">) {
  const { key, organization } = await requireSession();
  const { remove } = await searchParams;
  let channels: Awaited<ReturnType<typeof listAlertChannels>>["channels"];
  try {
    ({ channels } = await listAlertChannels(key));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
  const confirmRemoveId =
    typeof remove === "string" && ID_PATTERNS.chn.test(remove) && channels.some((channel) => channel.id === remove)
      ? remove
      : undefined;

  return (
    <AppShell organization={organization} current="alerts">
      <PageHeader title={t("alerts.title")} />
      <p className="text-fg-muted">{t("alerts.lead")}</p>

      <section aria-labelledby="alerts-list-title" className={SECTION}>
        <h2 id="alerts-list-title" className={SECTION_TITLE}>
          {t("nav.alerts")}
        </h2>
        <p data-testid="channel-count" className="code-3 text-fg-muted">
          {t("alerts.count", { count: channels.length, max: INCIDENT_LIMITS.channelsMax })}
        </p>
        <ChannelList key={confirmRemoveId ?? ""} channels={channels} confirmRemoveId={confirmRemoveId} />
      </section>

      <section aria-labelledby="alerts-add-title" className={SECTION}>
        <h2 id="alerts-add-title" className={SECTION_TITLE}>
          {t("alerts.add.title")}
        </h2>
        <AddChannelForm />
      </section>
    </AppShell>
  );
}
