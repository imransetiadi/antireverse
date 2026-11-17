import { CAMPAIGN_STAND_IN_NOTICE, type CampaignEngine, STAND_IN_ENGINE } from "@antireverse/protocol";
import { Icon } from "@/components/icons.tsx";
import { t } from "@/lib/t.ts";

/** The engine that ran a Campaign, as its own name (`stand-in`): a value, never translated. */
export function EngineTag({ engine }: { engine: CampaignEngine }) {
  return (
    <span
      data-testid="campaign-engine"
      title={`${engine.name} ${engine.version}`}
      className="inline-flex h-6 items-center rounded-control border border-border-strong px-2 code-3 whitespace-nowrap text-fg"
    >
      {engine.name}
    </span>
  );
}

/**
 * What the results of a Campaign are and are not, shown wherever a result is shown (ticket 15a). For the scripted
 * engine it is the protocol's sentence, word for word, whatever the API sent; another engine's notice is shown as the
 * plain text it is.
 */
export function CampaignNotice({ engine, notice }: { engine: CampaignEngine; notice: string }) {
  const text = engine.name === STAND_IN_ENGINE.name ? CAMPAIGN_STAND_IN_NOTICE : notice;
  return (
    <div
      role="note"
      aria-label={t("campaign.notice.label")}
      data-testid="campaign-notice"
      className="flex max-w-3xl flex-wrap items-center gap-x-3 gap-y-2 rounded-card border border-sev-medium p-3"
    >
      <Icon name="info" className="size-4 text-sev-medium" />
      <p data-testid="campaign-notice-text" className="min-w-0 flex-1 basis-64 body-4 text-fg">
        {text}
      </p>
      <span className="inline-flex items-center gap-2 caption-1 text-fg-muted">
        {t("campaign.engine")}
        <EngineTag engine={engine} />
      </span>
    </div>
  );
}
