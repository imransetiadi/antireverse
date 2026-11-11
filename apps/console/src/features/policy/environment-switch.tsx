import { ENVIRONMENTS, type Environment } from "@antireverse/protocol";
import Link from "next/link";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";

const LABEL: Record<Environment, MessageKey> = {
  production: "environment.production",
  staging: "environment.staging",
  development: "environment.development",
};

// The current Environment is carried by `aria-current`, by a filled segment with a bright boundary and by
// its weight; the others are plain underlined links. Height 32 px on pointer layouts, 48 px on touch layouts.
const SEGMENT =
  "press inline-flex h-8 items-center rounded-control border border-solid px-3 pointer-coarse:h-12 pointer-coarse:px-4";
const CURRENT = "border-fg bg-surface-raised heading-6 text-fg no-underline";
const OTHER = "border-border-strong title-4 text-fg-muted hover:text-fg";

/**
 * The switch between the Policies of the three Environments. Each one is its own address — a link, not
 * client state — so Back, a reload and a shared link all show the same Environment.
 */
export function EnvironmentSwitch({ appId, current }: { appId: string; current: Environment }) {
  return (
    <nav aria-label={t("app.environment")} data-testid="environment-switch" className="flex flex-wrap gap-2">
      {ENVIRONMENTS.map((environment) => (
        <Link
          key={environment}
          href={ROUTES.policy(appId, environment)}
          aria-current={environment === current ? "true" : undefined}
          data-environment={environment}
          className={`${SEGMENT} ${environment === current ? CURRENT : OTHER}`}
        >
          {t(LABEL[environment])}
        </Link>
      ))}
    </nav>
  );
}
