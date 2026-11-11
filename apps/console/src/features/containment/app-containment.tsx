import { CONTAINMENT_LIMITS, type Containment, ENVIRONMENTS } from "@antireverse/protocol";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { BlockList } from "./block-list.tsx";

interface AppContainmentProps {
  appId: string;
  appName: string;
  /** The App's active blocks, newest first, any Environment. */
  containments: readonly Containment[];
  /** The block whose lifting the address asks to confirm, if any. */
  confirmLiftId: string | undefined;
}

/** The App's active blocks, one section per Environment, each with its count against the cap and Lift. */
export function AppContainment({ appId, appName, containments, confirmLiftId }: AppContainmentProps) {
  return (
    <div data-testid="app-containment" className="flex flex-col gap-6">
      {ENVIRONMENTS.map((environment) => {
        const listed = containments.filter((containment) => containment.environment === environment);
        const titleId = `containment-${environment}-title`;
        return (
          <section
            key={environment}
            aria-labelledby={titleId}
            data-testid="containment-environment"
            data-environment={environment}
            className="flex flex-col gap-3"
          >
            <div className="flex flex-wrap items-center gap-3">
              <h2 id={titleId} className="heading-4">
                <EnvironmentTag environment={environment} />
              </h2>
              <p data-testid="containment-count" className="code-3 text-fg-muted">
                {t("appContainment.count", { count: listed.length, max: CONTAINMENT_LIMITS.activePerAppEnv })}
              </p>
            </div>
            <BlockList
              containments={listed}
              appName={appName}
              caption={t("blocks.caption.environment", { app: appName, environment })}
              empty={t("appContainment.empty", { environment })}
              base={ROUTES.containment(appId)}
              returnTo={{ appId }}
              confirmLiftId={confirmLiftId}
            />
          </section>
        );
      })}
    </div>
  );
}
