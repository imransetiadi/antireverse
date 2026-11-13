import Link from "next/link";
import { Icon } from "@/components/icons.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

/**
 * "Set up: n of 3" as a way to the App's Set up page, until all three steps are done; then "Done". `done` is null
 * when the API could not say: a plain "Set up" link, without a number.
 */
export function SetupProgressLink({ appId, appName, done }: { appId: string; appName: string; done: number | null }) {
  if (done !== null && done >= 3) {
    return (
      <span data-testid="setup-progress" className="inline-flex items-center gap-1 text-fg-muted">
        <Icon name="check-circle" className="size-4 text-primary" />
        {t("setup.done")}
      </span>
    );
  }
  return (
    <Link
      href={ROUTES.setup(appId)}
      data-testid="setup-progress"
      aria-label={
        done === null ? t("setup.link.for", { app: appName }) : t("setup.progress.for", { app: appName, done })
      }
    >
      {done === null ? t("nav.setup") : t("setup.progress", { done })}
    </Link>
  );
}
