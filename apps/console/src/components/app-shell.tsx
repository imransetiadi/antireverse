import type { Organization } from "@antireverse/protocol";
import Link from "next/link";
import type { ReactNode } from "react";
import { signOutAction } from "@/app/actions.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { BrandMark } from "./brand-mark.tsx";
import { Button } from "./button.tsx";

/** The top-level screen a page belongs to; its navigation entry is marked as current. */
export type ShellSection = "apps" | "incidents" | "findings" | "targets" | "rules" | "alerts" | "allowlist";

// The current entry is carried by `aria-current`, its weight and a solid underline — not by colour alone.
const NAV_LINK = "inline-flex h-8 items-center px-1 pointer-coarse:h-12";
const NAV_CURRENT = "heading-6 text-fg decoration-2 decoration-primary";

function NavLink({
  section,
  current,
  href,
  label,
}: {
  section: ShellSection;
  current?: ShellSection | undefined;
  href: string;
  label: string;
}) {
  const isCurrent = section === current;
  return (
    <Link
      href={href}
      aria-current={isCurrent ? "page" : undefined}
      data-testid={`nav-${section}`}
      className={`${NAV_LINK} ${isCurrent ? NAV_CURRENT : ""}`.trim()}
    >
      {label}
    </Link>
  );
}

interface AppShellProps {
  /** The Organization of the session; without it the bar shows the brand only. */
  organization?: Organization | undefined;
  /** `narrow` for a single form, `wide` for lists and tables. */
  width?: "narrow" | "wide";
  /** The navigation entry to mark as current. */
  current?: ShellSection | undefined;
  children: ReactNode;
}

/** The top bar (48 px: brand, Organization, navigation, settings, sign-out) and the main region. */
export function AppShell({ organization, width = "wide", current, children }: AppShellProps) {
  return (
    <>
      <header className="flex min-h-12 flex-wrap items-center gap-x-4 gap-y-1 border-border border-b bg-bg px-4 py-2">
        <span data-testid="brand" className="inline-flex items-center gap-2 heading-6 text-fg">
          <BrandMark />
          {t("brand")}
        </span>
        {organization ? (
          <>
            <span className="min-w-0 flex-1 basis-24 break-words text-fg-muted">
              <span className="sr-only">{t("session.organization")} </span>
              <span data-testid="organization-name">{organization.name}</span>
            </span>
            <nav aria-label={t("nav.main")} className="flex flex-wrap items-center gap-3">
              <NavLink section="apps" current={current} href={ROUTES.apps} label={t("nav.apps")} />
              <NavLink section="incidents" current={current} href={ROUTES.incidents()} label={t("nav.incidents")} />
              <NavLink section="findings" current={current} href={ROUTES.findings()} label={t("nav.findings")} />
            </nav>
            <nav aria-label={t("nav.prove")} className="flex flex-wrap items-center gap-3">
              <NavLink section="targets" current={current} href={ROUTES.targets} label={t("nav.targets")} />
              <NavLink section="rules" current={current} href={ROUTES.rulesOfEngagement} label={t("nav.rules")} />
            </nav>
            <nav aria-label={t("nav.settings")} className="flex flex-wrap items-center gap-3">
              <NavLink section="alerts" current={current} href={ROUTES.alerts()} label={t("nav.alerts")} />
              <NavLink section="allowlist" current={current} href={ROUTES.allowlist()} label={t("nav.allowlist")} />
            </nav>
            <form action={signOutAction}>
              <Button type="submit" variant="quiet">
                {t("session.signout")}
              </Button>
            </form>
          </>
        ) : null}
      </header>
      <main
        id="content"
        className={`mx-auto flex w-full flex-1 flex-col gap-6 px-4 py-6 ${width === "narrow" ? "max-w-xl" : "max-w-6xl"}`}
      >
        {children}
      </main>
    </>
  );
}
