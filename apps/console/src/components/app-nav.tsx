import Link from "next/link";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";

export type AppSection = "live" | "policy" | "builds" | "findings" | "containment";

const SECTIONS: ReadonlyArray<{ section: AppSection; label: MessageKey; href: (appId: string) => string }> = [
  { section: "live", label: "nav.live", href: (appId) => ROUTES.live(appId) },
  { section: "policy", label: "nav.policy", href: (appId) => ROUTES.policy(appId) },
  { section: "builds", label: "nav.builds", href: (appId) => ROUTES.builds(appId) },
  { section: "findings", label: "nav.findings", href: (appId) => ROUTES.appFindings(appId) },
  { section: "containment", label: "nav.containment", href: (appId) => ROUTES.containment(appId) },
];

// The current screen is carried by `aria-current`, by a solid bar under the word and by its weight — not
// by colour alone. Height 32 px on pointer layouts, 48 px on touch layouts.
const TAB =
  "press -mb-px inline-flex h-8 items-center border-b-2 px-3 no-underline pointer-coarse:h-12 pointer-coarse:px-4 hover:text-fg";
const CURRENT = "border-primary heading-6 text-fg";
const OTHER = "border-transparent title-4 text-fg-muted";

/** The screens of one App, as links that look like tabs: Live, Policy, Builds, Findings and Containment. */
export function AppNav({ appId, current }: { appId: string; current: AppSection }) {
  return (
    <nav aria-label={t("nav.app")} data-testid="app-nav" className="flex flex-wrap gap-1 border-border border-b">
      {SECTIONS.map(({ section, label, href }) => (
        <Link
          key={section}
          href={href(appId)}
          aria-current={section === current ? "page" : undefined}
          data-testid={`app-nav-${section}`}
          className={`${TAB} ${section === current ? CURRENT : OTHER}`}
        >
          {t(label)}
        </Link>
      ))}
    </nav>
  );
}
