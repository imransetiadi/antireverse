import Link from "next/link";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";

export type AppSection = "setup" | "live" | "policy" | "builds" | "findings" | "containment";

const SECTIONS: ReadonlyArray<{ section: AppSection; label: MessageKey; href: (appId: string) => string }> = [
  { section: "setup", label: "nav.setup", href: (appId) => ROUTES.setup(appId) },
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

/**
 * The screens of one App, as links that look like tabs: Set up, Live, Policy, Builds, Findings and Containment.
 * `setupDone` is how many of the three set-up steps are done (slice 16): below three the Set up tab reads
 * "Set up: n of 3"; left out (unknown), three, or on the Set up page itself (which shows the progress live), it
 * reads "Set up".
 */
export function AppNav({
  appId,
  current,
  setupDone,
}: {
  appId: string;
  current: AppSection;
  setupDone?: number | null;
}) {
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
          {section === "setup" && current !== "setup" && typeof setupDone === "number" && setupDone < 3
            ? t("setup.progress", { done: setupDone })
            : t(label)}
        </Link>
      ))}
    </nav>
  );
}
