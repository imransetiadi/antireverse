import type { OrganizationDeletion } from "@antireverse/protocol";
import Link from "next/link";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { utcTime } from "./format.ts";

/**
 * The banner of every signed-in page while the Organization's deletion is pending (slice 18b): above the bar, in the
 * destructive style, with the time after which the data is erased and the way to cancel. A named region (a labelled section), so that it
 * is found in the landmarks; it is not announced on its own — the page that opens says the same.
 */
export function DeletionBanner({ deletion }: { deletion: OrganizationDeletion | null | undefined }) {
  if (!deletion) return null;
  return (
    <section
      aria-labelledby="deletion-banner-title"
      data-testid="deletion-banner"
      className="border-destructive border-b-2 bg-surface-raised px-4 py-3"
    >
      <div className="mx-auto flex max-w-6xl flex-wrap items-baseline gap-x-4 gap-y-1">
        <p id="deletion-banner-title" className="heading-6 text-fg">
          {t("data.banner.title")}
        </p>
        <p className="min-w-0 flex-1 basis-64 body-4 text-fg">
          {t("data.banner.body", { date: utcTime(deletion.purge_after) })}
        </p>
        <Link href={ROUTES.dataControls()} className="body-4 text-fg" data-testid="deletion-banner-link">
          {t("data.banner.link")}
        </Link>
      </div>
    </section>
  );
}
