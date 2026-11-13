import type { App } from "@antireverse/protocol";
import { AUDIT_ACTIONS } from "@antireverse/protocol";
import { Button, ButtonLink } from "@/components/button.tsx";
import { Input, Select } from "@/components/input.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { ACTION_LABEL } from "./labels.ts";
import { AUDIT_DAY_MAX, AUDIT_DAY_MIN, type AuditQuery, filtered, rangeReversed } from "./query.ts";

interface AuditFiltersProps {
  query: AuditQuery;
  apps: ReadonlyArray<Pick<App, "id" | "name">>;
  /** True when the API refused the filters and the list shows every entry instead. */
  notApplied?: boolean | undefined;
}

/**
 * The filters of the audit log: a GET form of the page itself, so that it works without JavaScript and a filtered
 * view is an address that can be shared. Days are UTC; the To day is included.
 */
export function AuditFilters({ query, apps, notApplied = false }: AuditFiltersProps) {
  return (
    <search aria-label={t("audit.filter.title")}>
      <form
        method="get"
        action={ROUTES.audit()}
        data-testid="audit-filters"
        className="flex flex-col gap-3 rounded-card border border-border bg-surface p-3"
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Select id="audit-action" name="action" label={t("audit.filter.action")} defaultValue={query.action ?? ""}>
            <option value="">{t("audit.filter.action.all")}</option>
            {AUDIT_ACTIONS.map((action) => (
              <option key={action} value={action}>
                {t(ACTION_LABEL[action])}
              </option>
            ))}
          </Select>
          <Select id="audit-app" name="app" label={t("audit.filter.app")} defaultValue={query.app ?? ""}>
            <option value="">{t("audit.filter.app.all")}</option>
            {apps.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name}
              </option>
            ))}
          </Select>
          <Input
            id="audit-from"
            name="from"
            type="date"
            label={t("audit.filter.from")}
            defaultValue={query.from ?? ""}
            min={AUDIT_DAY_MIN}
            max={AUDIT_DAY_MAX}
          />
          <Input
            id="audit-to"
            name="to"
            type="date"
            label={t("audit.filter.to")}
            defaultValue={query.to ?? ""}
            min={AUDIT_DAY_MIN}
            max={AUDIT_DAY_MAX}
          />
        </div>
        {notApplied ? (
          <p role="alert" data-testid="audit-filters-not-applied" className="body-5 text-sev-medium">
            {t("audit.filter.notApplied")}
          </p>
        ) : null}
        {rangeReversed(query) ? (
          <p data-testid="audit-range-reversed" className="body-5 text-sev-medium">
            {t("audit.filter.reversed")}
          </p>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" variant="secondary">
            {t("audit.filter.apply")}
          </Button>
          {filtered(query) ? (
            <ButtonLink variant="quiet" href={ROUTES.audit()} prefetch={false}>
              {t("audit.filter.clear")}
            </ButtonLink>
          ) : null}
        </div>
      </form>
    </search>
  );
}
