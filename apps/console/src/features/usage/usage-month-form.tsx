import { Button } from "@/components/button.tsx";
import { Select } from "@/components/input.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { monthName } from "./query.ts";

interface UsageMonthFormProps {
  /** The months that can be read, newest first. */
  months: readonly string[];
  /** The month shown, chosen in the list. */
  selected: string;
}

/** The month picker: a GET form of the page itself, so it works without JavaScript and a month is a shareable address. */
export function UsageMonthForm({ months, selected }: UsageMonthFormProps) {
  return (
    <search aria-label={t("usage.month.title")}>
      <form
        method="get"
        action={ROUTES.usage()}
        data-testid="usage-month-form"
        className="flex flex-wrap items-end gap-2"
      >
        <div className="w-full max-w-xs">
          <Select id="usage-month" name="month" label={t("usage.month.label")} defaultValue={selected}>
            {months.map((month) => (
              <option key={month} value={month}>
                {monthName(month)}
              </option>
            ))}
          </Select>
        </div>
        <Button type="submit" variant="secondary">
          {t("usage.month.show")}
        </Button>
      </form>
    </search>
  );
}
