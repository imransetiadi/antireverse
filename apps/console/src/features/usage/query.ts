import { USAGE_HISTORY_MONTHS, usageMonthOf } from "@antireverse/protocol";
import { formatCount } from "@/lib/format.ts";

const MONTH_NAMES = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
] as const;

/**
 * The month of the address (`?month=`), as given — the API validates it and says why it refuses one. The first of
 * several values; none or an empty one means the current month.
 */
export function usageMonthParam(params: Record<string, string | string[] | undefined>): string | undefined {
  const value = params.month;
  const first = Array.isArray(value) ? value[0] : value;
  return first === undefined || first === "" ? undefined : first;
}

/** The months that can be read at `now`: the current UTC month and the `USAGE_HISTORY_MONTHS` before it, newest first. */
export function usageMonthOptions(now: Date): string[] {
  const current = usageMonthOf(now);
  const year = Number(current.slice(0, 4));
  const month = Number(current.slice(5, 7)) - 1;
  return Array.from({ length: USAGE_HISTORY_MONTHS + 1 }, (_, back) =>
    usageMonthOf(new Date(Date.UTC(year, month - back, 1))),
  );
}

/** `2026-11` → `November 2026`. Pure, so server and browser agree. */
export function monthName(month: string): string {
  const index = Number(month.slice(5, 7)) - 1;
  return `${MONTH_NAMES[index] ?? month.slice(5, 7)} ${month.slice(0, 4)}`;
}

/** Minutes with the thousands grouped and at most two decimals, trailing zeros dropped: `1,234.25`, `90.5`, `0`. */
export function formatMinutes(minutes: number): string {
  const [whole = "0", decimals = ""] = minutes.toFixed(2).split(".");
  const kept = decimals.replace(/0+$/, "");
  return `${formatCount(Number(whole))}${kept ? `.${kept}` : ""}`;
}
