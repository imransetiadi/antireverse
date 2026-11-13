import { t } from "@/lib/t.ts";

/** One decimal, without a trailing `.0`. */
const oneDecimal = (value: number): string => String(Math.round(value * 10) / 10);

/** Wall time as seconds below a minute, minutes below an hour, then hours, e.g. `3.2 s`, `30.5 min`, `2 h`. */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return t("assessment.duration.seconds", { value: oneDecimal(seconds) });
  if (seconds < 3600) return t("assessment.duration.minutes", { value: oneDecimal(seconds / 60) });
  return t("assessment.duration.hours", { value: oneDecimal(seconds / 3600) });
}
