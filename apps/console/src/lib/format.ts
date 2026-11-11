// Formatting of Event fields. Pure and time-zone independent: server render and browser render agree.

export interface FormattedTime {
  /** `HH:MM:SS` in UTC, or `--:--:--` when the value is not a date. */
  text: string;
  /** The value as it was given, for a `title` and a `<time dateTime>`. */
  iso: string;
}

const two = (value: number): string => String(value).padStart(2, "0");

export function formatTime(iso: string): FormattedTime {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return { text: "--:--:--", iso };
  return { text: `${two(date.getUTCHours())}:${two(date.getUTCMinutes())}:${two(date.getUTCSeconds())}`, iso };
}

/** `YYYY-MM-DD HH:MM:SS` in UTC, or dashes of the same width when the value is not a date. */
export function formatDateTime(iso: string): FormattedTime {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return { text: "---- -- -- --:--:--", iso };
  const day = `${date.getUTCFullYear()}-${two(date.getUTCMonth() + 1)}-${two(date.getUTCDate())}`;
  return { text: `${day} ${formatTime(iso).text}`, iso };
}

/** `<1 ms` below one millisecond, whole milliseconds below one second, then seconds with one decimal. */
export function formatLatency(ms: number): string {
  if (ms < 1) return "<1 ms";
  const rounded = Math.round(ms);
  if (rounded < 1000) return `${rounded} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

/**
 * A cost overhead as a signed percentage, e.g. `+12.5 %`, `0 %`, `-4 %`. One decimal at most, trailing
 * `.0` dropped. Pure, so a server render and a browser render of the same Build agree.
 */
export function formatOverhead(pct: number): string {
  const rounded = Math.round(pct * 10) / 10;
  const sign = rounded > 0 ? "+" : "";
  return `${sign}${rounded} %`;
}

/** A byte count with the thousands grouped by a comma, the same on the server and in the browser. */
export function formatBytes(bytes: number): string {
  return Math.trunc(bytes)
    .toString()
    .replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

export type StatusClass = "ok" | "client" | "server";

/** `client` for 4xx, `server` for 5xx, `ok` for everything below. */
export function statusClass(status: number): StatusClass {
  if (status >= 500) return "server";
  if (status >= 400) return "client";
  return "ok";
}
