import { formatDateTime } from "@/lib/format.ts";

/** A time of data controls in words a person reads: `YYYY-MM-DD HH:MM:SS UTC`. Pure, so server and browser agree. */
export function utcTime(iso: string): string {
  return `${formatDateTime(iso).text} UTC`;
}

/**
 * A time known only roughly — the erase time of a deletion not asked for yet, which moves with the moment it is
 * asked: `YYYY-MM-DD HH:MM UTC`, said with "about" by its message.
 */
export function utcMinute(iso: string): string {
  return `${formatDateTime(iso).text.slice(0, 16)} UTC`;
}
