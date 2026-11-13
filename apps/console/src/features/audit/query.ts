import { AUDIT_ACTIONS, type AuditAction, ID_PATTERNS } from "@antireverse/protocol";
import type { AuditFilter } from "@/lib/api.ts";

// The filters of the audit log address (slice 18a): `?action=&app=&from=&to=`. Dates are whole UTC days typed in
// date fields; `to` includes its day. Isomorphic: the page and the "Load more" action read the address the same way.

type QueryValue = string | string[] | undefined;

export interface AuditQuery {
  action?: AuditAction | undefined;
  app?: string | undefined;
  /** `YYYY-MM-DD`, the first UTC day shown. */
  from?: string | undefined;
  /** `YYYY-MM-DD`, the last UTC day shown. */
  to?: string | undefined;
}

const DAY = /^\d{4}-\d{2}-\d{2}$/;

/**
 * The first and last day a filter can name. The API takes times in the years 2000 to 2099 only, and a To day is sent
 * as the start of the next day, so the last one is 2099-12-30.
 */
export const AUDIT_DAY_MIN = "2000-01-01";
export const AUDIT_DAY_MAX = "2099-12-30";

/** True for a real calendar day written `YYYY-MM-DD`, from `AUDIT_DAY_MIN` to `AUDIT_DAY_MAX`. */
function isDay(value: QueryValue): value is string {
  if (typeof value !== "string" || !DAY.test(value)) return false;
  if (value < AUDIT_DAY_MIN || value > AUDIT_DAY_MAX) return false;
  const time = Date.parse(`${value}T00:00:00.000Z`);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 10) === value;
}

/** The filters of the address it knows; anything else, a repeated parameter among them, is dropped. */
export function auditQueryFrom(params: {
  action?: QueryValue;
  app?: QueryValue;
  from?: QueryValue;
  to?: QueryValue;
}): AuditQuery {
  const query: AuditQuery = {};
  const action = AUDIT_ACTIONS.find((one) => one === params.action);
  if (action !== undefined) query.action = action;
  if (typeof params.app === "string" && ID_PATTERNS.app.test(params.app)) query.app = params.app;
  if (isDay(params.from)) query.from = params.from;
  if (isDay(params.to)) query.to = params.to;
  return query;
}

/** True when both days are given and the first comes after the last: the range is then not applied. */
export function rangeReversed(query: AuditQuery): boolean {
  return query.from !== undefined && query.to !== undefined && query.from > query.to;
}

/** The day after `day`, at midnight UTC, as ISO text: the exclusive end of a range that includes `day`. */
function dayAfter(day: string): string {
  return new Date(Date.parse(`${day}T00:00:00.000Z`) + 86_400_000).toISOString();
}

/** The API filter of the address: `from` at the start of its day, `to` at the start of the day after. */
export function auditFilterFrom(query: AuditQuery): AuditFilter {
  const filter: AuditFilter = {};
  if (query.action !== undefined) filter.action = query.action;
  if (query.app !== undefined) filter.appId = query.app;
  if (!rangeReversed(query)) {
    if (query.from !== undefined) filter.from = `${query.from}T00:00:00.000Z`;
    if (query.to !== undefined) filter.to = dayAfter(query.to);
  }
  return filter;
}

/** True when the address narrows the log at all. */
export const filtered = (query: AuditQuery): boolean => Object.values(query).some((value) => value !== undefined);
