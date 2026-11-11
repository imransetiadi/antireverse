import {
  AdvisoryIdSchema,
  FINDING_SEVERITIES,
  FINDING_SOURCES,
  FINDING_STATUSES,
  type FindingSeverity,
  type FindingSource,
  type FindingStatus,
  ID_PATTERNS,
} from "@antireverse/protocol";
import type { FindingFilter } from "@/lib/api.ts";

type QueryValue = string | string[] | undefined;

/**
 * The filters of a Finding list address. Every one is passed to the API (`findingFilterFrom`), which filters
 * before it caps the list at 200.
 */
export interface FindingQuery {
  severity?: FindingSeverity | undefined;
  status?: FindingStatus | undefined;
  source?: FindingSource | undefined;
  /** An advisory id or one of its aliases, e.g. from a vulnerable component Incident. */
  advisory?: string | undefined;
  /** A Build id, from the Build page. */
  build?: string | undefined;
}

const oneOf = <T extends string>(options: readonly T[], value: QueryValue): T | undefined =>
  options.find((option) => option === value);

/** The filters of the address it knows; anything else, a repeated parameter among them, is dropped. */
export function findingQueryFrom(params: {
  severity?: QueryValue;
  status?: QueryValue;
  source?: QueryValue;
  advisory?: QueryValue;
  build?: QueryValue;
}): FindingQuery {
  const query: FindingQuery = {};
  const severity = oneOf(FINDING_SEVERITIES, params.severity);
  const status = oneOf(FINDING_STATUSES, params.status);
  const source = oneOf(FINDING_SOURCES, params.source);
  if (severity !== undefined) query.severity = severity;
  if (status !== undefined) query.status = status;
  if (source !== undefined) query.source = source;
  if (typeof params.advisory === "string" && AdvisoryIdSchema.safeParse(params.advisory).success) {
    query.advisory = params.advisory;
  }
  if (typeof params.build === "string" && ID_PATTERNS.bld.test(params.build)) query.build = params.build;
  return query;
}

/** True when any filter is set: an empty list then says that nothing matches rather than that nothing exists. */
export const isFiltered = (query: FindingQuery): boolean => Object.values(query).some((value) => value !== undefined);

/** True when the address asks for the ignore step: exactly `?confirm=ignore`. */
export function confirmIgnoreFrom(value: QueryValue): boolean {
  return value === "ignore";
}

/** The API filter for a list address, narrowed to one App on an App's list. Only filters that are set appear. */
export function findingFilterFrom(query: FindingQuery, appId?: string): FindingFilter {
  const filter: FindingFilter = {};
  if (appId !== undefined) filter.appId = appId;
  if (query.severity !== undefined) filter.severity = query.severity;
  if (query.status !== undefined) filter.status = query.status;
  if (query.source !== undefined) filter.source = query.source;
  if (query.advisory !== undefined) filter.advisoryId = query.advisory;
  if (query.build !== undefined) filter.buildId = query.build;
  return filter;
}
