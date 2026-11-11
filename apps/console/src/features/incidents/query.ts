import { INCIDENT_STATUSES, type IncidentStatus } from "@antireverse/protocol";

type QueryValue = string | string[] | undefined;

/** The status of `?status=`, or undefined (every status) for none and for anything that is not a status. */
export function statusFrom(value: QueryValue): IncidentStatus | undefined {
  return INCIDENT_STATUSES.find((status) => status === value);
}

/** True when the address asks for the confirmation step of resolving: exactly `?confirm=resolve`. */
export function confirmResolveFrom(value: QueryValue): boolean {
  return value === "resolve";
}
