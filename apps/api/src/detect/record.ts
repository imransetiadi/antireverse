import type { Db, Queryable } from "../db/db.ts";
import type { Notifier } from "../notify/notifier.ts";
import type { recordDetection } from "../stores/incidents.ts";

/** SQL state of a unique violation: here, a second open or acknowledged Incident for one group. */
export const UNIQUE_VIOLATION = "23505";

export type Recorded = Awaited<ReturnType<typeof recordDetection>>;

/**
 * The one write path of every Detection, Event-counted (the Detector) or reported (the Clone Beacon): runs
 * `record` in one transaction of the Organization, and after the commit tells the notifier about a newly opened
 * Incident only (a joined Incident has alerted already). `record` returns null to record nothing.
 *
 * Another writer may open the group's Incident between `record`'s lookup and its insert: the one-active-Incident
 * index refuses the second insert and the transaction rolls back. Then once more: the Detection now joins that
 * Incident. A second failure, and any other error, is the caller's to log.
 */
export async function recordAndAlert(
  db: Db,
  notifier: Pick<Notifier, "incidentOpened">,
  organizationId: string,
  record: (q: Queryable) => Promise<Recorded | null>,
): Promise<Recorded | null> {
  const run = () => db.tx({ organizationId }, record);
  let result: Recorded | null;
  try {
    result = await run();
  } catch (error) {
    if ((error as { code?: unknown }).code !== UNIQUE_VIOLATION) throw error;
    result = await run();
  }
  if (result?.opened === true) notifier.incidentOpened(result.incident, organizationId);
  return result;
}
