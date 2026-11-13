import type { AppSetup, Environment } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

/**
 * The read of `appSetup`: Organization, App, Environment. One MIN() per step, each served by an index that a test
 * checks: Shield by `events_recent`, Guard by `events_first_attested` (migration 0030), Harden by
 * `builds_recent_by_environment`. Row-level security applies on top of the Organization named here.
 */
export const APP_SETUP_SQL = `SELECT
       (SELECT MIN(received_at) FROM events
         WHERE organization_id = $1 AND app_id = $2 AND environment = $3) AS shield,
       (SELECT MIN(received_at) FROM events
         WHERE organization_id = $1 AND app_id = $2 AND environment = $3
           AND payload->'attestation'->>'status' = 'valid') AS guard,
       (SELECT MIN(registered_at) FROM builds
         WHERE organization_id = $1 AND app_id = $2 AND environment = $3) AS harden`;

/**
 * When each set-up step of one App Environment of the transaction's Organization was first done (slice 16): Shield
 * by the first Event received, Guard by the first Event received whose Attestation Token Shield verified (status
 * `valid`, any verdict), Harden by the first Build registered. Null while a step is not done. Read only.
 */
export async function appSetup(
  q: Queryable,
  target: { organizationId: string; appId: string; environment: Environment },
): Promise<AppSetup> {
  const { rows } = await q.query<{ shield: Date | null; guard: Date | null; harden: Date | null }>(APP_SETUP_SQL, [
    target.organizationId,
    target.appId,
    target.environment,
  ]);
  const row = rows[0];
  const at = (value: Date | null | undefined) => ({ done_at: value == null ? null : value.toISOString() });
  return { environment: target.environment, shield: at(row?.shield), guard: at(row?.guard), harden: at(row?.harden) };
}

/**
 * The Environment of the App's first Shield key, the one made with the App: the Environment its set-up starts in.
 * Null when the transaction's Organization has no such App.
 */
export async function firstEnvironment(q: Queryable, appId: string): Promise<Environment | null> {
  const { rows } = await q.query<{ environment: Environment }>(
    `SELECT environment FROM api_keys
     WHERE app_id = $1 AND kind = 'shield'
     ORDER BY created_at, id
     LIMIT 1`,
    [appId],
  );
  return rows[0]?.environment ?? null;
}
