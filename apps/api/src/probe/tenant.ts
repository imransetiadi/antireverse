import { generateKey, newId } from "@antireverse/protocol/server";
import { audit, systemActor } from "../audit.ts";
import type { OwnedDb } from "../db/db.ts";
import { findApp, insertApp } from "../stores/apps.ts";
import { insertKey } from "../stores/keys.ts";
import { findOrganization, insertOrganization } from "../stores/organizations.ts";
import { registerSystemOrganization } from "../stores/system-organizations.ts";

// Slice 18g: the Organization the synthetic probes live in (Jev: one registered system Organization, keys in memory).
//
// - One Organization and one App, registered in the owner-only `system_organizations`. The registry row is written
//   first, with identifiers made here; the Organization and the App follow in the Organization's own tenant
//   transaction, with their audit entries by the system actor. A start that was cut in between is completed here.
// - Events are kept 7 days, the shortest retention there is: the daily retention job bounds what the probe stores.
// - Keys: every call removes the Organization's key rows and makes one admin key and one production Shield key. Their
//   plaintext is returned and never stored, logged or audited: after a restart nobody can use the old ones, and
//   nothing has to be kept in a file. It is called once per process (`connect.ts`), so the table holds one pair.
//
// The probe then acts through the HTTP routes with these keys, like a customer.

export const PROBE_ORGANIZATION_NAME = "Airverse synthetic probes";
export const PROBE_APP_NAME = "Synthetic probe";
export const PROBE_ENVIRONMENT = "production";
/** The shortest Event retention (slice 18c). */
const PROBE_EVENT_RETENTION_DAYS = 7;

export interface ProbeTenant {
  organizationId: string;
  appId: string;
  /** Plaintext, for this process only. */
  adminKey: string;
  shieldKey: string;
}

export async function provisionProbeTenant(options: {
  db: OwnedDb;
  now?: (() => Date) | undefined;
}): Promise<ProbeTenant> {
  const { db } = options;
  const at = (options.now ?? (() => new Date()))();
  const { organizationId, appId } = await db.owner((q) =>
    registerSystemOrganization(q, "probe", { organizationId: newId("org"), appId: newId("app") }, at),
  );
  // The keys of an earlier start (review F1): nobody holds their plaintext, so their rows go — a restart leaves the
  // current pair and nothing else. As the owner (the request role cannot delete a key), and for the registered probe
  // Organization only. Nothing refers to a key row: audit entries and Policy versions keep the key's id as text.
  await db.owner((q) => q.query("DELETE FROM api_keys WHERE organization_id = $1", [organizationId]));
  const admin = generateKey("admin");
  const shield = generateKey("shield", PROBE_ENVIRONMENT);
  await db.tx({ organizationId }, async (q) => {
    if ((await findOrganization(q, organizationId)) === null) {
      await insertOrganization(q, { id: organizationId, name: PROBE_ORGANIZATION_NAME });
      await q.query("UPDATE organizations SET event_retention_days = $2 WHERE id = $1", [
        organizationId,
        PROBE_EVENT_RETENTION_DAYS,
      ]);
      await audit(q, systemActor(organizationId), {
        action: "organization.create",
        target: { kind: "organization", id: organizationId },
        summary: "The API created its own Organization for the synthetic probes (slice 18g). It holds no tenant data.",
        at,
      });
    }
    if ((await findApp(q, appId)) === null) {
      await insertApp(q, { id: appId, organizationId, name: PROBE_APP_NAME });
      await audit(q, systemActor(organizationId), {
        action: "app.create",
        appId,
        target: { kind: "app", id: appId },
        summary: "The API created the App of the synthetic probes. Its keys are made anew at every start.",
        at,
      });
    }
    await insertKey(q, { id: newId("key"), organizationId, kind: "admin", generated: admin });
    await insertKey(q, {
      id: newId("key"),
      organizationId,
      kind: "shield",
      appId,
      environment: PROBE_ENVIRONMENT,
      generated: shield,
    });
  });
  return { organizationId, appId, adminKey: admin.key, shieldKey: shield.key };
}
