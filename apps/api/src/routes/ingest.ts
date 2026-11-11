import { EventBatchSchema, type IngestResponse, type StoredEvent } from "@antireverse/protocol";
import { Hono } from "hono";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { EventBus } from "../bus.ts";
import type { Db } from "../db/db.ts";
import { insertEvents } from "../stores/events.ts";
import { validateJson } from "../validate.ts";

export function ingestRoutes(deps: { db: Db; bus: EventBus; now?: () => Date }): Hono<AppEnv> {
  const { db, bus } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();

  // A batch is atomic: one invalid Event refuses all of it (validation), one failed insert stores none of it.
  routes.post("/v1/events", requireKey(db, "shield"), limitBody(), validateJson(EventBatchSchema), async (c) => {
    // Organization, App and Environment come from the key. The validated batch has no such members left:
    // the schema stripped every key outside the privacy allowlist.
    const { organizationId, appId, environment } = c.var.principal;
    const receivedAt = now();
    // PostgreSQL compares identifiers case-insensitively; one spelling keeps the payload consistent with it.
    const events = c.req.valid("json").events.map((event) => ({ ...event, event_id: event.event_id.toLowerCase() }));

    const stored = await db.tx({ organizationId }, (q) =>
      insertEvents(q, { organizationId, appId, environment, receivedAt }, events),
    );
    const accepted = stored.size;

    // Only now, after the commit, and only for what was newly stored: a live stream never shows an Event
    // that was rolled back, and never shows one twice (an identifier may repeat inside a batch).
    const stamp = {
      organization_id: organizationId,
      app_id: appId,
      environment,
      received_at: receivedAt.toISOString(),
    };
    for (const event of events) {
      if (stored.delete(event.event_id)) bus.publish({ ...event, ...stamp } satisfies StoredEvent);
    }

    return c.json({ accepted, duplicates: events.length - accepted } satisfies IngestResponse, 202);
  });

  return routes;
}
