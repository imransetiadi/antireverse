import { ID_PATTERNS, LIMITS, type ListEventsResponse } from "@antireverse/protocol";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { z } from "zod";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import type { EventBus } from "../bus.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { findApp } from "../stores/apps.ts";
import { listEvents } from "../stores/events.ts";
import { validateQuery } from "../validate.ts";

/** Query of `GET /v1/apps/:appId/events`: `limit` is a plain decimal integer from 1 to 200, default 50. */
const ListEventsQuerySchema = z.object({
  limit: z
    .string()
    .regex(/^[0-9]{1,9}$/, `Expected an integer from 1 to ${LIMITS.listMax}.`)
    .transform(Number)
    .pipe(z.int().min(1).max(LIMITS.listMax))
    .default(LIMITS.listDefault),
});

const DEFAULT_HEARTBEAT_MS = 15_000;

/**
 * What a live stream may hold back for a consumer that is not reading, in messages and in characters.
 * Beyond either, the stream is ended and its connection is cut, so that what was queued is released:
 * the consumer reconnects and reads the list again, and the API's memory stays bounded.
 */
const MAX_PENDING_MESSAGES = 1_024;
const MAX_PENDING_CHARACTERS = 1_048_576;

export function eventRoutes(deps: {
  db: Db;
  bus: EventBus;
  heartbeatMs?: number;
  shutdown?: AbortSignal;
}): Hono<AppEnv> {
  const { db, bus, shutdown } = deps;
  const heartbeatMs = deps.heartbeatMs ?? DEFAULT_HEARTBEAT_MS;
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  /** True when the App exists in the caller's Organization. Another Organization's App does not, for the caller. */
  async function appExists(organizationId: string, appId: string): Promise<boolean> {
    if (!ID_PATTERNS.app.test(appId)) return false;
    return (await db.tx({ organizationId }, (q) => findApp(q, appId))) !== null;
  }

  routes.get("/v1/apps/:appId/events", admin, validateQuery(ListEventsQuerySchema), async (c) => {
    const { organizationId } = c.var.principal;
    const appId = c.req.param("appId");
    const { limit } = c.req.valid("query");
    const events = ID_PATTERNS.app.test(appId)
      ? await db.tx({ organizationId }, async (q) =>
          (await findApp(q, appId)) === null ? null : listEvents(q, { organizationId, appId, limit }),
        )
      : null;
    if (events === null) return problem(c, "not-found");
    return c.json({ events } satisfies ListEventsResponse);
  });

  routes.get("/v1/apps/:appId/events/stream", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const appId = c.req.param("appId");
    // hono answers HEAD through the GET handler and throws the body away without cancelling it: a stream
    // opened for a HEAD request would never be released.
    if (c.req.raw.method !== "GET") return problem(c, "method-not-allowed");
    if (!(await appExists(organizationId, appId))) return problem(c, "not-found");
    // Nothing is awaited between this check and the subscription below, so the limit cannot be overrun.
    if (bus.count(organizationId) >= LIMITS.streamsPerOrganization) return problem(c, "too-many-streams");

    // Tells a buffering reverse proxy (nginx) to pass each message on as it is written.
    c.header("X-Accel-Buffering", "no");
    return streamSSE(c, async (stream) => {
      const { promise: ended, resolve } = Promise.withResolvers<void>();
      const end = () => resolve();

      let pending = 0;
      let pendingCharacters = 0;
      const overflow = () => {
        end();
        // Ending alone would wait for the consumer to read what is queued. Cutting the connection drops it.
        // (`outgoing` is the Node response; it is absent when the app is called without a server.)
        (c.env as { outgoing?: { destroy(): void } } | undefined)?.outgoing?.destroy();
      };
      const send = (size: number, write: () => Promise<unknown>) => {
        if (pending >= MAX_PENDING_MESSAGES || pendingCharacters + size > MAX_PENDING_CHARACTERS) return overflow();
        pending++;
        pendingCharacters += size;
        write()
          .catch(end)
          .finally(() => {
            pending--;
            pendingCharacters -= size;
          });
      };

      const unsubscribe = bus.subscribe({ organizationId, appId }, (event) => {
        const data = JSON.stringify(event);
        send(data.length, () => stream.writeSSE({ id: event.event_id, event: "security-event", data }));
      });
      const heartbeat = setInterval(() => send(16, () => stream.write(": heartbeat\n\n")), heartbeatMs);
      stream.onAbort(end);
      shutdown?.addEventListener("abort", end, { once: true });
      if (shutdown?.aborted) end();
      try {
        // The first bytes leave at once, so that the consumer knows the stream is open.
        send(16, () => stream.write(": connected\n\n"));
        await ended;
      } finally {
        clearInterval(heartbeat);
        unsubscribe();
        shutdown?.removeEventListener("abort", end);
      }
    });
  });

  return routes;
}
