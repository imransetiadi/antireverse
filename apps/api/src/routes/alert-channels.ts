import {
  type AlertChannel,
  CreateAlertChannelRequestSchema,
  type CreateAlertChannelResponse,
  ID_PATTERNS,
  INCIDENT_LIMITS,
  type ListAlertChannelsResponse,
  type TestAlertChannelResponse,
} from "@antireverse/protocol";
import { generateSigningSecret, newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import type { Notifier } from "../notify/notifier.ts";
import { checkDestination, LOOKUP_TIMEOUT_MS, type Resolve, resolveWithin } from "../notify/ssrf.ts";
import { problem } from "../problem.ts";
import {
  countChannels,
  deleteChannel,
  findChannel,
  insertChannel,
  listChannels,
  lockOrganization,
} from "../stores/alert-channels.ts";
import { validateJson } from "../validate.ts";

export function alertChannelRoutes(deps: {
  db: Db;
  notifier: Notifier;
  resolve: Resolve;
  allowPrivateAlertUrls: boolean;
  /** Bound of the host lookup at creation. Default 5,000 ms. */
  alertLookupTimeoutMs?: number;
  now?: () => Date;
}): Hono<AppEnv> {
  const { db, notifier, resolve } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  routes.get("/v1/alert-channels", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const channels = await db.tx({ organizationId }, (q) => listChannels(q));
    return c.json({ channels } satisfies ListAlertChannelsResponse);
  });

  // The URL and a webhook's signing secret go in here; only the secret comes back, in this response only.
  routes.post("/v1/alert-channels", admin, limitBody(), validateJson(CreateAlertChannelRequestSchema), async (c) => {
    const { organizationId } = c.var.principal;
    const { kind, name, url } = c.req.valid("json");
    // Fast feedback: the same check runs again before every delivery (DNS can change). The message is fixed
    // text: it never echoes the URL, which may itself be a secret.
    // The lookup is bounded: a host that does not answer in time is "could not be resolved".
    const lookupBound = AbortSignal.timeout(deps.alertLookupTimeoutMs ?? LOOKUP_TIMEOUT_MS);
    const destination = await checkDestination(url, {
      resolve: resolveWithin(resolve, lookupBound),
      allowPrivate: deps.allowPrivateAlertUrls,
    });
    if (!destination.ok) return problem(c, "validation", [{ path: "url", message: destination.reason }]);

    const signingSecret = kind === "webhook" ? generateSigningSecret() : null;
    const channel = await db.tx<AlertChannel | null>({ organizationId }, async (q) => {
      // Serialises creations per Organization, so that the limit holds under concurrent requests.
      await lockOrganization(q, organizationId);
      if ((await countChannels(q)) >= INCIDENT_LIMITS.channelsMax) return null;
      return insertChannel(q, { id: newId("chn"), organizationId, kind, name, url, signingSecret, createdAt: now() });
    });
    if (channel === null) return problem(c, "conflict");
    const body: CreateAlertChannelResponse =
      signingSecret === null ? { channel } : { channel, signing_secret: signingSecret };
    return c.json(body, 201);
  });

  routes.delete("/v1/alert-channels/:channelId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const channelId = c.req.param("channelId");
    const deleted = ID_PATTERNS.chn.test(channelId)
      ? await db.tx({ organizationId }, (q) => deleteChannel(q, channelId))
      : false;
    if (!deleted) return problem(c, "not-found");
    return c.body(null, 204);
  });

  // Sends one test alert, synchronously, one attempt. Needs no body.
  routes.post("/v1/alert-channels/:channelId/test", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const channelId = c.req.param("channelId");
    const exists =
      ID_PATTERNS.chn.test(channelId) && (await db.tx({ organizationId }, (q) => findChannel(q, channelId))) !== null;
    if (!exists) return problem(c, "not-found");
    const delivery = await notifier.test(channelId, organizationId);
    // Deleted in the meantime.
    if (delivery === null) return problem(c, "not-found");
    return c.json({ delivery } satisfies TestAlertChannelResponse);
  });

  return routes;
}
