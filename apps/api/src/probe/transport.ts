import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { AUDIT_REASON_HEADER } from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import { type Logger, redacting } from "../log.ts";
import type { ProbeTransport } from "./runner.ts";
import { PROBE_ENVIRONMENT, type ProbeTenant } from "./tenant.ts";

// Slice 18g: the real transport of the probe runner. Everything goes the way a customer's traffic goes:
//
// - the marked block is published with `PUT /v1/apps/:appId/policies/production` and the probe's admin key (a reason
//   header, an audit entry, a new version: the route as it is);
// - a real Shield (`@antireverse/shield-node`, the SDK customers install) with the probe's Shield key polls
//   `GET /v1/policy-bundle`, verifies the signature against the API's public signing key and applies the bundle on
//   its own timer. The probe never calls `refreshPolicy()` or `flush()`: it waits as a customer's Shield does;
// - the marked request goes over HTTP to a loopback server whose only handler is behind that Shield's middleware;
// - the Shield sends the Event with `POST /v1/events` on its own flush timer, and the probe reads
//   `GET /v1/apps/:appId/events` with the admin key, the route the Console reads.
//
// `endpoint` is the API's own listening address. The keys are held here, in memory, and passed to nothing but those
// requests and the Shield; the Shield's warnings (which never hold the key) go through the redacting logger.

export interface HttpProbeOptions {
  /** The API's base URL: its own listening address. */
  endpoint: string;
  tenant: ProbeTenant;
  /**
   * The public key of the API's Policy signing key, as `GET /v1/signing-key` answers it: the value a customer copies
   * into their Shield's configuration once. Configuration, not part of the measured path — and given directly so that
   * setting the probe up sends no request (a keyless one could not be told apart from a tenant's in SLO-03).
   */
  policyPublicKey: string;
  logger: Logger;
  /** One request of the probe to the API or to its loopback server. Default 5,000 ms. */
  requestTimeoutMs?: number | undefined;
  /** Tests only: shorter timers of the probe's Shield. Production uses the SDK's defaults, as customers do. */
  shield?: { policyPollIntervalMs?: number | undefined; flushIntervalMs?: number | undefined } | undefined;
}

const REASON = "Synthetic probe: the marked block of this minute";
const RULE_NAME = "Synthetic probe";
/** How many of the newest Events are read: the marked one is among the last few. */
const EVENTS_READ = 20;

function listenLoopback(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve((server.address() as AddressInfo).port);
    });
  });
}

export async function createHttpProbeTransport(
  options: HttpProbeOptions,
  signal: AbortSignal,
): Promise<ProbeTransport> {
  const { tenant } = options;
  const endpoint = options.endpoint.replace(/\/+$/, "");
  const logger = redacting(options.logger);
  const timeoutMs = options.requestTimeoutMs ?? 5_000;
  const within = (s: AbortSignal) => AbortSignal.any([s, AbortSignal.timeout(timeoutMs)]);
  const admin = { authorization: `Bearer ${tenant.adminKey}` };

  if (signal.aborted) throw new Error("stopped");
  const { policyPublicKey } = options;

  const shield: Shield = createShield({
    key: tenant.shieldKey,
    endpoint,
    policyPublicKey,
    // Explicit, so that the environment of the API process (AR_SHIELD_DISABLED, AR_ACTOR_KEY, AR_SHIELD_INVENTORY)
    // never changes what the probe measures.
    disabled: false,
    actorKey: "",
    inventory: false,
    logger: { warn: (line: string) => logger.warn(`probe ${line}`) },
    ...(options.shield?.policyPollIntervalMs === undefined
      ? {}
      : { policyPollIntervalMs: options.shield.policyPollIntervalMs }),
    ...(options.shield?.flushIntervalMs === undefined ? {} : { flushIntervalMs: options.shield.flushIntervalMs }),
  });
  const middleware = shield.express();
  // The "application" behind the Shield: it answers 204 to whatever the Shield lets through.
  const server = createServer((request, response) => {
    middleware(request, response, () => {
      response.statusCode = 204;
      response.end();
    });
  });
  let port: number;
  try {
    port = await listenLoopback(server);
  } catch (error) {
    await shield.close();
    throw error;
  }

  return {
    async publishBlock(path, s) {
      const response = await fetch(`${endpoint}/v1/apps/${tenant.appId}/policies/${PROBE_ENVIRONMENT}`, {
        method: "PUT",
        headers: { ...admin, "content-type": "application/json", [AUDIT_REASON_HEADER]: REASON },
        body: JSON.stringify({ rules: [{ name: RULE_NAME, path, action: "block", mode: "enforce" }] }),
        signal: within(s),
      });
      await response.body?.cancel().catch(() => {});
      if (response.status !== 201) throw new Error(`publish ${response.status}`);
    },
    blocks(path) {
      try {
        const decision = shield.decide({ method: "GET", path });
        return decision.action === "block" && decision.mode === "enforce";
      } catch {
        return false;
      }
    },
    async request(path, s) {
      const response = await fetch(`http://127.0.0.1:${port}${path}`, { signal: within(s) });
      await response.body?.cancel().catch(() => {});
      return response.status;
    },
    async eventVisible(route, s) {
      const response = await fetch(`${endpoint}/v1/apps/${tenant.appId}/events?limit=${EVENTS_READ}`, {
        headers: admin,
        signal: within(s),
      });
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => {});
        throw new Error(`events ${response.status}`);
      }
      const { events } = (await response.json()) as { events: { request?: { route?: unknown } }[] };
      return events.some((event) => event.request?.route === route);
    },
    async close() {
      await shield.close();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    },
  };
}
