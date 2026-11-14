import { SLO_CATALOG, type SloId, type SloVariant } from "@antireverse/protocol";
import type { MiddlewareHandler } from "hono";
import { matchedRoutes } from "hono/route";
import type { AppEnv } from "../auth/authenticate.ts";
import type { SloSink } from "./recorder.ts";

// Slice 18d: the request feed of SLO-01, SLO-02, SLO-03 and SLO-07. After each response: the class of the route that
// answered (from its template, never the concrete path), its status and its server time. Hot path: a classification
// by a few string comparisons and one in-memory count; no I/O.
//
// Counting (Jev, decision on client errors, 0.63): a 5xx is bad; a 4xx is the client's doing (validation, key,
// unknown resource, rate limit) and is not counted at all, neither good nor bad, so that anonymous traffic cannot
// dilute the error rate of a public endpoint; anything else is good when within the SLO's bound, if it has one.

export interface RouteClass {
  slo: SloId;
  variant: SloVariant;
}

const SLO_01: RouteClass = { slo: "SLO-01", variant: "all" };
const SLO_02: RouteClass = { slo: "SLO-02", variant: "all" };
const SLO_03: RouteClass = { slo: "SLO-03", variant: "all" };
const READ: RouteClass = { slo: "SLO-07", variant: "read" };
const WRITE: RouteClass = { slo: "SLO-07", variant: "write" };

/** Public `/v1` routes without a key: not the Control API of an admin key. */
export const KEYLESS_ROUTES: readonly string[] = Object.freeze([
  "/v1/beacon",
  "/v1/organizations",
  "/v1/alert-recipients/confirm",
  "/v1/audit/public-key",
  "/v1/deletions/:deletionId/report",
]);

/**
 * Routes whose answer waits on a destination the tenant chose (review M3): its DNS, its server, its speed. The alert
 * channel's creation (the host lookup of the SSRF check), its test alert, and the ownership check of a Target.
 */
export const TENANT_DESTINATION_ROUTES: readonly string[] = Object.freeze([
  "POST /v1/alert-channels",
  "POST /v1/alert-channels/:channelId/test",
  "POST /v1/targets/:targetId/verify",
]);

/**
 * `/v1` routes outside the Control API besides those: a live stream (its duration is the stream's) and the Shield's
 * inventory report (a Shield key).
 */
const NOT_CONTROL = new Set(["/v1/apps/:appId/events/stream", "/v1/inventory", ...KEYLESS_ROUTES]);
const TENANT_DESTINATION = new Set(TENANT_DESTINATION_ROUTES);

/** The SLI a route feeds, or null when it feeds none. */
export function classifyRoute(method: string, template: string): RouteClass | null {
  if (template === "/v1/attest" || template === "/v1/attest/challenge") return method === "POST" ? SLO_01 : null;
  if (template === "/v1/events" && method === "POST") return SLO_02;
  if (template === "/v1/policy-bundle" || template === "/v1/signing-key") {
    return method === "GET" || method === "HEAD" ? SLO_03 : null;
  }
  if (!template.startsWith("/v1/") || template.startsWith("/v1/ops/") || NOT_CONTROL.has(template)) return null;
  if (TENANT_DESTINATION.has(`${method} ${template}`)) return null;
  if (method === "OPTIONS") return null;
  return method === "GET" || method === "HEAD" ? READ : WRITE;
}

const BOUNDS = new Map(SLO_CATALOG.map((def) => [def.id, def]));

/** Whether a request event is good, or null when it is not counted (a client error). */
export function judgeRequest(cls: RouteClass, status: number, ms: number): boolean | null {
  if (status >= 500) return false;
  if (status >= 400) return null;
  const def = BOUNDS.get(cls.slo);
  const bound = cls.variant === "write" ? def?.write_good_within_ms : def?.good_within_ms;
  return bound === null || bound === undefined || ms <= bound;
}

function templateOf(c: Parameters<typeof matchedRoutes>[0]): string {
  const path = matchedRoutes(c).at(-1)?.path;
  return path === undefined || path === "*" || path === "/*" ? "(unmatched)" : path;
}

/**
 * Records every classified request in `sink`. `monotonic`: a millisecond clock (default `performance.now`). The server
 * time starts when the request arrives, or once its body has been read (`limitBody` calls `bodyRead`): a slow upload
 * is the client's time. A request whose client has gone away (its signal aborted) is not recorded.
 */
export function sloRequests(
  sink: SloSink,
  monotonic: () => number = () => performance.now(),
): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const signal = c.req.raw.signal;
    let started = monotonic();
    c.set("bodyRead", () => {
      started = monotonic();
    });
    await next();
    const ms = monotonic() - started;
    if (signal.aborted) return;
    const cls = classifyRoute(c.req.method, templateOf(c));
    if (cls === null) return;
    const good = judgeRequest(cls, c.res.status, ms);
    if (good !== null) sink.record(cls.slo, good, ms, cls.variant);
  };
}
