import { BEACON_LIMITS } from "@antireverse/protocol";
import { type Context, Hono } from "hono";
import type { AppEnv } from "../auth/authenticate.ts";
import { discard } from "../body.ts";
import type { BeaconRecorder } from "../detect/beacon.ts";

/**
 * How much of an oversize report is still read and thrown away, so that the client gets its 204 on an intact
 * connection; past this the rest is cancelled and the connection closed. A real beacon is a few hundred bytes.
 */
export const BEACON_DRAIN_CAP_BYTES = 16 * BEACON_LIMITS.bodyBytesMax;

/** The client address of a request, or undefined. Reduced to its prefix by the recorder at once. */
export type ClientAddress = (c: Context) => string | undefined;

/** The body, at most `max` bytes; `oversize` when there was more (the rest is discarded, never parsed). */
async function readBounded(c: Context, max: number): Promise<{ body: Uint8Array; oversize: boolean }> {
  const raw = c.req.raw;
  if (raw.body === null) return { body: new Uint8Array(0), oversize: false };
  const reader = raw.body.getReader();
  const declared = raw.headers.has("transfer-encoding") ? Number.NaN : Number(raw.headers.get("content-length"));
  const chunks: Uint8Array[] = [];
  let size = 0;
  let oversize = declared > max;
  try {
    while (!oversize) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) oversize = true;
      else chunks.push(value);
    }
  } catch {
    // The client went away while sending: nothing counts.
    return { body: new Uint8Array(0), oversize: true };
  }
  if (oversize) {
    if (!(await discard(reader, BEACON_DRAIN_CAP_BYTES))) c.header("Connection", "close");
    return { body: new Uint8Array(0), oversize: true };
  }
  return { body: Buffer.concat(chunks), oversize: false };
}

/**
 * `POST /v1/beacon`: the public Clone Beacon endpoint. No key. Any content type (sendBeacon sends a string as
 * `text/plain`). Always 204 with no body, the same headers as every other answer of the API (`Cache-Control:
 * no-store`), whatever the report: the response never says whether a token exists or a report counted. The
 * report is judged after the response by the recorder. Only POST is routed: any other method is the API's usual
 * 404.
 */
export function beaconRoutes(deps: { recorder: BeaconRecorder; clientAddress: ClientAddress }): Hono<AppEnv> {
  const routes = new Hono<AppEnv>();

  routes.post("/v1/beacon", async (c) => {
    const { body, oversize } = await readBounded(c, BEACON_LIMITS.bodyBytesMax);
    deps.recorder.report({
      body,
      oversize,
      originHeader: c.req.header("origin"),
      address: deps.clientAddress(c),
    });
    return c.body(null, 204);
  });

  return routes;
}
