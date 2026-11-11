import { LIMITS } from "@antireverse/protocol";
import type { MiddlewareHandler } from "hono";
import { problem } from "./problem.ts";

/**
 * How much of a body that is too large is still read and thrown away, so that the client receives the
 * 413 on an intact connection: an answer sent while the client is still writing surfaces there as a
 * reset socket instead of a status code. Past this bound the connection is closed instead.
 * (A body no handler touched, for example after a refused key, is drained by @hono/node-server itself.)
 */
export const DRAIN_CAP_BYTES = 4 * LIMITS.bodyBytesMax;

/** Reads and discards the rest of a body. False when more than `cap` bytes were left: the rest is cancelled. */
export async function discard(reader: ReadableStreamDefaultReader<Uint8Array>, cap: number): Promise<boolean> {
  let discarded = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return true;
      discarded += value.byteLength;
      if (discarded > cap) {
        void reader.cancel().catch(() => {});
        return false;
      }
    }
  } catch {
    // The client went away while sending; there is nothing left to drain and nobody to answer.
    return false;
  }
}

/**
 * Refuses a request body larger than `maxBytes` with a 413 problem, whether or not the client declared
 * its length. An accepted body is buffered (it is bounded) and handed on unchanged.
 */
export function limitBody(
  maxBytes: number = LIMITS.bodyBytesMax,
  kind:
    | "payload-too-large"
    | "attestation-payload-too-large"
    | "inventory-payload-too-large"
    | "build-payload-too-large" = "payload-too-large",
): MiddlewareHandler {
  return async (c, next) => {
    const raw = c.req.raw;
    if (raw.body === null) return next();

    const declared = raw.headers.has("transfer-encoding") ? Number.NaN : Number(raw.headers.get("content-length"));
    const reader = raw.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    let tooLarge = declared > maxBytes;
    while (!tooLarge) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) tooLarge = true;
      else chunks.push(value);
    }

    if (tooLarge) {
      if (!(await discard(reader, DRAIN_CAP_BYTES))) c.header("Connection", "close");
      return problem(c, kind);
    }
    c.req.raw = new Request(raw, { body: Buffer.concat(chunks) });
    return next();
  };
}
