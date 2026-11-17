import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { createServer as createTlsServer, type TLSSocket, type Server as TlsServer } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  FRAMING_OVERHEAD_BYTES_MAX,
  pinnedRequest,
  RESPONSE_HEADER_BYTES_MAX,
  TLS_OVERHEAD_BYTES_MAX,
} from "../src/prove/verify.ts";

// Slice 15a, third independent safety review, F1: the pinned transport against targets that inflate what the socket
// reads without growing the decoded body — chunked framing with one-byte chunks and with 16 KB chunk extensions. The
// whole request has one cap on what the socket may read, whatever the bytes are.
const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const CA = fixture("ca.pem");
const HOST = "shop.acme-shop.io";
const BODY_MAX = 65_536;
/** What one request may read from its socket in all. */
const READ_MAX = RESPONSE_HEADER_BYTES_MAX + BODY_MAX + TLS_OVERHEAD_BYTES_MAX + FRAMING_OVERHEAD_BYTES_MAX;
/** Reads that can arrive before a socket over its cap is destroyed: a few socket reads on loopback. */
const LATE = 300_000;

let tls: TlsServer;
let port = 0;
let script: (socket: TLSSocket) => void = (s) => s.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

beforeAll(async () => {
  tls = createTlsServer({ key: fixture("key.pem"), cert: fixture("cert.pem") }, (socket) => {
    socket.on("error", () => {});
    socket.once("data", () => script(socket));
  });
  await new Promise<void>((resolve) => tls.listen(0, "127.0.0.1", resolve));
  port = (tls.address() as AddressInfo).port;
});
afterAll(async () => {
  await new Promise<void>((resolve) => tls.close(() => resolve()));
});

const send = (over: Partial<Parameters<typeof pinnedRequest>[0]> = {}) =>
  pinnedRequest({
    host: HOST,
    address: "127.0.0.1",
    method: "GET",
    path: "/",
    headers: { "user-agent": "Airverse-Campaign/1" },
    signal: AbortSignal.timeout(4000),
    bodyBytesMax: BODY_MAX,
    testing: { ca: CA, port, allowLoopback: true },
    ...over,
  });

/** Writes `piece` again and again until the peer goes away or `limit` bytes were written. */
function flood(socket: TLSSocket, piece: string, limit: number): void {
  let written = 0;
  const pump = (): void => {
    while (!socket.destroyed && written < limit) {
      written += piece.length;
      if (!socket.write(piece)) return void socket.once("drain", pump);
    }
    if (!socket.destroyed) socket.end();
  };
  pump();
}

describe("review3 F1: one cap on what the socket reads for the whole request", () => {
  it("the allowance is fixed: 16 KB for TLS and 64 KB for framing", () => {
    expect(TLS_OVERHEAD_BYTES_MAX).toBe(16_384);
    expect(FRAMING_OVERHEAD_BYTES_MAX).toBe(65_536);
  });

  it("cuts a chunked body of one-byte chunks with 16 KB chunk extensions (the review's 1 GB read)", async () => {
    script = (s) => {
      s.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
      flood(s, `1;x=${"a".repeat(16_000)}\r\nX\r\n`, 200_000_000);
    };
    const response = await send();
    expect(response).toMatchObject({ ok: false, reason: "read_limit" });
    expect(response.bytesRead).toBeGreaterThan(READ_MAX);
    expect(response.bytesRead).toBeLessThan(READ_MAX + LATE);
  }, 20_000);

  it("cuts a plain stream of one-byte chunks at the same cap (it read 418,753 bytes for 65,536 of body)", async () => {
    script = (s) => {
      s.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
      flood(s, "1\r\nX\r\n".repeat(2000), 50_000_000);
    };
    const response = await send();
    expect(response).toMatchObject({ ok: false, reason: "read_limit" });
    expect(response.bytesRead).toBeLessThan(READ_MAX + LATE);
  }, 20_000);

  it("the cap holds for a small body cap too (the ownership file's 1 KB)", async () => {
    script = (s) => {
      s.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
      flood(s, `1;x=${"a".repeat(16_000)}\r\nX\r\n`, 200_000_000);
    };
    const response = await send({ bodyBytesMax: 1024 });
    expect(response).toMatchObject({ ok: false, reason: "read_limit" });
    expect(response.bytesRead).toBeLessThan(
      RESPONSE_HEADER_BYTES_MAX + 1024 + TLS_OVERHEAD_BYTES_MAX + FRAMING_OVERHEAD_BYTES_MAX + LATE,
    );
  }, 20_000);

  it("does not cut a body streamed in 100-byte chunks: it is read to the body cap and marked truncated", async () => {
    script = (s) => {
      s.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
      const piece = `64\r\n${"y".repeat(100)}\r\n`;
      let n = 0;
      const pump = (): void => {
        // One write per chunk and tick, so that each chunk is its own TLS record.
        if (s.destroyed || n++ >= 1000) return;
        s.write(piece);
        setImmediate(pump);
      };
      pump();
    };
    const response = await send();
    expect(response).toMatchObject({ ok: true, status: 200, truncated: true });
    expect(response.ok && response.body.byteLength).toBe(BODY_MAX);
    expect(response.bytesRead).toBeLessThan(READ_MAX);
  }, 20_000);

  it("still answers an ordinary response whole", async () => {
    script = (s) => s.end(`HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n${"x".repeat(5000)}`);
    const response = await send();
    expect(response).toMatchObject({ ok: true, status: 200, truncated: false });
    expect(response.ok && response.body.byteLength).toBe(5000);
  });
});
