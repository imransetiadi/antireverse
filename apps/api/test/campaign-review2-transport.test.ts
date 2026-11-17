import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { createServer as createTlsServer, type TLSSocket, type Server as TlsServer } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pinnedRequest, RESPONSE_HEADER_BYTES_MAX, sameAddress, TLS_OVERHEAD_BYTES_MAX } from "../src/prove/verify.ts";

// Slice 15a, second independent safety review: the pinned transport against hostile raw TLS servers on loopback —
// what it counts as read (L5), what it answers when no response comes (L6), and how it compares addresses.
const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const CA = fixture("ca.pem");
const HOST = "shop.acme-shop.io";

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
    signal: AbortSignal.timeout(3000),
    bodyBytesMax: 65_536,
    testing: { ca: CA, port, allowLoopback: true },
    ...over,
  });

describe("review2 L5: what the connection read is counted, whatever the outcome", () => {
  it("says how many bytes the connection read for a response", async () => {
    script = (s) => s.end(`HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n${"x".repeat(5000)}`);
    const response = await send();
    expect(response).toMatchObject({ ok: true, status: 200 });
    // The body, the headers and the TLS handshake.
    expect(response.bytesRead).toBeGreaterThan(5000);
    expect(response.bytesRead).toBeLessThan(5000 + TLS_OVERHEAD_BYTES_MAX);
  });

  it("drops a connection that floods informational (1xx) responses, and counts what it read", async () => {
    const hint = `HTTP/1.1 103 Early Hints\r\nLink: <${"a".repeat(8000)}>\r\n\r\n`;
    script = (s) => {
      for (let i = 0; i < 400; i++) s.write(hint);
      s.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    };
    const response = await send({ bodyBytesMax: 1000 });
    expect(response).toMatchObject({ ok: false, reason: "invalid_response" });
    // More than a response may be (16 KB of headers, the body cap, the TLS share) was read, and not much more:
    // far from the 3.2 MB the target wrote.
    const allowed = RESPONSE_HEADER_BYTES_MAX + 1000 + TLS_OVERHEAD_BYTES_MAX;
    expect(response.bytesRead).toBeGreaterThan(allowed);
    expect(response.bytesRead).toBeLessThan(allowed + 300_000);
  });

  it("counts the bytes of a response that then never ends", async () => {
    script = (s) =>
      s.write(`HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nX-Pad: ${"p".repeat(12_000)}\r\n\r\n${"x".repeat(40_000)}`);
    const response = await send({ signal: AbortSignal.timeout(400) });
    expect(response).toMatchObject({ ok: false, reason: "timeout" });
    expect(response.bytesRead).toBeGreaterThan(52_000);
  });

  it("counts nothing for a connection that was never made", async () => {
    const response = await send({ testing: { ca: CA, port: 1, allowLoopback: true } });
    expect(response).toMatchObject({ ok: false, reason: "connect_failed", bytesRead: 0 });
  });
});

describe("review2 L6: no response is an invalid response, at once", () => {
  it("answers a 101 Switching Protocols at once, not at the deadline", async () => {
    script = (s) => s.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n");
    const started = performance.now();
    const response = await send({ signal: AbortSignal.timeout(2500) });
    expect(response).toMatchObject({ ok: false, reason: "invalid_response" });
    expect(performance.now() - started).toBeLessThan(1500);
  });

  it("answers a connection closed without a response at once", async () => {
    script = (s) => s.end();
    const started = performance.now();
    const response = await send({ signal: AbortSignal.timeout(2500) });
    expect(response).toMatchObject({ ok: false, reason: "invalid_response" });
    expect(performance.now() - started).toBeLessThan(1500);
  });

  it("never hands on a pipelined second response", async () => {
    script = (s) =>
      s.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nEVIL!");
    const response = await send();
    expect(response.ok && response.body.toString()).toBe("ok");
  });
});

describe("review2: sameAddress compares addresses, not spellings", () => {
  it("knows every spelling of one address, and nothing else", () => {
    const same: [string, string][] = [
      ["127.0.0.1", "::ffff:127.0.0.1"],
      ["::FFFF:127.0.0.1", "127.0.0.1"],
      ["2606:4700:4700::1111", "2606:4700:4700:0:0:0:0:1111"],
      ["2606:4700:4700::1111", "2606:4700:4700:0000:0000:0000:0000:1111"],
      ["2606:4700:4700::1111", "2606:4700:4700::1111".toUpperCase()],
      ["::1", "0:0:0:0:0:0:0:1"],
      ["8.8.8.8", "::ffff:808:808"],
      ["::ffff:808:808", "::ffff:8.8.8.8"],
      ["8.8.8.8", "0:0:0:0:0:FFFF:0808:0808"],
    ];
    const different: [string, string][] = [
      ["127.0.0.1", "127.0.0.2"],
      ["127.0.0.1", "::127.0.0.1"],
      ["127.0.0.1", "::ffff:0:127.0.0.1"],
      ["8.8.8.8", "64:ff9b::8.8.8.8"],
      ["8.8.8.8", "::ffff:808:809"],
      ["fe80::1", "fe80::1%lo0"],
      ["fe80::1%lo0", "fe80::1%lo0"],
      ["", ""],
      ["x", "x"],
      ["1.2.3.4", "1.2.3.4 "],
      ["1.2.3.4", "01.2.3.4"],
    ];
    const wrong: string[] = [];
    for (const [a, b] of same) if (!sameAddress(a, b) || !sameAddress(b, a)) wrong.push(`same failed: ${a} ~ ${b}`);
    for (const [a, b] of different)
      if (sameAddress(a, b) || sameAddress(b, a)) wrong.push(`different passed: ${a} ~ ${b}`);
    expect(wrong).toEqual([]);
  });
});
