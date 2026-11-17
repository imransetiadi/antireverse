import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { type AddressInfo, createServer as createTcpServer, type Server as TcpServer } from "node:net";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pinnedRequest, READ_OVERSHOOT_BYTES_MAX, requestReadMax } from "../src/prove/verify.ts";

// Slice 15a, fourth independent safety review, R7: the read cap of a request against bytes that never become
// application data. The review's case is a TLS 1.3 session-ticket flood (`openssl s_server -num_tickets N`): records
// the TLS layer consumes without handing anything on. The cap is counted on the raw TCP reads themselves, before TLS
// sees them, so the overshoot is bounded by one TCP read, whatever the bytes are.
const path = (name: string) => fileURLToPath(new URL(`./fixtures/prove-tls/${name}`, import.meta.url));
const CA = readFileSync(path("ca.pem"), "utf8");
const HOST = "shop.acme-shop.io";
const OPENSSL = spawnSync("openssl", ["version"], { encoding: "utf8" });
const hasOpenssl = OPENSSL.status === 0 && /^OpenSSL [3-9]/.test(OPENSSL.stdout);

const send = (port: number, bodyBytesMax: number) =>
  pinnedRequest({
    host: HOST,
    address: "127.0.0.1",
    method: "GET",
    path: "/",
    headers: { "user-agent": "Airverse-Campaign/1" },
    signal: AbortSignal.timeout(8000),
    bodyBytesMax,
    testing: { ca: CA, port, allowLoopback: true },
  });

describe("review4 R7: the read cap is counted on the raw reads", () => {
  it("the bound is one TCP read, and it is stated", () => {
    expect(READ_OVERSHOOT_BYTES_MAX).toBe(65_536);
  });

  describe.skipIf(!hasOpenssl)("a TLS 1.3 session-ticket flood (openssl s_server)", () => {
    let server: ChildProcess;
    let port = 0;

    beforeAll(async () => {
      // A free port: taken, released, and handed to openssl.
      const probe: TcpServer = createTcpServer();
      await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
      port = (probe.address() as AddressInfo).port;
      await new Promise<void>((resolve) => probe.close(() => resolve()));
      server = spawn(
        "openssl",
        [
          "s_server",
          "-accept",
          `127.0.0.1:${port}`,
          "-cert",
          path("cert.pem"),
          "-key",
          path("key.pem"),
          "-tls1_3",
          "-www",
          "-num_tickets",
          "20000",
          "-quiet",
        ],
        { stdio: "ignore" },
      );
      // Until it accepts connections.
      for (let attempt = 0; attempt < 100; attempt++) {
        const up = spawnSync("nc", ["-z", "127.0.0.1", String(port)]).status === 0;
        if (up) break;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    }, 20_000);
    afterAll(() => {
      server?.kill("SIGKILL");
    });

    it("is cut at the cap plus at most one TCP read, every time (it overshot by 79 to 262 KB)", async () => {
      const over: number[] = [];
      for (let run = 0; run < 12; run++) {
        const bodyBytesMax = run % 2 === 0 ? 65_536 : 1024;
        const response = await send(port, bodyBytesMax);
        expect(response).toMatchObject({ ok: false, reason: "read_limit" });
        over.push((response.bytesRead ?? 0) - requestReadMax(bodyBytesMax));
      }
      expect(Math.min(...over)).toBeGreaterThan(0);
      expect(Math.max(...over)).toBeLessThanOrEqual(READ_OVERSHOOT_BYTES_MAX);
    }, 60_000);
  });

  it("a raw flood before any TLS record is understood: cut within one TCP read of the cap", async () => {
    // Not TLS at all: a server that answers the ClientHello with bytes without end. Whatever the TLS layer makes of
    // them, the count is of the raw reads.
    const flood: TcpServer = createTcpServer((socket) => {
      socket.on("error", () => {});
      socket.once("data", () => {
        // A TLS record header for 16 KB of application data, again and again: read as one record after another.
        const record = Buffer.concat([Buffer.from([0x17, 0x03, 0x03, 0x40, 0x00]), Buffer.alloc(16_384, 0x41)]);
        const pump = (): void => {
          while (!socket.destroyed) if (!socket.write(record)) return void socket.once("drain", pump);
        };
        pump();
      });
    });
    await new Promise<void>((resolve) => flood.listen(0, "127.0.0.1", resolve));
    try {
      const response = await send((flood.address() as AddressInfo).port, 1024);
      expect(response.ok).toBe(false);
      expect(response.bytesRead ?? 0).toBeLessThanOrEqual(requestReadMax(1024) + READ_OVERSHOOT_BYTES_MAX);
    } finally {
      await new Promise<void>((resolve) => flood.close(() => resolve()));
    }
  }, 20_000);
});
