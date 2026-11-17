import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import { type AddressInfo, createServer as createTcpServer, connect as netConnect, type Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { pinnedRequest, type Resolver, resolvePinned, sameAddress } from "../src/prove/verify.ts";

// Slice 15a: the pinned HTTPS request the Campaign gate sends through — the guarded fetcher of slice 14, generalised
// to a method and a path. Against local TLS servers on loopback with the test CA; nothing leaves the machine.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const CA = fixture("ca.pem");
const HOST = "shop.acme-shop.io";

interface Seen {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage["headers"];
  servername: string | false | null | undefined;
  body: number;
}

function tlsServer(log: Seen[], handle: () => (req: IncomingMessage, res: ServerResponse) => void): Promise<Server> {
  const server = createServer({ key: fixture("key.pem"), cert: fixture("cert.pem") }, (req, res) => {
    const entry: Seen = {
      method: req.method,
      url: req.url,
      headers: req.headers,
      servername: (req.socket as TLSSocket).servername,
      body: 0,
    };
    req.on("data", (chunk: Buffer) => {
      entry.body += chunk.byteLength;
    });
    log.push(entry);
    handle()(req, res);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

let server: Server;
let other: Server;
let port: number;
let otherPort: number;
const seen: Seen[] = [];
const otherSeen: Seen[] = [];
const otherTls = { handshakes: 0, connections: 0, bytesRead: 0 };
let handler: (req: IncomingMessage, res: ServerResponse) => void = (_req, res) => res.end("ok");

beforeAll(async () => {
  server = await tlsServer(seen, () => handler);
  other = await tlsServer(otherSeen, () => (_req, res) => res.end("other"));
  other.on("secureConnection", () => otherTls.handshakes++);
  other.on("connection", (socket: Socket) => {
    otherTls.connections++;
    socket.on("close", () => {
      otherTls.bytesRead += socket.bytesRead;
    });
  });
  port = (server.address() as AddressInfo).port;
  otherPort = (other.address() as AddressInfo).port;
});
afterAll(async () => {
  for (const s of [server, other]) {
    s.closeAllConnections();
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
});
beforeEach(() => {
  seen.length = 0;
  otherSeen.length = 0;
  otherTls.handshakes = 0;
  otherTls.connections = 0;
  otherTls.bytesRead = 0;
  handler = (_req, res) => res.end("ok");
});

const send = (
  overrides: Partial<Parameters<typeof pinnedRequest>[0]> = {},
  internals?: Parameters<typeof pinnedRequest>[1],
) =>
  pinnedRequest(
    {
      host: HOST,
      address: "127.0.0.1",
      method: "GET",
      path: "/",
      headers: { "user-agent": "Airverse-Campaign/1", "x-airverse-campaign": "cmp_0123456789abcdef01234567" },
      signal: AbortSignal.timeout(5000),
      bodyBytesMax: 65_536,
      testing: { ca: CA, port, allowLoopback: true },
      ...overrides,
    },
    internals,
  );

describe("pinnedRequest", () => {
  it("sends a GET to the pinned address with SNI and Host for the name, identity encoding and no cookie or body", async () => {
    handler = (_req, res) => {
      res.writeHead(200, { "content-type": "text/plain", "set-cookie": "a=b" });
      res.end("hello");
    };
    const response = await send({ path: "/search?q=a%20b" });
    expect(response).toMatchObject({ ok: true, status: 200, truncated: false, remoteAddress: "127.0.0.1" });
    expect(response.ok && response.body.toString()).toBe("hello");
    expect(response.ok && response.headers["set-cookie"]).toEqual(["a=b"]);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ method: "GET", url: "/search?q=a%20b", servername: HOST, body: 0 });
    expect(seen[0]?.headers).toMatchObject({
      host: HOST,
      "user-agent": "Airverse-Campaign/1",
      "x-airverse-campaign": "cmp_0123456789abcdef01234567",
      "accept-encoding": "identity",
      connection: "close",
    });
    expect(seen[0]?.headers.cookie).toBeUndefined();
    expect(seen[0]?.headers.authorization).toBeUndefined();
    expect(seen[0]?.headers["content-length"]).toBeUndefined();
    expect(seen[0]?.headers["transfer-encoding"]).toBeUndefined();
  });

  it("sends a HEAD", async () => {
    const response = await send({ method: "HEAD", path: "/x" });
    expect(response).toMatchObject({ ok: true, status: 200 });
    expect(seen[0]).toMatchObject({ method: "HEAD", url: "/x" });
  });

  it("refuses any other method, a path that does not start with / and a header it does not know, before connecting", async () => {
    for (const method of ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "get"]) {
      await expect(send({ method: method as "GET" })).rejects.toThrow(TypeError);
    }
    await expect(send({ path: "https://evil.example.net/" })).rejects.toThrow(TypeError);
    await expect(send({ path: "//evil.example.net/" })).rejects.toThrow(TypeError);
    await expect(send({ headers: { cookie: "a=b" } })).rejects.toThrow(TypeError);
    await expect(send({ headers: { authorization: "Bearer x" } })).rejects.toThrow(TypeError);
    await expect(send({ headers: { host: "evil.example.net" } })).rejects.toThrow(TypeError);
    expect(seen).toEqual([]);
  });

  it("never follows a redirect: the 3xx comes back as it is and the other server sees nothing", async () => {
    handler = (_req, res) => {
      res.writeHead(302, { location: `https://${HOST}:${otherPort}/landing` });
      res.end();
    };
    const response = await send({ path: "/go" });
    expect(response).toMatchObject({ ok: true, status: 302 });
    expect(seen).toHaveLength(1);
    expect(otherSeen).toEqual([]);
  });

  it("reads at most the cap, says so, and drops the connection", async () => {
    const total = 5 * 1024 * 1024;
    let closedEarly = false;
    handler = (req, res) => {
      res.writeHead(200, { "content-type": "application/octet-stream" });
      const chunk = Buffer.alloc(64 * 1024, 0x61);
      let written = 0;
      const pump = () => {
        while (written < total) {
          written += chunk.byteLength;
          if (!res.write(chunk)) return void res.once("drain", pump);
        }
        res.end();
      };
      req.socket.on("close", () => {
        closedEarly = written < total || !res.writableFinished;
      });
      pump();
    };
    const response = await send({ path: "/large" });
    expect(response.ok).toBe(true);
    if (!response.ok) return;
    expect(response.truncated).toBe(true);
    expect(response.body.byteLength).toBe(65_536);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(closedEarly).toBe(true);
    // A smaller cap, as the gate passes when little of the byte budget is left.
    const small = await send({ path: "/large", bodyBytesMax: 100 });
    expect(small.ok && small.body.byteLength).toBe(100);
  });

  it("answers timeout when the signal aborts, and connect_failed or tls_failed otherwise", async () => {
    handler = () => {};
    expect(await send({ signal: AbortSignal.timeout(100) })).toMatchObject({ ok: false, reason: "timeout" });
    expect(await send({ testing: { ca: CA, port: 1, allowLoopback: true } })).toMatchObject({
      ok: false,
      reason: "connect_failed",
    });
    expect(await send({ testing: { port, allowLoopback: true } })).toMatchObject({ ok: false, reason: "tls_failed" });
    expect(await send({ host: "other.acme-shop.io" })).toMatchObject({ ok: false, reason: "tls_failed" });
  });

  it("asserts that the connected address is the pinned one before TLS starts: not even a ClientHello goes elsewhere", async () => {
    // The pin says 127.0.0.2; the TCP connection is forced to the other server on 127.0.0.1.
    const response = await send(
      { address: "127.0.0.2" },
      { dial: () => netConnect({ host: "127.0.0.1", port: otherPort }) },
    );
    expect(response).toMatchObject({ ok: false, reason: "address_mismatch" });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(otherSeen).toEqual([]);
    expect(seen).toEqual([]);
    // The TCP connection was opened and dropped: not one byte was written to it, so no ClientHello either.
    expect(otherTls).toEqual({ handshakes: 0, connections: 1, bytesRead: 0 });
  });

  it("refuses an address that is not public by itself, whoever resolved it", async () => {
    for (const address of ["169.254.169.254", "10.0.0.1", "192.168.1.1", "::ffff:10.0.0.1", "0.0.0.0", "fd00::1"]) {
      // Without the test-only option, and with it: loopback is all it lets through.
      await expect(send({ address, testing: undefined })).rejects.toThrow(TypeError);
      await expect(send({ address })).rejects.toThrow(TypeError);
    }
    await expect(send({ address: "127.0.0.1", testing: undefined })).rejects.toThrow(TypeError);
    await expect(send({ address: "127.0.0.1", testing: { ca: CA, port } })).rejects.toThrow(TypeError);
    expect(seen).toEqual([]);
  });

  it("caps the request target at 1,024 characters", async () => {
    await expect(send({ path: `/${"a".repeat(1024)}` })).rejects.toThrow(TypeError);
    expect((await send({ path: `/${"a".repeat(1023)}` })).ok).toBe(true);
  });

  it("answers invalid_response for a status outside 100 to 599", async () => {
    handler = (_req, res) => {
      res.writeHead(999).end("odd");
    };
    expect(await send()).toMatchObject({ ok: false, reason: "invalid_response" });
    expect(seen).toHaveLength(1);
  });

  it("reads at most 16 KB of response headers, and says how many bytes they were", async () => {
    const pad = (count: number) => (_req: IncomingMessage, res: ServerResponse) => {
      for (let i = 0; i < count; i++) res.setHeader(`x-pad-${i}`, "p".repeat(1000));
      res.end("ok");
    };
    handler = pad(14);
    const within = await send({ bodyBytesMax: 1 });
    expect(within).toMatchObject({ ok: true, status: 200, truncated: true });
    expect(within.ok && within.headerBytes).toBeGreaterThan(14_000);
    expect(within.ok && within.headerBytes).toBeLessThanOrEqual(16_384);
    handler = pad(20);
    expect(await send()).toMatchObject({ ok: false, reason: "invalid_response" });
    handler = (_req, res) => res.end("ok");
    const small = await send();
    expect(small.ok && small.headerBytes).toBeGreaterThan(20);
    expect(small.ok && small.headerBytes).toBeLessThan(400);
  });

  it("does not honour NODE_TLS_REJECT_UNAUTHORIZED=0", async () => {
    const saved = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    try {
      expect(await send({ testing: { port, allowLoopback: true } })).toMatchObject({ ok: false, reason: "tls_failed" });
      expect(await send({ host: "other.acme-shop.io" })).toMatchObject({ ok: false, reason: "tls_failed" });
    } finally {
      if (saved === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = saved;
    }
    expect(seen).toEqual([]);
  });

  it("ignores proxy variables: the connection goes to the pinned address and the proxy sees nothing", async () => {
    let proxied = 0;
    const proxy = createTcpServer((socket) => {
      proxied++;
      socket.destroy();
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
    const names = [
      "HTTPS_PROXY",
      "https_proxy",
      "HTTP_PROXY",
      "http_proxy",
      "ALL_PROXY",
      "all_proxy",
      "NODE_USE_ENV_PROXY",
    ];
    const saved = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    for (const name of names) process.env[name] = name === "NODE_USE_ENV_PROXY" ? "1" : url;
    try {
      expect(await send()).toMatchObject({ ok: true, status: 200, remoteAddress: "127.0.0.1" });
    } finally {
      for (const name of names) {
        if (saved[name] === undefined) delete process.env[name];
        else process.env[name] = saved[name];
      }
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
    }
    expect(proxied).toBe(0);
    expect(seen).toHaveLength(1);
  });
});

describe("sameAddress", () => {
  it("compares addresses, not their spelling", () => {
    expect(sameAddress("127.0.0.1", "127.0.0.1")).toBe(true);
    expect(sameAddress("127.0.0.1", "127.0.0.2")).toBe(false);
    expect(sameAddress("2001:DB8:0:0:0:0:0:1", "2001:db8::1")).toBe(true);
    expect(sameAddress("::ffff:127.0.0.1", "127.0.0.1")).toBe(true);
    expect(sameAddress("::1", "127.0.0.1")).toBe(false);
    expect(sameAddress(undefined, "127.0.0.1")).toBe(false);
    expect(sameAddress("", "")).toBe(false);
  });
});

describe("resolvePinned", () => {
  const resolver = (answer: string[] | Error): Resolver => ({
    async txt() {
      return [];
    },
    async addresses() {
      if (answer instanceof Error) throw answer;
      return answer;
    },
  });
  const signal = () => AbortSignal.timeout(1000);

  it("pins the first address only when every address is public", async () => {
    expect(
      await resolvePinned(HOST, { resolver: resolver(["93.184.216.34", "2606:2800:220:1::1"]), signal: signal() }),
    ).toEqual({
      ok: true,
      address: "93.184.216.34",
    });
    for (const answer of [
      ["127.0.0.1"],
      ["93.184.216.34", "10.0.0.1"],
      ["169.254.169.254"],
      ["::1"],
      ["fd00::1"],
      ["::ffff:10.0.0.1"],
    ]) {
      expect(await resolvePinned(HOST, { resolver: resolver(answer), signal: signal() })).toMatchObject({
        ok: false,
        reason: "address_not_public",
      });
    }
    expect(await resolvePinned(HOST, { resolver: resolver([]), signal: signal() })).toMatchObject({
      ok: false,
      reason: "resolve_failed",
    });
    expect(await resolvePinned(HOST, { resolver: resolver(new Error("x")), signal: signal() })).toMatchObject({
      ok: false,
      reason: "resolve_failed",
    });
  });

  it("lets loopback pass only with the test-only option, and nothing else private even then", async () => {
    const testing = { port: 1, allowLoopback: true };
    expect(await resolvePinned(HOST, { resolver: resolver(["127.0.0.1"]), signal: signal(), testing })).toEqual({
      ok: true,
      address: "127.0.0.1",
    });
    expect(await resolvePinned(HOST, { resolver: resolver(["10.0.0.1"]), signal: signal(), testing })).toMatchObject({
      ok: false,
      reason: "address_not_public",
    });
  });
});
