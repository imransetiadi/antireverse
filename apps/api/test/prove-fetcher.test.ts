import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import type { TLSSocket } from "node:tls";
import { VERIFICATION_FILE_PATH } from "@antireverse/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createGuardedFetcher, type Resolver } from "../src/prove/verify.ts";

// The guarded HTTPS GET of the file method, against a local TLS server whose certificate (for shop.acme-shop.io)
// is issued by a test CA. Loopback and the test CA are reachable only through the fetcher's explicit test-only
// option; without it the same server is refused before any connection is made.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const CA = fixture("ca.pem");
const HOST = "shop.acme-shop.io";

interface Seen {
  method: string | undefined;
  url: string | undefined;
  host: string | undefined;
  servername: string | false | null | undefined;
  cookie: string | undefined;
  authorization: string | undefined;
}

let server: Server;
let port: number;
let connections = 0;
let seen: Seen[] = [];
let handler: (req: IncomingMessage, res: ServerResponse) => void = (_req, res) => res.end("ok");

beforeAll(async () => {
  server = createServer({ key: fixture("key.pem"), cert: fixture("cert.pem") }, (req, res) => {
    seen.push({
      method: req.method,
      url: req.url,
      host: req.headers.host,
      servername: (req.socket as TLSSocket).servername,
      cookie: req.headers.cookie,
      authorization: req.headers.authorization,
    });
    handler(req, res);
  });
  server.on("secureConnection", () => {
    connections++;
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  connections = 0;
  seen = [];
  handler = (_req, res) => res.end("ok");
});

function resolverOf(answers: Record<string, string[]>) {
  const asked: string[] = [];
  const resolver: Resolver = {
    txt: async () => [],
    async addresses(host) {
      asked.push(host);
      const answer = answers[host];
      if (answer === undefined) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      return answer;
    },
  };
  return Object.assign(resolver, { asked });
}

const testing = () => ({ ca: CA, port, allowLoopback: true as const });

describe("guarded fetcher: the SSRF guard (no test-only option)", () => {
  it.each([
    ["loopback", ["127.0.0.1"]],
    ["private", ["10.0.0.7"]],
    ["metadata", ["169.254.169.254"]],
    ["CGNAT", ["100.64.1.1"]],
    ["IPv6 loopback", ["::1"]],
    ["unique-local", ["fd00::1"]],
    ["IPv4-mapped loopback", ["::ffff:127.0.0.1"]],
    ["one public, one private", ["93.184.216.34", "192.168.0.1"]],
    ["one private, one public", ["192.168.0.1", "93.184.216.34"]],
    ["one public, one link-local IPv6", ["93.184.216.34", "fe80::1"]],
  ])("refuses a host resolving to %s, before any connection", async (_name, addresses) => {
    const fetcher = createGuardedFetcher({ resolver: resolverOf({ [HOST]: addresses }), testing: { port } });
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "address_not_public" });
    expect(connections).toBe(0);
  });

  it("refuses loopback even with the test CA unless loopback is explicitly allowed", async () => {
    const fetcher = createGuardedFetcher({
      resolver: resolverOf({ [HOST]: ["127.0.0.1"] }),
      testing: { ca: CA, port },
    });
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "address_not_public" });
    expect(connections).toBe(0);
  });

  it("answers resolve_failed for a name without addresses or a failed lookup", async () => {
    expect(await createGuardedFetcher({ resolver: resolverOf({ [HOST]: [] }) })(HOST)).toEqual({
      ok: false,
      reason: "resolve_failed",
    });
    expect(await createGuardedFetcher({ resolver: resolverOf({}) })(HOST)).toEqual({
      ok: false,
      reason: "resolve_failed",
    });
    expect(await createGuardedFetcher({ resolver: resolverOf({ [HOST]: ["not-an-address"] }) })(HOST)).toEqual({
      ok: false,
      reason: "address_not_public",
    });
  });

  it("answers timeout when the lookup never answers", async () => {
    const resolver: Resolver = { txt: async () => [], addresses: () => new Promise(() => {}) };
    expect(await createGuardedFetcher({ resolver, timeoutMs: 30 })(HOST)).toEqual({ ok: false, reason: "timeout" });
  });

  it("refuses a host that is not a normalised public DNS name", async () => {
    const resolver = resolverOf({});
    const fetcher = createGuardedFetcher({ resolver });
    await expect(fetcher("127.0.0.1")).rejects.toThrow(TypeError);
    await expect(fetcher("Shop.Acme-Shop.io")).rejects.toThrow(TypeError);
    expect(resolver.asked).toEqual([]);
  });
});

describe("guarded fetcher: the request (local TLS server, test-only option)", () => {
  it("GETs the well-known file over TLS from the pinned address, with SNI and Host for the name and no cookies", async () => {
    handler = (_req, res) => res.end("  the-body\n");
    const resolver = resolverOf({ [HOST]: ["127.0.0.1"] });
    const fetcher = createGuardedFetcher({ resolver, testing: testing() });
    expect(await fetcher(HOST)).toEqual({ ok: true, body: "  the-body\n" });
    // One resolution only: the connection goes to the address that was checked.
    expect(resolver.asked).toEqual([HOST]);
    expect(seen).toEqual([
      {
        method: "GET",
        url: VERIFICATION_FILE_PATH,
        host: HOST,
        servername: HOST,
        cookie: undefined,
        authorization: undefined,
      },
    ]);
  });

  it.each([301, 302, 303, 307, 308])("never follows a redirect (%i fails)", async (status) => {
    handler = (_req, res) => {
      res.writeHead(status, { location: "https://127.0.0.1/" });
      res.end();
    };
    const fetcher = createGuardedFetcher({ resolver: resolverOf({ [HOST]: ["127.0.0.1"] }), testing: testing() });
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "redirect" });
    expect(seen).toHaveLength(1);
  });

  it.each([204, 404, 500])("fails on status %i", async (status) => {
    handler = (_req, res) => {
      res.writeHead(status);
      res.end();
    };
    const fetcher = createGuardedFetcher({ resolver: resolverOf({ [HOST]: ["127.0.0.1"] }), testing: testing() });
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "status" });
  });

  it("reads 1,024 bytes and refuses a body beyond them (announced or streamed)", async () => {
    const fetcher = createGuardedFetcher({ resolver: resolverOf({ [HOST]: ["127.0.0.1"] }), testing: testing() });
    handler = (_req, res) => res.end("a".repeat(1024));
    expect(await fetcher(HOST)).toEqual({ ok: true, body: "a".repeat(1024) });
    handler = (_req, res) => res.end("a".repeat(1025));
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "too_large" });
    handler = (_req, res) => {
      // Chunked, no length announced: the fetcher stops reading once past the cap.
      res.write("a".repeat(800));
      res.write("a".repeat(800));
      setTimeout(() => res.end("a".repeat(1_000_000)), 10);
    };
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "too_large" });
  });

  it("gives up after the total timeout on a server that never answers or answers slowly", async () => {
    const fetcher = createGuardedFetcher({
      resolver: resolverOf({ [HOST]: ["127.0.0.1"] }),
      testing: testing(),
      timeoutMs: 200,
    });
    handler = () => {};
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "timeout" });
    handler = (_req, res) => {
      res.writeHead(200);
      res.write("a");
      // A trickle that would stay under the cap but never finish.
    };
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "timeout" });
  });

  it("fails TLS for a certificate of another name", async () => {
    const other = "other.acme-shop.io";
    const fetcher = createGuardedFetcher({ resolver: resolverOf({ [other]: ["127.0.0.1"] }), testing: testing() });
    expect(await fetcher(other)).toEqual({ ok: false, reason: "tls_failed" });
    expect(seen).toEqual([]);
  });

  it("fails TLS for a certificate whose issuer is not trusted (no test CA)", async () => {
    const fetcher = createGuardedFetcher({
      resolver: resolverOf({ [HOST]: ["127.0.0.1"] }),
      testing: { port, allowLoopback: true },
    });
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "tls_failed" });
    expect(seen).toEqual([]);
  });

  it("answers connect_failed when nothing listens", async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const freePort = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const fetcher = createGuardedFetcher({
      resolver: resolverOf({ [HOST]: ["127.0.0.1"] }),
      testing: { ca: CA, port: freePort, allowLoopback: true },
    });
    expect(await fetcher(HOST)).toEqual({ ok: false, reason: "connect_failed" });
  });
});
