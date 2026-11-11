import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createNodeTransport } from "../src/transport.ts";

const servers: http.Server[] = [];

async function listen(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => {
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
});

describe("default transport (node:http)", () => {
  it("POSTs the body with the given headers and resolves with the status", async () => {
    const seen: {
      method: string | undefined;
      url: string | undefined;
      headers: http.IncomingHttpHeaders;
      body: string;
    }[] = [];
    const base = await listen((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
        res.statusCode = 202;
        res.setHeader("content-type", "application/json");
        res.end('{"accepted":1,"duplicates":0}');
      });
    });
    const transport = createNodeTransport();
    const body = JSON.stringify({ text: "héllo ✓" }); // multi-byte: content-length must count bytes
    const result = await transport.send({
      url: `${base}/v1/events`,
      headers: { authorization: "Bearer synthetic", "content-type": "application/json" },
      body,
      timeoutMs: 2_000,
    });
    transport.close();
    expect(result).toEqual({ status: 202 });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ method: "POST", url: "/v1/events", body });
    expect(seen[0]?.headers.authorization).toBe("Bearer synthetic");
    expect(seen[0]?.headers["content-type"]).toBe("application/json");
    expect(seen[0]?.headers["content-length"]).toBe(String(Buffer.byteLength(body)));
  });

  it("resolves with error statuses instead of rejecting", async () => {
    const base = await listen((_req, res) => {
      res.statusCode = 503;
      res.end();
    });
    const transport = createNodeTransport();
    await expect(
      transport.send({ url: `${base}/v1/events`, headers: {}, body: "{}", timeoutMs: 2_000 }),
    ).resolves.toEqual({ status: 503 });
    transport.close();
  });

  it("rejects after timeoutMs when the server never answers", async () => {
    let requests = 0;
    const base = await listen(() => {
      requests += 1; // never answers
    });
    const transport = createNodeTransport();
    const started = performance.now();
    await expect(transport.send({ url: `${base}/v1/events`, headers: {}, body: "{}", timeoutMs: 150 })).rejects.toThrow(
      /timed out/i,
    );
    const elapsed = performance.now() - started;
    transport.close();
    expect(requests).toBe(1);
    expect(elapsed).toBeGreaterThanOrEqual(140);
    expect(elapsed).toBeLessThan(1_000);
  });

  it("rejects when nothing listens, and for a URL that is not http(s)", async () => {
    const base = await listen(() => {});
    const dead = servers.pop() as http.Server;
    await new Promise<void>((resolve) => dead.close(() => resolve()));
    const transport = createNodeTransport();
    await expect(
      transport.send({ url: `${base}/v1/events`, headers: {}, body: "{}", timeoutMs: 1_000 }),
    ).rejects.toBeInstanceOf(Error);
    await expect(
      transport.send({ url: "ftp://127.0.0.1/v1/events", headers: {}, body: "{}", timeoutMs: 1_000 }),
    ).rejects.toBeInstanceOf(Error);
    await expect(
      transport.send({ url: "not a url", headers: {}, body: "{}", timeoutMs: 1_000 }),
    ).rejects.toBeInstanceOf(Error);
    transport.close();
  });
});

describe("default transport (node:http): GET with a capped response body", () => {
  const CAP = 131_072;

  it("sends a GET without a body and resolves with status, body and ETag", async () => {
    const seen: {
      method: string | undefined;
      url: string | undefined;
      headers: http.IncomingHttpHeaders;
      bytes: number;
    }[] = [];
    const base = await listen((req, res) => {
      let bytes = 0;
      req.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
      });
      req.on("end", () => {
        seen.push({ method: req.method, url: req.url, headers: req.headers, bytes });
        res.writeHead(200, { "content-type": "application/json", etag: '"v7"' });
        res.write('{"bundle":"hé');
        res.end('llo ✓"}'); // multi-byte text across two chunks
      });
    });
    const transport = createNodeTransport();
    const result = await transport.send({
      method: "GET",
      url: `${base}/v1/policy-bundle`,
      headers: { authorization: "Bearer synthetic", "if-none-match": '"v6"' },
      timeoutMs: 2_000,
    });
    transport.close();
    expect(result).toEqual({ status: 200, body: '{"bundle":"héllo ✓"}', etag: '"v7"' });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ method: "GET", url: "/v1/policy-bundle", bytes: 0 });
    expect(seen[0]?.headers.authorization).toBe("Bearer synthetic");
    expect(seen[0]?.headers["if-none-match"]).toBe('"v6"');
    expect(seen[0]?.headers["content-length"]).toBeUndefined();
    expect(seen[0]?.headers["transfer-encoding"]).toBeUndefined();
  });

  it("resolves a 304 with an empty body, and an error status with its body", async () => {
    const base = await listen((req, res) => {
      if (req.headers["if-none-match"] === '"v7"') {
        res.writeHead(304, { etag: '"v7"' }).end();
        return;
      }
      res.writeHead(401, { "content-type": "application/problem+json" }).end('{"title":"Unauthorized"}');
    });
    const transport = createNodeTransport();
    await expect(
      transport.send({ method: "GET", url: `${base}/x`, headers: { "if-none-match": '"v7"' }, timeoutMs: 2_000 }),
    ).resolves.toEqual({ status: 304, body: "", etag: '"v7"' });
    await expect(transport.send({ method: "GET", url: `${base}/x`, headers: {}, timeoutMs: 2_000 })).resolves.toEqual({
      status: 401,
      body: '{"title":"Unauthorized"}',
    });
    transport.close();
  });

  it.each([
    ["with a content-length", true],
    ["chunked", false],
  ])("accepts a body of exactly 131,072 bytes (%s)", async (_name, declared) => {
    const body = Buffer.alloc(CAP, "a");
    const base = await listen((_req, res) => {
      if (declared) res.setHeader("content-length", body.length);
      res.end(body);
    });
    const transport = createNodeTransport();
    const result = await transport.send({ method: "GET", url: `${base}/x`, headers: {}, timeoutMs: 2_000 });
    transport.close();
    expect(result.status).toBe(200);
    expect(result.body?.length).toBe(CAP);
  });

  it("rejects a declared body over the cap without reading it", async () => {
    let sent = 0;
    const base = await listen((_req, res) => {
      res.writeHead(200, { "content-length": 1_048_576 });
      const chunk = Buffer.alloc(16_384, "a");
      const pump = (): void => {
        while (sent < 1_048_576 && !res.destroyed) {
          sent += chunk.length;
          if (!res.write(chunk)) {
            res.once("drain", pump);
            return;
          }
        }
        res.end();
      };
      pump();
    });
    const transport = createNodeTransport();
    await expect(transport.send({ method: "GET", url: `${base}/x`, headers: {}, timeoutMs: 2_000 })).rejects.toThrow(
      /exceeds 131072 bytes/,
    );
    transport.close();
  });

  it("stops reading a chunked body once it exceeds the cap, and rejects", async () => {
    let sent = 0;
    let closed = false;
    const base = await listen((_req, res) => {
      res.on("close", () => {
        closed = true;
      });
      const chunk = Buffer.alloc(8_192, "a");
      const pump = (): void => {
        // An endless body: only the cap ends this.
        while (!res.destroyed) {
          sent += chunk.length;
          if (!res.write(chunk)) {
            res.once("drain", pump);
            return;
          }
          if (sent > 64 * 1_048_576) return;
        }
      };
      pump();
    });
    const transport = createNodeTransport();
    const started = performance.now();
    await expect(transport.send({ method: "GET", url: `${base}/x`, headers: {}, timeoutMs: 5_000 })).rejects.toThrow(
      /exceeds 131072 bytes/,
    );
    expect(performance.now() - started).toBeLessThan(2_000); // by the cap, not by the timeout
    transport.close();
    for (let i = 0; i < 100 && !closed; i++) await new Promise((resolve) => setTimeout(resolve, 10));
    expect(closed).toBe(true); // the connection was dropped, not drained
    expect(sent).toBeLessThan(64 * 1_048_576);
  });

  it("rejects after timeoutMs when the body stalls half-way", async () => {
    const base = await listen((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"bundle":"'); // and nothing more
    });
    const transport = createNodeTransport();
    const started = performance.now();
    await expect(transport.send({ method: "GET", url: `${base}/x`, headers: {}, timeoutMs: 150 })).rejects.toThrow(
      /timed out/i,
    );
    expect(performance.now() - started).toBeLessThan(1_000);
    transport.close();
  });

  it("rejects when the server drops the connection half-way through the body", async () => {
    const base = await listen((_req, res) => {
      res.writeHead(200, { "content-length": 1_000 });
      res.write("partial");
      setTimeout(() => res.destroy(), 20);
    });
    const transport = createNodeTransport();
    await expect(
      transport.send({ method: "GET", url: `${base}/x`, headers: {}, timeoutMs: 2_000 }),
    ).rejects.toBeInstanceOf(Error);
    transport.close();
  });

  it("a POST still resolves with the status only, whatever the response carries", async () => {
    const base = await listen((_req, res) => {
      res.writeHead(202, { etag: '"x"', "content-type": "application/json" }).end('{"accepted":1}');
    });
    const transport = createNodeTransport();
    await expect(
      transport.send({ url: `${base}/v1/events`, headers: {}, body: "{}", timeoutMs: 2_000 }),
    ).resolves.toEqual({
      status: 202,
    });
    await expect(
      transport.send({ method: "POST", url: `${base}/v1/events`, headers: {}, body: "{}", timeoutMs: 2_000 }),
    ).resolves.toEqual({ status: 202 });
    transport.close();
  });

  it("a POST answered 429 resolves with its retry-after header (A7)", async () => {
    const base = await listen((_req, res) => {
      res.writeHead(429, { "retry-after": "42", "content-type": "application/problem+json" }).end("{}");
    });
    const transport = createNodeTransport();
    await expect(
      transport.send({ url: `${base}/v1/inventory`, headers: {}, body: "{}", timeoutMs: 2_000 }),
    ).resolves.toEqual({ status: 429, retryAfter: "42" });
    transport.close();
  });
});
