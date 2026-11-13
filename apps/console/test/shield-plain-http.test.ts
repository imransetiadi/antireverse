// @vitest-environment node
import http from "node:http";
import type { AddressInfo } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { EventBatchSchema, type ShieldEvent } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { createShield, type Transport } from "@antireverse/shield-node";
import { afterEach, describe, expect, it } from "vitest";
import { shieldNodeHttpSnippet } from "@/features/apps/shield-snippet.ts";

// The Set up page offers a plain `node:http` snippet (slice 16) only because Shield's middleware works on a plain
// server: this runs it there, wired exactly as the snippet wires it, and reads what Shield would send.

const stops: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const stop of stops.splice(0)) await stop();
});

async function serve(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  stops.push(
    () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  );
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("Shield on a plain node:http server", () => {
  it("lets the request through to the handler and records one Event the protocol accepts", async () => {
    const batches: string[] = [];
    const transport: Transport = async (request) => {
      batches.push(request.body ?? "");
      return { status: 202 };
    };
    const shield = createShield({
      key: generateKey("shield", "development").key,
      endpoint: "http://ingest.test",
      transport,
      flushIntervalMs: 3_600_000,
      inventory: false,
      logger: { warn: () => {} },
    });
    stops.push(() => shield.close());

    // The wiring of the snippet: the middleware first, the application's handler as its `next`.
    const protect = shield.express();
    const base = await serve((req, res) => {
      protect(req, res, () => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("hello");
      });
    });

    const response = await fetch(`${base}/api/products/7?colour=red`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("hello");

    for (let i = 0; i < 400 && shield.stats().buffered + shield.stats().sent < 1; i++) await sleep(5);
    await shield.flush();
    const events: ShieldEvent[] = batches.flatMap((body) => EventBatchSchema.parse(JSON.parse(body)).events);
    expect(events).toHaveLength(1);
    expect(events[0]?.request).toMatchObject({ method: "GET", status: 200 });
    // Without a router Shield cannot name a route template: the page says so next to the snippet.
    expect(events[0]?.request.route).toBe("(unmatched)");
    expect(shield.stats().internalErrors).toBe(0);
  });

  it("is the wiring the snippet shows", () => {
    const snippet = shieldNodeHttpSnippet("https://api.example.test");
    expect(snippet).toContain("const protect = shield.express();");
    expect(snippet).toContain("protect(req, res, () => handle(req, res));");
    expect(snippet).toContain('endpoint: "https://api.example.test"');
  });
});
