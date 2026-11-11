// Contract: whatever the adapter observes, every batch that leaves Shield is a valid body of POST /v1/events.
import http from "node:http";
import { setTimeout as sleep } from "node:timers/promises";
import { EventBatchSchema, LIMITS, PROTOCOL_VERSION, SignedBundleSchema, UNMATCHED_ROUTE } from "@antireverse/protocol";
import { parseKey } from "@antireverse/protocol/server";
import express from "express";
import { describe, expect, it } from "vitest";
import { createShield, SDK_NAME, SDK_VERSION } from "../src/index.ts";
import { captureShield, KEY, listen } from "./helpers.ts";
import { createSigner, payload, signed } from "./policy-helpers.ts";

/** Called when the next request for /slow has reached its handler. */
let onSlow: (() => void) | undefined;

function makeApp(middleware: express.RequestHandler): express.Express {
  const app = express();
  app.use(middleware);
  app.get("/api/products/:id", (req, res) => void res.json({ id: req.params.id }));
  app.post("/api/login", (_req, res) => void res.status(401).json({ error: "invalid_credentials" }));
  app.all("/status/:code", (req, res) => void res.writeHead(Number(req.params.code)).end());
  app.get(`/${"long-segment/".repeat(30)}:id`, (_req, res) => void res.send("long")); // a template of 394 characters
  app.get("/slow", (_req, res) => {
    onSlow?.();
    setTimeout(() => res.send("slow"), 200);
  });
  app.get("/boom", () => {
    throw new Error("synthetic failure");
  });
  const nested = express.Router();
  nested.get("/apps/:appId", (_req, res) => void res.send("ok"));
  app.use("/orgs/:orgId", nested);
  app.use((_err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).end();
  });
  return app;
}

/** One request with any method, including ones `fetch` refuses to send. */
function raw(base: string, method: string, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = http.request(base + path, { method, agent: false }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode ?? 0));
    });
    request.on("error", reject);
    request.end();
  });
}

async function exercise(base: string): Promise<number> {
  await raw(base, "GET", "/api/products/42?token=secret");
  await raw(base, "POST", "/api/login");
  await raw(base, "GET", "/orgs/9/apps/7");
  await raw(base, "GET", "/nothing/here");
  await raw(base, "GET", "/boom");
  await raw(base, "HEAD", "/api/products/1");
  await raw(base, "OPTIONS", "/api/products/1");
  await raw(base, "PROPFIND", "/api/products/1");
  await raw(base, "M-SEARCH", "/api/products/1");
  await raw(base, "GET", "/status/204");
  await raw(base, "GET", "/status/599");
  await raw(base, "GET", "/status/799"); // node accepts status codes up to 999; the protocol stops at 599
  await raw(base, "GET", `/${"long-segment/".repeat(30)}1`);
  // The client gives up while the handler is still busy. It aborts once the request has arrived, not after a
  // fixed time: on a busy machine a short timeout can fire before the request was even sent.
  const abort = new AbortController();
  const arrived = new Promise<void>((resolve) => {
    onSlow = resolve;
  });
  const aborted = fetch(`${base}/slow`, { signal: abort.signal }).catch(() => {});
  await arrived;
  abort.abort();
  await aborted;
  return 14;
}

describe("contract: batches from the Express adapter", () => {
  it("every captured batch passes EventBatchSchema", async () => {
    const captured = captureShield({ maxBatchSize: 4 });
    const listening = await listen(makeApp(captured.shield.express()));
    try {
      const count = await exercise(listening.base);
      const events = await captured.events(count);
      expect(events).toHaveLength(count);
      expect(captured.requests.length).toBe(Math.ceil(count / 4));
      for (const request of captured.requests) {
        expect(request.url).toBe("http://ingest.test/v1/events");
        expect(request.headers).toEqual({ authorization: `Bearer ${KEY}`, "content-type": "application/json" });
        const body = request.body ?? "";
        expect(Buffer.byteLength(body)).toBeLessThan(LIMITS.bodyBytesMax);
        const parsed = EventBatchSchema.safeParse(JSON.parse(body));
        expect(parsed.error?.issues ?? []).toEqual([]);
        // the schema strips unknown keys: nothing was stripped, so nothing outside the allowlist was sent
        expect(parsed.data).toEqual(JSON.parse(body));
        expect(parsed.data).toMatchObject({
          protocol: PROTOCOL_VERSION,
          sdk: { name: SDK_NAME, version: SDK_VERSION },
        });
      }
      const requests = events.map((event) => event.request);
      expect(requests.map((request) => request.method)).toEqual([
        "GET",
        "POST",
        "GET",
        "GET",
        "GET",
        "HEAD",
        "OPTIONS",
        "PROPFIND",
        "M-SEARCH",
        "GET",
        "GET",
        "GET",
        "GET",
        "GET",
      ]);
      expect(requests.slice(0, 5).map((request) => [request.route, request.status])).toEqual([
        ["/api/products/:id", 200],
        ["/api/login", 401],
        ["/orgs/:orgId/apps/:appId", 200],
        [UNMATCHED_ROUTE, 404],
        ["/boom", 500],
      ]);
      // values the protocol would refuse are brought into range instead of costing the whole batch
      expect(requests[11]).toMatchObject({ route: "/status/:code", status: 599 });
      expect(requests[12]?.route).toHaveLength(LIMITS.routeMax);
      expect(requests[12]?.route.startsWith("/long-segment/long-segment/")).toBe(true);
      for (const request of requests) {
        expect(request.latency_ms).toBeGreaterThanOrEqual(0);
        expect(request.route.length).toBeLessThanOrEqual(LIMITS.routeMax);
      }
    } finally {
      await listening.stop();
    }
  });

  it("the default transport delivers the same contract to a real ingest endpoint", async () => {
    const received: {
      method: string | undefined;
      url: string | undefined;
      headers: http.IncomingHttpHeaders;
      body: string;
    }[] = [];
    const ingest = await listen((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        received.push({
          method: req.method,
          url: req.url,
          headers: req.headers,
          body: Buffer.concat(chunks).toString(),
        });
        res.writeHead(202, { "content-type": "application/json" }).end('{"accepted":1,"duplicates":0}');
      });
    });
    const warnings: string[] = [];
    const shield = createShield({
      key: KEY,
      endpoint: ingest.base,
      flushIntervalMs: 25,
      logger: { warn: (message) => void warnings.push(message) },
    });
    const target = await listen(makeApp(shield.express()));
    try {
      expect(await raw(target.base, "GET", "/api/products/42?token=secret")).toBe(200);
      for (let i = 0; i < 200 && received.length === 0; i++) await sleep(10); // sent by the flush timer, unprompted
      expect(received).toHaveLength(1);
      const request = received[0] as (typeof received)[number];
      expect(request).toMatchObject({ method: "POST", url: "/v1/events" });
      expect(request.headers["content-type"]).toBe("application/json");
      const bearer = /^Bearer (.+)$/.exec(request.headers.authorization ?? "")?.[1];
      expect(parseKey(bearer)).toEqual({ kind: "shield", environment: "development" });
      const batch = EventBatchSchema.parse(JSON.parse(request.body));
      expect(batch.events).toHaveLength(1);
      expect(batch.events[0]?.request).toMatchObject({ method: "GET", route: "/api/products/:id", status: 200 });
      expect(request.body).not.toContain("secret");
      for (let i = 0; i < 200 && shield.stats().sent === 0; i++) await sleep(5);
      expect(shield.stats()).toMatchObject({
        sent: 1,
        buffered: 0,
        failedBatches: 0,
        internalErrors: 0,
        lastError: null,
      });
      expect(warnings).toEqual([expect.stringMatching(/observes only/)]); // no policyPublicKey: said once
    } finally {
      await shield.close();
      await target.stop();
      await ingest.stop();
    }
  });

  it("the default transport fetches the Policy Bundle from a real endpoint, and conditionally from then on", async () => {
    const signer = createSigner();
    const envelope = signed(signer, payload(KEY, { version: 3, issued_at: new Date().toISOString() }));
    expect(SignedBundleSchema.safeParse(envelope).success).toBe(true);
    const seen: { authorization: string | undefined; accept: string | undefined; ifNoneMatch: string | undefined }[] =
      [];
    const inventoryTypes: (string | undefined)[] = [];
    const api = await listen((req, res) => {
      req.resume();
      if (req.method === "POST" && req.url === "/v1/inventory") {
        inventoryTypes.push(req.headers["content-type"]); // the runtime inventory (slice 19)
        res.writeHead(202).end();
        return;
      }
      if (req.method !== "GET" || req.url !== "/v1/policy-bundle") {
        res.writeHead(404).end();
        return;
      }
      seen.push({
        authorization: req.headers.authorization,
        accept: req.headers.accept,
        ifNoneMatch: req.headers["if-none-match"],
      });
      if (req.headers["if-none-match"] === '"v3"') {
        res.writeHead(304, { etag: '"v3"' }).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json", etag: '"v3"' }).end(JSON.stringify(envelope));
    });
    const warnings: string[] = [];
    const shield = createShield({
      key: KEY,
      endpoint: api.base,
      policyPublicKey: signer.publicKey,
      policyPollIntervalMs: 100,
      logger: { warn: (message) => void warnings.push(message) },
    });
    try {
      // Unprompted: the first request leaves shortly after Shield was created.
      for (let i = 0; i < 400 && shield.stats().policyVersion !== 3; i++) await sleep(5);
      expect(shield.stats()).toMatchObject({
        policyVersion: 3,
        policyRules: 1,
        policyStale: false,
        lastPolicyError: null,
      });
      expect(shield.decide({ method: "GET", path: "/api/admin/reports" })).toMatchObject({
        action: "block",
        mode: "enforce",
        policyVersion: 3,
      });
      for (let i = 0; i < 400 && seen.length < 3; i++) await sleep(5);
      expect(seen[0]).toEqual({ authorization: `Bearer ${KEY}`, accept: "application/json", ifNoneMatch: undefined });
      expect(seen[1]?.ifNoneMatch).toBe('"v3"');
      expect(seen[2]?.ifNoneMatch).toBe('"v3"');
      expect(shield.stats()).toMatchObject({ policyVersion: 3, lastPolicyError: null });
      // The inventory of the working directory went out once, after the first successful fetch.
      for (let i = 0; i < 400 && shield.stats().inventory === "pending"; i++) await sleep(5);
      expect(shield.stats().inventory).toBe("sent");
      expect(inventoryTypes).toEqual(["application/json"]);
      expect(warnings).toEqual([]);
    } finally {
      await shield.close();
      await api.stop();
    }
  });
});
