// Slice 03, contract P4, through the Express adapter: one attestation result per request on the Event, the response
// never changed, the token (and its sub and jti) never in an Event or a log line, and fail open.
import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import net from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { type BundlePayload, EventBatchSchema, type ShieldEvent } from "@antireverse/protocol";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createExpressMiddleware } from "../src/express.ts";
import { createShield, type Shield } from "../src/index.ts";
import { APP_ID, claims, createAttestationKey, OTHER_APP_ID, token } from "./attestation-helpers.ts";
import { exchange, KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, type FakeApi, fakeApi, NOW, payload, signed } from "./policy-helpers.ts";

const signer = createSigner();
const current = createAttestationKey();
const next = createAttestationKey();
const stranger = createAttestationKey();
/** Shield's clock in these tests: a minute after the bundle was issued. */
const CLOCK = NOW + 60_000;
const CLOCK_S = Math.floor(CLOCK / 1000);

const open: Listening[] = [];
const shields: Shield[] = [];
let consoleLines: string[] = [];

beforeEach(() => {
  consoleLines = [];
  for (const method of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      consoleLines.push(args.map(String).join(" "));
    });
  }
});

afterEach(async () => {
  for (const listening of open.splice(0)) await listening.stop();
  for (const shield of shields.splice(0)) await shield.close();
  vi.restoreAllMocks();
});

interface Watched {
  shield: Shield;
  api: FakeApi;
  events(count: number): Promise<ShieldEvent[]>;
  leaked(): string;
}

async function watch(overrides: Partial<BundlePayload> = {}): Promise<Watched> {
  const api = fakeApi();
  const warnings: string[] = [];
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    now: () => CLOCK,
    logger: { warn: (message) => void warnings.push(message) },
  });
  shields.push(shield);
  api.publish(
    signed(signer, payload(KEY, { app_id: APP_ID, attestation_keys: [current.entry, next.entry], ...overrides })),
  );
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();
  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  return {
    shield,
    api,
    async events(count) {
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return api.posts.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    },
    leaked: () =>
      [
        ...api.posts.map((request) => `${request.url} ${JSON.stringify(request.headers)} ${request.body ?? ""}`),
        ...api.gets.map((request) => `${request.url} ${JSON.stringify(request.headers)}`),
        ...warnings,
        ...consoleLines,
        shield.stats().lastPolicyError ?? "",
        shield.stats().lastError ?? "",
      ].join("\n"),
  };
}

function makeApp(shield?: Shield): express.Express {
  const app = express();
  app.disable("x-powered-by");
  if (shield) app.use(shield.express());
  app.get("/api/data", (req, res) => {
    res.setHeader("x-data", "yes");
    res.json({ items: [1, 2, 3], saw: typeof req.headers["ar-attestation"] });
  });
  app.use((_req, res) => void res.status(404).send("no such page"));
  return app;
}

async function serve(app: express.Express): Promise<Listening> {
  const listening = await listen(app);
  open.push(listening);
  return listening;
}

/** One raw request: lets a header be sent twice. */
function raw(port: number, headers: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write(`GET /api/data HTTP/1.1\r\nHost: target.test\r\n${headers}Connection: close\r\n\r\n`);
    });
    let data = "";
    socket.setEncoding("latin1");
    socket.on("data", (chunk: string) => {
      data += chunk;
    });
    socket.on("error", reject);
    socket.on("close", () => resolve(data.replace(/\r\nDate: [^\r]*/i, "")));
  });
}

const NONE = { verdict: null, risk: null };

describe("the attestation of each request on its Event", () => {
  it("valid, missing, invalid, expired, other App, unknown key: one result per request, the token nowhere", async () => {
    const watched = await watch();
    const { base } = await serve(makeApp(watched.shield));
    const valid = token(current, claims(CLOCK_S, { verdict: "trusted", risk: 5, sig: [] }));
    const rotated = token(next, claims(CLOCK_S, {}, 2));
    const expired = token(current, claims(CLOCK_S - 1000, {}, 3));
    const otherApp = token(current, claims(CLOCK_S, { aud: OTHER_APP_ID }, 4));
    const unknownKey = token(stranger, claims(CLOCK_S, {}, 5));
    const forged = `${valid.slice(0, valid.lastIndexOf("."))}.${unknownKey.split(".")[2]}`;
    const sent = [valid, valid, undefined, rotated, expired, otherApp, unknownKey, forged, "garbage"];
    for (const header of sent) {
      const response = await exchange(
        `${base}/api/data`,
        header === undefined ? {} : { headers: { "ar-attestation": header } },
      );
      expect(response.status).toBe(200);
    }
    const events = await watched.events(sent.length);
    expect(events.map((event) => event.attestation)).toEqual([
      { status: "valid", verdict: "trusted", risk: 5 },
      { status: "valid", verdict: "trusted", risk: 5 },
      { status: "missing", ...NONE },
      { status: "valid", verdict: "suspect", risk: 70 },
      { status: "expired", ...NONE },
      { status: "invalid", ...NONE },
      { status: "invalid", ...NONE },
      { status: "invalid", ...NONE },
      { status: "invalid", ...NONE },
    ]);
    const leaked = watched.leaked();
    for (const given of [valid, rotated, expired, otherApp, unknownKey, forged]) {
      const [h, p, s] = given.split(".") as [string, string, string];
      for (const part of [h, p, s]) expect(leaked).not.toContain(part);
    }
    const example = claims(CLOCK_S);
    expect(leaked).not.toContain(example.sub);
    for (let n = 1; n <= 5; n++) expect(leaked).not.toContain(n.toString(16).padStart(32, "0"));
    expect(leaked).not.toContain(example.cnf.jkt);
    expect(leaked).not.toContain("ar-attestation");
  });

  it("the Event carries only status, verdict and risk under attestation", async () => {
    const watched = await watch();
    const { base } = await serve(makeApp(watched.shield));
    await exchange(`${base}/api/data`, { headers: { "ar-attestation": token(current, claims(CLOCK_S)) } });
    await watched.events(1);
    const body = JSON.parse(watched.api.posts[0]?.body ?? "") as { events: Record<string, Record<string, unknown>>[] };
    expect(Object.keys(body.events[0]?.attestation ?? {}).sort()).toEqual(["risk", "status", "verdict"]);
  });

  it("a header sent twice is invalid", async () => {
    const watched = await watch();
    const { port } = await serve(makeApp(watched.shield));
    const valid = token(current, claims(CLOCK_S));
    const response = await raw(port, `ar-attestation: ${valid}\r\nar-attestation: ${valid}\r\n`);
    expect(response).toMatch(/^HTTP\/1\.1 200 /);
    const events = await watched.events(1);
    expect(events[0]?.attestation).toEqual({ status: "invalid", ...NONE });
  });

  it("an oversize header is invalid, and the request is served", async () => {
    const watched = await watch();
    const { base } = await serve(makeApp(watched.shield));
    const response = await exchange(`${base}/api/data`, { headers: { "ar-attestation": "a".repeat(2049) } });
    expect(response.status).toBe(200);
    expect((await watched.events(1))[0]?.attestation).toEqual({ status: "invalid", ...NONE });
  });

  it("before any bundle (no keys, no App) a token is invalid and a request without one is missing", async () => {
    const api = fakeApi();
    const shield = createShield({
      key: KEY,
      endpoint: "http://api.test",
      transport: api.transport,
      flushIntervalMs: 3_600_000,
      now: () => CLOCK,
      logger: { warn: () => {} },
    });
    shields.push(shield);
    const { base } = await serve(makeApp(shield));
    await exchange(`${base}/api/data`, { headers: { "ar-attestation": token(current, claims(CLOCK_S)) } });
    await exchange(`${base}/api/data`);
    for (let i = 0; i < 400 && shield.stats().buffered < 2; i++) await sleep(5);
    await shield.flush();
    const events = api.posts.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    expect(events.map((event) => event.attestation?.status)).toEqual(["invalid", "missing"]);
  });
});

describe("the response never changes", () => {
  it.each([
    ["a valid token", () => token(current, claims(CLOCK_S))],
    ["an expired token", () => token(current, claims(CLOCK_S - 1000))],
    ["a forged token", () => "a.b.c"],
    ["no token", () => undefined],
  ])("%s: same status, headers and body as without Shield", async (_name, make) => {
    const watched = await watch();
    const withShield = await serve(makeApp(watched.shield));
    const without = await serve(makeApp());
    const header = make();
    const init = header === undefined ? {} : { headers: { "ar-attestation": header } };
    expect(await exchange(`${withShield.base}/api/data`, init)).toEqual(
      await exchange(`${without.base}/api/data`, init),
    );
  });
});

describe("fail open", () => {
  class ResponseDouble extends EventEmitter {
    statusCode = 200;
    headersSent = false;
    setHeader(): void {}
    end(): void {
      this.headersSent = true;
    }
  }

  it("a failing attestation check records invalid, counts the error, and the request proceeds", () => {
    const recorded: ShieldEvent[] = [];
    let errors = 0;
    const middleware = createExpressMiddleware({
      decide: () => ({ action: "allow", mode: "monitor", ruleId: null, policyVersion: 0 }),
      attest: () => {
        throw new Error("synthetic failure");
      },
      routeOf: () => undefined,
      record: (event) => void recorded.push(event),
      now: () => CLOCK,
      clientAddress: undefined,
      onInternalError: () => {
        errors += 1;
      },
    });
    const request = { method: "GET", url: "/api/data", headers: { "ar-attestation": "a.b.c" }, socket: {} };
    const response = new ResponseDouble();
    const next = vi.fn();
    middleware(request as unknown as IncomingMessage, response as unknown as ServerResponse, next);
    expect(next).toHaveBeenCalledOnce();
    response.emit("close");
    expect(errors).toBe(1);
    expect(recorded[0]?.attestation).toEqual({ status: "invalid", ...NONE });
    expect(response.statusCode).toBe(200);
  });

  it("an adapter without an attestation check records null", () => {
    const recorded: ShieldEvent[] = [];
    const middleware = createExpressMiddleware({
      decide: () => ({ action: "allow", mode: "monitor", ruleId: null, policyVersion: 0 }),
      routeOf: () => undefined,
      record: (event) => void recorded.push(event),
      now: () => CLOCK,
      clientAddress: undefined,
      onInternalError: () => {},
    });
    const response = new ResponseDouble();
    middleware(
      { method: "GET", url: "/", headers: {}, socket: {} } as unknown as IncomingMessage,
      response as unknown as ServerResponse,
      () => {},
    );
    response.emit("close");
    expect(recorded[0]?.attestation).toBeNull();
  });
});
