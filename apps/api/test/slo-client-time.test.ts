import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { CreateAlertChannelResponseSchema } from "@antireverse/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { classifyRoute } from "../src/slo/middleware.ts";
import { createSloService, type SloService } from "../src/slo/service.ts";
import { readSloBuckets } from "../src/slo/store.ts";
import {
  batchOf,
  bearer,
  createAppFor,
  createOrganization,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
  withReason,
} from "./helpers.ts";

// Slice 18d review: what the client controls is not the server's time or failure.
// H1 — the upload of a slow client is not server time, and an upload the client aborts is a client error (4xx, not
//      counted), not a 500 against SLO-01 or SLO-02.
// M3 — routes that wait on a destination the tenant chose (alert channel test and creation, target verification) are
//      left out of SLO-07.
// L1 — HEAD of the distribution routes counts in SLO-03; keyless public routes are left out of SLO-07.

let db: OwnedDb;
let api: TestApi;
let slo: SloService;
let admin: string;
let shield: string;
let appId: string;
let hook: Server;
let hookUrl: string;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** A request whose body arrives in `parts`, `gapMs` apart; `failAt`: the stream errors instead of sending that part. */
function streamed(parts: string[], gapMs: number, headers: Record<string, string>, failAt?: number): RequestInit {
  let i = 0;
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (i > 0) await sleep(gapMs);
      if (failAt !== undefined && i === failAt) {
        controller.error(new Error("the client went away"));
        return;
      }
      const part = parts[i++];
      if (part === undefined) controller.close();
      else controller.enqueue(encoder.encode(part));
    },
  });
  return {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
    duplex: "half",
  } as RequestInit;
}

/** Splits a JSON text into three parts. */
function thirds(text: string): string[] {
  const a = Math.floor(text.length / 3);
  return [text.slice(0, a), text.slice(a, 2 * a), text.slice(2 * a)];
}

async function recorded(id: string): Promise<{ good: number; total: number }> {
  await slo.recorder.flush();
  const rows = (await db.owner((q) => readSloBuckets(q))).filter((b) => b.slo === id);
  return { good: rows.reduce((n, b) => n + b.good, 0), total: rows.reduce((n, b) => n + b.total, 0) };
}

beforeAll(async () => {
  hook = createServer((_req, res) => {
    // A slow destination of the tenant's choosing.
    setTimeout(() => res.writeHead(204).end(), 700);
  });
  hook.listen(0, "127.0.0.1");
  await once(hook, "listening");
  hookUrl = `http://127.0.0.1:${(hook.address() as AddressInfo).port}/hook`;
  db = await openDb();
  slo = createSloService({ db });
  // The real latency clock (performance.now).
  api = await makeTestApi({ db, slo, allowPrivateAlertUrls: true });
  const organization = await createOrganization(api);
  admin = organization.admin_key.key;
  const created = await createAppFor(api, admin);
  shield = created.shield_key.key;
  appId = created.app.id;
});
beforeEach(async () => {
  await slo.recorder.flush();
  await db.owner((q) => q.query("DELETE FROM slo_minutes"));
});
afterAll(async () => {
  hook.closeAllConnections();
  hook.close();
  await api.close();
});

describe("H1: client upload time and aborts", () => {
  it("does not count a slow upload of an Event batch against the 150 ms of SLO-02", async () => {
    const text = JSON.stringify(batchOf([shieldEvent(Date.now())]));
    const res = await api.app.request("/v1/events", streamed(thirds(text), 120, bearer(shield)));
    expect(res.status).toBe(202);
    expect(await recorded("SLO-02")).toEqual({ good: 1, total: 1 });
  });

  it("does not count a slow upload of a challenge against the 120 ms of SLO-01", async () => {
    const text = JSON.stringify({ app_id: appId });
    const res = await api.app.request("/v1/attest/challenge", streamed(thirds(text), 100, {}));
    expect(res.status).toBe(200);
    expect(await recorded("SLO-01")).toEqual({ good: 1, total: 1 });
  });

  it("answers an aborted upload with a client error, counted nowhere", async () => {
    const batch = JSON.stringify(batchOf([shieldEvent(Date.now())]));
    const events = await api.app.request("/v1/events", streamed(thirds(batch), 10, bearer(shield), 1));
    expect(events.status).toBe(400);
    const challenge = await api.app.request(
      "/v1/attest/challenge",
      streamed(thirds(JSON.stringify({ app_id: appId })), 10, {}, 2),
    );
    expect(challenge.status).toBe(400);
    expect(await recorded("SLO-02")).toEqual({ good: 0, total: 0 });
    expect(await recorded("SLO-01")).toEqual({ good: 0, total: 0 });
  });

  it("does not record a request whose client has gone away", async () => {
    const controller = new AbortController();
    controller.abort();
    const res = await api.app.request(new Request("http://localhost/v1/signing-key", { signal: controller.signal }));
    expect(res.status).toBe(200);
    expect(await recorded("SLO-03")).toEqual({ good: 0, total: 0 });
  });
});

describe("M3: destinations of the tenant's choosing", () => {
  it("leaves the alert channel test out of SLO-07, however slow the tenant's webhook", async () => {
    const created = await api.app.request(
      "/v1/alert-channels",
      json({ kind: "webhook", name: "Slow hook", url: hookUrl }, withReason(bearer(admin))),
    );
    expect(created.status).toBe(201);
    const channel = CreateAlertChannelResponseSchema.parse(await created.json()).channel;
    await slo.recorder.flush();
    await db.owner((q) => q.query("DELETE FROM slo_minutes"));
    const tested = await api.app.request(`/v1/alert-channels/${channel.id}/test`, json({}, withReason(bearer(admin))));
    expect(tested.status).toBe(200);
    expect(await recorded("SLO-07")).toEqual({ good: 0, total: 0 });
  });

  it("leaves every route that awaits a tenant-chosen destination out of SLO-07", () => {
    expect(classifyRoute("POST", "/v1/alert-channels/:channelId/test")).toBeNull();
    expect(classifyRoute("POST", "/v1/alert-channels")).toBeNull();
    expect(classifyRoute("POST", "/v1/targets/:targetId/verify")).toBeNull();
    // Reads of the same resources stay in.
    expect(classifyRoute("GET", "/v1/alert-channels")).toEqual({ slo: "SLO-07", variant: "read" });
  });
});

describe("L1: HEAD and keyless routes", () => {
  it("counts HEAD of the bundle and the signing key in SLO-03", () => {
    expect(classifyRoute("HEAD", "/v1/policy-bundle")).toEqual({ slo: "SLO-03", variant: "all" });
    expect(classifyRoute("HEAD", "/v1/signing-key")).toEqual({ slo: "SLO-03", variant: "all" });
  });

  it("leaves keyless public routes out of SLO-07", () => {
    expect(classifyRoute("GET", "/v1/audit/public-key")).toBeNull();
    expect(classifyRoute("GET", "/v1/deletions/:deletionId/report")).toBeNull();
  });
});
