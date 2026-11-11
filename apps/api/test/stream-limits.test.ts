// Resource bounds of the live stream and of error logging (review findings F1, F4, F6, F8).
import net from "node:net";
import { StoredEventSchema } from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.ts";
import type { Db } from "../src/db/db.ts";
import { type Listening, listen } from "../src/server.ts";
import {
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  expectProblem,
  makeTestApi,
  shieldEvent,
  type TestApi,
  tick,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T10:00:00.000Z");

async function until(condition: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await condition()) return true;
    if (Date.now() > deadline) return false;
    await tick(10);
  }
}

describe("live stream limits", () => {
  let api: TestApi;
  let organizationId: string;
  let adminKey: string;
  let appId: string;

  beforeAll(async () => {
    api = await makeTestApi();
    const organization = await createOrganization(api);
    organizationId = organization.organization.id;
    adminKey = organization.admin_key.key;
    appId = (await createAppFor(api, adminKey)).app.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("closes the connection of a consumer that stopped reading, so nothing stays queued for it", async () => {
    const listening: Listening = await listen(api.app, { port: 0 });
    const connections = () =>
      new Promise<number>((resolve, reject) =>
        listening.server.getConnections((error, count) => (error ? reject(error) : resolve(count))),
      );
    const socket = net.connect(listening.port, "127.0.0.1");
    socket.on("error", () => {});
    try {
      socket.write(
        `GET /v1/apps/${appId}/events/stream HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer ${adminKey}\r\n\r\n`,
      );
      // The consumer never reads a byte.
      socket.pause();
      expect(await until(() => api.bus.count() === 1, 2_000)).toBe(true);

      const template = StoredEventSchema.parse({
        ...shieldEvent(T0),
        organization_id: organizationId,
        app_id: appId,
        environment: "development",
        received_at: new Date(T0).toISOString(),
      });
      for (let index = 0; index < 20_000; index++) api.bus.publish(template);

      expect(await until(() => api.bus.count() === 0, 2_000)).toBe(true);
      // The server let go of the connection although the client still holds its end open and unread.
      expect(await until(async () => (await connections()) === 0, 2_000)).toBe(true);
    } finally {
      socket.destroy();
      listening.server.closeAllConnections();
      await new Promise<void>((resolve) => listening.server.close(() => resolve()));
    }
  });

  it("answers HEAD with 405 and opens no stream", async () => {
    for (let index = 0; index < 25; index++) {
      const res = await api.app.request(`/v1/apps/${appId}/events/stream`, {
        method: "HEAD",
        headers: bearer(adminKey),
      });
      expect(res.status).toBe(405);
      expect(res.headers.get("allow")).toBe("GET");
    }
    await tick();
    expect(api.bus.count()).toBe(0);

    // The Organization's 20 slots are all still free.
    const res = await api.app.request(`/v1/apps/${appId}/events/stream`, { headers: bearer(adminKey) });
    expect(res.status).toBe(200);
    await res.body?.cancel();
    await tick();
    expect(api.bus.count()).toBe(0);
  });

  it("opens 20 streams on one shutdown signal without a listener warning", async () => {
    const warnings: string[] = [];
    const onWarning = (warning: Error) => warnings.push(warning.name);
    process.on("warning", onWarning);
    const shutdown = new AbortController();
    const app = createApp({
      db: api.db,
      bus: api.bus,
      signer: api.signer,
      logger: captureLogger(),
      shutdown: shutdown.signal,
    });
    const bodies: (ReadableStream<Uint8Array> | null)[] = [];
    try {
      for (let index = 0; index < 20; index++) {
        const res = await app.request(`/v1/apps/${appId}/events/stream`, { headers: bearer(adminKey) });
        expect(res.status).toBe(200);
        bodies.push(res.body);
      }
      await tick(20);
      expect(warnings).not.toContain("MaxListenersExceededWarning");
    } finally {
      for (const body of bodies) await body?.cancel().catch(() => {});
      await tick();
      process.off("warning", onWarning);
    }
    expect(api.bus.count()).toBe(0);
  });
});

describe("unexpected errors", () => {
  it("answers 500 without internals and logs the kind of error, never its message", async () => {
    const failing: Db = {
      tx() {
        return Promise.reject(new RangeError('date/time field value out of range: "client-supplied-value"'));
      },
      close: () => Promise.resolve(),
    };
    const logger = captureLogger();
    const { bus, signer } = await makeTestApi({ db: failing });
    const app = createApp({ db: failing, bus, signer, logger });

    const res = await app.request("/v1/organizations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Acme" }),
    });

    const problem = await expectProblem(res, 500);
    expect(JSON.stringify(problem)).not.toContain("client-supplied-value");
    expect(logger.lines.some((line) => line.includes("RangeError"))).toBe(true);
    for (const line of logger.lines) expect(line).not.toContain("client-supplied-value");
  });
});
