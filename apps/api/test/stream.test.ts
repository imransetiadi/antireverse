import { LIMITS, ListEventsResponseSchema, StoredEventSchema } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.ts";
import {
  batchOf,
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  expectProblem,
  json,
  makeTestApi,
  shieldEvent,
  sseReader,
  type TestApi,
  tick,
  within,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T10:00:00.000Z");

interface Tenant {
  organizationId: string;
  adminKey: string;
  appId: string;
  shieldKey: string;
}

describe("live stream", () => {
  let api: TestApi;
  let a: Tenant;
  let b: Tenant;
  const open: ReturnType<typeof sseReader>[] = [];

  async function tenant(name: string): Promise<Tenant> {
    const organization = await createOrganization(api, name);
    const created = await createAppFor(api, organization.admin_key.key);
    return {
      organizationId: organization.organization.id,
      adminKey: organization.admin_key.key,
      appId: created.app.id,
      shieldKey: created.shield_key.key,
    };
  }

  function request(appId: string, adminKey: string, app = api.app): Promise<Response> {
    return Promise.resolve(app.request(`/v1/apps/${appId}/events/stream`, { headers: bearer(adminKey) }));
  }

  /** Opens a stream and waits until the API has subscribed it. */
  async function stream(t: Tenant, app = api.app): Promise<ReturnType<typeof sseReader>> {
    const res = await request(t.appId, t.adminKey, app);
    expect(res.status).toBe(200);
    if (res.body === null) throw new Error("The stream has no body.");
    const reader = sseReader(res.body);
    open.push(reader);
    expect(await within(reader.next(), 1_000, "the first bytes of the stream")).toBe(": connected");
    return reader;
  }

  async function ingest(t: Tenant, ms: number) {
    const event = shieldEvent(ms);
    const res = await api.app.request("/v1/events", json(batchOf([event]), bearer(t.shieldKey)));
    expect(res.status).toBe(202);
    return event;
  }

  beforeAll(async () => {
    api = await makeTestApi();
    a = await tenant("Organization A");
    b = await tenant("Organization B");
  });
  afterEach(async () => {
    for (const reader of open.splice(0)) await reader.cancel().catch(() => {});
    await tick();
    expect(api.bus.count()).toBe(0);
  });
  afterAll(async () => {
    await api.close();
  });

  it("delivers an ingested Event as one security-event message", async () => {
    const res = await request(a.appId, a.adminKey);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    expect(res.headers.get("cache-control")).toBe("no-cache");
    if (res.body === null) throw new Error("The stream has no body.");
    const reader = sseReader(res.body);
    open.push(reader);
    expect(await reader.next()).toBe(": connected");

    const event = await ingest(a, T0 + 1);
    const message = await within(reader.nextEvent(), 1_000, "the security-event");

    expect(message.event).toBe("security-event");
    expect(message.id).toBe(event.event_id);
    const stored = StoredEventSchema.parse(JSON.parse(message.data ?? ""));
    expect(stored).toMatchObject({ ...event, organization_id: a.organizationId, app_id: a.appId });

    const listed = await api.app.request(`/v1/apps/${a.appId}/events?limit=1`, { headers: bearer(a.adminKey) });
    expect(ListEventsResponseSchema.parse(await listed.json()).events).toEqual([stored]);
  });

  it("carries an Event's attestation in the security-event message", async () => {
    const reader = await stream(a);
    const attestation = { status: "valid" as const, verdict: "suspect" as const, risk: 70 };
    const event = shieldEvent(T0 + 5, { attestation });
    const res = await api.app.request("/v1/events", json(batchOf([event]), bearer(a.shieldKey)));
    expect(res.status).toBe(202);

    const message = await within(reader.nextEvent(), 1_000, "the security-event");
    expect(message.id).toBe(event.event_id);
    const stored = StoredEventSchema.parse(JSON.parse(message.data ?? ""));
    expect(stored.attestation).toEqual(attestation);
    expect(JSON.parse(message.data ?? "").attestation).toEqual(attestation);
  });

  it("sends each Event once: a batch sent again produces no second message", async () => {
    const reader = await stream(a);
    const first = shieldEvent(T0 + 10);
    const send = () => api.app.request("/v1/events", json(batchOf([first]), bearer(a.shieldKey)));

    await send();
    await send();
    const second = await ingest(a, T0 + 11);

    expect((await within(reader.nextEvent(), 1_000, "the first message")).id).toBe(first.event_id);
    expect((await within(reader.nextEvent(), 1_000, "the second message")).id).toBe(second.event_id);
  });

  it("answers 404 when another Organization asks for the App's stream, as for an App that does not exist", async () => {
    const foreign = await expectProblem(await request(a.appId, b.adminKey), 404);
    expect(await expectProblem(await request(newId("app"), b.adminKey), 404)).toEqual(foreign);
    expect(await expectProblem(await request("app_1", b.adminKey), 404)).toEqual(foreign);
    expect(api.bus.count()).toBe(0);
  });

  it("keeps Organizations and Apps apart: a stream receives only the Events of its own App", async () => {
    const secondAppOfA = await createAppFor(api, a.adminKey, { name: "Back office" });
    const streamB = await stream(b);
    const streamOfSecondApp = await stream({ ...a, appId: secondAppOfA.app.id });

    await ingest(a, T0 + 20);
    const ofB = await ingest(b, T0 + 21);
    const ofSecondApp = await ingest({ ...a, shieldKey: secondAppOfA.shield_key.key }, T0 + 22);

    // The first message each stream sees is its own Event: A's Event of the other App never arrived.
    expect((await within(streamB.nextEvent(), 1_000, "B's message")).id).toBe(ofB.event_id);
    expect((await within(streamOfSecondApp.nextEvent(), 1_000, "the second App's message")).id).toBe(
      ofSecondApp.event_id,
    );
  });

  it("requires an admin key", async () => {
    const none = await api.app.request(`/v1/apps/${a.appId}/events/stream`);
    await expectProblem(none, 401);
    expect(none.headers.get("www-authenticate")).toBe("Bearer");
    await expectProblem(await request(a.appId, a.shieldKey), 403);
  });

  it("releases the subscription when the consumer disappears", async () => {
    const first = await stream(a);
    const second = await stream(a);
    expect(api.bus.count()).toBe(2);
    expect(api.bus.count(a.organizationId)).toBe(2);

    await first.cancel();
    await tick();
    expect(api.bus.count()).toBe(1);

    await second.cancel();
    await tick();
    expect(api.bus.count()).toBe(0);

    // Ingest keeps working with nobody listening.
    await ingest(a, T0 + 30);
  });

  it("sends a comment heartbeat while nothing happens", async () => {
    const app = createApp({ db: api.db, bus: api.bus, signer: api.signer, logger: captureLogger(), heartbeatMs: 50 });
    const reader = await stream(a, app);

    const frame = await within(reader.next(), 200, "a heartbeat");

    expect(frame.startsWith(":")).toBe(true);
    expect(frame).toBe(": heartbeat");
  });

  it("refuses the 21st concurrent stream of an Organization with 429, and only that Organization", async () => {
    const readers = [];
    for (let index = 0; index < LIMITS.streamsPerOrganization; index++) readers.push(await stream(a));
    expect(api.bus.count(a.organizationId)).toBe(20);

    const refused = await request(a.appId, a.adminKey);
    const problem = await expectProblem(refused, 429);
    expect(problem.detail).toContain("20");
    expect(api.bus.count(a.organizationId)).toBe(20);

    // Another Organization is not affected, and a freed slot can be taken again.
    await stream(b);
    await readers[0]?.cancel();
    await tick();
    await stream(a);
    expect(api.bus.count(a.organizationId)).toBe(20);
  });

  it("ends every stream when the server shuts down", async () => {
    const shutdown = new AbortController();
    const app = createApp({
      db: api.db,
      bus: api.bus,
      signer: api.signer,
      logger: captureLogger(),
      shutdown: shutdown.signal,
    });
    const reader = await stream(a, app);
    expect(api.bus.count()).toBe(1);

    shutdown.abort();

    await expect(within(reader.next(), 1_000, "the end of the stream")).rejects.toThrow("The stream ended.");
    expect(api.bus.count()).toBe(0);
  });

  it("disconnects a consumer that stopped reading instead of buffering without bound", async () => {
    const res = await request(a.appId, a.adminKey);
    if (res.body === null) throw new Error("The stream has no body.");
    const reader = sseReader(res.body);
    open.push(reader);
    await tick();
    expect(api.bus.count()).toBe(1);

    // Nobody reads while far more Events arrive than a stream may hold back.
    const template = StoredEventSchema.parse({
      ...shieldEvent(T0 + 40),
      organization_id: a.organizationId,
      app_id: a.appId,
      environment: "development",
      received_at: new Date(T0).toISOString(),
    });
    for (let index = 0; index < 5_000; index++) api.bus.publish(template);
    await tick();

    expect(api.bus.count()).toBe(0);
  });
});
