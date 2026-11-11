import { ListEventsResponseSchema, type StoredEvent } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  batchOf,
  bearer,
  createAppFor,
  createOrganization,
  expectProblem,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T09:00:00.000Z");

describe("Event list", () => {
  let api: TestApi;
  const clock = { now: new Date(T0) };
  let adminA: string;
  let adminB: string;
  let appA: string;
  let otherAppA: string;
  let shieldA: string;
  let shieldOtherA: string;
  /** Identifiers of the 60 Events of appA, in the order they were ingested. */
  const ingested: string[] = [];

  async function ingest(shieldKey: string, ms: number, count: number): Promise<string[]> {
    const events = Array.from({ length: count }, (_, index) => shieldEvent(ms + index));
    clock.now = new Date(ms + 1_000);
    const res = await api.app.request("/v1/events", json(batchOf(events), bearer(shieldKey)));
    expect(res.status).toBe(202);
    return events.map((event) => event.event_id);
  }

  async function list(path: string, key = adminA): Promise<StoredEvent[]> {
    const res = await api.app.request(path, { headers: bearer(key) });
    expect(res.status).toBe(200);
    return ListEventsResponseSchema.parse(await res.json()).events;
  }

  beforeAll(async () => {
    api = await makeTestApi({ now: () => clock.now });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    const first = await createAppFor(api, adminA, { name: "Storefront" });
    const second = await createAppFor(api, adminA, { name: "Back office" });
    appA = first.app.id;
    shieldA = first.shield_key.key;
    otherAppA = second.app.id;
    shieldOtherA = second.shield_key.key;

    // Three batches received at increasing times; the middle one is received before it is "sent" last.
    ingested.push(...(await ingest(shieldA, T0, 20)));
    ingested.push(...(await ingest(shieldA, T0 + 60_000, 20)));
    ingested.push(...(await ingest(shieldA, T0 + 120_000, 20)));
    await ingest(shieldOtherA, T0 + 180_000, 2);
  });
  afterAll(async () => {
    await api.close();
  });

  it("returns at most 50 Events by default, newest first", async () => {
    const events = await list(`/v1/apps/${appA}/events`);
    expect(events).toHaveLength(50);
    expect(events.map((event) => event.event_id)).toEqual([...ingested].reverse().slice(0, 50));
  });

  it("honours a limit from 1 to 200", async () => {
    expect((await list(`/v1/apps/${appA}/events?limit=1`)).map((event) => event.event_id)).toEqual([ingested.at(-1)]);
    expect(await list(`/v1/apps/${appA}/events?limit=200`)).toHaveLength(60);
  });

  it("orders by the time of receipt first, then by event identifier", async () => {
    const organization = await createOrganization(api, "Ordering");
    const created = await createAppFor(api, organization.admin_key.key);
    // The batch received first carries the later event identifiers.
    const late = [shieldEvent(T0 + 900_000), shieldEvent(T0 + 900_001)];
    const early = [shieldEvent(T0 + 1), shieldEvent(T0 + 2)];
    clock.now = new Date(T0 + 1_000_000);
    await api.app.request("/v1/events", json(batchOf(late), bearer(created.shield_key.key)));
    clock.now = new Date(T0 + 1_000_001);
    await api.app.request("/v1/events", json(batchOf(early), bearer(created.shield_key.key)));

    const events = await list(`/v1/apps/${created.app.id}/events`, organization.admin_key.key);

    expect(events.map((event) => event.event_id)).toEqual([
      early[1]?.event_id,
      early[0]?.event_id,
      late[1]?.event_id,
      late[0]?.event_id,
    ]);
  });

  it("lists only the Events of the App asked for", async () => {
    const events = await list(`/v1/apps/${otherAppA}/events`);
    expect(events).toHaveLength(2);
    expect(events.every((event) => event.app_id === otherAppA)).toBe(true);
  });

  it("returns an empty list for an App without Events", async () => {
    const created = await createAppFor(api, adminB, { name: "Quiet" });
    expect(await list(`/v1/apps/${created.app.id}/events`, adminB)).toEqual([]);
  });

  it.each(["0", "201", "abc", "", "-1", "1.5", "1e2", " 5", "5&limit=6"])("refuses limit=%s", async (limit) => {
    const res = await api.app.request(`/v1/apps/${appA}/events?limit=${limit}`, { headers: bearer(adminA) });
    const problem = await expectProblem(res, 400);
    expect(problem.errors?.[0]?.path).toBe("limit");
  });

  it("answers 404 for another Organization's App exactly as for an App that does not exist", async () => {
    const foreign = await api.app.request(`/v1/apps/${appA}/events`, { headers: bearer(adminB) });
    const missing = await api.app.request(`/v1/apps/${newId("app")}/events`, { headers: bearer(adminB) });
    const malformed = await api.app.request("/v1/apps/app_1/events", { headers: bearer(adminB) });

    const problem = await expectProblem(foreign, 404);
    expect(await expectProblem(missing, 404)).toEqual(problem);
    expect(await expectProblem(malformed, 404)).toEqual(problem);
  });

  it("requires an admin key", async () => {
    const none = await api.app.request(`/v1/apps/${appA}/events`);
    await expectProblem(none, 401);
    expect(none.headers.get("www-authenticate")).toBe("Bearer");
    await expectProblem(await api.app.request(`/v1/apps/${appA}/events`, { headers: bearer(shieldA) }), 403);
  });
});
