import { EXAMPLE_STORED_EVENT, type StoredEvent } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { createEventBus } from "../src/bus.ts";

const organizationA = newId("org");
const organizationB = newId("org");
const appA1 = newId("app");
const appA2 = newId("app");
const appB1 = newId("app");

function eventFor(organizationId: string, appId: string): StoredEvent {
  return { ...EXAMPLE_STORED_EVENT, organization_id: organizationId, app_id: appId };
}

describe("event bus", () => {
  it("delivers an Event only to subscribers of its Organization and App", () => {
    const bus = createEventBus();
    const seen: Record<string, StoredEvent[]> = { a1: [], a1Again: [], a2: [], b1: [], bAskingForA1: [] };
    bus.subscribe({ organizationId: organizationA, appId: appA1 }, (event) => seen.a1?.push(event));
    bus.subscribe({ organizationId: organizationA, appId: appA1 }, (event) => seen.a1Again?.push(event));
    bus.subscribe({ organizationId: organizationA, appId: appA2 }, (event) => seen.a2?.push(event));
    bus.subscribe({ organizationId: organizationB, appId: appB1 }, (event) => seen.b1?.push(event));
    // Even a subscription that names another Organization's App receives nothing from that Organization.
    bus.subscribe({ organizationId: organizationB, appId: appA1 }, (event) => seen.bAskingForA1?.push(event));

    const event = eventFor(organizationA, appA1);
    bus.publish(event);

    expect(seen).toEqual({ a1: [event], a1Again: [event], a2: [], b1: [], bAskingForA1: [] });
  });

  it("stops delivering after unsubscribing, and unsubscribing twice is harmless", () => {
    const bus = createEventBus();
    const seen: StoredEvent[] = [];
    const filter = { organizationId: organizationA, appId: appA1 };
    const unsubscribe = bus.subscribe(filter, (event) => seen.push(event));
    const other = bus.subscribe(filter, () => {});

    unsubscribe();
    unsubscribe();
    bus.publish(eventFor(organizationA, appA1));

    expect(seen).toHaveLength(0);
    expect(bus.count()).toBe(1);
    other();
    expect(bus.count()).toBe(0);
  });

  it("keeps delivering to the others when one subscriber throws", () => {
    const bus = createEventBus();
    const seen: StoredEvent[] = [];
    const filter = { organizationId: organizationA, appId: appA1 };
    bus.subscribe(filter, () => {
      throw new Error("subscriber failed");
    });
    bus.subscribe(filter, (event) => seen.push(event));

    const event = eventFor(organizationA, appA1);
    expect(() => bus.publish(event)).not.toThrow();
    expect(seen).toEqual([event]);
  });

  it("lets a subscriber unsubscribe while an Event is being delivered", () => {
    const bus = createEventBus();
    const filter = { organizationId: organizationA, appId: appA1 };
    const seen: string[] = [];
    const first = bus.subscribe(filter, () => {
      seen.push("first");
      first();
    });
    bus.subscribe(filter, () => seen.push("second"));

    bus.publish(eventFor(organizationA, appA1));
    bus.publish(eventFor(organizationA, appA1));

    expect(seen).toEqual(["first", "second", "second"]);
  });

  it("counts subscriptions, in total and per Organization", () => {
    const bus = createEventBus();
    expect(bus.count()).toBe(0);
    const a1 = bus.subscribe({ organizationId: organizationA, appId: appA1 }, () => {});
    const a2 = bus.subscribe({ organizationId: organizationA, appId: appA2 }, () => {});
    const b1 = bus.subscribe({ organizationId: organizationB, appId: appB1 }, () => {});

    expect(bus.count()).toBe(3);
    expect(bus.count(organizationA)).toBe(2);
    expect(bus.count(organizationB)).toBe(1);
    expect(bus.count(newId("org"))).toBe(0);

    a1();
    a2();
    b1();
    expect(bus.count()).toBe(0);
    expect(bus.count(organizationA)).toBe(0);
  });
  describe("subscribeAll", () => {
    it("delivers every Event of every Organization and App, beside the per-App subscriptions", () => {
      const bus = createEventBus();
      const all: StoredEvent[] = [];
      const a1: StoredEvent[] = [];
      bus.subscribeAll((event) => all.push(event));
      bus.subscribe({ organizationId: organizationA, appId: appA1 }, (event) => a1.push(event));

      const first = eventFor(organizationA, appA1);
      const second = eventFor(organizationB, appB1);
      bus.publish(first);
      bus.publish(second);

      expect(all).toEqual([first, second]);
      expect(a1).toEqual([first]);
    });

    it("is not counted as a live stream, stops after unsubscribing, and unsubscribing twice is harmless", () => {
      const bus = createEventBus();
      const all: StoredEvent[] = [];
      const unsubscribe = bus.subscribeAll((event) => all.push(event));
      expect(bus.count()).toBe(0);
      expect(bus.count(organizationA)).toBe(0);

      unsubscribe();
      unsubscribe();
      bus.publish(eventFor(organizationA, appA1));
      expect(all).toHaveLength(0);
    });

    it("keeps delivering to the others when an all-events subscriber throws", () => {
      const bus = createEventBus();
      const seen: StoredEvent[] = [];
      bus.subscribeAll(() => {
        throw new Error("subscriber failed");
      });
      bus.subscribe({ organizationId: organizationA, appId: appA1 }, (event) => seen.push(event));
      bus.subscribeAll((event) => seen.push(event));

      const event = eventFor(organizationA, appA1);
      expect(() => bus.publish(event)).not.toThrow();
      expect(seen).toEqual([event, event]);
    });
  });
});
