import { EventBatchSchema, EXAMPLE_SHIELD_EVENT, LIMITS, type ShieldEvent } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createEmitter, type EmitterOptions } from "../src/emitter.ts";
import { SDK_NAME, SDK_VERSION, SHIELD_DEFAULTS, type Transport } from "../src/types.ts";

const KEY = generateKey("shield", "development").key;
const ENDPOINT = "http://ingest.test";

type Sent = Parameters<Transport>[0];

/** A valid Event whose `latency_ms` is its sequence number, so tests can read the order back. */
function event(n: number, route = "/api/products/:id"): ShieldEvent {
  return { ...EXAMPLE_SHIELD_EVENT, request: { ...EXAMPLE_SHIELD_EVENT.request, route, latency_ms: n } };
}

function sequence(sent: Sent): number[] {
  return EventBatchSchema.parse(JSON.parse(sent.body ?? "")).events.map((e) => e.request.latency_ms);
}

interface Harness {
  emitter: ReturnType<typeof createEmitter>;
  calls: Sent[];
  /** Milliseconds of the fake clock at each transport call. */
  times: number[];
  warnings: string[];
}

/** `respond` decides the outcome of the n-th transport call (0-based): a status, or an Error to reject with. */
function harness(
  respond: (call: number) => number | Error = () => 202,
  overrides: Partial<EmitterOptions> = {},
): Harness {
  const calls: Sent[] = [];
  const times: number[] = [];
  const warnings: string[] = [];
  const transport: Transport = async (request) => {
    const outcome = respond(calls.length);
    calls.push(request);
    times.push(Date.now());
    if (outcome instanceof Error) throw outcome;
    return { status: outcome };
  };
  const emitter = createEmitter({
    ...SHIELD_DEFAULTS,
    key: KEY,
    endpoint: ENDPOINT,
    transport,
    now: () => Date.now(),
    warn: (condition) => warnings.push(condition),
    ...overrides,
  });
  return { emitter, calls, times, warnings };
}

const unhandled: unknown[] = [];
const onUnhandled = (reason: unknown): void => {
  unhandled.push(reason);
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-11-10T08:00:00.000Z"));
  vi.spyOn(Math, "random").mockReturnValue(0); // no jitter unless a test asks for it
  unhandled.length = 0;
  process.on("unhandledRejection", onUnhandled);
});

afterEach(async () => {
  await vi.advanceTimersByTimeAsync(0);
  process.off("unhandledRejection", onUnhandled);
  vi.restoreAllMocks();
  vi.useRealTimers();
  expect(unhandled).toEqual([]);
});

describe("defaults", () => {
  it("are the documented Shield defaults", () => {
    expect(SHIELD_DEFAULTS).toEqual({
      flushIntervalMs: 1_000,
      maxBatchSize: 100,
      maxBufferSize: 10_000,
      requestTimeoutMs: 5_000,
    });
  });
});

describe("emitter: batching", () => {
  it("sends nothing before the flush interval, then one request to {endpoint}/v1/events", async () => {
    const { emitter, calls } = harness();
    emitter.record(event(1));
    await vi.advanceTimersByTimeAsync(999);
    expect(calls).toHaveLength(0);
    expect(emitter.stats().buffered).toBe(1);

    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(1);
    const sent = calls[0] as Sent;
    expect(sent.url).toBe("http://ingest.test/v1/events");
    expect(sent.headers).toEqual({ authorization: `Bearer ${KEY}`, "content-type": "application/json" });
    const batch = EventBatchSchema.parse(JSON.parse(sent.body ?? ""));
    expect(batch.protocol).toBe(1);
    expect(batch.sdk).toEqual({ name: SDK_NAME, version: SDK_VERSION });
    expect(batch.events).toEqual([event(1)]);
    expect(emitter.stats()).toMatchObject({ buffered: 0, sent: 1, dropped: 0, failedBatches: 0, lastError: null });
  });

  it("joins the endpoint and the path with exactly one slash", async () => {
    const { emitter, calls } = harness(() => 202, { endpoint: "http://ingest.test/base/" });
    emitter.record(event(1));
    await emitter.flush();
    expect(calls[0]?.url).toBe("http://ingest.test/base/v1/events");
  });

  it("is idle without Events: no timer exists until the first Event is recorded", async () => {
    const { emitter, calls } = harness();
    expect(vi.getTimerCount()).toBe(0);
    emitter.record(event(1));
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(calls).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("sends 250 buffered Events as three requests of 100, 100 and 50, in order", async () => {
    const { emitter, calls } = harness();
    for (let i = 0; i < 250; i++) emitter.record(event(i));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(calls.map((c) => sequence(c).length)).toEqual([100, 100, 50]);
    expect(calls.flatMap(sequence)).toEqual(Array.from({ length: 250 }, (_, i) => i));
    expect(emitter.stats()).toMatchObject({ buffered: 0, sent: 250 });
  });

  it("keeps the newest Events when the buffer overflows and counts the drops", async () => {
    const { emitter, calls } = harness(() => 202, { maxBufferSize: 10 });
    for (let i = 0; i < 15; i++) emitter.record(event(i));
    expect(emitter.stats()).toMatchObject({ buffered: 10, dropped: 5 });
    await emitter.flush();
    expect(calls.flatMap(sequence)).toEqual([5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
  });

  it("keeps every request body well under the ingest limit, whatever the batch size", async () => {
    const { emitter, calls } = harness(() => 202, { maxBatchSize: 500 });
    const longRoute = `/${"é".repeat(255)}`; // 256 characters, 511 bytes
    for (let i = 0; i < 500; i++) emitter.record(event(i, longRoute));
    await emitter.flush();
    expect(calls.length).toBeGreaterThan(1);
    for (const call of calls) expect(Buffer.byteLength(call.body ?? "")).toBeLessThan(LIMITS.bodyBytesMax * 0.8);
    expect(calls.flatMap(sequence)).toEqual(Array.from({ length: 500 }, (_, i) => i));
  });

  it("never sends more than the protocol's batch maximum in one request", async () => {
    const { emitter, calls } = harness(() => 202, { maxBatchSize: 5_000 });
    for (let i = 0; i < 1_200; i++) emitter.record(event(i, "/"));
    await emitter.flush();
    for (const call of calls) expect(sequence(call).length).toBeLessThanOrEqual(LIMITS.batchMax);
    expect(calls.flatMap(sequence)).toHaveLength(1_200);
  });
});

describe("emitter: failures", () => {
  it("attempts a batch 3 times with backoff 500 ms and 1,000 ms, then drops it", async () => {
    const { emitter, calls, times, warnings } = harness(() => new Error("connect ECONNREFUSED"));
    const t0 = Date.now();
    emitter.record(event(1));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(times.map((t) => t - t0)).toEqual([1_000, 1_500, 2_500]);
    expect(calls.map(sequence)).toEqual([[1], [1], [1]]);
    expect(emitter.stats()).toMatchObject({ buffered: 0, sent: 0, failedBatches: 1 });
    expect(emitter.stats().lastError).toEqual(expect.any(String));
    expect(warnings).toEqual(["unreachable"]);
  });

  it("waits 2,000 ms after a dropped batch before it tries the next one", async () => {
    const { emitter, times } = harness(() => new Error("connect ECONNREFUSED"));
    const t0 = Date.now();
    for (let i = 0; i < 150; i++) emitter.record(event(i));
    await vi.advanceTimersByTimeAsync(10_000);
    expect(times.map((t) => t - t0)).toEqual([1_000, 1_500, 2_500, 4_500, 5_000, 6_000]);
    expect(emitter.stats()).toMatchObject({ buffered: 0, failedBatches: 2 });
  });

  it("adds jitter to the backoff", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0.999);
    const { emitter, times } = harness(() => new Error("socket hang up"));
    const t0 = Date.now();
    emitter.record(event(1));
    await vi.advanceTimersByTimeAsync(60_000);
    const [first, second, third] = times.map((t) => t - t0) as [number, number, number];
    expect(first).toBe(1_000);
    expect(second - first).toBeGreaterThan(500);
    expect(second - first).toBeLessThanOrEqual(750);
    expect(third - second).toBeGreaterThan(1_000);
    expect(third - second).toBeLessThanOrEqual(1_500);
  });

  it.each([500, 503, 429])("retries a %i response", async (status) => {
    const { emitter, calls } = harness((call) => (call === 0 ? status : 202));
    emitter.record(event(1));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(500);
    expect(calls).toHaveLength(2);
    expect(emitter.stats()).toMatchObject({ sent: 1, failedBatches: 0, buffered: 0 });
  });

  it.each([400, 404, 413])("drops a batch answered with %i without a retry and carries on", async (status) => {
    const { emitter, calls, warnings } = harness((call) => (call === 0 ? status : 202));
    for (let i = 0; i < 150; i++) emitter.record(event(i));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls.map((c) => sequence(c).length)).toEqual([100, 50]);
    // The 100 Events of the refused batch are counted as dropped, and the host is told once (review F7):
    // a wrong `endpoint` must not fail silently.
    expect(emitter.stats()).toMatchObject({ sent: 50, failedBatches: 1, buffered: 0, dropped: 100 });
    expect(emitter.stats().lastError).toContain(String(status));
    expect(warnings).toEqual(["rejected"]);
  });

  it.each([401, 403])("after a %i pauses sending for 60,000 ms and sets lastError", async (status) => {
    const { emitter, calls, times, warnings } = harness((call) => (call === 0 ? status : 202));
    const t0 = Date.now();
    emitter.record(event(1));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(calls).toHaveLength(1);
    expect(emitter.stats().lastError).toContain(String(status));
    expect(emitter.stats().failedBatches).toBe(1);
    expect(warnings).toEqual(["unauthorized"]);

    emitter.record(event(2));
    await emitter.flush(); // an explicit flush does not break the pause either
    await vi.advanceTimersByTimeAsync(59_999);
    expect(calls).toHaveLength(1);
    expect(emitter.stats().buffered).toBe(1);

    await vi.advanceTimersByTimeAsync(1_001);
    expect(calls).toHaveLength(2);
    expect((times[1] as number) - t0).toBeGreaterThanOrEqual(61_000);
    expect(sequence(calls[1] as Sent)).toEqual([2]);
    expect(emitter.stats()).toMatchObject({ sent: 1, buffered: 0 });
  });

  it("never puts the key into lastError", async () => {
    const { emitter } = harness(() => new Error(`request with Bearer ${KEY} failed`));
    emitter.record(event(1));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(emitter.stats().lastError).toEqual(expect.any(String));
    expect(emitter.stats().lastError).not.toContain(KEY);
    expect(emitter.stats().lastError).not.toContain(KEY.slice(-20));
  });

  it("passes requestTimeoutMs to the transport as timeoutMs", async () => {
    const { emitter, calls } = harness(() => 202, { requestTimeoutMs: 1_234 });
    emitter.record(event(1));
    await emitter.flush();
    expect(calls[0]?.timeoutMs).toBe(1_234);
  });

  it("flush() never rejects: a transport that throws synchronously or answers nonsense counts as a failure", async () => {
    const throwing = harness(() => 202, {
      transport: () => {
        throw new Error("exploded before returning a promise");
      },
    });
    throwing.emitter.record(event(1));
    const first = throwing.emitter.flush();
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(first).resolves.toBeUndefined();
    expect(throwing.emitter.stats().failedBatches).toBe(1);

    const nonsense = harness(() => 202, { transport: (() => undefined) as unknown as Transport });
    nonsense.emitter.record(event(1));
    const second = nonsense.emitter.flush();
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(second).resolves.toBeUndefined();
    expect(nonsense.emitter.stats().failedBatches).toBe(1);
  });

  it("stays bounded while ingest is down and the host is busy", async () => {
    const { emitter } = harness(() => new Error("connect ECONNREFUSED"));
    for (let round = 0; round < 50; round++) {
      for (let i = 0; i < 1_000; i++) emitter.record(event(i));
      await vi.advanceTimersByTimeAsync(700);
      expect(emitter.stats().buffered).toBeLessThanOrEqual(SHIELD_DEFAULTS.maxBufferSize);
    }
    expect(emitter.stats().dropped).toBeGreaterThan(0);
    await emitter.close();
    const stats = emitter.stats();
    expect(stats.sent).toBe(0);
    expect(stats.buffered).toBe(0);
    expect(stats.failedBatches).toBeGreaterThan(5);
    // every Event is accounted for as dropped: lost to the full buffer, or part of a batch that was given up
    expect(stats.dropped).toBe(50_000);
  });
});

describe("emitter: flush and close", () => {
  it("flush() sends everything buffered without waiting for the interval", async () => {
    const { emitter, calls } = harness();
    for (let i = 0; i < 250; i++) emitter.record(event(i));
    await emitter.flush();
    expect(calls.flatMap(sequence)).toHaveLength(250);
    expect(emitter.stats()).toMatchObject({ buffered: 0, sent: 250 });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("flush() with nothing buffered resolves and sends nothing", async () => {
    const { emitter, calls } = harness();
    await expect(emitter.flush()).resolves.toBeUndefined();
    expect(calls).toHaveLength(0);
  });

  it("close() flushes and stops the timer; recording afterwards does nothing", async () => {
    const { emitter, calls } = harness();
    emitter.record(event(1));
    emitter.record(event(2));
    expect(vi.getTimerCount()).toBe(1);
    await emitter.close();
    expect(calls.flatMap(sequence)).toEqual([1, 2]);
    expect(vi.getTimerCount()).toBe(0);

    emitter.record(event(3));
    expect(emitter.stats().buffered).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
    await emitter.flush();
    await emitter.close(); // closing twice is harmless
    await vi.advanceTimersByTimeAsync(10_000);
    expect(calls).toHaveLength(1);
  });

  it("close() does not wait through retries when ingest is down: one attempt, the rest is counted as dropped", async () => {
    const { emitter, calls } = harness(() => new Error("connect ECONNREFUSED"));
    for (let i = 0; i < 250; i++) emitter.record(event(i));
    await emitter.close(); // resolves without any timer being advanced
    expect(calls).toHaveLength(1);
    expect(emitter.stats()).toMatchObject({ buffered: 0, sent: 0, failedBatches: 1, dropped: 250 });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("close() during a backoff wait ends the wait", async () => {
    const { emitter, calls } = harness(() => new Error("connect ECONNREFUSED"));
    emitter.record(event(1));
    await vi.advanceTimersByTimeAsync(1_100); // first attempt failed, waiting 500 ms
    expect(calls).toHaveLength(1);
    await emitter.close();
    expect(emitter.stats()).toMatchObject({ buffered: 0, failedBatches: 1 });
    expect(vi.getTimerCount()).toBe(0);
  });
});
