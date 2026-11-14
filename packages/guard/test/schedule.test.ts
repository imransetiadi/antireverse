import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createGuard, type GuardFetch } from "../src/index.js";
import {
  APP_ID,
  ATTEST_URL,
  cleanNavigator,
  ENDPOINT,
  fakeService,
  memoryStorage,
  response,
  spyCrypto,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-11T08:00:00.000Z");

function setup(opts: { ttlS?: number; fetch?: GuardFetch } = {}) {
  const service = fakeService({ nowMs: () => Date.now(), ...(opts.ttlS === undefined ? {} : { ttlS: opts.ttlS }) });
  const guard = createGuard({
    appId: APP_ID,
    endpoint: ENDPOINT,
    fetch: opts.fetch ?? service.fetch,
    crypto: spyCrypto().crypto,
    storage: memoryStorage(),
    navigator: cleanNavigator(),
    now: () => Date.now(),
  });
  return { guard, service };
}

beforeEach(() => {
  vi.useFakeTimers({ now: T0, toFake: ["setTimeout", "clearTimeout", "Date"] });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("re-attest", () => {
  it("re-attests 60 s before expiry, and again after that", async () => {
    const { guard, service } = setup();
    const first = await guard.attest();
    expect(service.challenges()).toBe(1);

    await vi.advanceTimersByTimeAsync(240_000 - 1);
    expect(service.challenges()).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(service.challenges()).toBe(2);
    expect(service.requests).toHaveLength(4); // the re-attest completed
    const second = guard.token();
    expect(second).not.toBeNull();
    expect(second).not.toBe(first);

    await vi.advanceTimersByTimeAsync(240_000);
    expect(service.challenges()).toBe(3);
    guard.stop();
  });

  it("keeps sending the current token while a re-attest is in flight", async () => {
    const service = fakeService();
    let release: (() => void) | undefined;
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => {
        if (service.challenges() >= 1 && url !== ATTEST_URL) await new Promise<void>((resolve) => (release = resolve));
        return service.fetch(url, init);
      }),
    });
    const first = await guard.attest();
    await vi.advanceTimersByTimeAsync(240_000); // the re-attest starts and waits on its challenge
    expect(release).toBeDefined();
    expect(guard.headers()).toEqual({ "ar-attestation": first });
    release?.();
    const second = await guard.attest(); // joins the re-attest
    expect(second).not.toBeNull();
    expect(second).not.toBe(first);
    expect(guard.headers()).toEqual({ "ar-attestation": second });
    guard.stop();
  });

  it("an explicit attest replaces the pending re-attest instead of adding one", async () => {
    const { guard, service } = setup();
    await guard.attest();
    await vi.advanceTimersByTimeAsync(100_000);
    await guard.attest();
    expect(service.challenges()).toBe(2);
    await vi.advanceTimersByTimeAsync(239_000); // 339 s after the first: its timer must be gone
    expect(service.challenges()).toBe(2);
    await vi.advanceTimersByTimeAsync(1_000); // 240 s after the second
    expect(service.challenges()).toBe(3);
    await guard.attest();
    guard.stop();
  });

  it("does not hammer the API when the client clock is ahead of the token's expiry", async () => {
    const service = fakeService({ nowMs: () => Date.now() - 600_000 }); // the API's clock is 10 minutes behind
    const { guard } = setup({ fetch: service.fetch });
    expect(await guard.attest()).not.toBeNull();
    await vi.advanceTimersByTimeAsync(29_999);
    expect(service.challenges()).toBe(1);
    guard.stop();
  });

  it("re-attests within the token's lifetime when the client clock is behind", async () => {
    const service = fakeService({ nowMs: () => Date.now() + 3_600_000 }); // the API's clock is an hour ahead
    const { guard } = setup({ fetch: service.fetch });
    await guard.attest();
    await vi.advanceTimersByTimeAsync(240_000);
    expect(service.challenges()).toBe(2);
    await guard.attest();
    guard.stop();
  });

  it("token() returns null once the token has expired locally", async () => {
    const service = fakeService();
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => {
        if (service.challenges() >= 1 && url !== ATTEST_URL) return response(503, {});
        return service.fetch(url, init);
      }),
    });
    expect(await guard.attest()).not.toBeNull();
    await vi.advanceTimersByTimeAsync(240_000); // the re-attest fails
    await guard.attest();
    expect(guard.token()).toBeNull();
    expect(guard.headers()).toEqual({});
    guard.stop();
  });
});

describe("stop()", () => {
  it("cancels the pending re-attest", async () => {
    const { guard, service } = setup();
    await guard.attest();
    guard.stop();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(service.challenges()).toBe(1);
    expect(guard.token()).toBeNull(); // expired by now; nothing renewed it
  });

  it("an attest in flight when stop() is called schedules nothing", async () => {
    const { guard, service } = setup();
    const pending = guard.attest();
    guard.stop();
    expect(await pending).not.toBeNull();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(service.challenges()).toBe(1);
  });

  it("cancels a scheduled start", async () => {
    vi.stubGlobal("requestIdleCallback", undefined);
    const { guard, service } = setup();
    guard.start();
    guard.stop();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(service.fetch).not.toHaveBeenCalled();
  });
});

describe("start()", () => {
  it("runs the first attest in idle time through requestIdleCallback", async () => {
    const callbacks: Array<() => void> = [];
    const requestIdleCallback = vi.fn((callback: () => void, _options?: { timeout: number }) => {
      callbacks.push(callback);
      return 7;
    });
    const cancelIdleCallback = vi.fn();
    vi.stubGlobal("requestIdleCallback", requestIdleCallback);
    vi.stubGlobal("cancelIdleCallback", cancelIdleCallback);
    const { guard, service } = setup();
    guard.start();
    guard.start(); // idempotent while scheduled
    expect(requestIdleCallback).toHaveBeenCalledTimes(1);
    expect(requestIdleCallback.mock.calls[0]?.[1]).toEqual({ timeout: expect.any(Number) });
    expect(service.fetch).not.toHaveBeenCalled();
    callbacks[0]?.();
    expect(await guard.attest()).not.toBeNull(); // joins the started one
    expect(service.challenges()).toBe(1);
    guard.stop();
  });

  it("stop() cancels a pending idle callback", () => {
    const cancelIdleCallback = vi.fn();
    vi.stubGlobal(
      "requestIdleCallback",
      vi.fn(() => 7),
    );
    vi.stubGlobal("cancelIdleCallback", cancelIdleCallback);
    const { guard } = setup();
    guard.start();
    guard.stop();
    expect(cancelIdleCallback).toHaveBeenCalledWith(7);
  });

  it("calls requestIdleCallback and cancelIdleCallback with globalThis as receiver (else Illegal invocation)", () => {
    const receivers: unknown[] = [];
    vi.stubGlobal("requestIdleCallback", function (this: unknown) {
      if (this !== globalThis) throw new TypeError("Illegal invocation");
      receivers.push(this);
      return 7;
    });
    vi.stubGlobal("cancelIdleCallback", function (this: unknown) {
      if (this !== globalThis) throw new TypeError("Illegal invocation");
      receivers.push(this);
    });
    const { guard } = setup();
    guard.start();
    guard.stop();
    expect(receivers).toEqual([globalThis, globalThis]);
  });

  it("falls back to setTimeout 0 without requestIdleCallback", async () => {
    vi.stubGlobal("requestIdleCallback", undefined);
    const { guard, service } = setup();
    guard.start();
    expect(service.fetch).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(0);
    expect(service.challenges()).toBe(1);
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
  });

  it("never throws, even when scheduling throws", () => {
    vi.stubGlobal("requestIdleCallback", () => {
      throw new Error("nope");
    });
    const { guard } = setup();
    expect(() => guard.start()).not.toThrow();
    expect(() => guard.stop()).not.toThrow();
  });
});

describe("request timeout", () => {
  /** A fetch that never settles, recording each init it was given. */
  function hanging() {
    const inits: Parameters<GuardFetch>[1][] = [];
    const fetch = vi.fn<GuardFetch>((_url, init) => {
      inits.push(init);
      return new Promise(() => {});
    });
    return { fetch, inits };
  }

  /** Resolves true when the promise settles within the current fake time (after flushing microtasks). */
  async function settled(promise: Promise<unknown>) {
    let done = false;
    void promise.then(() => (done = true));
    await vi.advanceTimersByTimeAsync(0);
    return done;
  }

  it("a challenge that never answers settles as null after 10 s, aborting the request; a later attest succeeds", async () => {
    const service = fakeService();
    const hang = hanging();
    let down = true;
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>((url, init) => (down ? hang.fetch(url, init) : service.fetch(url, init))),
    });
    const pending = guard.attest();
    await vi.advanceTimersByTimeAsync(9_999);
    expect(await settled(pending)).toBe(false);
    expect(hang.inits[0]?.signal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await pending).toBeNull();
    expect(hang.inits[0]?.signal?.aborted).toBe(true);
    expect(guard.token()).toBeNull();

    down = false;
    expect(await guard.attest()).not.toBeNull(); // the in-flight promise was cleared
    guard.stop();
  });

  it("an attest call that never answers settles as null after 10 s", async () => {
    const service = fakeService();
    const hang = hanging();
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>((url, init) => (url === ATTEST_URL ? hang.fetch(url, init) : service.fetch(url, init))),
    });
    const pending = guard.attest();
    // The session key is generated by real WebCrypto between the two calls: wait (in real time) for the attest call.
    while (hang.inits.length === 0) await new Promise((resolve) => setImmediate(resolve));
    await vi.advanceTimersByTimeAsync(9_999);
    expect(await settled(pending)).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await pending).toBeNull();
    expect(hang.inits[0]?.signal?.aborted).toBe(true);
    guard.stop();
  });

  it("a body that never arrives (json() hangs) also times out", async () => {
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async () => ({ ok: true, status: 200, json: () => new Promise(() => {}) })),
    });
    const pending = guard.attest();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(await pending).toBeNull();
    guard.stop();
  });

  it("without AbortController, a timer race still settles the request as null after 10 s", async () => {
    vi.stubGlobal("AbortController", undefined);
    const hang = hanging();
    const { guard } = setup({ fetch: hang.fetch });
    const pending = guard.attest();
    await vi.advanceTimersByTimeAsync(9_999);
    expect(await settled(pending)).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await pending).toBeNull();
    expect(hang.inits[0]).not.toHaveProperty("signal");
    guard.stop();
  });

  it("leaves no timer behind once a request answers", async () => {
    const { guard } = setup();
    await guard.attest();
    expect(vi.getTimerCount()).toBe(2); // the re-attest, and the integrity collector's one start (slice 21b)
    guard.stop();
    expect(vi.getTimerCount()).toBe(0);
  });
});
