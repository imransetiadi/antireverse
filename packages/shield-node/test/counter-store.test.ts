// Slice 08: the in-memory counter store. A sliding window as two fixed sub-windows, the previous one weighted by the
// share of it still inside the window; bounded; expired entries swept; a full table drops the oldest idle key and
// never refuses a hit; a clock that steps back neither resets a counter nor freezes it.
import { describe, expect, it } from "vitest";
import {
  COUNTER_KEYS_MAX,
  COUNTER_TIMESTAMPS_MAX,
  type CounterStore,
  EXACT_LIMIT_MAX,
  MemoryCounterStore,
} from "../src/counters.ts";

const W = 10_000;
const T0 = Date.parse("2026-11-11T08:00:00.000Z");

function hits(store: CounterStore, key: string, count: number, now: number, windowMs = W): number {
  let last = 0;
  for (let i = 0; i < count; i++) last = store.hit(key, windowMs, now);
  return last;
}

describe("MemoryCounterStore: counting", () => {
  it("counts the hits of one key and returns the count including the hit", () => {
    const store = new MemoryCounterStore();
    expect(store.hit("a", W, T0)).toBe(1);
    expect(store.hit("a", W, T0 + 1)).toBe(2);
    expect(store.hit("a", W, T0 + 2)).toBe(3);
    expect(store.peek("a", W, T0 + 3)).toBe(3);
    expect(store.hit("b", W, T0 + 3)).toBe(1);
    expect(store.size()).toBe(2);
  });

  it("peek counts nothing and creates nothing", () => {
    const store = new MemoryCounterStore();
    expect(store.peek("a", W, T0)).toBe(0);
    expect(store.size()).toBe(0);
    store.hit("a", W, T0);
    expect(store.peek("a", W, T0)).toBe(1);
    expect(store.peek("a", W, T0)).toBe(1);
  });

  it("a burst within one millisecond is counted hit by hit", () => {
    const store = new MemoryCounterStore();
    expect(hits(store, "a", 1_000, T0)).toBe(1_000);
  });

  it("at the window boundaries: full until the window ends, then weighted down to nothing after two windows", () => {
    const store = new MemoryCounterStore();
    hits(store, "a", 5, T0);
    expect(store.peek("a", W, T0 + W - 1)).toBe(5); // the last millisecond of the first sub-window
    expect(store.peek("a", W, T0 + W)).toBe(5); // the sub-window turned: all of the previous one still weighs
    expect(store.peek("a", W, T0 + W + 1)).toBe(4); // 5 × 0.9999 rounds down
    expect(store.peek("a", W, T0 + W + W / 2)).toBe(2); // 5 × 0.5
    expect(store.peek("a", W, T0 + 2 * W - 1)).toBe(0); // 5 × 0.0001
    expect(store.peek("a", W, T0 + 2 * W)).toBe(0);
    expect(store.hit("a", W, T0 + 2 * W)).toBe(1); // a new window starts with this hit
  });

  it("weighs the previous sub-window by the share of it that is still inside the window", () => {
    const store = new MemoryCounterStore();
    hits(store, "a", 4, T0);
    // A quarter into the second sub-window: 4 × 0.75 = 3 remain, plus the hit.
    expect(store.hit("a", W, T0 + W + W / 4)).toBe(4);
    expect(store.hit("a", W, T0 + W + W / 2)).toBe(4); // 4 × 0.5 + 2
    // The second sub-window (2 hits) becomes the previous one.
    expect(store.peek("a", W, T0 + 2 * W)).toBe(2);
    expect(store.peek("a", W, T0 + 2 * W + W / 2)).toBe(1);
  });

  it("never counts more than the hits of the last two windows, nor fewer than those of the running sub-window", () => {
    let seed = 0x9e3779b9;
    const random = (): number => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return (seed >>> 0) / 0x1_0000_0000;
    };
    const exact = new MemoryCounterStore();
    const times: number[] = [];
    let now = T0;
    for (let i = 0; i < 5_000; i++) {
      now += Math.floor(random() * (random() < 0.05 ? 3 * W : W / 20));
      const hit = random() < 0.7;
      const count = hit ? exact.hit("k", W, now) : exact.peek("k", W, now);
      if (hit) times.push(now);
      const lastTwoWindows = times.filter((at) => at > now - 2 * W).length;
      expect(count).toBeLessThanOrEqual(lastTwoWindows);
      if (hit) expect(count).toBeGreaterThanOrEqual(1);
    }
  });

  it("keeps each key apart and each key's window as it was given", () => {
    const store = new MemoryCounterStore();
    hits(store, "short", 3, T0, 1_000);
    hits(store, "long", 3, T0, 60_000);
    expect(store.peek("short", 1_000, T0 + 2_000)).toBe(0);
    expect(store.peek("long", 60_000, T0 + 2_000)).toBe(3);
  });
});

describe("MemoryCounterStore: the clock", () => {
  it("a clock that steps back keeps the count: nothing is reset", () => {
    const store = new MemoryCounterStore();
    hits(store, "a", 3, T0);
    expect(store.hit("a", W, T0 - 500)).toBe(4);
    expect(store.peek("a", W, T0 - 400)).toBe(4);
  });

  it("a clock that steps back by an hour does not freeze the counter: it clears two windows after the step", () => {
    const store = new MemoryCounterStore();
    hits(store, "a", 5, T0);
    const back = T0 - 3_600_000;
    expect(store.peek("a", W, back)).toBe(5);
    expect(store.peek("a", W, back + W - 1)).toBe(5);
    expect(store.peek("a", W, back + W + W / 2)).toBe(2);
    expect(store.peek("a", W, back + 2 * W)).toBe(0);
  });

  it.each([
    ["now is NaN", W, Number.NaN],
    ["now is infinite", W, Number.POSITIVE_INFINITY],
    ["the window is 0", 0, T0],
    ["the window is negative", -5, T0],
    ["the window is NaN", Number.NaN, T0],
  ])("counts nothing and never throws when %s", (_name, windowMs, now) => {
    const store = new MemoryCounterStore();
    expect(store.hit("a", windowMs, now)).toBe(0);
    expect(store.peek("a", windowMs, now)).toBe(0);
    expect(store.retryAfterMs("a", windowMs, 1, now)).toBe(0);
    expect(store.size()).toBe(0);
  });
});

describe("MemoryCounterStore: bounded", () => {
  it("holds at most 100,000 keys by default", () => {
    expect(COUNTER_KEYS_MAX).toBe(100_000);
    const store = new MemoryCounterStore();
    for (let i = 0; i <= COUNTER_KEYS_MAX; i++) {
      // A full table never refuses a hit: the new key is counted.
      if (store.hit(`k${i}`, 3_600_000, T0) !== 1) throw new Error(`hit ${i} was not counted`);
    }
    expect(store.size()).toBe(COUNTER_KEYS_MAX);
    expect(store.peek("k0", 3_600_000, T0)).toBe(0); // the oldest idle key went
    expect(store.peek("k1", 3_600_000, T0)).toBe(1);
    expect(store.peek(`k${COUNTER_KEYS_MAX}`, 3_600_000, T0)).toBe(1);
  });

  it("when full, drops the key that has been idle longest, not the one first created", () => {
    const store = new MemoryCounterStore({ maxKeys: 3 });
    store.hit("a", W, T0);
    store.hit("b", W, T0 + 1);
    store.hit("c", W, T0 + 2);
    store.hit("a", W, T0 + 3); // a is the most recently used now
    expect(store.hit("d", W, T0 + 4)).toBe(1);
    expect(store.size()).toBe(3);
    expect(store.peek("b", W, T0 + 4)).toBe(0);
    expect(store.peek("a", W, T0 + 4)).toBe(2);
    expect(store.peek("c", W, T0 + 4)).toBe(1);
  });

  it("a dropped key starts again from nothing: eviction never adds to a count", () => {
    const store = new MemoryCounterStore({ maxKeys: 2 });
    hits(store, "a", 9, T0);
    store.hit("b", W, T0);
    store.hit("c", W, T0); // drops a
    expect(store.hit("a", W, T0)).toBe(1);
  });

  it("sweeps expired entries while it is used", () => {
    const store = new MemoryCounterStore();
    for (let i = 0; i < 50; i++) store.hit(`old${i}`, W, T0);
    expect(store.size()).toBe(50);
    hits(store, "live", 40, T0 + 2 * W + 1);
    expect(store.size()).toBe(1);
    expect(store.peek("live", W, T0 + 2 * W + 1)).toBe(40);
  });

  it("sweeps a short window's expired entries that sit behind a long window's live one", () => {
    const store = new MemoryCounterStore();
    store.hit("long", 3_600_000, T0);
    for (let i = 0; i < 20; i++) store.hit(`short${i}`, 1_000, T0);
    hits(store, "live", 40, T0 + 5_000, 1_000);
    expect(store.size()).toBe(2);
    expect(store.peek("long", 3_600_000, T0 + 5_000)).toBe(1);
  });

  it("a full table costs the same per hit as an empty one: an eviction never walks the table", () => {
    // Found by the bench: dropping the first key of a JavaScript Map leaves a hole the next lookup of "the first
    // key" has to step over, so evicting from a Map alone grows with the table. 300,000 hits on new keys, each an
    // insert and an eviction, and as many on held keys, must stay far below a millisecond each.
    const store = new MemoryCounterStore();
    for (let i = 0; i < COUNTER_KEYS_MAX; i++) store.hit(`warm${i}`, 3_600_000, T0);
    const started = performance.now();
    for (let i = 0; i < 300_000; i++) {
      store.hit(`new${i}`, 3_600_000, T0 + i);
      store.hit(`new${i - (i % 7)}`, 3_600_000, T0 + i);
    }
    const perHitMs = (performance.now() - started) / 600_000;
    expect(store.size()).toBe(COUNTER_KEYS_MAX);
    expect(perHitMs).toBeLessThan(0.01);
  });

  it("an unusable maxKeys falls back to the default", () => {
    for (const maxKeys of [0, -1, 1.5, Number.NaN, 200_000]) {
      const store = new MemoryCounterStore({ maxKeys });
      expect(store.maxKeys).toBe(COUNTER_KEYS_MAX);
    }
    expect(new MemoryCounterStore({ maxKeys: 7 }).maxKeys).toBe(7);
  });
});

describe("MemoryCounterStore: how long until the count is below a limit", () => {
  it("is 0 for a key below the limit and for a key it does not hold", () => {
    const store = new MemoryCounterStore();
    expect(store.retryAfterMs("a", W, 5, T0)).toBe(0);
    hits(store, "a", 4, T0);
    expect(store.retryAfterMs("a", W, 5, T0)).toBe(0);
  });

  it("a key at its limit in the running sub-window waits for the window to turn", () => {
    const store = new MemoryCounterStore();
    hits(store, "a", 5, T0);
    const wait = store.retryAfterMs("a", W, 5, T0 + 1_000);
    expect(wait).toBe(W - 1_000);
    expect(store.peek("a", W, T0 + 1_000 + wait)).toBe(5);
    expect(store.peek("a", W, T0 + 1_000 + wait + 1)).toBe(4);
  });

  it("is exact to the millisecond on generated states: afterwards the count is below the limit, and not before", () => {
    let seed = 0x2545f491;
    const random = (): number => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return (seed >>> 0) / 0x1_0000_0000;
    };
    let checked = 0;
    for (let round = 0; round < 400; round++) {
      const store = new MemoryCounterStore();
      const limit = 1 + Math.floor(random() * 12);
      let now = T0;
      const steps = 1 + Math.floor(random() * 40);
      for (let i = 0; i < steps; i++) {
        now += Math.floor(random() * (W / 4));
        store.hit("k", W, now);
      }
      now += Math.floor(random() * W);
      const count = store.peek("k", W, now);
      const wait = store.retryAfterMs("k", W, limit, now);
      if (count < limit) {
        expect(wait).toBe(0);
        continue;
      }
      checked += 1;
      expect(wait).toBeGreaterThan(0);
      expect(wait).toBeLessThanOrEqual(2 * W);
      // To the millisecond (the wait is a floating-point number): two milliseconds before its end the count is still
      // at the limit, one millisecond after it the count is below. Peek only moves forward, so look before first.
      const at = now + Math.ceil(wait);
      if (at - 2 >= now) expect(store.peek("k", W, at - 2)).toBeGreaterThanOrEqual(limit);
      expect(store.peek("k", W, at + 1)).toBeLessThan(limit);
    }
    expect(checked).toBeGreaterThan(50);
  });
});

// --- Amendment A7 F2: an exact sliding log for limits up to 1,000 --------------------------------------------------

/** The hits of `times` inside the real window ending at `now`: what an exact sliding window counts. */
const inWindow = (times: number[], now: number, windowMs: number): number =>
  times.filter((at) => now - at < windowMs).length;

describe("MemoryCounterStore: the exact log (A7 F2)", () => {
  it("is used for limits from 1 to 1,000; above, and without a limit, the weighted sub-windows", () => {
    expect(EXACT_LIMIT_MAX).toBe(1_000);
    const store = new MemoryCounterStore();
    hits(store, "a", 5, T0);
    // Weighted (no limit given): a quarter into the second sub-window 5 × 0.75 remain.
    expect(store.peek("a", W, T0 + W + W / 4)).toBe(3);
    // Exact: the hits at T0 are out of the window once W has passed.
    for (let i = 0; i < 5; i++) store.hit("b", W, T0, 10);
    expect(store.peek("b", W, T0 + W - 1, 10)).toBe(5);
    expect(store.peek("b", W, T0 + W, 10)).toBe(0);
  });

  it("t3b F: a burst at the end of a window cannot be followed by another at the start of the next", () => {
    // The reviewer's scenario (limit 10 per 60 s): one request at 0, a burst of 20 at 59.9 s, then one every 0.1 s
    // to 119.8 s; requests are counted only when admitted (count + 1 <= limit).
    const store = new MemoryCounterStore();
    const accepted: number[] = [];
    const go = (at: number): void => {
      if (store.peek("k", 60_000, T0 + at, 10) + 1 <= 10) {
        store.hit("k", 60_000, T0 + at, 10);
        accepted.push(at);
      }
    };
    go(0);
    for (let i = 0; i < 20; i++) go(59_900);
    for (let t = 60_000; t <= 119_800; t += 100) go(t);
    let worst = 0;
    for (const a of accepted) worst = Math.max(worst, accepted.filter((x) => x >= a && x < a + 60_000).length);
    expect(worst).toBeLessThanOrEqual(10);
    expect(accepted.length).toBeGreaterThan(10);
  });

  it("t4 I: a client that sends 10 every 61 s under 10 per 60 s is never refused", () => {
    const store = new MemoryCounterStore();
    for (let round = 0; round < 6; round++) {
      for (let i = 0; i < 10; i++) {
        const now = T0 + round * 61_000;
        expect(store.peek("k", 60_000, now, 10) + 1).toBeLessThanOrEqual(10);
        store.hit("k", 60_000, now, 10);
      }
    }
  });

  it("counts exactly on generated sequences, up to one past the limit", () => {
    let seed = 0x51ed27;
    const random = (): number => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return (seed >>> 0) / 0x1_0000_0000;
    };
    for (let round = 0; round < 50; round++) {
      const limit = 1 + Math.floor(random() * 20);
      const store = new MemoryCounterStore();
      const times: number[] = [];
      let now = T0;
      for (let i = 0; i < 300; i++) {
        now += Math.floor(random() * (W / 5));
        if (random() < 0.6) {
          const count = store.hit("k", W, now, limit);
          times.push(now);
          expect(count).toBe(Math.min(inWindow(times, now, W), limit + 1));
        } else {
          expect(store.peek("k", W, now, limit)).toBe(Math.min(inWindow(times, now, W), limit + 1));
        }
      }
    }
  });

  it("how long until below the limit: from the oldest timestamp that still counts, exact to the millisecond", () => {
    const store = new MemoryCounterStore();
    store.hit("k", W, T0, 3);
    store.hit("k", W, T0 + 1_000, 3);
    store.hit("k", W, T0 + 2_000, 3);
    store.hit("k", W, T0 + 3_000, 3); // over: 4 in the window
    // Below 3 once two have left: the one at T0 + 1,000 leaves at T0 + 11,000.
    expect(store.retryAfterMs("k", W, 3, T0 + 5_000)).toBe(6_000);
    expect(store.peek("k", W, T0 + 10_999, 3)).toBe(3);
    expect(store.peek("k", W, T0 + 11_000, 3)).toBe(2);
    expect(store.retryAfterMs("k", W, 3, T0 + 11_000)).toBe(0);
  });

  it("a clock that steps back keeps the hits and lets them leave a window after the step", () => {
    const store = new MemoryCounterStore();
    for (let i = 0; i < 3; i++) store.hit("k", W, T0, 3);
    const back = T0 - 365 * 86_400_000;
    expect(store.peek("k", W, back, 3)).toBe(3);
    expect(store.peek("k", W, back + W - 1, 3)).toBe(3);
    expect(store.peek("k", W, back + W, 3)).toBe(0);
  });

  it("a limit that changes on a held key keeps the count it can", () => {
    const store = new MemoryCounterStore();
    for (let i = 0; i < 8; i++) store.hit("k", W, T0, 10);
    expect(store.peek("k", W, T0 + 1, 5)).toBe(6); // a smaller log: one past the limit at most
    expect(store.peek("k", W, T0 + 1, 2_000)).toBeGreaterThanOrEqual(6); // weighted from the log
    expect(store.peek("k", W, T0 + 2, 10)).toBeGreaterThanOrEqual(6);
  });

  it("memory is bounded: at most 2,000,000 timestamps in all, the key idle longest gives way", () => {
    expect(COUNTER_TIMESTAMPS_MAX).toBe(2_000_000);
    const store = new MemoryCounterStore({ maxTimestamps: 3_000 });
    // 10 keys of 1,000 hits each would need 10,010 slots.
    for (let k = 0; k < 10; k++) for (let i = 0; i < 1_000; i++) store.hit(`k${k}`, 3_600_000, T0 + i, 1_000);
    expect(store.timestamps()).toBeLessThanOrEqual(3_000);
    expect(store.peek("k9", 3_600_000, T0 + 1_000, 1_000)).toBe(1_000);
    expect(store.peek("k0", 3_600_000, T0 + 1_000, 1_000)).toBe(0);
    // A hit is never refused for it.
    expect(store.hit("new", 3_600_000, T0 + 2_000, 1_000)).toBe(1);
  });
});

describe("MemoryCounterStore: a key that is looked at is in use (A7 F8)", () => {
  it("t4 J: a refused client that keeps asking keeps its counter while other keys fill the table", () => {
    const store = new MemoryCounterStore({ maxKeys: 1_000 });
    for (let i = 0; i < 3; i++) store.hit("attacker", W, T0, 3);
    for (let i = 0; i < 1_000; i++) {
      store.hit(`other${i}`, W, T0, 3);
      if (i % 100 === 99) expect(store.peek("attacker", W, T0, 3)).toBe(3); // refused, and looked at
    }
    expect(store.peek("attacker", W, T0, 3)).toBe(3);
    expect(store.size()).toBe(1_000);
  });
});
