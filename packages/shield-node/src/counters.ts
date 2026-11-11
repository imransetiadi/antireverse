// Counters of limit Rules (slice 08): how many requests, or failed responses, one key has in a sliding window.
//
// The store is an interface so that a shared store can replace the in-memory one later. In this slice it is
// synchronous: Shield calls it on the request path, where nothing may wait.
//
// `MemoryCounterStore` keeps one of two kinds of counter per key, chosen by the limit the caller holds the key to
// (amendment A7, F2):
//
// - **An exact log** for a limit from 1 to `EXACT_LIMIT_MAX` (1,000): the times of the last `limit + 1` hits, in a
//   ring. The count at `now` is the number of those hits less than `windowMs` ago — exactly what a sliding window
//   holds, up to one past the limit (all a caller needs to tell "over"). So no real window of `windowMs` ever holds
//   more admitted requests than the limit, and a client that keeps to the limit is never refused. How long until the
//   count is below the limit is read from the hit that must leave first: the `limit`-th most recent.
// - **Weighted sub-windows** above that, or when no limit is given: two fixed sub-windows of `windowMs`, the count at
//   `now` being `current + previous × (1 − elapsed / windowMs)` rounded down. Two numbers per key whatever the limit;
//   it never counts more than the hits of the last two windows nor fewer than those of the running sub-window, and
//   lets a burst at the end of one window be followed by part of another at the start of the next (the Console says
//   "about" for such limits).
//
// A key whose limit changes keeps what it can: a log cut to its newest hits, a log read as a weighted count, or a
// weighted count turned into that many hits at `now` (it can only last longer, never less).
//
// Bounded, in two ways, both in order of last use (a hit or a look at the key, so that a client that keeps asking
// while it is refused keeps its counter — F8):
// - at most `maxKeys` keys (100,000): a new key on a full table drops the key idle longest;
// - at most `maxTimestamps` hit times in all logs together (2,000,000; a ring grows as its key is hit, up to
//   `limit + 1`): a ring that would pass it drops the keys idle longest first.
// A full table never refuses a hit: the dropped key simply starts again from nothing (it can only under-count: fail
// open). Expired keys (nothing left to count) are swept a few at a time on every hit, so no timer is needed and no
// hit pays for the whole table. The worst case at 100,000 keys: the keys and their entries (about 40 MB of heap
// measured by the review's t4.ts K) plus 2,000,000 × 8 bytes of hit times (16 MB) — under 60 MB, whatever the
// traffic.
//
// A clock that steps back does not reset a counter (that would be a way around a limit) and does not freeze it
// either: hit times ahead of the clock are brought back to it, and the running sub-window is re-based to it, so the
// counts leave over the window (the two windows) after the step. A clock or a window that is not a usable number
// counts nothing.

/** Keys `MemoryCounterStore` holds at most. */
export const COUNTER_KEYS_MAX = 100_000;
/** Hit times all exact logs of a `MemoryCounterStore` hold together, at most. */
export const COUNTER_TIMESTAMPS_MAX = 2_000_000;
/** The largest limit counted with an exact log; above it, weighted sub-windows. */
export const EXACT_LIMIT_MAX = 1_000;
/** Entries looked at for expiry on every hit. */
const SWEEP_PER_HIT = 4;
/** Slots of a new ring; it doubles as it fills, up to `limit + 1`. */
const RING_START = 8;

/**
 * Where limit Rules count. Synchronous: Shield calls it while it decides a request and must not wait. A method that
 * throws is contained by Shield and the request proceeds (fail open); an answer that is not a finite number is read
 * as 0.
 *
 * A key names one counter: a limit Rule (its id, window and count kind, as text) and a client. The client part is
 * a keyed hash made by Shield with a secret of the process: a store never receives an address or a device id, and
 * a key means nothing in another process or after a restart.
 *
 * `limit` is what the caller holds the key to: a store may use it to count exactly (the in-memory store keeps an
 * exact log up to 1,000). A store may count past it, but need not.
 */
export interface CounterStore {
  /** Counts one more for `key` at `now` (milliseconds) and returns its count in the window, this one included. */
  hit(key: string, windowMs: number, now: number, limit?: number): number;
  /**
   * The count of `key` in the window at `now`, without counting anything. 0 for a key it does not hold. A look is a
   * use: it keeps the key from being the first to go.
   */
  peek(key: string, windowMs: number, now: number, limit?: number): number;
  /**
   * Milliseconds from `now` until the count of `key` is below `limit` if nothing more is counted: 0 when it already
   * is, at least 1 otherwise. Optional: without it Shield answers `Retry-After` with the whole window.
   */
  retryAfterMs?(key: string, windowMs: number, limit: number, now: number): number;
  /** Keys held now. */
  size(): number;
}

interface Entry {
  readonly key: string;
  /** The window the key was last counted with: what tells when the entry has expired. */
  windowMs: number;
  // Weighted sub-windows (`ring` null).
  /** When the running sub-window started, in milliseconds. */
  start: number;
  /** Hits of the running sub-window. */
  current: number;
  /** Hits of the sub-window before it. */
  previous: number;
  // Exact log (`ring` set): the hit times, oldest first from `head`, `length` of them, in a circular buffer.
  ring: Float64Array | null;
  head: number;
  length: number;
  /** Hits the log keeps at most: `limit + 1`. */
  capacity: number;
  /** The entry used just before this one, and the one used just after: the table in order of last use. */
  older: Entry | null;
  newer: Entry | null;
}

const usable = (windowMs: number, now: number): boolean =>
  Number.isFinite(now) && Number.isFinite(windowMs) && windowMs > 0;

/** Slots of an exact log for `limit`, or 0 for weighted sub-windows. */
function capacityFor(limit: number | undefined): number {
  return typeof limit === "number" && Number.isSafeInteger(limit) && limit >= 1 && limit <= EXACT_LIMIT_MAX
    ? limit + 1
    : 0;
}

/** Brings weighted sub-windows up to `now`. */
function roll(entry: Entry, windowMs: number, now: number): void {
  entry.windowMs = windowMs;
  const elapsed = now - entry.start;
  if (elapsed < windowMs) {
    // The clock stepped back: keep the counts and let them fade from the new time on.
    if (elapsed < 0) entry.start = now;
    return;
  }
  if (elapsed >= 2 * windowMs) {
    entry.previous = 0;
    entry.current = 0;
    entry.start = now;
    return;
  }
  entry.previous = entry.current;
  entry.current = 0;
  entry.start += windowMs;
}

/** The count of rolled sub-windows at `now`. */
function weightedCount(entry: Entry, windowMs: number, now: number): number {
  if (entry.previous === 0) return entry.current;
  return Math.floor(entry.current + entry.previous * (1 - (now - entry.start) / windowMs));
}

/** The `i`-th hit time of a log, oldest first. */
function timeAt(entry: Entry, i: number): number {
  const ring = entry.ring as Float64Array;
  return ring[(entry.head + i) % ring.length] as number;
}

/** Drops the hits of a log that left the window; brings hits ahead of a clock set back to it. */
function prune(entry: Entry, windowMs: number, now: number): void {
  entry.windowMs = windowMs;
  const ring = entry.ring as Float64Array;
  // Newest first: the times are in order, so those ahead of the clock are at the end.
  for (let i = entry.length - 1; i >= 0; i--) {
    const at = (entry.head + i) % ring.length;
    if ((ring[at] as number) <= now) break;
    ring[at] = now;
  }
  while (entry.length > 0 && now - (ring[entry.head] as number) >= windowMs) {
    entry.head = (entry.head + 1) % ring.length;
    entry.length -= 1;
  }
}

/** When a key has nothing left to count, if it is not hit again. */
function expiresAt(entry: Entry): number {
  if (entry.ring === null) return entry.start + 2 * entry.windowMs;
  return entry.length === 0 ? Number.NEGATIVE_INFINITY : timeAt(entry, entry.length - 1) + entry.windowMs;
}

/** The in-memory counter store of one Shield instance. See the top of this file. */
export class MemoryCounterStore implements CounterStore {
  /** Keys held at most. */
  readonly maxKeys: number;
  /** Hit times held at most, in all exact logs together. */
  readonly maxTimestamps: number;
  readonly #entries = new Map<string, Entry>();
  /** The entry idle longest, and the one used last. */
  #oldest: Entry | null = null;
  #newest: Entry | null = null;
  /** Where the sweep goes on at the next hit; null: at the oldest entry. */
  #cursor: Entry | null = null;
  /** Slots of all rings together. */
  #slots = 0;

  /**
   * `maxKeys`: a whole number from 1 to 100,000; anything else is 100,000. `maxTimestamps`: a whole number from
   * 1,001 to 2,000,000; anything else is 2,000,000.
   */
  constructor(options: { maxKeys?: number; maxTimestamps?: number } = {}) {
    const keys = options?.maxKeys;
    this.maxKeys =
      typeof keys === "number" && Number.isSafeInteger(keys) && keys >= 1 && keys <= COUNTER_KEYS_MAX
        ? keys
        : COUNTER_KEYS_MAX;
    const times = options?.maxTimestamps;
    this.maxTimestamps =
      typeof times === "number" &&
      Number.isSafeInteger(times) &&
      times > EXACT_LIMIT_MAX &&
      times <= COUNTER_TIMESTAMPS_MAX
        ? times
        : COUNTER_TIMESTAMPS_MAX;
  }

  hit(key: string, windowMs: number, now: number, limit?: number): number {
    if (!usable(windowMs, now)) return 0;
    const capacity = capacityFor(limit);
    const entries = this.#entries;
    let entry = entries.get(key);
    if (entry === undefined) {
      // Full: the key idle longest goes. The hit is counted all the same.
      if (entries.size >= this.maxKeys && this.#oldest !== null) this.#drop(this.#oldest);
      entry = {
        key,
        windowMs,
        start: now,
        current: 0,
        previous: 0,
        ring: null,
        head: 0,
        length: 0,
        capacity: 0,
        older: null,
        newer: null,
      };
      entries.set(key, entry);
      this.#append(entry);
    } else {
      this.#use(entry);
    }
    this.#count(entry, windowMs, now, capacity);
    let result: number;
    if (entry.ring === null) {
      entry.current += 1;
      result = weightedCount(entry, windowMs, now);
    } else {
      this.#push(entry, now);
      result = entry.length;
    }
    this.#sweep(now);
    return result;
  }

  peek(key: string, windowMs: number, now: number, limit?: number): number {
    if (!usable(windowMs, now)) return 0;
    const entry = this.#entries.get(key);
    if (entry === undefined) return 0;
    this.#use(entry); // a look is a use (F8)
    return this.#count(entry, windowMs, now, capacityFor(limit));
  }

  retryAfterMs(key: string, windowMs: number, limit: number, now: number): number {
    if (!usable(windowMs, now) || !Number.isFinite(limit)) return 0;
    const entry = this.#entries.get(key);
    if (entry === undefined) return 0;
    if (entry.ring !== null) {
      prune(entry, windowMs, now);
      if (entry.length < limit || limit < 1) return 0;
      // Below the limit once the `limit`-th most recent hit has left the window.
      return Math.max(1, timeAt(entry, entry.length - limit) + windowMs - now);
    }
    roll(entry, windowMs, now);
    if (weightedCount(entry, windowMs, now) < limit) return 0;
    const elapsed = now - entry.start;
    if (entry.current >= limit) {
      // Not before the sub-window turns; from then on these hits fade, and are below the limit once the share
      // `limit / current` of them remains.
      return Math.max(1, windowMs - elapsed + windowMs * (1 - limit / entry.current));
    }
    // The running sub-window alone is below the limit: wait until the previous one has faded to the difference.
    const at = windowMs * (1 - (limit - entry.current) / entry.previous);
    return Math.max(1, at - elapsed);
  }

  size(): number {
    return this.#entries.size;
  }

  /** Hit-time slots held by all exact logs together. */
  timestamps(): number {
    return this.#slots;
  }

  /** The count of an entry at `now`, after bringing it to the kind `capacity` asks for (0: weighted). */
  #count(entry: Entry, windowMs: number, now: number, capacity: number): number {
    if (capacity === 0) {
      if (entry.ring !== null) {
        // A log read as weighted sub-windows: its hits in the window, all in a running sub-window from now on.
        prune(entry, windowMs, now);
        const hits = entry.length;
        this.#free(entry);
        entry.current = hits;
        entry.previous = 0;
        entry.start = now;
      }
      roll(entry, windowMs, now);
      return weightedCount(entry, windowMs, now);
    }
    if (entry.ring === null) {
      // Weighted sub-windows turned into a log: their count as that many hits at `now` (it can only last longer).
      roll(entry, windowMs, now);
      const hits = Math.min(weightedCount(entry, windowMs, now), capacity);
      entry.current = 0;
      entry.previous = 0;
      entry.capacity = capacity;
      entry.ring = this.#allocate(entry, Math.min(capacity, Math.max(RING_START, hits)));
      entry.head = 0;
      entry.length = 0;
      for (let i = 0; i < hits; i++) this.#push(entry, now);
    } else if (entry.capacity !== capacity) {
      // Another limit: the newest hits it can keep.
      prune(entry, windowMs, now);
      const keep = Math.min(entry.length, capacity);
      const times: number[] = [];
      for (let i = entry.length - keep; i < entry.length; i++) times.push(timeAt(entry, i));
      this.#free(entry);
      entry.capacity = capacity;
      entry.ring = this.#allocate(entry, Math.min(capacity, Math.max(RING_START, keep)));
      entry.head = 0;
      entry.length = 0;
      for (const at of times) this.#push(entry, at);
    }
    prune(entry, windowMs, now);
    return entry.length;
  }

  /** Adds a hit time to a log: the oldest goes when the log is full; the ring grows while it can. */
  #push(entry: Entry, at: number): void {
    let ring = entry.ring as Float64Array;
    if (entry.length === entry.capacity) {
      entry.head = (entry.head + 1) % ring.length;
      entry.length -= 1;
    } else if (entry.length === ring.length) {
      const grown = this.#allocate(entry, Math.min(entry.capacity, ring.length * 2));
      for (let i = 0; i < entry.length; i++) grown[i] = timeAt(entry, i);
      this.#slots -= ring.length;
      entry.ring = grown;
      entry.head = 0;
      ring = grown;
    }
    ring[(entry.head + entry.length) % ring.length] = at;
    entry.length += 1;
  }

  /** A ring of `slots` for `entry`, after dropping the keys idle longest while the slots would pass the bound. */
  #allocate(entry: Entry, slots: number): Float64Array {
    while (this.#slots + slots > this.maxTimestamps && this.#oldest !== null && this.#oldest !== entry) {
      this.#drop(this.#oldest);
    }
    this.#slots += slots;
    return new Float64Array(slots);
  }

  #free(entry: Entry): void {
    if (entry.ring !== null) this.#slots -= entry.ring.length;
    entry.ring = null;
    entry.head = 0;
    entry.length = 0;
    entry.capacity = 0;
  }

  /** Marks the entry as used now: last in the order of last use. */
  #use(entry: Entry): void {
    if (entry === this.#newest) return;
    this.#unlink(entry);
    this.#append(entry);
  }

  #append(entry: Entry): void {
    entry.older = this.#newest;
    entry.newer = null;
    if (this.#newest === null) this.#oldest = entry;
    else this.#newest.newer = entry;
    this.#newest = entry;
  }

  /** Takes the entry out of the order of last use. The sweep, if it stood on it, moves on. */
  #unlink(entry: Entry): void {
    if (this.#cursor === entry) this.#cursor = entry.newer;
    if (entry.older === null) this.#oldest = entry.newer;
    else entry.older.newer = entry.newer;
    if (entry.newer === null) this.#newest = entry.older;
    else entry.newer.older = entry.older;
    entry.older = null;
    entry.newer = null;
  }

  #drop(entry: Entry): void {
    this.#unlink(entry);
    this.#free(entry);
    this.#entries.delete(entry.key);
  }

  /** Looks at a few entries, from the idlest on, and drops those with nothing left to count. */
  #sweep(now: number): void {
    for (let i = 0; i < SWEEP_PER_HIT; i++) {
      const entry = this.#cursor ?? this.#oldest;
      if (entry === null) return;
      // Null at the newest entry: the next step starts over at the oldest.
      this.#cursor = entry.newer;
      if (now >= expiresAt(entry)) this.#drop(entry);
      if (this.#cursor === null) return;
    }
  }
}
