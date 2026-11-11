// A fixed-window request counter per key (a caller prefix, an App), like the beacon recorder's prefix cap. Bounded
// at `maxKeys` tracked keys, and a window that is still running is never forgotten: forgetting one would hand its
// key a fresh budget (review F1). Only a window that has ended makes room; while every tracked window runs, a new
// key is refused until the oldest one ends.

export interface WindowLimiter {
  /** Counts one request of `key` at `ms`. Refused when the key's window is full, or when no room is left for a new key; then `retryAfterS` > 0. */
  take(key: string, ms: number): { allowed: boolean; retryAfterS: number };
  /** Keys tracked now. */
  size(): number;
}

export function createWindowLimiter(options: { limit: number; windowMs: number; maxKeys: number }): WindowLimiter {
  const { limit, windowMs } = options;
  const maxKeys = Math.max(1, options.maxKeys);
  // Insertion order is window start order (a renewed window is inserted again): the first entry started first.
  const windows = new Map<string, { start: number; count: number }>();

  const ended = (entry: { start: number }, ms: number) => ms - entry.start >= windowMs || ms < entry.start;
  const retryAfter = (entry: { start: number }, ms: number) =>
    Math.max(1, Math.ceil((entry.start + windowMs - ms) / 1_000));

  return {
    take(key, ms) {
      let entry = windows.get(key);
      if (entry === undefined || ended(entry, ms)) {
        windows.delete(key);
        // Room is made only from windows that have ended, oldest first.
        for (const [candidate, held] of windows) {
          if (windows.size < maxKeys || !ended(held, ms)) break;
          windows.delete(candidate);
        }
        if (windows.size >= maxKeys) {
          const oldest = windows.values().next();
          return { allowed: false, retryAfterS: oldest.done ? 1 : retryAfter(oldest.value, ms) };
        }
        entry = { start: ms, count: 0 };
        windows.set(key, entry);
      }
      if (entry.count >= limit) return { allowed: false, retryAfterS: retryAfter(entry, ms) };
      entry.count++;
      return { allowed: true, retryAfterS: 0 };
    },
    size: () => windows.size,
  };
}
