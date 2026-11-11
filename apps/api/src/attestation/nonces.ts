import { randomBytes } from "node:crypto";

// Challenge nonces of `POST /v1/attest/challenge`, in this process's memory (a known limit of slice 03: nonces do
// not survive a restart and are not shared between processes). Each is 128 random bits as 32 hex characters, bound
// to the App it was issued for, valid for `ttlMs`, and spent by the first attempt to take it, right or wrong.
// Bounded: over `max`, the oldest nonce goes first. A nonce is a value from a public request: never log it.

export interface NonceStore {
  /** A new nonce for the App, valid until `expiresAt` (ms, exclusive). */
  issue(appId: string, ms: number): { nonce: string; expiresAt: number };
  /** True when the nonce was issued for this App and has not expired. Spends it either way. */
  take(nonce: string, appId: string, ms: number): boolean;
  /** Nonces held now. */
  size(): number;
}

export function createNonceStore(options: { max: number; ttlMs: number }): NonceStore {
  const max = Math.max(1, options.max);
  const { ttlMs } = options;
  // Insertion order is issue order: the first entry is the oldest.
  const nonces = new Map<string, { appId: string; expiresAt: number }>();

  return {
    issue(appId, ms) {
      // Expired nonces at the front are swept; a clock that went back leaves them for the bound to evict.
      for (const [nonce, entry] of nonces) {
        if (entry.expiresAt > ms) break;
        nonces.delete(nonce);
      }
      const nonce = randomBytes(16).toString("hex");
      const expiresAt = ms + ttlMs;
      nonces.set(nonce, { appId, expiresAt });
      while (nonces.size > max) {
        const oldest = nonces.keys().next();
        if (oldest.done) break;
        nonces.delete(oldest.value);
      }
      return { nonce, expiresAt };
    },
    take(nonce, appId, ms) {
      const entry = nonces.get(nonce);
      if (entry === undefined) return false;
      nonces.delete(nonce);
      return entry.appId === appId && ms < entry.expiresAt;
    },
    size: () => nonces.size,
  };
}
