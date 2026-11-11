// Containment (slice 09): the actor hash of a client and the Containments of the applied Policy that block it.
//
// The actor hash is computed here with node:crypto, as `actorHash` of the protocol's server entry computes it
// (pinned by test/address.test.ts): "iph_" and the first 32 hex characters of HMAC-SHA256(key = the actor key,
// "antireverse/actor/v1\n" + subject), the subject being a whole IPv4 address, or the /64 of an IPv6 address as
// four groups of 4 lower-case hex digits. It is computed once per request and goes into the Event; the address
// itself never leaves the process and is never logged. The actor key is held by the customer (`actorKey`,
// AR_ACTOR_KEY), never the Shield key, which the API receives on every request (review F1, owner's decision):
// without an actor key there is no hash at all.
//
// A request is contained when its address is in no allowlist CIDR and an unexpired block names its actor hash or
// its /24 or /48. Both lookups are exact Map lookups, built once per applied bundle; the allowlist is read only when
// a block matched.
import { createHmac } from "node:crypto";
import { inCidr, type ParsedAddress, parseAddress, prefixOf } from "./address.ts";
import type { AppliedPolicy } from "./policy/store.ts";
import type { Decision } from "./types.ts";

/** Domain separation of the actor hash. Equal to the protocol's (pinned by a test). */
export const ACTOR_HASH_DOMAIN = "antireverse/actor/v1\n";

/** Characters of an actor key at least. */
export const ACTOR_KEY_MIN = 32;

/**
 * The actor key to hash with: `given` when it is a string of at least `ACTOR_KEY_MIN` characters without
 * whitespace that is not the Shield key; null otherwise. `unusable` is true when something was given but cannot be
 * used. Never repeats the value.
 */
export function resolveActorKey(given: unknown, shieldKey: string): { key: string | null; unusable: boolean } {
  if (given === undefined || given === null || given === "") return { key: null, unusable: false };
  if (typeof given !== "string" || given.length < ACTOR_KEY_MIN || /\s/.test(given) || given === shieldKey) {
    return { key: null, unusable: true };
  }
  return { key: given, unusable: false };
}

/** What Shield knows of the client of one request. */
export interface Client {
  /** The parsed address, or null when it is unknown or cannot be parsed. Stays inside the process. */
  readonly address: ParsedAddress | null;
  /** The actor hash of the address under the actor key, or null (no key, or no address). Recorded in the Event. */
  readonly hash: string | null;
}

export const UNKNOWN_CLIENT: Client = Object.freeze({ address: null, hash: null });

/** The actor hash of a parsed address for one actor key; null for an unknown address or without a key. */
export function actorHashOf(key: string | null, address: ParsedAddress | null): string | null {
  if (address === null || key === null) return null;
  const w = address.words;
  const subject =
    address.version === 4
      ? `${(w[0] as number) >> 8}.${(w[0] as number) & 255}.${(w[1] as number) >> 8}.${(w[1] as number) & 255}`
      : `${hex4(w[0] as number)}:${hex4(w[1] as number)}:${hex4(w[2] as number)}:${hex4(w[3] as number)}`;
  return `iph_${createHmac("sha256", key)
    .update(ACTOR_HASH_DOMAIN + subject, "utf8")
    .digest("hex")
    .slice(0, 32)}`;
}

function hex4(word: number): string {
  return word.toString(16).padStart(4, "0");
}

/**
 * The client of a request whose address is `address` (as the socket or `clientAddress` gave it). `actorKey` is the
 * customer-held actor key, or null: then the hash is null, and only prefix blocks can match the client.
 */
export function describeClient(actorKey: string | null, address: unknown): Client {
  const parsed = parseAddress(address);
  if (parsed === null) return UNKNOWN_CLIENT;
  return { address: parsed, hash: actorHashOf(actorKey, parsed) };
}

/** A Containment that blocks a request: the Decision to record and the Containment's id. */
export interface ContainmentHit {
  readonly decision: Decision;
  readonly id: string;
}

/**
 * The Containment of `policy` that blocks `client` now, or null. The actor block is looked at first, then the
 * prefix block; a block counts while its `expires_at` is after `now()` (read only when a block names the client).
 * A client whose address is in an allowlist CIDR is never contained. Throws only if `now` throws: the caller
 * fails open.
 */
export function containmentOf(policy: AppliedPolicy, client: Client, now: () => number): ContainmentHit | null {
  const address = client.address;
  if (address === null) return null;
  const byHash = policy.blocksByHash;
  const byPrefix = policy.blocksByPrefix;
  if (byHash.size === 0 && byPrefix.size === 0) return null;
  const actor = client.hash === null || byHash.size === 0 ? undefined : byHash.get(client.hash);
  const network = byPrefix.size === 0 ? undefined : byPrefix.get(prefixOf(address));
  if (actor === undefined && network === undefined) return null;
  const at = now();
  // A clock that returns nonsense blocks nothing: `x > NaN` is false.
  const block =
    actor !== undefined && actor.expiresMs > at
      ? actor
      : network !== undefined && network.expiresMs > at
        ? network
        : undefined;
  if (block === undefined) return null;
  const allowlist = policy.allowlist;
  for (let i = 0; i < allowlist.length; i++)
    if (inCidr(allowlist[i] as (typeof allowlist)[number], address)) return null;
  return { decision: policy.containedDecision, id: block.id };
}
