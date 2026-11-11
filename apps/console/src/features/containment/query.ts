import {
  CONTAINMENT_DEFAULT_TTL,
  CONTAINMENT_TTLS,
  type Containment,
  type ContainmentTtl,
} from "@antireverse/protocol";

type QueryValue = string | string[] | undefined;

/** The block a confirmation step asks about: one Actor of the Incident, or its network. */
export type BlockRequest =
  | { kind: "actor"; ipHash: string; ttl: ContainmentTtl }
  | { kind: "prefix"; ttl: ContainmentTtl };

/** The duration of `?ttl=`: absent means the default (1 hour); anything that is not an offered duration is null. */
function ttlFrom(value: QueryValue): ContainmentTtl | null {
  if (value === undefined) return CONTAINMENT_DEFAULT_TTL;
  return CONTAINMENT_TTLS.find((ttl) => String(ttl) === value) ?? null;
}

/**
 * The block step of the Incident's address: `?contain=actor&actor=<hash>&ttl=<s>` or `?contain=prefix&ttl=<s>`
 * — what the containment bar's form sends. Null for anything else, and for an Actor the Incident does not list.
 */
export function blockRequestFrom(
  query: { contain?: QueryValue; actor?: QueryValue; ttl?: QueryValue },
  actors: ReadonlyArray<{ ip_hash: string }>,
): BlockRequest | null {
  const ttl = ttlFrom(query.ttl);
  if (ttl === null) return null;
  if (query.contain === "prefix") return { kind: "prefix", ttl };
  if (query.contain !== "actor") return null;
  const actor = actors.find((candidate) => candidate.ip_hash === query.actor);
  return actor === undefined ? null : { kind: "actor", ipHash: actor.ip_hash, ttl };
}

/** The block of `?lift=`, when it is listed and still active; otherwise undefined. */
export function liftFrom(value: QueryValue, containments: readonly Containment[]): string | undefined {
  return containments.find((containment) => containment.id === value && containment.status === "active")?.id;
}
