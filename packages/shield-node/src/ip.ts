import { parseAddress, prefixOf } from "./address.ts";

/**
 * The network prefix of a client address: the only part of an address an Event carries.
 * IPv4 gives `a.b.c.0/24`; IPv4-mapped IPv6 is treated as IPv4; IPv6 gives its first three groups without leading
 * zeros followed by `::/48` (so `::1` gives `0:0:0::/48`). Anything that is not an address gives null. Never throws.
 *
 * Built on the same parser as the actor hash and the containment matcher (`parseAddress` of address.ts, the
 * protocol's rules: zone id stripped, an empty zone refused, 128 characters at most), so the Event's prefix, its
 * hash and whether a prefix block contains the client always agree (review F2).
 */
export function truncateIp(address: unknown): string | null {
  const parsed = parseAddress(address);
  return parsed === null ? null : prefixOf(parsed);
}
