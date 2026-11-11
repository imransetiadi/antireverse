import { parseAddress } from "@antireverse/protocol";

/**
 * The network prefix of a client address in the Event's form (`IP_PREFIX_PATTERN`): IPv4 `a.b.c.0/24`, IPv6 its
 * first three groups without leading zeros and `::/48` (as Shield's `truncateIp`). An IPv4-mapped IPv6 address is
 * its IPv4 address; a zone id is ignored. Null for a missing or unparsable address. The API reduces an address to
 * this at once: the full address is never stored or logged.
 */
export function addressPrefix(address: string | null | undefined): string | null {
  const parsed = parseAddress(address);
  if (parsed === null) return null;
  const [a, b, c] = parsed.words as [number, number, number];
  if (parsed.version === 4) return `${a >> 8}.${a & 255}.${b >> 8}.0/24`;
  return `${a.toString(16)}:${b.toString(16)}:${c.toString(16)}::/48`;
}
