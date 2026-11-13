import { isIP } from "node:net";

// The SSRF classifier of the Prove file fetch (slice 14, D-069). The verification file is fetched from a host an
// Organization names, from inside our network: only a globally routable unicast address may ever be contacted.
// The rule is an allow rule, stricter than the alert-channel guard (notify/ssrf.ts): IPv4 outside every
// special-purpose range; IPv6 only inside global unicast 2000::/3 and outside its special-purpose blocks, or an
// IPv4-mapped, IPv4-translated, NAT64 (64:ff9b::/96) or 6to4 (2002::/16) form whose embedded IPv4 address is
// itself public. Anything that does not parse as a plain address (zones, brackets, ports, shortened or
// leading-zero IPv4 forms) is refused.

/** IPv4 ranges never contacted: [network as a 32-bit number, prefix length]. */
const NON_PUBLIC_V4: readonly (readonly [number, number])[] = [
  [v4("0.0.0.0"), 8], // "this network", including the unspecified address
  [v4("10.0.0.0"), 8], // private
  [v4("100.64.0.0"), 10], // shared address space (CGNAT)
  [v4("127.0.0.0"), 8], // loopback
  [v4("169.254.0.0"), 16], // link-local, including 169.254.169.254 (cloud metadata)
  [v4("168.63.129.16"), 32], // Azure WireServer: a public address only the host platform answers (review F7)
  [v4("172.16.0.0"), 12], // private
  [v4("192.0.0.0"), 24], // IETF protocol assignments (192.0.0.170 NAT64 discovery, DS-Lite)
  [v4("192.0.2.0"), 24], // documentation TEST-NET-1
  [v4("192.88.99.0"), 24], // 6to4 relay anycast (deprecated)
  [v4("192.168.0.0"), 16], // private
  [v4("198.18.0.0"), 15], // benchmarking
  [v4("198.51.100.0"), 24], // documentation TEST-NET-2
  [v4("203.0.113.0"), 24], // documentation TEST-NET-3
  [v4("224.0.0.0"), 4], // multicast
  [v4("240.0.0.0"), 4], // reserved, including the limited broadcast 255.255.255.255
];

function v4(address: string): number {
  return address.split(".").reduce((value, octet) => value * 256 + Number(octet), 0);
}

function inRange(value: number, base: number, bits: number): boolean {
  return Math.floor(value / 2 ** (32 - bits)) === Math.floor(base / 2 ** (32 - bits));
}

function publicV4(value: number): boolean {
  return !NON_PUBLIC_V4.some(([base, bits]) => inRange(value, base, bits));
}

const V4_TEXT = /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/;
const V6_TEXT = /^[0-9A-Fa-f:.]+$/;

/** The eight 16-bit groups of a plain IPv6 address (dotted IPv4 tail allowed), or null. */
function v6Groups(address: string): number[] | null {
  let text = address.toLowerCase();
  const tail = /(?:^|:)([0-9.]+)$/.exec(text);
  if (tail?.[1]?.includes(".")) {
    const dotted = tail[1];
    if (!V4_TEXT.test(dotted) || isIP(dotted) !== 4) return null;
    const value = v4(dotted);
    text = `${text.slice(0, -dotted.length)}${Math.floor(value / 65_536).toString(16)}:${(value % 65_536).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parse = (part: string | undefined): number[] | null => {
    if (part === undefined || part === "") return [];
    const groups = part.split(":");
    if (!groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))) return null;
    return groups.map((group) => Number.parseInt(group, 16));
  };
  const head = parse(halves[0]);
  const rest = parse(halves[1]);
  if (head === null || rest === null) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const missing = 8 - head.length - rest.length;
  if (missing < 1) return null;
  return [...head, ...Array<number>(missing).fill(0), ...rest];
}

function publicV6(groups: readonly number[]): boolean {
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = groups;
  const embedded = g6 * 65_536 + g7;
  const firstFourZero = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0;
  // IPv4-mapped ::ffff:a.b.c.d and IPv4-translated ::ffff:0:a.b.c.d: as public as the IPv4 address.
  if (firstFourZero && g4 === 0 && g5 === 0xffff) return publicV4(embedded);
  if (firstFourZero && g4 === 0xffff && g5 === 0) return publicV4(embedded);
  // NAT64 well-known prefix 64:ff9b::/96: as public as the IPv4 address. Local-use 64:ff9b:1::/48 never.
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) return publicV4(embedded);
  // Everything else outside global unicast 2000::/3 is never contacted: ::, ::1, IPv4-compatible ::a.b.c.d,
  // 64:ff9b:1::/48, discard-only 100::/64, unique-local fc00::/7, link-local fe80::/10, site-local fec0::/10,
  // multicast ff00::/8 and the unassigned space.
  if ((g0 & 0xe000) !== 0x2000) return false;
  // IETF protocol assignments 2001::/23: Teredo 2001::/32 (embeds an obfuscated client IPv4 address),
  // benchmarking 2001:2::/48, ORCHID 2001:10::/28 and 2001:20::/28, and the rest of the block.
  if (g0 === 0x2001 && g1 <= 0x01ff) return false;
  if (g0 === 0x2001 && g1 === 0x0db8) return false; // documentation 2001:db8::/32
  if (g0 === 0x3fff && (g1 & 0xf000) === 0) return false; // documentation 3fff::/20
  // 6to4 2002::/16: the IPv4 address is bits 16..48.
  if (g0 === 0x2002) return publicV4(g1 * 65_536 + g2);
  return true;
}

/**
 * True only for a globally routable unicast address written plainly (no zone, brackets or port): the only kind the
 * Prove file fetch may connect to. False for anything else, including a value that is not a string.
 */
export function isPublicAddress(address: string): boolean {
  if (typeof address !== "string") return false;
  const family = isIP(address);
  if (family === 4) return V4_TEXT.test(address) && publicV4(v4(address));
  if (family === 6) {
    if (!V6_TEXT.test(address)) return false;
    const groups = v6Groups(address);
    return groups !== null && publicV6(groups);
  }
  return false;
}
