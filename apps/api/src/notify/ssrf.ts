import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

// The SSRF guard of alert channels. A channel URL is chosen by a tenant, and the API sends requests to it from
// inside our network: it must never reach loopback, private, link-local (cloud metadata) or shared (CGNAT)
// addresses. The check runs when a channel is created and again before every delivery attempt, and the
// address it vetted is the one the delivery connects to (see notifier.ts), so a host that later resolves
// elsewhere (DNS rebinding) is caught or cannot redirect the connection.

/** Every address a host name resolves to, as `dns.lookup(host, { all: true })` answers. */
export type Resolve = (host: string) => Promise<{ address: string; family: number }[]>;

export const defaultResolve: Resolve = (host) => lookup(host, { all: true, verbatim: true });

/** How long the host lookup of a channel creation may take, by default. */
export const LOOKUP_TIMEOUT_MS = 5_000;

/**
 * `resolve`, bounded by `signal`: the answer is abandoned (rejected) when the signal aborts first, so a resolver
 * that never answers cannot hold a request or a delivery attempt. `checkDestination` then reports the host as
 * unresolvable.
 */
export function resolveWithin(resolve: Resolve, signal: AbortSignal): Resolve {
  return (host) =>
    new Promise((fulfil, reject) => {
      if (signal.aborted) {
        reject(signal.reason);
        return;
      }
      const onAbort = () => reject(signal.reason);
      signal.addEventListener("abort", onAbort, { once: true });
      resolve(host)
        .then(fulfil, reject)
        .finally(() => signal.removeEventListener("abort", onAbort));
    });
}

export type DestinationCheck = { ok: true; address: string; family: 4 | 6 } | { ok: false; reason: string };

export interface DestinationOptions {
  resolve: Resolve;
  /**
   * Allows `http:` and the forbidden address ranges: for local development and tests only
   * (`AR_ALLOW_PRIVATE_ALERT_URLS=1`). Never another scheme, never a host that does not resolve.
   */
  allowPrivate: boolean;
}

// Fixed phrases: a reason is shown to the tenant and may be logged, so it never quotes the URL or the host.
const REASONS = {
  url: "Must be a valid URL.",
  scheme: "Must be an https: URL.",
  unresolvable: "The host could not be resolved.",
  forbidden: "Must not point to a loopback, private, link-local or otherwise internal address.",
} as const;

/** IPv4 ranges never contacted: [first octets as a 32-bit number, prefix length]. */
const FORBIDDEN_V4: readonly (readonly [number, number])[] = [
  [v4("0.0.0.0"), 8], // "this network", including the unspecified address
  [v4("10.0.0.0"), 8], // private
  [v4("100.64.0.0"), 10], // shared address space (CGNAT)
  [v4("127.0.0.0"), 8], // loopback
  [v4("169.254.0.0"), 16], // link-local, including 169.254.169.254 (cloud metadata)
  [v4("172.16.0.0"), 12], // private
  [v4("192.0.0.0"), 24], // IETF protocol assignments (e.g. 192.0.0.170, NAT64 discovery)
  [v4("192.0.2.0"), 24], // TEST-NET-1 (documentation)
  [v4("192.88.99.0"), 24], // 6to4 relay anycast (deprecated)
  [v4("192.168.0.0"), 16], // private
  [v4("198.18.0.0"), 15], // benchmarking
  [v4("198.51.100.0"), 24], // TEST-NET-2 (documentation)
  [v4("203.0.113.0"), 24], // TEST-NET-3 (documentation)
  [v4("224.0.0.0"), 4], // multicast
  [v4("240.0.0.0"), 4], // reserved, including the broadcast address
];

function v4(address: string): number {
  return address.split(".").reduce((value, octet) => value * 256 + Number(octet), 0);
}

function forbiddenV4(value: number): boolean {
  return FORBIDDEN_V4.some(
    ([base, bits]) => Math.floor(value / 2 ** (32 - bits)) === Math.floor(base / 2 ** (32 - bits)),
  );
}

/** The eight 16-bit groups of an IPv6 address (dotted IPv4 tail allowed), or null when it does not parse. */
function v6Groups(address: string): number[] | null {
  let text = address.toLowerCase();
  const zone = text.indexOf("%");
  if (zone >= 0) text = text.slice(0, zone);
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (tail?.[1] !== undefined) {
    if (isIP(tail[1]) !== 4) return null;
    const value = v4(tail[1]);
    text = `${text.slice(0, -tail[1].length)}${Math.floor(value / 65_536).toString(16)}:${(value % 65_536).toString(16)}`;
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

function forbiddenV6(groups: number[]): boolean {
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = groups;
  const embeddedV4 = g6 * 65_536 + g7;
  const firstSixZero = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;
  if (firstSixZero && g5 === 0 && g6 === 0 && (g7 === 0 || g7 === 1)) return true; // :: and ::1
  if (firstSixZero && g5 === 0xffff) return forbiddenV4(embeddedV4); // IPv4-mapped ::ffff:a.b.c.d
  if (firstSixZero && g5 === 0) return forbiddenV4(embeddedV4); // IPv4-compatible ::a.b.c.d (deprecated)
  // IPv4-translated ::ffff:0:a.b.c.d (::ffff:0:0/96)
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0xffff && g5 === 0) return forbiddenV4(embeddedV4);
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) return forbiddenV4(embeddedV4); // NAT64
  // Local-use NAT64 64:ff9b:1::/48: the IPv4 address is in the last 32 bits.
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 1) return forbiddenV4(embeddedV4);
  // 6to4 2002::/16: the IPv4 address is bits 16..48.
  if (g0 === 0x2002) return forbiddenV4(g1 * 65_536 + g2);
  if (g0 === 0x100 && g1 === 0 && g2 === 0 && g3 === 0) return true; // discard-only 100::/64
  if (g0 === 0x2001 && g1 === 0xdb8) return true; // documentation 2001:db8::/32
  if ((g0 & 0xfe00) === 0xfc00) return true; // unique local fc00::/7
  if ((g0 & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((g0 & 0xffc0) === 0xfec0) return true; // site-local fec0::/10 (deprecated)
  if ((g0 & 0xff00) === 0xff00) return true; // multicast ff00::/8
  return false;
}

/** True when the address must never be contacted (or does not parse as an address at all). */
export function isForbiddenAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return forbiddenV4(v4(address));
  if (family === 6) {
    const groups = v6Groups(address);
    return groups === null || forbiddenV6(groups);
  }
  return true;
}

/**
 * Whether alerts may be sent to `url`, and if so, the address to connect to. A host name is resolved and
 * refused when **any** of its addresses is forbidden; the first address is the vetted one.
 */
export async function checkDestination(url: string, options: DestinationOptions): Promise<DestinationCheck> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: REASONS.url };
  }
  const allowedSchemes = options.allowPrivate ? ["https:", "http:"] : ["https:"];
  if (!allowedSchemes.includes(parsed.protocol)) return { ok: false, reason: REASONS.scheme };

  // The URL parser keeps IPv6 literals in brackets and normalises them (::ffff:127.0.0.1 becomes ::ffff:7f00:1).
  const host = parsed.hostname.startsWith("[") ? parsed.hostname.slice(1, -1) : parsed.hostname;
  let addresses: { address: string; family: number }[];
  if (isIP(host) !== 0) {
    addresses = [{ address: host, family: isIP(host) }];
  } else {
    try {
      addresses = await options.resolve(host);
    } catch {
      return { ok: false, reason: REASONS.unresolvable };
    }
  }
  const usable = addresses.filter((entry) => isIP(entry.address) !== 0);
  const first = usable[0];
  if (first === undefined || usable.length !== addresses.length) return { ok: false, reason: REASONS.unresolvable };
  if (!options.allowPrivate && addresses.some((entry) => isForbiddenAddress(entry.address))) {
    return { ok: false, reason: REASONS.forbidden };
  }
  return { ok: true, address: first.address, family: isIP(first.address) === 6 ? 6 : 4 };
}
