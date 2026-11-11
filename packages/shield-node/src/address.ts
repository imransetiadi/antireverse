// Client addresses and allowlist CIDRs as 16-bit words (slice 09). A hand copy of `parseAddress`, `parseCidr` and
// `cidrContains` of the protocol's containment.ts, because Shield imports no protocol code at run time;
// test/address.test.ts pins the agreement over one corpus. A rule that changes there must change here.
//
// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, any spelling) IS the IPv4 address: it is parsed, prefixed, hashed
// and matched as IPv4. A zone id (`%eth0`) is stripped from an address and refused in a CIDR. Nothing here throws
// and nothing here logs.

/** A parsed address: 16-bit words, most significant first: 2 for IPv4, 8 for IPv6. */
export interface ParsedAddress {
  readonly version: 4 | 6;
  readonly words: readonly number[];
}

/** A parsed CIDR: the network address, its prefix length and its canonical text. */
export interface ParsedCidr extends ParsedAddress {
  readonly prefix: number;
  readonly cidr: string;
}

/** Longest address text (IPv6 with a dotted tail is 45 characters) plus a zone id. Equal to the protocol's. */
const ADDRESS_TEXT_MAX = 128;
const OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
const IPV4 = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);
const HEXTET = /^[0-9A-Fa-f]{1,4}$/;
const PREFIX_LENGTH = /^[1-9][0-9]{0,2}$/;
/** The prefix lengths an allowlist CIDR may have. Equal to `CIDR_PREFIX_BOUNDS` of the protocol. */
const BOUNDS = { 4: { min: 8, max: 32 }, 6: { min: 16, max: 128 } } as const;

function ipv4Words(value: string): number[] | null {
  const match = IPV4.exec(value);
  if (match === null) return null;
  return [(Number(match[1]) << 8) | Number(match[2]), (Number(match[3]) << 8) | Number(match[4])];
}

/** The words of `a:b:c` (possibly empty); `dottedTail` allows the last piece to be a dotted IPv4 address. */
function hextets(part: string, dottedTail: boolean): number[] | null {
  if (part === "") return [];
  const pieces = part.split(":");
  const words: number[] = [];
  for (let i = 0; i < pieces.length; i++) {
    const piece = pieces[i] as string;
    if (dottedTail && i === pieces.length - 1 && piece.includes(".")) {
      const tail = ipv4Words(piece);
      if (tail === null) return null;
      words.push(tail[0] as number, tail[1] as number);
    } else if (HEXTET.test(piece)) {
      words.push(Number.parseInt(piece, 16));
    } else {
      return null;
    }
  }
  return words;
}

function ipv6Words(value: string): number[] | null {
  const gap = value.indexOf("::");
  if (gap === -1) {
    const words = hextets(value, true);
    return words !== null && words.length === 8 ? words : null;
  }
  if (value.indexOf("::", gap + 1) !== -1) return null;
  const head = hextets(value.slice(0, gap), false);
  const tail = hextets(value.slice(gap + 2), true);
  // `::` stands for at least one zero group.
  if (head === null || tail === null || head.length + tail.length > 7) return null;
  const words = head;
  for (let i = head.length + tail.length; i < 8; i++) words.push(0);
  for (const word of tail) words.push(word);
  return words;
}

const isMapped = (words: readonly number[]): boolean =>
  words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0xffff;

function ipv4Text(words: readonly number[]): string {
  const high = words[0] as number;
  const low = words[1] as number;
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

/** RFC 5952 section 4 text of eight words: the longest run of two or more zero groups (the first on a tie) as `::`. */
function ipv6Text(words: readonly number[]): string {
  let start = -1;
  let length = 0;
  for (let i = 0; i < 8; ) {
    if (words[i] !== 0) {
      i++;
      continue;
    }
    let end = i;
    while (end < 8 && words[end] === 0) end++;
    if (end - i > length) {
      start = i;
      length = end - i;
    }
    i = end;
  }
  const hex = words.map((word) => word.toString(16));
  if (length < 2) return hex.join(":");
  return `${hex.slice(0, start).join(":")}::${hex.slice(start + length).join(":")}`;
}

/**
 * An IPv4 or IPv6 address given as text; null for anything else (no trimming, no port, no brackets, no leading
 * zeros in an IPv4 octet). An IPv6 zone id is stripped. An IPv4-mapped IPv6 address is returned as IPv4.
 */
export function parseAddress(value: unknown): ParsedAddress | null {
  if (typeof value !== "string" || value.length === 0 || value.length > ADDRESS_TEXT_MAX) return null;
  if (!value.includes(":")) {
    const words = ipv4Words(value);
    return words === null ? null : { version: 4, words };
  }
  const zone = value.indexOf("%");
  if (zone === value.length - 1) return null;
  const words = ipv6Words(zone === -1 ? value : value.slice(0, zone));
  if (words === null) return null;
  return isMapped(words) ? { version: 4, words: words.slice(6) } : { version: 6, words };
}

/**
 * A CIDR given as text; null unless it is a valid address, "/", and a length within the bounds with every host
 * bit zero. `cidr` of the result is the canonical text (a bundle accepts only that text). A zone id and an IPv6
 * CIDR inside the IPv4-mapped block are refused.
 */
export function parseCidr(value: unknown): ParsedCidr | null {
  if (typeof value !== "string" || value.length > ADDRESS_TEXT_MAX) return null;
  const slash = value.indexOf("/");
  if (slash <= 0) return null;
  const lengthText = value.slice(slash + 1);
  if (!PREFIX_LENGTH.test(lengthText)) return null;
  const prefix = Number(lengthText);
  const address = value.slice(0, slash);
  const version = address.includes(":") ? 6 : 4;
  const words = version === 6 ? ipv6Words(address) : ipv4Words(address);
  if (words === null) return null;
  const bounds = BOUNDS[version];
  if (prefix < bounds.min || prefix > bounds.max) return null;
  if (version === 6 && prefix >= 96 && isMapped(words)) return null;
  for (let i = 0; i < words.length; i++) {
    const bits = Math.min(16, Math.max(0, prefix - 16 * i));
    if (((words[i] as number) & (0xffff >> bits)) !== 0) return null;
  }
  const cidr = `${version === 6 ? ipv6Text(words) : ipv4Text(words)}/${prefix}`;
  return { version, words, prefix, cidr };
}

/** Whether the address lies inside the range. False across IP versions. */
export function inCidr(range: ParsedCidr, address: ParsedAddress): boolean {
  if (range.version !== address.version) return false;
  const a = range.words;
  const b = address.words;
  const whole = range.prefix >> 4;
  for (let i = 0; i < whole; i++) if (a[i] !== b[i]) return false;
  const rest = range.prefix & 15;
  if (rest === 0) return true;
  const mask = (0xffff << (16 - rest)) & 0xffff;
  return (((a[whole] as number) ^ (b[whole] as number)) & mask) === 0;
}

/**
 * The network prefix of an address in the Event's form (`IP_PREFIX_PATTERN`): IPv4 `a.b.c.0/24`, IPv6 its first
 * three groups without leading zeros and `::/48`. Equal to `truncateIp` of the same text (pinned by a test).
 */
export function prefixOf(address: ParsedAddress): string {
  const w = address.words;
  if (address.version === 4) {
    const high = w[0] as number;
    const low = w[1] as number;
    return `${high >> 8}.${high & 255}.${low >> 8}.0/24`;
  }
  return `${(w[0] as number).toString(16)}:${(w[1] as number).toString(16)}:${(w[2] as number).toString(16)}::/48`;
}
