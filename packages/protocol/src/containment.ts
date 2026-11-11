// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ACTOR_HASH_PATTERN, ENVIRONMENTS, ID_PATTERNS } from "./constants.ts";
import { IP_PREFIX_PATTERN } from "./events.ts";
import { deepFreeze, text } from "./shared.ts";

// The containment contract: time-limited blocks of one Actor (by actor hash) or one network prefix, created
// from an Incident, and the Organization's never-block allowlist of address ranges. Every object schema is a
// plain `z.object`, which strips unknown keys. No schema here carries a full client address: an Actor is its
// keyed hash, a network is the Event's /24 or /48 prefix. The address and CIDR helpers at the end are pure
// (16-bit number words, no BigInt, no Node built-in), so Shield, the API and the Console share one parser.
//
// Canonical CIDR text (the only form a schema accepts; nothing is rewritten):
//   IPv4: dotted decimal without leading zeros, "/", the length without leading zeros: `203.0.113.0/24`.
//   IPv6: RFC 5952 section 4: lowercase hex, no leading zeros in a group, the longest run of two or more
//         zero groups written `::` (the first run on a tie), a single zero group never compressed; then "/"
//         and the length: `2001:db8::/32`. Always hex groups, never the mixed dotted form of section 5.
//   Host bits are zero. Lengths: IPv4 /8 to /32, IPv6 /16 to /128.
// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) IS the IPv4 address everywhere: it is hashed, prefixed and
// matched as IPv4. So an IPv6 CIDR never contains an IPv4 address, and an IPv6 CIDR inside `::ffff:0:0/96` is
// refused (it could never match): write the IPv4 CIDR instead.

/** How long a Containment may last, in seconds: 15 minutes, 1 hour, 24 hours. */
export const CONTAINMENT_TTLS = deepFreeze([900, 3600, 86_400] as const);
export type ContainmentTtl = (typeof CONTAINMENT_TTLS)[number];

/** The TTL a Console form starts with. */
export const CONTAINMENT_DEFAULT_TTL = 3600 satisfies ContainmentTtl;

export const CONTAINMENT_LIMITS = {
  /** Active Containments per App and Environment; also the blocks a Policy Bundle may carry. */
  activePerAppEnv: 150,
  /** Allowlist entries per Organization; also the CIDRs a Policy Bundle may carry. */
  allowlistMax: 100,
  /** Actors returned with one Incident. */
  actorsListed: 10,
  /** Characters of an allowlist entry's note, after trimming. */
  noteMax: 80,
} as const;

/** `active` until `expires_at`, then `expired`; `lifted` when an admin ended it early. Computed by the API. */
export const CONTAINMENT_STATUSES = ["active", "expired", "lifted"] as const;
export type ContainmentStatus = (typeof CONTAINMENT_STATUSES)[number];

/** The prefix lengths an allowlist CIDR may have, by IP version. */
export const CIDR_PREFIX_BOUNDS = deepFreeze({ 4: { min: 8, max: 32 }, 6: { min: 16, max: 128 } } as const);

/** An actor hash: `iph_` and 32 lowercase hex characters (`actorHash` of the server entry). */
export const ActorHashSchema = z.string().regex(ACTOR_HASH_PATTERN);

const IpPrefixSchema = z.string().regex(IP_PREFIX_PATTERN);
/** The id of the admin key that acted. */
const KeyIdSchema = z.string().regex(ID_PATTERNS.key);

/** What a Containment blocks: one Actor, or every client of one Event network prefix. */
export const ContainmentTargetSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("actor"), ip_hash: ActorHashSchema }),
  z.object({ kind: z.literal("prefix"), ip_prefix: IpPrefixSchema }),
]);
export type ContainmentTarget = z.infer<typeof ContainmentTargetSchema>;

/** One Containment of one App and Environment. Never deleted: lifting records who and when. */
export const ContainmentSchema = z
  .object({
    id: z.string().regex(ID_PATTERNS.cnt),
    app_id: z.string().regex(ID_PATTERNS.app),
    environment: z.enum(ENVIRONMENTS),
    /** The Incident it was created from. */
    incident_id: z.string().regex(ID_PATTERNS.inc).nullable(),
    target: ContainmentTargetSchema,
    created_at: z.iso.datetime(),
    expires_at: z.iso.datetime(),
    created_by: KeyIdSchema,
    lifted_at: z.iso.datetime().nullable(),
    lifted_by: KeyIdSchema.nullable(),
    status: z.enum(CONTAINMENT_STATUSES),
  })
  .refine(
    (containment) =>
      (containment.status === "lifted") === (containment.lifted_at !== null) &&
      (containment.lifted_at !== null) === (containment.lifted_by !== null),
    { message: "A lifted Containment, and only a lifted one, carries who lifted it and when.", path: ["status"] },
  );
export type Containment = z.infer<typeof ContainmentSchema>;

/**
 * Body of `POST /v1/incidents/:incidentId/containments`. An actor block names an actor hash of the Incident.
 * A prefix block always uses the Incident's own prefix (a prefix sent in `target` is stripped) and needs
 * `confirm_prefix`, the prefix as the admin typed it; whether it equals the Incident's is the API's check.
 */
export const CreateContainmentRequestSchema = z
  .object({
    target: z.discriminatedUnion("kind", [
      z.object({ kind: z.literal("actor"), ip_hash: ActorHashSchema }),
      z.object({ kind: z.literal("prefix") }),
    ]),
    ttl_s: z.literal(CONTAINMENT_TTLS),
    confirm_prefix: IpPrefixSchema.optional(),
  })
  .refine((request) => request.target.kind !== "prefix" || request.confirm_prefix !== undefined, {
    message: "Blocking a network needs its prefix typed as confirmation.",
    path: ["confirm_prefix"],
  });
export type CreateContainmentRequest = z.infer<typeof CreateContainmentRequestSchema>;

/** 201 (or 200 for an existing active block) of the create route; 200 of `POST /v1/containments/:id/lift`. */
export const ContainmentResponseSchema = z.object({ containment: ContainmentSchema });
export type ContainmentResponse = z.infer<typeof ContainmentResponseSchema>;

/** 200 of `GET /v1/containments`, newest first. */
export const ListContainmentsResponseSchema = z.object({ containments: z.array(ContainmentSchema) });
export type ListContainmentsResponse = z.infer<typeof ListContainmentsResponseSchema>;

/** A CIDR in canonical text (see the top of this module). Anything else is refused, not rewritten. */
export const CidrSchema = z
  .string()
  .refine(
    (value) => parseCidr(value)?.cidr === value,
    "Must be a normalised CIDR: IPv4 /8 to /32 or IPv6 /16 to /128, host bits zero, such as 203.0.113.0/24 or 2001:db8::/32.",
  );

/** One never-block range of an Organization. */
export const AllowlistEntrySchema = z.object({
  id: z.string().regex(ID_PATTERNS.alw),
  cidr: CidrSchema,
  /** Why the range must never be blocked; may be empty. */
  note: text(CONTAINMENT_LIMITS.noteMax),
  created_at: z.iso.datetime(),
  created_by: KeyIdSchema,
});
export type AllowlistEntry = z.infer<typeof AllowlistEntrySchema>;

/** Body of `POST /v1/allowlist`. The note is trimmed first and may be empty. */
export const CreateAllowlistEntryRequestSchema = z.object({
  cidr: CidrSchema,
  note: z.string().trim().pipe(text(CONTAINMENT_LIMITS.noteMax)),
});
export type CreateAllowlistEntryRequest = z.infer<typeof CreateAllowlistEntryRequestSchema>;

/** 201 of `POST /v1/allowlist`: the entry created. */
export const AllowlistEntryResponseSchema = z.object({ entry: AllowlistEntrySchema });
export type AllowlistEntryResponse = z.infer<typeof AllowlistEntryResponseSchema>;

/** 200 of `GET /v1/allowlist`. */
export const ListAllowlistResponseSchema = z.object({
  entries: z.array(AllowlistEntrySchema).max(CONTAINMENT_LIMITS.allowlistMax),
});
export type ListAllowlistResponse = z.infer<typeof ListAllowlistResponseSchema>;

// Addresses and CIDRs.

/** A parsed address: 16-bit words, most significant first: 2 for IPv4, 8 for IPv6. Frozen. */
export interface ParsedAddress {
  readonly version: 4 | 6;
  readonly words: readonly number[];
}

/** A parsed CIDR: the network address, its prefix length and its canonical text. Frozen. */
export interface ParsedCidr extends ParsedAddress {
  readonly prefix: number;
  readonly cidr: string;
}

/** Longest address text (IPv6 with a dotted tail is 45 characters) plus a zone id. */
const ADDRESS_TEXT_MAX = 128;
const OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
const IPV4 = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);
const HEXTET = /^[0-9A-Fa-f]{1,4}$/;
const PREFIX_LENGTH = /^[1-9][0-9]{0,2}$/;

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
      words.push(...tail);
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
  return [...head, ...new Array<number>(8 - head.length - tail.length).fill(0), ...tail];
}

const isMapped = (words: readonly number[]): boolean =>
  words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0xffff;

function ipv4Text(words: readonly number[]): string {
  const [high, low] = words as [number, number];
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

/** RFC 5952 section 4 text of eight words. */
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

/** Whether the first `bits` bits of two word lists are equal. */
function samePrefix(a: readonly number[], b: readonly number[], bits: number): boolean {
  const whole = bits >> 4;
  for (let i = 0; i < whole; i++) if (a[i] !== b[i]) return false;
  const rest = bits & 15;
  if (rest === 0) return true;
  const mask = (0xffff << (16 - rest)) & 0xffff;
  return (((a[whole] as number) ^ (b[whole] as number)) & mask) === 0;
}

/**
 * An IPv4 or IPv6 address given as text; null for anything else (no trimming, no port, no brackets, no
 * leading zeros in an IPv4 octet). An IPv6 zone id (`%eth0`) is stripped. An IPv4-mapped IPv6 address, in any
 * spelling, is returned as its IPv4 address.
 */
export function parseAddress(value: unknown): ParsedAddress | null {
  if (typeof value !== "string" || value.length === 0 || value.length > ADDRESS_TEXT_MAX) return null;
  if (!value.includes(":")) {
    const words = ipv4Words(value);
    return words === null ? null : deepFreeze({ version: 4, words });
  }
  const zone = value.indexOf("%");
  if (zone === value.length - 1) return null;
  const words = ipv6Words(zone === -1 ? value : value.slice(0, zone));
  if (words === null) return null;
  return isMapped(words) ? deepFreeze({ version: 4, words: words.slice(6) }) : deepFreeze({ version: 6, words });
}

/**
 * A CIDR given as text; null unless it is a valid address, "/", and a length within `CIDR_PREFIX_BOUNDS`
 * with every host bit zero. IPv6 may be spelled in any valid way (upper case, uncompressed); `cidr` of the
 * result is the canonical text. A zone id and an IPv6 CIDR inside the IPv4-mapped block are refused.
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
  const bounds = CIDR_PREFIX_BOUNDS[version];
  if (prefix < bounds.min || prefix > bounds.max) return null;
  if (version === 6 && prefix >= 96 && isMapped(words)) return null;
  for (let i = 0; i < words.length; i++) {
    const bits = Math.min(16, Math.max(0, prefix - 16 * i));
    const hostMask = 0xffff >> bits;
    if (((words[i] as number) & hostMask) !== 0) return null;
  }
  const cidr = `${version === 6 ? ipv6Text(words) : ipv4Text(words)}/${prefix}`;
  return deepFreeze({ version, words, prefix, cidr });
}

/**
 * Whether the address lies inside the CIDR. Both may be text or already parsed (parse once, match often).
 * False for an invalid or non-normalised CIDR, an invalid or unknown address, and across IP versions (an
 * IPv4-mapped IPv6 address counts as IPv4).
 */
export function cidrContains(cidr: string | ParsedCidr, address: string | ParsedAddress | null | undefined): boolean {
  const range = typeof cidr === "string" ? parseCidr(cidr) : cidr;
  const subject = typeof address === "string" ? parseAddress(address) : address;
  if (range === null || typeof range !== "object" || subject === null || typeof subject !== "object") return false;
  return range.version === subject.version && samePrefix(range.words, subject.words, range.prefix);
}

/**
 * Whether the CIDR and an Event network prefix (`a.b.c.0/24` or `x:y:z::/48`, `IP_PREFIX_PATTERN`) share
 * any address: one contains the other. False for an invalid CIDR, any other prefix form, and across versions.
 */
export function cidrOverlapsPrefix(cidr: string | ParsedCidr, ipPrefix: string): boolean {
  const range = typeof cidr === "string" ? parseCidr(cidr) : cidr;
  if (range === null || typeof range !== "object") return false;
  if (typeof ipPrefix !== "string" || !IP_PREFIX_PATTERN.test(ipPrefix)) return false;
  const address = ipPrefix.slice(0, ipPrefix.indexOf("/"));
  const version = address.includes(":") ? 6 : 4;
  const words = version === 6 ? ipv6Words(address) : ipv4Words(address);
  if (words === null || version !== range.version) return false;
  return samePrefix(range.words, words, Math.min(range.prefix, version === 6 ? 48 : 24));
}

// Documented examples, reused by the tests of every workspace. They are synthetic and deeply frozen.

/**
 * An active one-hour block of one Actor, created from `EXAMPLE_INCIDENT`. The hash is `actorHash` of the
 * synthetic Shield key (`ark_dev_` followed by 43 times `A`) and the address 203.0.113.7.
 */
export const EXAMPLE_CONTAINMENT: Containment = deepFreeze({
  id: "cnt_0123456789abcdef01234567",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  incident_id: "inc_0123456789abcdef01234567",
  target: { kind: "actor", ip_hash: "iph_2932b22cf89905dbc929c64247ddad3e" },
  created_at: "2026-11-10T08:21:00.000Z",
  expires_at: "2026-11-10T09:21:00.000Z",
  created_by: "key_0123456789abcdef01234567",
  lifted_at: null,
  lifted_by: null,
  status: "active",
});

/** A never-block range as the API returns it. */
export const EXAMPLE_ALLOWLIST_ENTRY: AllowlistEntry = deepFreeze({
  id: "alw_0123456789abcdef01234567",
  cidr: "198.51.100.0/24",
  note: "Office network",
  created_at: "2026-11-10T08:00:00.000Z",
  created_by: "key_0123456789abcdef01234567",
});
