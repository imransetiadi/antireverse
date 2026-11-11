// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ID_PATTERNS } from "./constants.ts";
import { parseAddress } from "./containment.ts";

// The Clone Beacon contract. Harden plants a beacon statement carrying a per-Build token (`deriveBeaconToken`
// of the server entry) and the origins the developer allowed; a copy of the bundle running on any other,
// non-local origin sends one report `{ a, t, o }` (App id, token, origin) to `POST /v1/beacon`. Every object schema is a plain
// `z.object`, which strips unknown keys.
//
// Canonical origin text (the only form `OriginSchema` accepts; `canonicalOrigin` produces it):
//   `scheme://host[:port]`, scheme `http` or `https`, ≤ 255 characters, exactly as a browser serialises
//   `location.origin` (the WHATWG URL origin): host in lower case, an IDN as punycode (`xn--`), an IPv4 address
//   in dotted decimal, an IPv6 address in brackets in RFC 5952 section 4 form (as `parseCidr` writes it), the
//   port omitted when it is the scheme's default. No path (an input may end in a single "/"), no query, no
//   fragment, no userinfo, no white space, control character or backslash anywhere in the input.
// Host canonicalisation (IDN to punycode, IPv6 compression) uses the global WHATWG `URL`, present in every
// browser and in Node without an import; the strict shape check before it refuses what `URL` would forgive.

export const BEACON_LIMITS = {
  /** Allowed origins of one Build. */
  originsMax: 20,
  /** Bytes of a report body the API reads. */
  bodyBytesMax: 1024,
  /** Distinct new origins counted per Build per hour (per API process). */
  newOriginsPerHour: 20,
  /** Reports counted per Build per hour (per API process). */
  reportsPerHour: 600,
} as const;

/**
 * A Build's Clone Beacon token: `bcn_` followed by 24 lowercase hex characters (`deriveBeaconToken` of the
 * server entry). It is derived, never generated, so it is not one of `ID_PATTERNS` (like the actor hash).
 */
export const BEACON_TOKEN_PATTERN = /^bcn_[0-9a-f]{24}$/;

/** Characters of a canonical origin. */
const ORIGIN_MAX = 255;
/** Characters of an input `canonicalOrigin` looks at: a non-canonical spelling may be longer than its result. */
const INPUT_MAX = 1024;
/** `scheme://authority` with an optional single "/": no userinfo, path, query, fragment, space or backslash. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point.
const ORIGIN_SHAPE = /^(https?):\/\/([^/?#@\\\s\u0000-\u001f\u007f]+)\/?$/i;

/**
 * The canonical text of an http or https origin, or null when the input is not one (see the rules at the top
 * of this module). The result is its own canonical form.
 */
export function canonicalOrigin(text: unknown): string | null {
  if (typeof text !== "string" || text.length > INPUT_MAX) return null;
  const shape = ORIGIN_SHAPE.exec(text);
  if (shape === null) return null;
  let url: URL;
  try {
    url = new URL(`${(shape[1] as string).toLowerCase()}://${shape[2] as string}/`);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username !== "" || url.password !== "" || url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    return null;
  }
  if (url.hostname === "") return null;
  const origin = url.origin;
  return origin.length <= ORIGIN_MAX ? origin : null;
}

const LOCAL_SUFFIXES = [".localhost", ".local", ".test", ".internal"] as const;

function isLocalAddress(host: string): boolean | null {
  const address = parseAddress(host);
  if (address === null) return null;
  const words = address.words;
  const w0 = words[0] as number;
  if (words.every((word) => word === 0)) return true; // 0.0.0.0 and :: (unspecified; mapped forms are IPv4)
  if (address.version === 4) {
    const first = w0 >> 8;
    return (
      first === 127 || // 127.0.0.0/8 loopback
      first === 10 || // 10.0.0.0/8 private
      (w0 & 0xfff0) === 0xac10 || // 172.16.0.0/12 private
      w0 === 0xc0a8 || // 192.168.0.0/16 private
      w0 === 0xa9fe // 169.254.0.0/16 link-local
    );
  }
  const loopback = words.slice(0, 7).every((word) => word === 0) && words[7] === 1; // ::1
  return loopback || (w0 & 0xfe00) === 0xfc00 || (w0 & 0xffc0) === 0xfe80; // fc00::/7, fe80::/10
}

/**
 * Whether an origin is local and so never reported, by the beacon or by the API: host `localhost` or ending in
 * `.localhost`, `.local`, `.test` or `.internal` (a trailing dot ignored); IPv4 127/8, 10/8, 172.16/12,
 * 192.168/16, 169.254/16 and the unspecified 0.0.0.0; IPv6 ::1, the unspecified ::, fc00::/7, fe80::/10, an IPv4-mapped IPv6 address judged as its IPv4
 * address. Anything that is not an http or https origin (`null`, `file:`, an extension, malformed text) is
 * local too: only a well-formed foreign origin is ever reported.
 */
export function isLocalOrigin(origin: string): boolean {
  const canonical = canonicalOrigin(origin);
  if (canonical === null) return true;
  const authority = canonical.slice(canonical.indexOf("://") + 3);
  if (authority.startsWith("[")) {
    return isLocalAddress(authority.slice(1, authority.indexOf("]"))) ?? true;
  }
  const colon = authority.lastIndexOf(":");
  const host = colon === -1 ? authority : authority.slice(0, colon);
  const address = isLocalAddress(host);
  if (address !== null) return address;
  const name = host.endsWith(".") ? host.slice(0, -1) : host;
  return name === "localhost" || LOCAL_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

/** A canonical http or https origin: only text that `canonicalOrigin` leaves unchanged. */
export const OriginSchema = z
  .string()
  .max(ORIGIN_MAX)
  .refine((value) => canonicalOrigin(value) === value, "Must be a canonical http or https origin.");

/** A Build's beacon token: `bcn_` followed by 24 lowercase hex characters (`deriveBeaconToken`). */
export const BeaconTokenSchema = z.string().regex(BEACON_TOKEN_PATTERN);

/**
 * The body of `POST /v1/beacon`: the App id the beacon was planted for, its token and the page's
 * `location.origin`. A token names a Build only within its App (tokens are unique per App). Whether `o` is
 * canonical, local or allowed is the API's decision; here it is only bounded.
 */
export const BeaconReportSchema = z.object({
  a: z.string().regex(ID_PATTERNS.app),
  t: BeaconTokenSchema,
  o: z.string().max(ORIGIN_MAX),
});
export type BeaconReport = z.infer<typeof BeaconReportSchema>;

/** The allowed origins of a Build: 1..20 canonical origins, each once, none local. */
const AllowedOriginsSchema = z
  .array(OriginSchema)
  .min(1)
  .max(BEACON_LIMITS.originsMax)
  .refine((origins) => new Set(origins).size === origins.length, { message: "Must not list an origin twice." })
  .refine((origins) => !origins.some(isLocalOrigin), { message: "Must not list a local origin." });

/** The beacon a Manifest records: the token planted in the bundle and the allowed origins. */
export const ManifestBeaconSchema = z.object({
  token: BeaconTokenSchema,
  origins: AllowedOriginsSchema,
});
export type ManifestBeacon = z.infer<typeof ManifestBeaconSchema>;

/** The beacon as a Build response shows it: the allowed origins only; a token given here is stripped. */
export const BuildBeaconSchema = z.object({
  origins: AllowedOriginsSchema,
});
export type BuildBeacon = z.infer<typeof BuildBeaconSchema>;
