// The Clone Beacon statement (slice 10). Planted beside the Canaries, after all transforms, as plain text. It is
// one self-contained statement: an IIFE in try/catch that does nothing unless `location`, `navigator` and
// `navigator.sendBeacon` exist; reads `location.origin`; returns when the origin is allowed or local; otherwise
// calls `navigator.sendBeacon("<endpoint>/v1/beacon", JSON.stringify({a:"<appId>",t:"<token>",o:origin}))` once
// (review F4: the App id travels with the report). No global binding (everything is a local of the IIFE), no
// timers, no listeners, no other side effect. Every embedded string goes through JSON.stringify with `<`, `>`
// and `&` escaped as \u003c, \u003e, \u0026 (review F6: the bundle may be inlined in HTML), and every input is
// validated first, so nothing can break out of a literal or a <script> element.
//
// Trailing dot (review F2): a browser keeps a host's trailing dot in `location.origin`
// (`http://shop.example.:8080`). The page origin is compared with ONE trailing dot removed from its host, and the
// local check runs on that host too, as `isLocalOrigin` does; allowed origins are embedded the same way. The
// report still carries the origin exactly as the browser gave it.
//
// Size: at most 700 bytes before gzip apart from the embedded origins (Jev: restore_guards, 0.94; the plan's
// 600 bytes for 20 origins cannot hold the local check). About 670 bytes with one origin.
//
// The client-side local check mirrors the protocol's `isLocalOrigin` for the host forms a browser produces in
// `location.origin` (the WHATWG serialisation: lower-case host, punycode IDN, dotted-decimal IPv4, bracketed
// RFC 5952 IPv6). It is one regular expression over the host (brackets and port removed):
//   names     `localhost`, `*.localhost`, `*.local`, `*.test`, `*.internal`, each with an optional trailing dot;
//   IPv4      127/8, 10/8, 172.16/12, 192.168/16, 169.254/16 (a host of digits and dots is always an IPv4
//             address once a browser has serialised it), and exactly 0.0.0.0;
//   IPv6      `::`, `::1`, fc00::/7 (a 4-digit first group fc.. or fd..), fe80::/10 (fe8. to feb.);
//   mapped    `::ffff:X:Y` judged as its IPv4 address: X is the high word, so 7f.. = 127/8, a.. = 10/8,
//             ac1. = 172.16/12, c0a8 = 192.168/16, a9fe = 169.254/16, and `::ffff:0:0` = 0.0.0.0.
// Anything that is not `http(s)://host[:port]` (`null`, `file://`, an extension origin) does not match the
// shape and is treated as local: only a well-formed foreign origin is ever reported. The test suite pins this
// against `isLocalOrigin` over a corpus by running the statement in a `vm` context.
import { BEACON_TOKEN_PATTERN, ID_PATTERNS, ManifestBeaconSchema } from "@antireverse/protocol";

/** The beacon a Build plants: its App id, token, the allowed origins and the API base URL reports go to. */
export interface BeaconConfig {
  appId: string;
  token: string;
  origins: readonly string[];
  endpoint: string;
}

// The host of an http(s) origin: group 2 is a bracketed IPv6 address, group 1 otherwise; an optional port.
// Applied to the origin with one trailing dot already removed from its host.
const SHAPE = String.raw`/^https?:\/\/(\[(.+)\]|[^:\/]+)(:\d+)?$/`;
// One trailing dot of the host (just before the optional port, at the end of the origin).
const TRAILING_DOT = String.raw`/\.(?=(:\d+)?$)/`;
// The local hosts (see the header). Kept as source text: it is embedded verbatim in the planted statement.
const LOCAL = String.raw`/(^|\.)localhost$|\.(local|test|internal)$|^(127|10|172\.(1[6-9]|2\d|3[01])|192\.168|169\.254)\.[\d.]+$|^0\.0\.0\.0$|^::(1|ffff:(0:0|(7f\w\w|a\w\w|ac1\w|c0a8|a9fe):\w+))?$|^f[cd]\w\w:|^fe[89ab]\w:/`;

/**
 * The report URL for an `--endpoint` value: any trailing slash removed, then `/v1/beacon`. Throws unless the
 * endpoint is a plain http(s) URL: no credentials (the URL ends up in a public bundle), query, fragment, white
 * space or control character.
 */
export function beaconEndpointUrl(endpoint: string): string {
  const refuse = (why: string): never => {
    throw new Error(`harden: the Clone Beacon endpoint must be a plain http(s) URL (${why})`);
  };
  // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point.
  if (typeof endpoint !== "string" || endpoint.length === 0 || /[\s\u0000-\u001f\u007f<>]/.test(endpoint)) {
    refuse("empty, or white space, a control character, < or >");
  }
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return refuse("not a URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") refuse("scheme is not http or https");
  if (url.username !== "" || url.password !== "") refuse("credentials are not allowed");
  if (url.search !== "" || url.hash !== "" || endpoint.includes("?") || endpoint.includes("#")) {
    refuse("query or fragment");
  }
  return `${endpoint.replace(/\/+$/, "")}/v1/beacon`;
}

/** A JS string literal for `value`, safe inside an HTML <script> element too (review F6). */
function literal(value: string): string {
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
}

/** An origin with one trailing dot removed from its host (review F2). */
function withoutTrailingDot(origin: string): string {
  return origin.replace(/\.(?=(:\d+)?$)/, "");
}

/**
 * The planted Clone Beacon statement for a Build. Deterministic: the same App id, token, origins (in order) and
 * endpoint give the same text. Throws on an App id that is not `app_<24 hex>`, a token that is not
 * `bcn_<24 hex>`, origins that are not 1..20 distinct canonical non-local origins, and an endpoint
 * `beaconEndpointUrl` refuses.
 */
export function beaconStatement(appId: string, token: string, origins: readonly string[], endpoint: string): string {
  if (typeof appId !== "string" || !ID_PATTERNS.app.test(appId)) {
    throw new Error("harden: the Clone Beacon needs the App id (app_ followed by 24 lowercase hex characters)");
  }
  if (typeof token !== "string" || !BEACON_TOKEN_PATTERN.test(token)) {
    throw new Error("harden: the Clone Beacon token must be bcn_ followed by 24 lowercase hex characters");
  }
  const parsed = ManifestBeaconSchema.safeParse({ token, origins: [...origins] });
  if (!parsed.success) {
    throw new Error(
      "harden: the Clone Beacon origins must be 1 to 20 distinct canonical http(s) origins, none of them local",
    );
  }
  const url = beaconEndpointUrl(endpoint);
  // Canonical origins hold no white space, so one space-separated string (padded) is an exact membership test.
  const list = literal(` ${[...new Set(origins.map(withoutTrailingDot))].join(" ")} `);
  return (
    ";(function(){try{" +
    // The typeof guards return before anything is touched outside a browser, so nothing throws there at all
    // (Jev: restore_guards, 0.94). A non-string origin throws a TypeError inside the try and is swallowed.
    'if(typeof location>"u"||typeof navigator>"u"||typeof navigator.sendBeacon!="function")return;' +
    `var o=location.origin,n=o.replace(${TRAILING_DOT},""),m=${SHAPE}.exec(n);` +
    `if(!m||${list}.indexOf(" "+n+" ")>=0||${LOCAL}.test(m[2]||m[1]))return;` +
    `navigator.sendBeacon(${literal(url)},JSON.stringify({a:${literal(appId)},t:${literal(token)},o:o}))` +
    "}catch(e){}})();"
  );
}
