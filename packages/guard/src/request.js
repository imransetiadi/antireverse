// What a signed request is made of: the resolved URL, the body bytes and the merged fetch init. Every function may
// throw; the caller (guard.js) turns any failure into an unsigned request.

/** @param {unknown} value */
const tag = (value) => Object.prototype.toString.call(value);

/**
 * The URL the browser will request: `url` resolved against `location.href` (absolute URLs need no base). Throws
 * for a URL that does not parse.
 * @param {unknown} url
 * @param {unknown} location
 */
export function resolveUrl(url, location) {
  if (typeof url !== "string") throw new TypeError("url must be a string");
  const base = /** @type {{ href?: unknown } | null} */ (location)?.href;
  return typeof base === "string" ? new URL(url, base) : new URL(url);
}

/**
 * What a signed request is sent to and signs (review F4): the resolved URL serialised as fetch serialises it, without
 * its fragment (`href`), and the request target exactly as it goes on the wire — `href` from the path on, so an
 * empty query (`/a?`) stays as it is. Throws for a URL that is not http or https.
 * @param {URL} resolved
 * @returns {{ href: string, target: string }}
 */
export function serialised(resolved) {
  if (resolved.protocol !== "http:" && resolved.protocol !== "https:") throw new TypeError("not an http(s) URL");
  const whole = resolved.href;
  // A `#` before the fragment is percent-encoded in a serialised URL: the first one starts the fragment.
  const cut = whole.indexOf("#");
  const href = cut === -1 ? whole : whole.slice(0, cut);
  // After `scheme://` the authority holds no `/` (a `/` in userinfo is percent-encoded): the next one starts the path.
  const start = href.indexOf("/", resolved.protocol.length + 2);
  if (start === -1) throw new TypeError("no path");
  return { href, target: href.slice(start) };
}

/** What fetch sends as the content type of a string body. */
export const TEXT_CONTENT_TYPE = "text/plain;charset=UTF-8";
/** What fetch sends as the content type of a URLSearchParams body. */
export const FORM_CONTENT_TYPE = "application/x-www-form-urlencoded;charset=UTF-8";

/**
 * The content type fetch itself sends for `body` when the caller set none (review F1): a string `text/plain`, a
 * URLSearchParams form-urlencoded (both with `;charset=UTF-8`), a Blob its own type when it has one; null for no
 * body, bytes and a Blob without a type (fetch sends none).
 * @param {unknown} body
 * @returns {string | null}
 */
export function defaultContentType(body) {
  if (typeof body === "string") return TEXT_CONTENT_TYPE;
  if (typeof body !== "object" || body === null) return null;
  if (tag(body) === "[object URLSearchParams]") return FORM_CONTENT_TYPE;
  if (tag(body) === "[object ArrayBuffer]" || ArrayBuffer.isView(body)) return null;
  const type = /** @type {{ type?: unknown }} */ (body).type;
  return typeof type === "string" && type !== "" ? type : null;
}

/**
 * The `content-type` the caller's headers carry, as the Headers class reads it (combined and trimmed as it is
 * sent), or null when they carry none. Throws when headers are given but cannot be read.
 * @param {unknown} source
 * @param {unknown} Headers The Headers class, or null.
 * @returns {string | null}
 */
export function callerContentType(source, Headers) {
  if (source === undefined) return null;
  if (typeof Headers !== "function") throw new TypeError("Headers is unavailable");
  const list = new /** @type {typeof globalThis.Headers} */ (Headers)(/** @type {HeadersInit} */ (source));
  return list.get("content-type");
}

/**
 * The headers fetch will send for a call: the init's, or, as fetch does, the Request's when the init has none.
 * @param {unknown} input
 * @param {RequestInit | undefined} init
 * @returns {HeadersInit | undefined}
 */
export function callerHeaders(input, init) {
  return init?.headers !== undefined ? init.headers : isRequest(input) ? input.headers : undefined;
}

/**
 * The exact bytes fetch sends for `body`: null for no body, undefined for a body Guard does not sign (FormData,
 * ReadableStream, SharedArrayBuffer and anything else). Strings and URLSearchParams are UTF-8, as fetch encodes them.
 * @param {unknown} body
 * @returns {Promise<Uint8Array | null | undefined>}
 */
export async function bodyBytes(body) {
  if (body === undefined || body === null) return null;
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (typeof body !== "object") return undefined;
  if (tag(body) === "[object ArrayBuffer]") return new Uint8Array(/** @type {ArrayBuffer} */ (body));
  if (ArrayBuffer.isView(body)) {
    if (tag(body.buffer) !== "[object ArrayBuffer]") return undefined; // a view over shared memory
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }
  if (tag(body) === "[object URLSearchParams]") return new TextEncoder().encode(String(body));
  const blob = /** @type {{ arrayBuffer?: unknown, size?: unknown, type?: unknown, slice?: unknown }} */ (body);
  if (
    typeof blob.arrayBuffer === "function" &&
    typeof blob.slice === "function" &&
    typeof blob.size === "number" &&
    typeof blob.type === "string"
  ) {
    return new Uint8Array(await /** @type {Blob} */ (body).arrayBuffer());
  }
  return undefined;
}

/**
 * Whether `input` is a Request (or looks like one: a url and a method).
 * @param {unknown} input
 * @returns {input is Request}
 */
export function isRequest(input) {
  if (typeof input !== "object" || input === null) return false;
  const request = /** @type {{ url?: unknown, method?: unknown }} */ (input);
  return typeof request.url === "string" && typeof request.method === "string";
}

/**
 * The init to send: the caller's init with its headers (or, as fetch does, the Request's when the init has none)
 * as a plain record of lower-case names, and Guard's headers set over them. Nothing else is added or changed; in
 * particular no `credentials`. Throws when the caller's headers cannot be read.
 * @param {unknown} input
 * @param {RequestInit | undefined} init
 * @param {Record<string, string>} guardHeaders
 * @param {unknown} Headers The Headers class, or null.
 * @returns {RequestInit}
 */
export function mergeInit(input, init, guardHeaders, Headers) {
  const source = callerHeaders(input, init);
  /** @type {Record<string, string>} */
  const headers = {};
  if (source !== undefined) {
    if (typeof Headers !== "function") throw new TypeError("Headers is unavailable");
    const list = new /** @type {typeof globalThis.Headers} */ (Headers)(source);
    // Browsers yield lower-case names already; lower-casing makes a caller's `AR-Signature` one name with Guard's.
    list.forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });
  }
  for (const [name, value] of Object.entries(guardHeaders)) headers[name] = value;
  return { ...init, headers };
}
