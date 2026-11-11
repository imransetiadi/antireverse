// Device id and session key. Every function may throw; the caller (guard.js) turns any failure into `null`.
import { PATTERNS } from "./constants.js";

/** @typedef {import("./index.js").GuardCrypto} GuardCrypto */
/** @typedef {{ kty: "EC", crv: "P-256", x: string, y: string }} PublicJwk */

/**
 * Base64url without padding.
 * @param {Uint8Array} bytes
 */
export function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * A new device id: 128 random bits as 22 base64url characters.
 * @param {GuardCrypto} crypto
 */
export function randomDeviceId(crypto) {
  return base64url(crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * RFC 7638 thumbprint of an EC P-256 public JWK: SHA-256 over `{"crv","kty","x","y"}` in that order, no white
 * space, as base64url.
 * @param {GuardCrypto} crypto
 * @param {unknown} jwk
 */
export async function jwkThumbprint(crypto, jwk) {
  const { kty, crv, x, y } = /** @type {{ kty?: unknown, crv?: unknown, x?: unknown, y?: unknown }} */ (jwk ?? {});
  if (kty !== "EC" || crv !== "P-256" || typeof x !== "string" || typeof y !== "string") {
    throw new TypeError("not a P-256 public key");
  }
  if (!PATTERNS.coordinate.test(x) || !PATTERNS.coordinate.test(y)) throw new TypeError("bad coordinate");
  const subtle = requireSubtle(crypto);
  const canonical = `{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`;
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return base64url(new Uint8Array(digest));
}

/** @param {GuardCrypto} crypto */
function requireSubtle(crypto) {
  const subtle = crypto.subtle;
  if (!subtle) throw new TypeError("WebCrypto is unavailable");
  return subtle;
}

/**
 * Creates the session key: ECDSA P-256 with a non-extractable private key (request signing, slice 04), its public
 * half as a JWK of the four public members only (`cnf.jwk`; never `d`, `ext` or `key_ops`) and the thumbprint of
 * that JWK (`cnf.jkt`).
 * @param {GuardCrypto} crypto
 * @returns {Promise<{ pair: { publicKey: unknown, privateKey: unknown }, jwk: PublicJwk, jkt: string }>}
 */
export async function createSessionKey(crypto) {
  const subtle = requireSubtle(crypto);
  const generated = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const pair = /** @type {{ publicKey?: unknown, privateKey?: unknown } | null} */ (generated);
  if (!pair?.publicKey || !pair.privateKey) throw new TypeError("no key pair");
  const exported = /** @type {{ x?: unknown, y?: unknown } | null} */ (await subtle.exportKey("jwk", pair.publicKey));
  /** @type {PublicJwk} */
  const jwk = { kty: "EC", crv: "P-256", x: String(exported?.x), y: String(exported?.y) };
  const jkt = await jwkThumbprint(crypto, jwk); // also refuses coordinates that are not canonical
  return { pair: { publicKey: pair.publicKey, privateKey: pair.privateKey }, jwk, jkt };
}

/**
 * Base64url SHA-256 of bytes.
 * @param {GuardCrypto} crypto
 * @param {Uint8Array} bytes
 */
export async function sha256(crypto, bytes) {
  return base64url(new Uint8Array(await requireSubtle(crypto).digest("SHA-256", bytes)));
}

/**
 * ECDSA P-256 / SHA-256 signature of the UTF-8 bytes of `text`, as base64url. WebCrypto returns the IEEE P1363
 * form (64 bytes r‖s) the protocol requires; any other length is refused.
 * @param {GuardCrypto} crypto
 * @param {unknown} privateKey
 * @param {string} text
 */
export async function signText(crypto, privateKey, text) {
  const subtle = requireSubtle(crypto);
  if (typeof subtle.sign !== "function") throw new TypeError("signing is unavailable");
  const signature = new Uint8Array(
    await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, new TextEncoder().encode(text)),
  );
  if (signature.byteLength !== 64) throw new TypeError("not a P1363 signature");
  return base64url(signature);
}

/**
 * The `jti` of a compact JWS, read from its payload without verification (the server verifies the token); throws
 * when the payload is not base64url JSON or the jti is not 32 hex characters.
 * @param {string} token
 */
export function tokenJti(token) {
  const part = token.split(".")[1] ?? "";
  const binary = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  const claims = /** @type {{ jti?: unknown } | null} */ (JSON.parse(new TextDecoder().decode(bytes)));
  const jti = claims?.jti;
  if (typeof jti !== "string" || !PATTERNS.jti.test(jti)) throw new TypeError("no jti");
  return jti;
}
