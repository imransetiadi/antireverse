import { Resolver as DnsResolver } from "node:dns/promises";
import type { ClientRequest, IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, connect as netConnect, type Socket } from "node:net";
import { Duplex } from "node:stream";
import { type TLSSocket, connect as tlsConnect } from "node:tls";
import {
  challengeRecordName,
  type DnsVerifyFailure,
  type FileVerifyFailure,
  matchesDnsChallenge,
  matchesFileChallenge,
  normaliseHost,
  TARGET_LIMITS,
  VERIFICATION_FILE_PATH,
  type VerificationMethod,
} from "@antireverse/protocol";
import { isPublicAddress } from "./address.ts";

// Ownership checks of Verified Targets (slice 14, D-069): the DNS TXT record first, then the well-known file over
// a guarded HTTPS GET. Both reach the network through two seams that `createApp` and `startApi` accept as deps:
// `Resolver` (TXT, A and AAAA) and `Fetcher` (the guarded GET). Production uses `createDnsResolver` and
// `createGuardedFetcher`; tests pass fakes, or the guarded fetcher with its explicit test-only option pointed at a
// local TLS server. A token is never logged and never leaves this module except in the comparison.

/** The DNS seam. Both methods reject (with the node:dns `code`) when the name has no answer or the lookup fails. */
export interface Resolver {
  /** The TXT records at `name`, each a list of chunks as `dns.resolveTxt` returns them. */
  txt(name: string): Promise<string[][]>;
  /** Every A and AAAA address of `host`. Rejects unless both families answered (an empty family is fine). */
  addresses(host: string): Promise<string[]>;
}

/**
 * Why the file method failed, as the API knows it internally: the protocol's reasons, except that `not_reachable`
 * is split into `resolve_failed` (the name did not resolve) and `address_not_public` (the SSRF guard refused an
 * address). The split is kept for the re-check rule and for counts only; a response or a target record only ever
 * says `not_reachable` (`publicFileFailure`).
 */
export type FileCheckFailure = Exclude<FileVerifyFailure, "not_reachable"> | "resolve_failed" | "address_not_public";

/** The protocol reason of an internal file failure. */
export function publicFileFailure(failure: FileCheckFailure): FileVerifyFailure {
  return failure === "resolve_failed" || failure === "address_not_public" ? "not_reachable" : failure;
}

/** The outcome of the guarded GET of `https://<host>/.well-known/airverse-verification.txt`. */
export type FetchOutcome = { ok: true; body: string } | { ok: false; reason: Exclude<FileCheckFailure, "mismatch"> };

/** The file seam: fetches the verification file of a normalised host. Never rejects except for a bad host. */
export type Fetcher = (host: string) => Promise<FetchOutcome>;

export type OwnershipResult =
  | { verified: true; method: VerificationMethod }
  | { verified: false; dns: DnsVerifyFailure; file: FileCheckFailure };

/** The node:dns calls `createDnsResolver` uses; tests pass a stand-in. */
export interface DnsBackend {
  resolveTxt(name: string): Promise<string[][]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
}

/** A family that has no record of that type: not an error when the other family answers. */
const NO_DATA = new Set(["ENODATA"]);
/** The name or record does not exist: the DNS method reports `no_record`. */
const NO_RECORD = new Set(["ENOTFOUND", "ENODATA"]);

/** Per-query timeout and tries of the production resolver: bounded well inside the 5 s of a check. */
const DNS_QUERY_TIMEOUT_MS = 2_000;
const DNS_TRIES = 2;

/** The production resolver: node:dns `resolveTxt`, `resolve4` and `resolve6` (never the hosts file). */
export function createDnsResolver(options: { backend?: DnsBackend } = {}): Resolver {
  const backend = options.backend ?? new DnsResolver({ timeout: DNS_QUERY_TIMEOUT_MS, tries: DNS_TRIES });
  return {
    txt: (name) => backend.resolveTxt(name),
    async addresses(host) {
      const [a, aaaa] = await Promise.allSettled([backend.resolve4(host), backend.resolve6(host)]);
      const addresses: string[] = [];
      for (const answer of [a, aaaa]) {
        if (answer.status === "fulfilled") addresses.push(...answer.value);
        else if (!NO_DATA.has(String((answer.reason as { code?: unknown })?.code))) throw answer.reason;
      }
      if (addresses.length === 0) throw Object.assign(new Error("The host has no address."), { code: "ENODATA" });
      return addresses;
    },
  };
}

function normalised(host: string): string {
  if (normaliseHost(host) !== host) throw new TypeError("A target host must be a normalised public DNS name.");
  return host;
}

/** Settles with the promise, or with `onTimeout` after `ms`. The timer never keeps the process alive. */
function within<T>(promise: Promise<T>, ms: number, onTimeout: T): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => resolve(onTimeout), ms);
    timer.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

const TIMED_OUT = Symbol("timed out");

async function checkDns(
  host: string,
  token: string,
  resolver: Resolver,
  timeoutMs: number,
): Promise<DnsVerifyFailure | null> {
  try {
    const records = await within<string[][] | typeof TIMED_OUT>(
      resolver.txt(challengeRecordName(host)),
      timeoutMs,
      TIMED_OUT,
    );
    if (records === TIMED_OUT) return "lookup_failed";
    if (!Array.isArray(records) || records.length === 0) return "no_record";
    return matchesDnsChallenge(records, token) ? null : "mismatch";
  } catch (error) {
    return NO_RECORD.has(String((error as { code?: unknown })?.code)) ? "no_record" : "lookup_failed";
  }
}

/**
 * Whether the Organization controls `host` now: the TXT record at `_airverse-challenge.<host>` holds
 * `airverse-verification=<token>`, or else the well-known file holds the token. DNS is tried first; the file only
 * when DNS fails. Throws a TypeError for a host that is not normalised (nothing is asked then).
 */
export async function checkOwnership(
  host: string,
  token: string,
  deps: { resolver: Resolver; fetcher: Fetcher; dnsTimeoutMs?: number },
): Promise<OwnershipResult> {
  normalised(host);
  const dns = await checkDns(host, token, deps.resolver, deps.dnsTimeoutMs ?? TARGET_LIMITS.fetchTimeoutMs);
  if (dns === null) return { verified: true, method: "dns" };
  let file: FileCheckFailure;
  try {
    const fetched = await deps.fetcher(host);
    if (fetched.ok) {
      if (matchesFileChallenge(fetched.body, token)) return { verified: true, method: "file" };
      file = "mismatch";
    } else {
      file = fetched.reason;
    }
  } catch {
    file = "connect_failed";
  }
  return { verified: false, dns, file };
}

/**
 * Test-only transport settings of the guarded fetcher: a local TLS server with a test CA. Never set by production
 * configuration — no environment variable or `startApi` default reads it; only a test constructs it.
 */
export interface GuardedFetcherTesting {
  /** The CA that issued the local server's certificate (replaces the system roots). */
  ca?: string;
  /** The port of the local server instead of 443. */
  port: number;
  /** Lets the guard pass loopback addresses (127.0.0.0/8, ::1). Every other non-public address is still refused. */
  allowLoopback?: boolean;
}

export interface GuardedFetcherOptions {
  resolver: Resolver;
  /** Total bound of one fetch: lookup, connection, TLS, response and body. Default 5,000 ms. */
  timeoutMs?: number;
  /** Bytes of the body read at most. Default 1,024. */
  bodyBytesMax?: number;
  /** For tests only (see `GuardedFetcherTesting`). */
  testing?: GuardedFetcherTesting;
}

const USER_AGENT = "Airverse-Verification/1";
const TLS_ERROR = /^(?:ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|SELF_SIGNED_|DEPTH_ZERO_|EPROTO$|HOSTNAME_MISMATCH$)/;

function isLoopback(address: string): boolean {
  return (isIP(address) === 4 && address.startsWith("127.")) || address === "::1";
}

/** One spelling per address: IPv6 lower case and compressed, an IPv4-mapped IPv6 address as its IPv4 address. */
function canonicalAddress(address: string): string | null {
  const family = isIP(address);
  if (family === 4) return address;
  if (family !== 6) return null;
  let canonical: string;
  try {
    canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
  // An IPv4-mapped address in any spelling (`::ffff:1.2.3.4`, `::ffff:102:304`, written out in full) is its IPv4
  // address: the URL parser gives all of them as `::ffff:hhhh:hhhh`.
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonical);
  if (mapped === null) return canonical;
  const high = Number.parseInt(mapped[1] as string, 16);
  const low = Number.parseInt(mapped[2] as string, 16);
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

/** Whether two address texts name the same address. False for anything that is not an address. */
export function sameAddress(a: string | undefined, b: string | undefined): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = canonicalAddress(a);
  return left !== null && left === canonicalAddress(b);
}

export type PinFailure = "resolve_failed" | "address_not_public" | "timeout";

/**
 * Resolves `host` once and pins its first address: unless **every** A and AAAA address is public (`isPublicAddress`;
 * loopback too with the test-only option) nothing is pinned (`address_not_public`). The caller connects to the
 * pinned address only and never resolves the name again.
 */
export async function resolvePinned(
  host: string,
  options: { resolver: Resolver; signal: AbortSignal; testing?: GuardedFetcherTesting | undefined },
): Promise<{ ok: true; address: string } | { ok: false; reason: PinFailure }> {
  normalised(host);
  const { resolver, signal, testing } = options;
  const allowed = (address: string): boolean =>
    isPublicAddress(address) || (testing?.allowLoopback === true && isLoopback(address));
  if (signal.aborted) return { ok: false, reason: "timeout" };
  let addresses: string[] | typeof TIMED_OUT;
  try {
    addresses = await new Promise<string[] | typeof TIMED_OUT>((resolve, reject) => {
      signal.addEventListener("abort", () => resolve(TIMED_OUT), { once: true });
      resolver.addresses(host).then(resolve, reject);
    });
  } catch {
    return { ok: false, reason: "resolve_failed" };
  }
  if (addresses === TIMED_OUT) return { ok: false, reason: "timeout" };
  if (!Array.isArray(addresses) || addresses.length === 0) return { ok: false, reason: "resolve_failed" };
  if (!addresses.every((address) => typeof address === "string" && allowed(address))) {
    return { ok: false, reason: "address_not_public" };
  }
  return { ok: true, address: addresses[0] as string };
}

/**
 * The production `Fetcher`: a guarded HTTPS GET of `https://<host>/.well-known/airverse-verification.txt`.
 *
 * - The host's A and AAAA addresses are resolved once; unless **every** address is public (`isPublicAddress`) the
 *   fetch is refused before any connection (`address_not_public`).
 * - The connection goes to the first checked address only (pinned: no second resolution), with SNI and the Host
 *   header set to the name; the certificate is validated for the name (TLS 1.2 or later).
 * - GET only, no cookies or credentials, no keep-alive, no redirects (a 3xx fails), only a 200 counts.
 * - The whole fetch is bounded by `timeoutMs` (default 5 s); the body by `bodyBytesMax` (default 1 KB) — reading
 *   stops and the connection is dropped beyond it.
 */
export function createGuardedFetcher(options: GuardedFetcherOptions): Fetcher {
  const timeoutMs = options.timeoutMs ?? TARGET_LIMITS.fetchTimeoutMs;
  const bodyBytesMax = options.bodyBytesMax ?? TARGET_LIMITS.fetchBodyBytesMax;
  const { resolver, testing } = options;

  return async (host) => {
    normalised(host);
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), timeoutMs);
    timer.unref?.();
    try {
      const pinned = await resolvePinned(host, { resolver, signal: deadline.signal, testing });
      if (!pinned.ok) return pinned;
      return await fetchVerificationFile(host, pinned.address, { signal: deadline.signal, bodyBytesMax, testing });
    } finally {
      clearTimeout(timer);
    }
  };
}

/**
 * The guarded GET of the verification file from one pinned address: only a 200 whose whole body fits `bodyBytesMax`
 * counts. Slice 15a also uses it for the ownership check at the start of a Campaign, from the Campaign's own pin.
 */
export async function fetchVerificationFile(
  host: string,
  address: string,
  options: {
    signal: AbortSignal;
    bodyBytesMax?: number;
    testing?: GuardedFetcherTesting | undefined;
    /** Replace the identifying headers (a Campaign's `user-agent` and `x-airverse-campaign`). */
    headers?: Readonly<Record<string, string>>;
  },
): Promise<FetchOutcome> {
  const response = await pinnedRequest({
    host,
    address,
    method: "GET",
    path: VERIFICATION_FILE_PATH,
    headers: { "user-agent": USER_AGENT, ...options.headers, accept: "text/plain" },
    signal: options.signal,
    bodyBytesMax: options.bodyBytesMax ?? TARGET_LIMITS.fetchBodyBytesMax,
    testing: options.testing,
  });
  if (!response.ok) {
    if (response.reason === "address_mismatch") return { ok: false, reason: "connect_failed" };
    // The connection read more than a response may hold: the file is not one this check accepts.
    if (response.reason === "read_limit") return { ok: false, reason: "too_large" };
    return { ok: false, reason: response.reason === "invalid_response" ? "status" : response.reason };
  }
  if (response.status >= 300 && response.status < 400) return { ok: false, reason: "redirect" };
  if (response.status !== 200) return { ok: false, reason: "status" };
  if (response.truncated) return { ok: false, reason: "too_large" };
  return { ok: true, body: response.body.toString("utf8") };
}

/** One HTTPS request to a pinned address, as the Prove file fetch and the Campaign gate (slice 15a) send it. */
export interface PinnedRequest {
  /** The name: SNI, the Host header and the certificate's subject. Normalised. */
  host: string;
  /** The checked address the connection goes to. The name is never resolved here. */
  address: string;
  method: "GET" | "HEAD";
  /** The request target: starts with one `/`, at most 1,024 characters. */
  path: string;
  /** Only `user-agent`, `accept` and `x-airverse-campaign` may be set; everything else is fixed or absent. */
  headers: Readonly<Record<string, string>>;
  /** Aborting ends the request (`timeout`). */
  signal: AbortSignal;
  /** Bytes of the body read at most; the connection is then dropped and the response says `truncated`. */
  bodyBytesMax: number;
  /** For tests only (see `GuardedFetcherTesting`). */
  testing?: GuardedFetcherTesting | undefined;
}

export type PinnedResponse =
  | {
      ok: true;
      status: number;
      headers: IncomingHttpHeaders;
      /** Bytes of the status line's headers as received (names, values and separators): at most 16 KB. */
      headerBytes: number;
      /** At most `bodyBytesMax` bytes. */
      body: Buffer;
      /** True when the body was longer than `bodyBytesMax` (announced or streamed). */
      truncated: boolean;
      remoteAddress: string;
      /** Bytes the connection read in all: the TLS handshake, any 1xx responses, the headers and the body. */
      bytesRead: number;
    }
  | {
      ok: false;
      /**
       * `read_limit`: the connection read more than one request may (`requestReadMax`) and was destroyed, whatever it
       * was sending — a flood of 1xx responses, chunk framing that carries no body, tiny TLS records.
       */
      reason: "timeout" | "connect_failed" | "tls_failed" | "address_mismatch" | "invalid_response" | "read_limit";
      /** Bytes the connection read before it failed (0 or absent when it was never made). */
      bytesRead?: number;
    };

/** Not configuration: only a unit test of the pin assertion passes it. No option of the API reaches it. */
export interface PinnedRequestInternals {
  /** Opens the TCP connection instead of `net.connect` to the pinned address. */
  dial?: () => Socket;
}

/** Bytes of response headers read at most; a response with more fails (`invalid_response`). */
export const RESPONSE_HEADER_BYTES_MAX = 16_384;
/** Bytes kept for the TLS handshake of a connection (the certificate chain, mostly). */
export const TLS_OVERHEAD_BYTES_MAX = 16_384;
/**
 * Bytes kept for framing: TLS record headers and tags, and chunked transfer coding (chunk sizes, extensions, line
 * ends). Fixed, whatever the body cap: as much again as the largest body a Campaign reads (64 KB). A body streamed in
 * 100-byte writes carries about 24 KB of framing for 64 KB of body and passes; one-byte chunks (five bytes of framing
 * per byte of body) and chunk extensions do not.
 */
export const FRAMING_OVERHEAD_BYTES_MAX = 65_536;
/**
 * Bytes one connection can have read beyond its cap when it is cut: one TCP read. The cap is counted on each raw
 * read as it arrives, before TLS sees it; the read that crosses the cap is not handed on, and the socket is destroyed
 * in the same turn. Node reads at most 64 KB from a socket at a time, so `bytesRead` of a `read_limit` answer is at
 * most `requestReadMax(…) + READ_OVERSHOOT_BYTES_MAX`. (Measured with `openssl s_server -tls1_3 -www -num_tickets
 * 20000`, a flood of TLS records without application data: 79 to 262 KB over the cap when the cap was only checked
 * on decrypted data and a 10 ms timer; at most one read over it since.)
 */
export const READ_OVERSHOOT_BYTES_MAX = 65_536;
/**
 * Bytes the socket of one request may read in all, from the first byte of the TLS handshake to the last of the body:
 * the header cap, the body cap and the two fixed allowances. Checked on every raw TCP read, whatever the bytes are
 * — TLS records that carry nothing included — before and after the response's headers; a connection over it is
 * destroyed (`read_limit`), at most one read (`READ_OVERSHOOT_BYTES_MAX`) late.
 */
export function requestReadMax(bodyBytesMax: number): number {
  return RESPONSE_HEADER_BYTES_MAX + bodyBytesMax + TLS_OVERHEAD_BYTES_MAX + FRAMING_OVERHEAD_BYTES_MAX;
}
/** Characters of a request target at most. */
export const REQUEST_TARGET_MAX = 1024;

const SETTABLE_HEADERS = new Set(["user-agent", "accept", "x-airverse-campaign"]);
const HEADER_VALUE = /^[\x20-\x7e]{1,256}$/;
const REQUEST_TARGET = /^\/(?!\/)[\x21-\x7e]*$/;

/**
 * One guarded HTTPS request:
 *
 * - The address must be public (`isPublicAddress`; loopback too with the test-only option): checked here as well,
 *   whoever resolved it.
 * - A plain TCP connection is opened to `address` on port 443 — by this function itself, with no agent, so no proxy
 *   setting of the environment applies. TLS does not take that socket itself: it runs over a pass-through that
 *   counts every raw read against the cap first. Its remote address must be the pinned one, or it is destroyed
 *   (`address_mismatch`). Only then does TLS start on that socket, with SNI set to `host`: no ClientHello and no byte
 *   of a request can reach another address. The certificate is validated for the name (TLS 1.2 or later), whatever
 *   `NODE_TLS_REJECT_UNAUTHORIZED` says.
 * - GET or HEAD only, never a body; no cookie, no credential, no keep-alive; `accept-encoding: identity`.
 * - A redirect is never followed: a 3xx is answered like any other status. A status outside 100–599, or more than
 *   16 KB of response headers, is `invalid_response`.
 * - At most `bodyBytesMax` bytes of body are read; then the socket is destroyed.
 * - The socket reads at most `requestReadMax(bodyBytesMax)` bytes in all, whatever they are (TLS, 1xx responses,
 *   headers, chunk framing, body): beyond it the socket is destroyed and the answer is `read_limit`.
 *
 * Throws a TypeError (before any connection) for another method, an address that is not public, a target that does
 * not start with one `/` or is longer than 1,024 characters, or a header outside the three it may set. Never rejects
 * otherwise.
 */
export function pinnedRequest(options: PinnedRequest, internals: PinnedRequestInternals = {}): Promise<PinnedResponse> {
  const { host, address, method, path, signal, bodyBytesMax, testing } = options;
  try {
    normalised(host);
    if (method !== "GET" && method !== "HEAD") throw new TypeError("A pinned request is a GET or a HEAD.");
    if (typeof path !== "string" || path.length > REQUEST_TARGET_MAX || !REQUEST_TARGET.test(path)) {
      throw new TypeError(
        "A request target starts with one /, holds printable ASCII only and at most 1,024 characters.",
      );
    }
    if (isIP(address) === 0) throw new TypeError("The pinned address must be an IP address.");
    if (!isPublicAddress(address) && !(testing?.allowLoopback === true && isLoopback(address))) {
      throw new TypeError("The pinned address must be a public address.");
    }
    if (!Number.isInteger(bodyBytesMax) || bodyBytesMax < 0) {
      throw new TypeError("The body cap is a whole number of bytes.");
    }
    for (const [name, value] of Object.entries(options.headers)) {
      if (!SETTABLE_HEADERS.has(name) || typeof value !== "string" || !HEADER_VALUE.test(value)) {
        throw new TypeError("Only user-agent, accept and x-airverse-campaign may be set on a pinned request.");
      }
    }
  } catch (error) {
    return Promise.reject(error);
  }
  return new Promise<PinnedResponse>((resolve) => {
    let settled = false;
    let tcp: Socket | undefined;
    let secure: TLSSocket | undefined;
    let req: ClientRequest | undefined;
    type Outcome = PinnedResponse extends infer R ? (R extends unknown ? Omit<R, "bytesRead"> : never) : never;
    const finish = (outcome: Outcome): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      // What the connection read, whatever came of it: it counts toward the Campaign's bytes.
      resolve({ ...outcome, bytesRead: tcp?.bytesRead ?? 0 } as PinnedResponse);
      req?.destroy();
      secure?.destroy();
      tcp?.destroy();
    };
    const onAbort = (): void => finish({ ok: false, reason: "timeout" });
    if (signal.aborted) {
      resolve({ ok: false, reason: "timeout", bytesRead: 0 });
      return;
    }
    // No connection may read more than a response can hold, before its headers or after them: a flood of 1xx
    // responses is cut here, chunk framing that never becomes body (the body cap below counts decoded bytes only),
    // and TLS records that carry nothing. Checked on every raw read of the TCP socket, before TLS is given it.
    const readMax = requestReadMax(bodyBytesMax);
    const overRead = (): boolean => {
      if (settled || (tcp?.bytesRead ?? 0) <= readMax) return false;
      finish({ ok: false, reason: "read_limit" });
      return true;
    };
    signal.addEventListener("abort", onAbort, { once: true });
    const failed = (error: unknown, phase: "connect" | "tls"): void => {
      const code = String((error as { code?: unknown } | null)?.code ?? "");
      if (signal.aborted) finish({ ok: false, reason: "timeout" });
      else if (code === "HPE_HEADER_OVERFLOW") finish({ ok: false, reason: "invalid_response" });
      else finish({ ok: false, reason: phase === "tls" || TLS_ERROR.test(code) ? "tls_failed" : "connect_failed" });
    };

    // 1. TCP, to the checked address itself: the name is never resolved again, and no agent or proxy is involved.
    try {
      tcp =
        internals.dial?.() ??
        netConnect({ host: address, family: isIP(address) === 6 ? 6 : 4, port: testing?.port ?? 443 });
    } catch (error) {
      return failed(error, "connect");
    }
    const socket = tcp;
    socket.once("error", (error) => failed(error, "connect"));
    socket.once("connect", () => {
      // 2. The pin, asserted on the connected socket before anything is written to it.
      const remoteAddress = socket.remoteAddress ?? "";
      if (!sameAddress(remoteAddress, address)) return finish({ ok: false, reason: "address_mismatch" });

      // 3. TLS for the name, over that socket and no other — through a pass-through that counts each raw read
      // against the cap before TLS sees it. The read that crosses the cap is not handed on: the connection ends.
      const raw = new Duplex({
        read() {
          socket.resume();
        },
        write(chunk: Buffer, _encoding, callback) {
          socket.write(chunk, callback);
        },
        final(callback) {
          socket.end();
          callback();
        },
        destroy(error, callback) {
          socket.destroy();
          callback(error);
        },
      });
      socket.on("data", (chunk: Buffer) => {
        if (overRead()) return;
        if (!raw.push(chunk)) socket.pause();
      });
      socket.once("end", () => raw.push(null));
      socket.once("close", () => raw.destroy());
      let handshake = true;
      const tlsSocket = tlsConnect({
        socket: raw,
        servername: host,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        ALPNProtocols: ["http/1.1"],
        ...(testing?.ca === undefined ? {} : { ca: testing.ca }),
      });
      secure = tlsSocket;
      tlsSocket.once("error", (error) => failed(error, handshake ? "tls" : "connect"));
      tlsSocket.once("secureConnect", () => {
        handshake = false;
        if (!tlsSocket.authorized) return finish({ ok: false, reason: "tls_failed" });

        // 4. The request, on that connection only.
        const request = httpsRequest({
          createConnection: () => tlsSocket,
          host,
          path,
          method,
          headers: { ...options.headers, host, "accept-encoding": "identity", connection: "close" },
          maxHeaderSize: RESPONSE_HEADER_BYTES_MAX,
        });
        req = request;
        request.on("information", overRead);
        // A 101, or a connection that ends without a response, is no response: answered at once, not at the deadline.
        request.on("upgrade", () => finish({ ok: false, reason: "invalid_response" }));
        request.on("close", () => finish({ ok: false, reason: "invalid_response" }));
        request.on("response", (response) => {
          if (overRead()) return;
          const status = response.statusCode ?? 0;
          if (!Number.isInteger(status) || status < 100 || status > 599) {
            return finish({ ok: false, reason: "invalid_response" });
          }
          let headerBytes = 0;
          for (const part of response.rawHeaders) headerBytes += Buffer.byteLength(part, "latin1") + 2;
          if (headerBytes > RESPONSE_HEADER_BYTES_MAX) return finish({ ok: false, reason: "invalid_response" });
          const announced = Number(response.headers["content-length"]);
          const chunks: Buffer[] = [];
          let received = 0;
          const done = (truncated: boolean): void =>
            finish({
              ok: true,
              status,
              headers: response.headers,
              headerBytes,
              body: Buffer.concat(chunks),
              truncated,
              remoteAddress,
            });
          if (method === "HEAD") return done(false);
          if (bodyBytesMax === 0) return done(Number.isFinite(announced) ? announced > 0 : true);
          response.on("data", (chunk: Buffer) => {
            if (overRead()) return;
            const room = bodyBytesMax - received;
            if (chunk.byteLength > room) {
              if (room > 0) chunks.push(chunk.subarray(0, room));
              received = bodyBytesMax;
              return done(true);
            }
            received += chunk.byteLength;
            chunks.push(chunk);
          });
          response.on("end", () => done(Number.isFinite(announced) && announced > received));
          response.on("error", () => finish({ ok: false, reason: signal.aborted ? "timeout" : "connect_failed" }));
        });
        request.on("error", (error) => {
          // The target closed the connection without answering.
          if (!signal.aborted && (error as { code?: unknown }).code === "ECONNRESET") {
            finish({ ok: false, reason: "invalid_response" });
          } else failed(error, "connect");
        });
        request.end();
      });
    });
  });
}
