import { Resolver as DnsResolver } from "node:dns/promises";
import { request } from "node:https";
import { isIP } from "node:net";
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
  const allowed = (address: string): boolean =>
    isPublicAddress(address) || (testing?.allowLoopback === true && isLoopback(address));

  return async (host) => {
    normalised(host);
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), timeoutMs);
    timer.unref?.();
    try {
      let addresses: string[] | typeof TIMED_OUT;
      try {
        addresses = await new Promise<string[] | typeof TIMED_OUT>((resolve, reject) => {
          deadline.signal.addEventListener("abort", () => resolve(TIMED_OUT), { once: true });
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
      const pinned = addresses[0] as string;
      return await get(host, pinned, deadline.signal, bodyBytesMax, testing);
    } finally {
      clearTimeout(timer);
    }
  };
}

function get(
  host: string,
  address: string,
  signal: AbortSignal,
  bodyBytesMax: number,
  testing: GuardedFetcherTesting | undefined,
): Promise<FetchOutcome> {
  return new Promise<FetchOutcome>((resolve) => {
    let settled = false;
    const finish = (outcome: FetchOutcome): void => {
      if (settled) return;
      settled = true;
      resolve(outcome);
      req.destroy();
    };
    if (signal.aborted) {
      resolve({ ok: false, reason: "timeout" });
      return;
    }
    const req = request({
      // The checked address itself: the name is never resolved again.
      host: address,
      family: isIP(address) === 6 ? 6 : 4,
      port: testing?.port ?? 443,
      servername: host,
      path: VERIFICATION_FILE_PATH,
      method: "GET",
      headers: {
        host,
        "user-agent": USER_AGENT,
        accept: "text/plain",
        "accept-encoding": "identity",
        connection: "close",
      },
      agent: false,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
      ...(testing?.ca === undefined ? {} : { ca: testing.ca }),
      signal,
    });
    req.on("response", (response) => {
      const status = response.statusCode ?? 0;
      if (status >= 300 && status < 400) return finish({ ok: false, reason: "redirect" });
      if (status !== 200) return finish({ ok: false, reason: "status" });
      const announced = Number(response.headers["content-length"]);
      if (Number.isFinite(announced) && announced > bodyBytesMax) return finish({ ok: false, reason: "too_large" });
      const chunks: Buffer[] = [];
      let received = 0;
      response.on("data", (chunk: Buffer) => {
        received += chunk.byteLength;
        if (received > bodyBytesMax) return finish({ ok: false, reason: "too_large" });
        chunks.push(chunk);
      });
      response.on("end", () => finish({ ok: true, body: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", () => finish({ ok: false, reason: signal.aborted ? "timeout" : "connect_failed" }));
    });
    req.on("error", (error) => {
      if (signal.aborted) return finish({ ok: false, reason: "timeout" });
      const code = String((error as { code?: unknown }).code ?? "");
      finish({ ok: false, reason: TLS_ERROR.test(code) ? "tls_failed" : "connect_failed" });
    });
    req.end();
  });
}
