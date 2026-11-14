// Public types of @antireverse/guard (hand-written; the implementation is plain JavaScript checked against them).
// Every injectable is structural, so a page needs no DOM lib types beyond what it already has, and tests can pass
// fakes. Defaults are taken from globalThis when an option is undefined; `null` means "none" (for storage: keep
// the device id in memory only).

/** The request header that carries the Attestation Token. */
export declare const ATTESTATION_HEADER: "ar-attestation";

/** The request header that carries the request signature: `v1,t=<unix s>,n=<nonce>,s=<signature>`. */
export declare const SIGNATURE_HEADER: "ar-signature";

/** The request header that carries the base64url SHA-256 of the exact body bytes. */
export declare const CONTENT_HASH_HEADER: "ar-content-sha256";

/** The signal ids of Guard v1, in their canonical order. Ids only: no value is ever sent. */
export declare const ATTESTATION_SIGNALS: readonly ["automation.webdriver", "automation.headless", "env.inconsistent"];
export type AttestationSignal = (typeof ATTESTATION_SIGNALS)[number];

/** The subset of `Storage` Guard uses (`localStorage` by default). */
export interface GuardStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** The subset of `Navigator` Guard reads for Signals v1. */
export interface GuardNavigator {
  webdriver?: boolean;
  userAgent?: string;
  platform?: string;
  plugins?: { readonly length: number } | null;
  /** User-Agent Client Hints (Chromium only). */
  userAgentData?: { readonly platform?: string } | null;
  /** Under Save-Data the integrity collector does nothing (Chromium only). */
  connection?: { readonly saveData?: boolean } | null;
}

/** The subset of `SubtleCrypto` Guard uses. */
export interface GuardSubtle {
  generateKey(
    algorithm: { name: "ECDSA"; namedCurve: "P-256" },
    extractable: boolean,
    keyUsages: string[],
  ): Promise<unknown>;
  exportKey(format: "jwk", key: unknown): Promise<unknown>;
  digest(algorithm: "SHA-256", data: Uint8Array): Promise<ArrayBuffer>;
  /** Request signing (slice 04). Without it Guard still attests, and requests go out unsigned. */
  sign?(algorithm: { name: "ECDSA"; hash: "SHA-256" }, key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
}

/** The subset of `Crypto` Guard uses (`globalThis.crypto` by default). */
export interface GuardCrypto {
  getRandomValues<T extends Uint8Array>(array: T): T;
  readonly subtle?: GuardSubtle;
}

/** What Guard passes to `fetch`: always a JSON POST without credentials. */
export interface GuardRequestInit {
  method: "POST";
  headers: { "content-type": "application/json" };
  body: string;
  credentials: "omit";
  /** Aborts the request after 10 s; absent where AbortController is missing (a timer race applies instead). */
  signal?: AbortSignal;
}

/** The subset of `Response` Guard reads. */
export interface GuardResponse {
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
}

export type GuardFetch = (url: string, init: GuardRequestInit) => Promise<GuardResponse>;

export interface GuardOptions {
  /** The App id, `app_` and 24 hex characters. */
  appId: string;
  /** Base URL of the Attestation service, e.g. `https://api.example.com` (a trailing slash is ignored). */
  endpoint: string;
  /** Where the device id is kept (`localStorage` by default; `null`: memory only). */
  storage?: GuardStorage | null | undefined;
  /** Milliseconds since the epoch (`Date.now` by default). */
  now?: (() => number) | undefined;
  fetch?: GuardFetch | null | undefined;
  crypto?: GuardCrypto | null | undefined;
  navigator?: GuardNavigator | null | undefined;
  /**
   * `false` turns the integrity collector off. On (the default), when a hardened bundle planted its integrity
   * marker, Guard hashes that Build's files the page loaded from its own origin (the global `fetch`, once, about
   * 30 s after the first token) and sends `{ build, files: [{ i, h }], skipped }` with one early re-attest.
   */
  integrity?: boolean | undefined;
}

/** One request to sign, as it will be sent. */
export interface SignInput {
  /** HTTP method (`GET` when absent); signed upper-cased. */
  method?: string | undefined;
  /**
   * Absolute, or relative to `location.href`; http or https. The signed target is the resolved URL as fetch
   * serialises it, from the path on and without the fragment: `/a?` stays `/a?`.
   */
  url: string;
  /**
   * Signed bodies: none (undefined or null), string (UTF-8), ArrayBuffer, any ArrayBufferView, Blob (its bytes),
   * URLSearchParams (`toString()`, UTF-8). Anything else (FormData, ReadableStream, …) leaves the request unsigned:
   * only `ar-attestation` is returned.
   */
  body?: unknown;
  /**
   * The headers the request will carry; only `content-type` is read, and signed exactly as given (an empty line
   * when there is none). Without one, for a body that fetch types itself — a string (`text/plain;charset=UTF-8`),
   * URLSearchParams (`application/x-www-form-urlencoded;charset=UTF-8`), a Blob with a type — Guard signs that type
   * and returns it as `content-type`: send the returned headers as they are.
   */
  headers?: HeadersInit | undefined;
}

export interface Guard {
  /**
   * Runs challenge → attest and keeps the token; re-attests 60 s before it expires. Concurrent calls share one
   * handshake. Never rejects: resolves the token, or null on any failure (and then keeps no token).
   */
  attest(): Promise<string | null>;
  /** The current token, or null (none yet, failed, or expired). */
  token(): string | null;
  /** `{ "ar-attestation": token }`, or `{}` without a current token. Spread into a request's headers. */
  headers(): Record<string, string>;
  /**
   * The headers for one request: `ar-attestation`, `ar-signature`, `ar-content-sha256` and, when Guard chose the
   * body's content type, `content-type`. Attests first when
   * there is no token (sharing a handshake in flight). Never rejects: `{}` without a token, the attestation header
   * only when the request cannot be signed. Send the request to the same URL (resolved the same way) with the same
   * method and body bytes, or the signature will not verify.
   */
  sign(request: SignInput): Promise<Record<string, string>>;
  /**
   * `sign()` then the global `fetch`, called with the URL that was signed (its normalised href without the
   * fragment; a Request is sent as is) and the caller's init, whose headers become a plain record with the Guard
   * headers set over them. For a signed body without a caller content type, Guard sets the one fetch would set
   * itself, the one it signed. Nothing else is added: never `credentials`. A Request whose body is a stream, and unsupported bodies, go out
   * unsigned. When signing fails the request is still sent. Rejects only as `fetch` itself does (network error,
   * bad input), or with a TypeError when there is no global `fetch`.
   */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  /** The signal ids the environment shows now. */
  signals(): AttestationSignal[];
  /** Schedules the first attest in idle time (requestIdleCallback, else setTimeout 0). */
  start(): void;
  /** Cancels every pending timer; an attest in flight completes but schedules nothing. */
  stop(): void;
}

/** Creates a Guard. Lazy: nothing runs until `attest()` or `start()`. Never throws. */
export declare function createGuard(options: GuardOptions): Guard;
