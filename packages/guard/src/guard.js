// createGuard: challenge → attest → token, re-attested before expiry; sign() and fetch() sign requests with the
// session key (slice 04). Nothing here throws to the page and nothing is logged: every failure ends as `null`, no
// token, or an unsigned request.
import {
  ATTESTATION_HEADER,
  CONTENT_HASH_HEADER,
  DEVICE_STORAGE_KEY,
  EMPTY_CONTENT_SHA256,
  GUARD_LIMITS,
  PATTERNS,
  SIGNATURE_HEADER,
} from "./constants.js";
import { base64url, createSessionKey, randomDeviceId, sha256, signText, tokenJti } from "./crypto.js";
import {
  bodyBytes,
  callerContentType,
  callerHeaders,
  defaultContentType,
  isRequest,
  mergeInit,
  resolveUrl,
  serialised,
} from "./request.js";
import { collectSignals } from "./signals.js";

/** @typedef {import("./index.js").Guard} Guard */
/** @typedef {import("./index.js").GuardOptions} GuardOptions */
/** @typedef {import("./index.js").GuardCrypto} GuardCrypto */
/** @typedef {import("./index.js").GuardFetch} GuardFetch */
/** @typedef {import("./index.js").GuardStorage} GuardStorage */
/** @typedef {import("./index.js").GuardNavigator} GuardNavigator */
/** @typedef {{ [K in keyof GuardOptions]-?: GuardOptions[K] | undefined }} Options The options, read once. */
/** @typedef {import("./index.js").SignInput} SignInput */
/** @typedef {Awaited<ReturnType<typeof createSessionKey>>} SessionKey */
/** @typedef {{ value: string, jti: string | null, privateKey: unknown }} Signer What signs with one token. */

/** A body Guard does not sign (the stream of a Request is never read). */
const UNSIGNABLE = Object.freeze({});

const TTL_MS = GUARD_LIMITS.ttlS * 1000;
const MIN_LIFETIME_MS = GUARD_LIMITS.reattestLeadMs + GUARD_LIMITS.reattestMinMs;

/**
 * A global by name, or null. Reading a global may throw (localStorage in a sandboxed frame): that counts as absent.
 * @param {string} name
 * @returns {unknown}
 */
function globalValue(name) {
  try {
    return /** @type {Record<string, unknown>} */ (/** @type {unknown} */ (globalThis))[name] ?? null;
  } catch {
    return null;
  }
}

/**
 * An option, or the global of that name when the option is undefined.
 * @template T
 * @param {T | null | undefined} value
 * @param {string} name
 * @returns {T | null}
 */
function optionOrGlobal(value, name) {
  return value !== undefined ? value : /** @type {T | null} */ (globalValue(name));
}

/** @param {unknown} value */
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * POSTs JSON without credentials; resolves the parsed body of a 2xx answer as a record. Throws otherwise, and when
 * no complete answer arrived within `requestTimeoutMs` (the request is aborted where AbortController exists).
 * @param {GuardFetch} fetch
 * @param {string} url
 * @param {unknown} body
 * @returns {Promise<Record<string, unknown>>}
 */
async function post(fetch, url, body) {
  const Controller = globalValue("AbortController");
  const controller =
    typeof Controller === "function"
      ? /** @type {AbortController} */ (new /** @type {typeof AbortController} */ (Controller)())
      : null;
  /** @type {import("./index.js").GuardRequestInit} */
  const init = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    credentials: "omit",
  };
  if (controller !== null) init.signal = controller.signal;
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timer;
  /** @type {Promise<never>} */
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => {
      controller?.abort();
      reject(new Error("timeout"));
    }, GUARD_LIMITS.requestTimeoutMs);
  });
  const exchange = (async () => {
    const response = await fetch(url, init);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  })();
  try {
    const parsed = await Promise.race([exchange, timeout]);
    if (!isRecord(parsed)) throw new TypeError("not a JSON object");
    return /** @type {Record<string, unknown>} */ (parsed);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The global fetch, called with globalThis as receiver (an unbound window.fetch throws "Illegal invocation").
 * Rejects with a TypeError when there is none.
 * @param {RequestInfo | URL} input
 * @param {RequestInit | undefined} init
 * @returns {Promise<Response>}
 */
async function pageFetch(input, init) {
  const fetch = globalValue("fetch");
  if (typeof fetch !== "function") throw new TypeError("fetch is unavailable");
  return /** @type {typeof globalThis.fetch} */ (fetch).call(globalThis, input, init);
}

/** @type {Guard} */
const INERT = Object.freeze({
  attest: () => Promise.resolve(null),
  token: () => null,
  headers: () => ({}),
  sign: () => Promise.resolve({}),
  fetch: pageFetch,
  signals: () => [],
  start: () => {},
  stop: () => {},
});

/**
 * Copies the options once, so no getter or Proxy trap runs later. Throws when they are not a plain object or a
 * read throws.
 * @param {unknown} options
 * @returns {Options}
 */
function snapshot(options) {
  if (!isRecord(options)) throw new TypeError("options must be an object");
  const source = /** @type {Partial<GuardOptions>} */ (options);
  const { appId, endpoint, storage, now, fetch, crypto, navigator } = source;
  return { appId, endpoint, storage, now, fetch, crypto, navigator };
}

/**
 * Creates a Guard. Never throws: options that cannot be read (not an object, a throwing getter, a hostile Proxy)
 * give an inert Guard whose attest() resolves null.
 * @type {typeof import("./index.js").createGuard}
 */
export function createGuard(options) {
  try {
    return build(snapshot(options));
  } catch {
    return INERT;
  }
}

/**
 * @param {Options} opts
 * @returns {Guard}
 */
function build(opts) {
  const appId = opts.appId;
  const endpoint = typeof opts.endpoint === "string" ? opts.endpoint.replace(/\/+$/, "") : "";
  const clock = typeof opts.now === "function" ? opts.now : Date.now;
  /** The injected clock, or Date.now when it throws or returns no finite number. */
  const now = () => {
    try {
      const value = clock();
      if (typeof value === "number" && Number.isFinite(value)) return value;
    } catch {
      // Fall back below.
    }
    return Date.now();
  };

  /** @type {string | null} */
  let current = null;
  /** @type {Signer | null} */
  let signer = null;
  let currentUntil = 0;
  /** @type {Promise<string | null> | null} */
  let inFlight = null;
  /** @type {Promise<SessionKey> | null} */
  let sessionKey = null;
  /** In-memory device id, when storage is unavailable. */
  /** @type {string | null} */
  let memoryDevice = null;
  /** @type {ReturnType<typeof setTimeout> | null} */
  let timer = null;
  /** @type {{ cancel: () => void } | null} */
  let pendingStart = null;
  /** Bumped by stop(): an attest started before it schedules nothing. */
  let generation = 0;

  /** @returns {GuardFetch | null} */
  function resolveFetch() {
    if (typeof opts.fetch === "function") return opts.fetch;
    if (opts.fetch === null) return null;
    const global = globalValue("fetch");
    if (typeof global !== "function") return null;
    const fetchFn = /** @type {GuardFetch} */ (global);
    // Called with globalThis as receiver: an unbound window.fetch throws "Illegal invocation".
    return (url, init) => fetchFn.call(globalThis, url, init);
  }

  /** @param {GuardCrypto} crypto */
  function deviceId(crypto) {
    if (memoryDevice !== null) return memoryDevice;
    try {
      const storage = optionOrGlobal(opts.storage, "localStorage");
      if (storage !== null) {
        const stored = storage.getItem(DEVICE_STORAGE_KEY);
        if (typeof stored === "string" && PATTERNS.device.test(stored)) return stored;
        const fresh = randomDeviceId(crypto);
        storage.setItem(DEVICE_STORAGE_KEY, fresh);
        return fresh;
      }
    } catch {
      // Storage disabled or full: fall through to an id kept in memory for this Guard.
    }
    memoryDevice = randomDeviceId(crypto);
    return memoryDevice;
  }

  /** @param {GuardCrypto} crypto */
  function getSessionKey(crypto) {
    if (sessionKey === null) {
      const created = createSessionKey(crypto);
      sessionKey = created;
      created.catch(() => {
        if (sessionKey === created) sessionKey = null; // retry on the next attest
      });
    }
    return sessionKey;
  }

  function clearTimer() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  }

  /** @param {number} lifetimeMs */
  function schedule(lifetimeMs) {
    clearTimer();
    timer = setTimeout(() => {
      timer = null;
      void attest();
    }, lifetimeMs - GUARD_LIMITS.reattestLeadMs);
  }

  /**
   * One handshake. The current token stays in use while it runs; a failure drops it.
   * @returns {Promise<string | null>}
   */
  async function run() {
    const started = generation;
    try {
      const token = await handshake();
      if (token !== null) {
        current = token.value;
        signer = { value: token.value, jti: token.jti, privateKey: token.privateKey };
        currentUntil = now() + token.lifetimeMs;
        if (started === generation) schedule(token.lifetimeMs);
        return token.value;
      }
    } catch {
      // Any failure: no token.
    }
    current = null;
    signer = null;
    return null;
  }

  /**
   * challenge → attest. Resolves null or throws on any failure.
   * @returns {Promise<{ value: string, lifetimeMs: number, jti: string | null, privateKey: unknown } | null>}
   */
  async function handshake() {
    const fetch = resolveFetch();
    const crypto = optionOrGlobal(opts.crypto, "crypto");
    if (typeof appId !== "string" || endpoint === "" || fetch === null || crypto === null) return null;

    const challenge = await post(fetch, `${endpoint}/v1/attest/challenge`, { app_id: appId });
    const nonce = challenge.nonce;
    if (typeof nonce !== "string" || !PATTERNS.nonce.test(nonce)) return null;

    const signals = collectSignals(optionOrGlobal(opts.navigator, "navigator"));
    const device = deviceId(crypto);
    const { jkt, jwk, pair } = await getSessionKey(crypto);
    const answer = await post(fetch, `${endpoint}/v1/attest`, {
      app_id: appId,
      nonce,
      device,
      signals,
      cnf: { jkt, jwk },
    });

    const token = answer.token;
    const expiresAt = typeof answer.expires_at === "string" ? Date.parse(answer.expires_at) : Number.NaN;
    if (typeof token !== "string" || token.length > GUARD_LIMITS.headerMax || !PATTERNS.token.test(token)) {
      return null;
    }
    if (!Number.isFinite(expiresAt)) return null;

    // A fresh token lives at most ttlS; clamping keeps a skewed client clock from renewing too late or in a loop.
    /** @type {string | null} */
    let jti = null;
    try {
      jti = tokenJti(token);
    } catch {
      // A token whose jti cannot be read still attests; it only cannot back a signature.
    }
    return {
      value: token,
      lifetimeMs: Math.min(TTL_MS, Math.max(MIN_LIFETIME_MS, expiresAt - now())),
      jti,
      privateKey: pair.privateKey,
    };
  }

  function attest() {
    if (inFlight === null) {
      const running = run();
      inFlight = running;
      void running.then(() => {
        if (inFlight === running) inFlight = null;
      });
    }
    return inFlight;
  }

  function token() {
    if (current !== null && now() >= currentUntil) current = null;
    return current;
  }

  /**
   * The headers of one request and the URL they were signed for. Never rejects: without a token `{}`; when the
   * request cannot be signed (unsupported body, bad URL or method, unreadable caller headers, a token without a
   * readable jti, no WebCrypto signing) the attestation header only and no URL. When a body is signed and the caller
   * set no content type, the one fetch would send is signed and returned as a header, so that exactly what was
   * signed is sent (review F1).
   * @param {SignInput} request
   * @returns {Promise<{ headers: Record<string, string>, href: string | null }>}
   */
  async function prepare(request) {
    /** @type {Record<string, string>} */
    let headers = {};
    try {
      let value = token();
      if (value === null) value = await attest();
      if (value === null) return { headers, href: null };
      headers = { [ATTESTATION_HEADER]: value };
      const using = signer;
      const crypto = optionOrGlobal(opts.crypto, "crypto");
      if (using === null || using.value !== value || using.jti === null || crypto === null) {
        return { headers, href: null };
      }
      const { method = "GET", url, body, headers: given } = request;
      if (typeof method !== "string" || method.includes("\n")) return { headers, href: null };
      const { href, target } = serialised(resolveUrl(url, globalValue("location")));
      const callerType = callerContentType(given, globalValue("Headers"));
      const bytes = await bodyBytes(body);
      if (bytes === undefined) return { headers, href: null };
      // The content type sent: the caller's as given, else the one fetch sets for the body, else none ("").
      const chosen = callerType === null && bytes !== null ? defaultContentType(body) : null;
      const contentType = callerType ?? chosen ?? "";
      if (/[\r\n]/.test(contentType)) return { headers, href: null };
      const contentSha256 = bytes === null ? EMPTY_CONTENT_SHA256 : await sha256(crypto, bytes);
      const t = Math.floor(now() / 1000);
      const n = base64url(crypto.getRandomValues(new Uint8Array(16)));
      // Mirrors protocol `canonicalSigningString`; a serialised URL holds no line feed.
      const canonical = `ar-sig-v1\n${method.toUpperCase()}\n${target}\n${contentType}\n${contentSha256}\n${t}\n${n}\n${using.jti}`;
      const s = await signText(crypto, using.privateKey, canonical);
      return {
        headers: {
          ...headers,
          ...(chosen === null ? {} : { "content-type": chosen }),
          [SIGNATURE_HEADER]: `v1,t=${t},n=${n},s=${s}`,
          [CONTENT_HASH_HEADER]: contentSha256,
        },
        href,
      };
    } catch {
      return { headers, href: null };
    }
  }

  function cancelStart() {
    const pending = pendingStart;
    pendingStart = null;
    try {
      pending?.cancel();
    } catch {
      // Nothing to cancel.
    }
  }

  return {
    attest,
    token,
    headers() {
      const value = token();
      return value === null ? {} : { [ATTESTATION_HEADER]: value };
    },
    async sign(request) {
      return (await prepare(request)).headers;
    },
    async fetch(input, init) {
      let target = input;
      let sendInit = init;
      try {
        const fromRequest = isRequest(input);
        const hasBody = init?.body !== undefined;
        const given = callerHeaders(input, init);
        /** @type {SignInput} */
        const request = fromRequest
          ? {
              method: init?.method ?? input.method,
              url: input.url,
              body: hasBody ? init?.body : input.body == null ? undefined : UNSIGNABLE,
              headers: given,
            }
          : { method: init?.method, url: String(input), body: init?.body, headers: given };
        const { headers, href } = await prepare(request);
        sendInit = mergeInit(input, init, headers, globalValue("Headers"));
        // The exact URL that was signed; a Request is sent as is (its url is already that serialised URL).
        if (href !== null && !fromRequest) target = href;
      } catch {
        target = input;
        sendInit = init;
      }
      return pageFetch(target, sendInit);
    },
    signals() {
      return collectSignals(optionOrGlobal(opts.navigator, "navigator"));
    },
    start() {
      if (pendingStart !== null) return;
      const begin = () => {
        pendingStart = null;
        void attest();
      };
      try {
        const idle = globalValue("requestIdleCallback");
        if (typeof idle === "function") {
          // Window methods need globalThis as receiver (else "Illegal invocation").
          const handle = idle.call(globalThis, begin, { timeout: GUARD_LIMITS.idleTimeoutMs });
          pendingStart = {
            cancel: () => {
              const cancel = globalValue("cancelIdleCallback");
              if (typeof cancel === "function") cancel.call(globalThis, handle);
            },
          };
        } else {
          const handle = setTimeout(begin, 0);
          pendingStart = { cancel: () => clearTimeout(handle) };
        }
      } catch {
        pendingStart = null;
      }
    },
    stop() {
      generation += 1;
      clearTimer();
      cancelStart();
    },
  };
}
