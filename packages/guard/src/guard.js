// createGuard: challenge → attest → token, re-attested before expiry; sign() and fetch() sign requests with the
// session key (slice 04). Nothing here throws to the page and nothing is logged: every failure ends as `null`, no
// token, or an unsigned request.
import {
  ATTESTATION_HEADER,
  CONTENT_HASH_HEADER,
  DEVICE_STORAGE_KEY,
  EMPTY_CONTENT_SHA256,
  GUARD_LIMITS,
  INTEGRITY,
  PATTERNS,
  SIGNATURE_HEADER,
} from "./constants.js";
import { base64url, createSessionKey, randomDeviceId, sha256, signText, tokenJti } from "./crypto.js";
import { collect, remember, reported } from "./integrity.js";
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

/**
 * Runs `task` in idle time: requestIdleCallback (called with globalThis as receiver, else "Illegal invocation"),
 * or setTimeout 0. Throws when scheduling throws.
 * @param {() => void} task
 * @returns {{ cancel: () => void }}
 */
function whenIdle(task) {
  const idle = globalValue("requestIdleCallback");
  if (typeof idle === "function") {
    const handle = idle.call(globalThis, task, { timeout: GUARD_LIMITS.idleTimeoutMs });
    return {
      cancel: () => {
        const cancel = globalValue("cancelIdleCallback");
        if (typeof cancel === "function") cancel.call(globalThis, handle);
      },
    };
  }
  const handle = setTimeout(task, 0);
  return { cancel: () => clearTimeout(handle) };
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
  const { appId, endpoint, storage, now, fetch, crypto, navigator, integrity } = source;
  return { appId, endpoint, storage, now, fetch, crypto, navigator, integrity };
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
  // The integrity collector (integrity.js): once, 30 s after the first token and while the page is visible, it
  // hashes one registered Build's files in idle time and sends the report with a re-attest made then. A further
  // Build on the page is collected after that and goes with the next regular re-attest.
  /** The report the next handshake carries. */
  /** @type {import("./integrity.js").Report | null} */
  let pending = null;
  /** The collector's timer, visibility listener or idle callback. */
  /** @type {{ cancel: () => void } | null} */
  let watch = null;
  /** The collection that is running. */
  /** @type {import("./integrity.js").Job | null} */
  let job = null;
  /** Whether the first collection ran (to its end: stop() during it lets a later token start it again). */
  let collected = false;
  /** Whether the last handshake delivered a report: a further Build may then be collected. */
  let delivered = false;

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
   * Replaces what the collector waits on, cancelling what it waited on before: nothing is ever left behind.
   * @param {{ cancel: () => void } | null} next
   */
  function setWatch(next) {
    const previous = watch;
    watch = next;
    try {
      previous?.cancel();
    } catch {
      // Nothing to cancel.
    }
  }

  /** The first-party storage of the device id and the integrity memo, or null. */
  const store = () => optionOrGlobal(opts.storage, "localStorage");

  /**
   * Keeps a report for the next handshake. Until then other tabs are kept from collecting its Build: the memo holds
   * a claim that outlasts the wait (`pendingMs`).
   * @param {import("./integrity.js").Report} report
   */
  function hold(report) {
    pending = report;
    const at = now();
    remember(store(), `${appId}/${report.build}`, at + INTEGRITY.pendingMs - INTEGRITY.memoMs, at);
  }

  /**
   * Runs `task` now, or when the page is next visible. Throws when the page cannot be watched.
   * @param {() => void} task
   */
  function whenVisible(task) {
    const page = /** @type {Document | null} */ (globalValue("document"));
    if (page?.visibilityState !== "hidden") return task();
    const cancel = () => page.removeEventListener("visibilitychange", seen);
    const seen = () => {
      if (page.visibilityState === "hidden") return;
      setWatch(null);
      task();
    };
    page.addEventListener("visibilitychange", seen);
    setWatch({ cancel });
  }

  /**
   * Collects in idle time. The first report (`early`) goes with a re-attest of its own, made while the page is
   * visible and after any handshake in flight; a later one, or one a handshake took meanwhile, with the next.
   * @param {boolean} early
   */
  function gather(early) {
    try {
      setWatch(null);
      watch = whenIdle(async () => {
        watch = null;
        collected = true;
        const started = generation;
        const running = { aborted: false };
        job = running;
        const report = await collect(
          appId,
          optionOrGlobal(opts.crypto, "crypto"),
          optionOrGlobal(opts.navigator, "navigator"),
          store(),
          now,
          running,
        );
        if (job === running) job = null;
        // A report is kept even when stop() came as the collection ended: its Build stays claimed, so only this
        // Guard can still send it, with its next handshake.
        if (report === null) return;
        hold(report);
        if (!early || started !== generation) return;
        await inFlight;
        if (started !== generation) return;
        try {
          whenVisible(() => {
            if (pending !== null && started === generation) void attest(true);
          });
        } catch {
          // The report goes with the next regular re-attest.
        }
      });
    } catch {
      // No idle time to be had: no report.
    }
  }

  /** The first collection, `delayMs` after the first token or when the page is next visible after that. */
  function watchIntegrity() {
    if (opts.integrity === false || collected || watch !== null) return;
    const timer = setTimeout(() => {
      watch = null;
      try {
        whenVisible(() => gather(true));
      } catch {
        // No report.
      }
    }, INTEGRITY.delayMs);
    setWatch({ cancel: () => clearTimeout(timer) });
  }

  /**
   * One handshake. The current token stays in use while it runs; a failure drops it, unless the handshake was
   * brought forward for an integrity report (`early`): then the token and its re-attest timer stay.
   * @param {boolean} early
   * @returns {Promise<string | null>}
   */
  async function run(early) {
    const started = generation;
    try {
      const token = await handshake(started);
      if (token !== null) {
        current = token.value;
        signer = { value: token.value, jti: token.jti, privateKey: token.privateKey };
        currentUntil = now() + token.lifetimeMs;
        if (started === generation) {
          schedule(token.lifetimeMs);
          watchIntegrity();
          if (delivered) gather(false);
        }
        return token.value;
      }
    } catch {
      // Any failure: no token.
    }
    if (early) return token();
    current = null;
    signer = null;
    return null;
  }

  /**
   * challenge → attest. Resolves null or throws on any failure.
   * @param {number} started The generation the handshake belongs to: after stop() it carries no integrity report.
   * @returns {Promise<{ value: string, lifetimeMs: number, jti: string | null, privateKey: unknown } | null>}
   */
  async function handshake(started) {
    const fetch = resolveFetch();
    const crypto = optionOrGlobal(opts.crypto, "crypto");
    if (typeof appId !== "string" || endpoint === "" || fetch === null || crypto === null) return null;

    const challenge = await post(fetch, `${endpoint}/v1/attest/challenge`, { app_id: appId });
    const nonce = challenge.nonce;
    if (typeof nonce !== "string" || !PATTERNS.nonce.test(nonce)) return null;

    const signals = collectSignals(optionOrGlobal(opts.navigator, "navigator"));
    const device = deviceId(crypto);
    const { jkt, jwk, pair } = await getSessionKey(crypto);
    // The waiting integrity report goes with this request, and waits again when the request fails. Not after
    // stop(): the report then waits for a handshake made after it. And not when another tab reported its Build
    // meanwhile: then it is dropped.
    let report = started === generation ? pending : null;
    if (report !== null) {
      pending = null;
      if (reported(store(), `${appId}/${report.build}`, now())) report = null;
    }
    /** @type {Record<string, unknown>} */
    let answer;
    try {
      answer = await post(fetch, `${endpoint}/v1/attest`, {
        app_id: appId,
        nonce,
        device,
        signals,
        cnf: { jkt, jwk },
        ...(report === null ? {} : { integrity: report }),
      });
    } catch (error) {
      if (report !== null && pending === null) hold(report);
      throw error;
    }
    delivered = report !== null;
    if (report !== null) remember(store(), `${appId}/${report.build}`, now(), now());

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

  /** @param {boolean} [early] */
  function attest(early) {
    if (inFlight === null) {
      const running = run(early === true);
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
    attest: () => attest(),
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
      try {
        pendingStart = whenIdle(() => {
          pendingStart = null;
          void attest();
        });
      } catch {
        pendingStart = null;
      }
    },
    stop() {
      generation += 1;
      clearTimer();
      cancelStart();
      setWatch(null);
      try {
        // A running collection ends here and gives its Build back: a later token starts the collection again.
        if (job !== null) {
          job.aborted = true;
          job.cancel?.();
          collected = false;
        }
      } catch {
        // Nothing to cancel.
      }
      job = null;
    },
  };
}
