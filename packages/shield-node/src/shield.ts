import { createAttestationChecker, HEADER_NAME } from "./attestation.ts";
import { canarySignals } from "./canary.ts";
import { containmentOf, describeClient, resolveActorKey } from "./containment.ts";
import { decide } from "./decide.ts";
import { createEmitter, type Emitter } from "./emitter.ts";
import { createErrorHandler, createExpressMiddleware } from "./express.ts";
import {
  createInventorySender,
  INVENTORY_FALLBACK_MS,
  INVENTORY_START_DELAY_MS,
  type InventorySender,
  readInventory,
} from "./inventory.ts";
import { createPatchChecker } from "./patches.ts";
import { createPoller, type Poller } from "./policy/poller.ts";
import { BUILT_IN_POLICY, createPolicyStore, routeOfDecision } from "./policy/store.ts";
import { audienceOf, importPublicKey } from "./policy/verify.ts";
import { BodyMismatchError, createSignatureChecker, hasBody, type SessionBinding } from "./signature.ts";
import { createNodeTransport } from "./transport.ts";
import {
  POLICY_DEFAULTS,
  SHIELD_DEFAULTS,
  type Shield,
  type ShieldConfig,
  type ShieldLogger,
  type ShieldMiddleware,
  type ShieldStats,
} from "./types.ts";

/**
 * The format of a Shield key. Equal to `SHIELD_KEY_PATTERN` of the protocol package (pinned by a test);
 * repeated here because Shield has no runtime dependency, not even on the protocol.
 */
export const SHIELD_KEY_FORMAT = /^ark_(prod|stg|dev)_[A-Za-z0-9_-]{43}$/;

const passThrough: ShieldMiddleware = (_req, _res, next) => next();
/** Shield's body refusal: the error `verifyBody` throws on a mismatch under an enforced requirement. */
const isRefusal = (error: unknown): boolean => error instanceof BodyMismatchError;

/** `type/subtype` in lower case: RFC 9110 tokens, no wildcard. */
const MEDIA_TYPE = /^[a-z0-9!#$%&'^_`|~.+-]+\/[a-z0-9!#$%&'^_`|~.+-]+$/;
const BODY_VERIFIED_HELP =
  'bodyVerified must be { types: ["application/json", ...] }: the media types whose body parser carries shield.verifyBody';

/**
 * The media types of `bodyVerified`, lower case and without parameters; null when the option is absent. Throws a
 * TypeError for anything else (`true`, the form before review F1, included): a configuration error is reported at
 * startup rather than turned into a silently open or closed route.
 */
function bodyTypesOf(config: unknown): ReadonlySet<string> | null {
  if (config === null || typeof config !== "object") return null;
  let option: unknown;
  try {
    option = (config as { bodyVerified?: unknown }).bodyVerified;
  } catch {
    return null; // an unreadable configuration: createShield gives the disabled Shield
  }
  if (option === undefined) return null;
  if (option === null || typeof option !== "object" || Array.isArray(option)) {
    throw new TypeError(`${BODY_VERIFIED_HELP}; got ${option === true ? "true" : typeof option}.`);
  }
  const types = (option as { types?: unknown }).types;
  if (!Array.isArray(types)) throw new TypeError(`${BODY_VERIFIED_HELP}; types is not a list.`);
  const set = new Set<string>();
  for (const type of types) {
    if (typeof type !== "string") throw new TypeError(`${BODY_VERIFIED_HELP}; a type is not a string.`);
    const end = type.indexOf(";");
    const media = (end === -1 ? type : type.slice(0, end)).trim().toLowerCase();
    if (!MEDIA_TYPE.test(media)) throw new TypeError(`${BODY_VERIFIED_HELP}; "${media}" is not type/subtype.`);
    set.add(media);
  }
  return set;
}

/** Prints at most one line per distinct condition, never throws, and never receives the key. */
function createOnceLogger(logger: ShieldLogger | undefined): (condition: string, message: string) => void {
  const seen = new Set<string>();
  return (condition, message) => {
    if (seen.has(condition)) return;
    seen.add(condition);
    try {
      (logger ?? console).warn(`[shield] ${message}`);
    } catch {
      // the host's logger failed: nothing to do
    }
  };
}

function disabledShield(reason: string, warn: (condition: string, message: string) => void): Shield {
  warn("disabled", `Shield is disabled: ${reason}. Requests are served as usual and nothing is recorded.`);
  const stats: ShieldStats = {
    buffered: 0,
    sent: 0,
    dropped: 0,
    failedBatches: 0,
    internalErrors: 0,
    disabledReason: reason,
    lastError: null,
    policyVersion: 0,
    policyStale: false,
    policyRules: 0,
    lastPolicyError: null,
    actorHashing: false,
    inventory: "off",
  };
  return {
    decide: (input) => decide(BUILT_IN_POLICY, input),
    express: () => passThrough,
    flush: () => Promise.resolve(),
    refreshPolicy: () => Promise.resolve(),
    close: () => Promise.resolve(),
    stats: () => ({ ...stats }),
    verifyBody: () => {},
    errorHandler: () => createErrorHandler(() => false),
  };
}

/** Why this configuration cannot run, or null. The reason never contains the key. */
function reasonToDisable(config: ShieldConfig): string | null {
  const disabled = config.disabled;
  if (disabled === true) return "disabled by configuration";
  if (disabled === undefined && process.env.AR_SHIELD_DISABLED === "1") return "AR_SHIELD_DISABLED=1 is set";
  const key: unknown = config.key;
  if (key === undefined || key === null || key === "") return "no Shield key was given";
  if (typeof key !== "string" || !SHIELD_KEY_FORMAT.test(key)) {
    return "the Shield key is malformed (expected ark_<prod|stg|dev>_ followed by 43 characters)";
  }
  const endpoint: unknown = config.endpoint;
  if (typeof endpoint !== "string" || endpoint === "") return "no endpoint was given";
  let protocol: string;
  try {
    protocol = new URL(endpoint).protocol;
  } catch {
    return "the endpoint is not a URL";
  }
  if (protocol !== "http:" && protocol !== "https:") return "the endpoint is not an http or https URL";
  return null;
}

function activeShield(
  config: ShieldConfig,
  warn: (condition: string, message: string) => void,
  bodyTypes: ReadonlySet<string> | null,
): Shield {
  const now = typeof config.now === "function" ? config.now : Date.now;
  const ownTransport = typeof config.transport === "function" ? undefined : createNodeTransport();
  const transport = ownTransport?.send ?? (config.transport as NonNullable<ShieldConfig["transport"]>);
  const requestTimeoutMs = config.requestTimeoutMs ?? SHIELD_DEFAULTS.requestTimeoutMs;
  const emitter: Emitter = createEmitter({
    key: config.key,
    endpoint: config.endpoint,
    flushIntervalMs: config.flushIntervalMs ?? SHIELD_DEFAULTS.flushIntervalMs,
    maxBatchSize: config.maxBatchSize ?? SHIELD_DEFAULTS.maxBatchSize,
    maxBufferSize: config.maxBufferSize ?? SHIELD_DEFAULTS.maxBufferSize,
    requestTimeoutMs,
    transport,
    now,
    warn,
  });

  // The runtime component inventory: the option, else AR_SHIELD_INVENTORY=0 turns it off. Started below, once.
  const inventoryOn =
    typeof config.inventory === "boolean" ? config.inventory : process.env.AR_SHIELD_INVENTORY !== "0";
  const projectRoot =
    typeof config.projectRoot === "string" && config.projectRoot !== "" ? config.projectRoot : process.cwd();
  const inventory: InventorySender | undefined = inventoryOn
    ? createInventorySender({
        key: config.key,
        endpoint: config.endpoint,
        requestTimeoutMs: positiveOr(requestTimeoutMs, SHIELD_DEFAULTS.requestTimeoutMs),
        transport,
        load: () => readInventory(projectRoot),
        warn,
      })
    : undefined;
  /** Starts the inventory (once; later calls do nothing) and cancels the timer that would have started it. */
  function startInventory(): void {
    if (inventoryTimer !== undefined) clearTimeout(inventoryTimer);
    inventoryTimer = undefined;
    inventory?.start();
  }

  // The Policy. Without a usable public key nothing is fetched and the built-in Policy stays: Shield observes only.
  const store = createPolicyStore();
  let poller: Poller | undefined;
  /** Why no Policy is fetched although a public key was given. Never contains the value. */
  let policyConfigError: string | null = null;
  const given: unknown = config.policyPublicKey;
  if (given === undefined || given === null || given === "") {
    warn(
      "policy-off",
      'no "policyPublicKey" was given: Shield observes only. It records Events and blocks nothing, whatever Policy is published.',
    );
  } else {
    const publicKey = importPublicKey(given);
    if (publicKey === null) {
      policyConfigError = "policyPublicKey is not an Ed25519 public key in base64url";
      warn(
        "policy-key",
        '"policyPublicKey" is not an Ed25519 public key (the public_key of GET /v1/signing-key, base64url): Shield observes only. It records Events and blocks nothing.',
      );
    } else {
      poller = createPoller({
        key: config.key,
        endpoint: config.endpoint,
        publicKey,
        audience: audienceOf(config.key),
        intervalMs: config.policyPollIntervalMs ?? POLICY_DEFAULTS.pollIntervalMs,
        requestTimeoutMs: positiveOr(requestTimeoutMs, SHIELD_DEFAULTS.requestTimeoutMs),
        transport,
        now,
        warn,
        store,
        onFetched: () => startInventory(),
      });
    }
  }
  /**
   * Without a Policy to fetch, the inventory starts after a short delay; with one, after the first successful fetch,
   * or after the fallback delay if none succeeded by then. Unref'd: it never holds the process.
   */
  let inventoryTimer: NodeJS.Timeout | undefined;
  if (inventory !== undefined) {
    inventoryTimer = setTimeout(
      () => {
        inventoryTimer = undefined;
        inventory.start();
      },
      poller === undefined ? INVENTORY_START_DELAY_MS : INVENTORY_FALLBACK_MS,
    );
    inventoryTimer.unref();
  }

  // The actor key: the option, else AR_ACTOR_KEY. Never the Shield key, never repeated anywhere.
  const actor = resolveActorKey(config.actorKey !== undefined ? config.actorKey : process.env.AR_ACTOR_KEY, config.key);
  if (actor.unusable) {
    warn(
      "actor-key",
      'the actor key ("actorKey" or AR_ACTOR_KEY) is not usable: it needs at least 32 characters, no whitespace, and must not be the Shield key. Events carry no actor hash and actor blocks never match; network blocks still apply.',
    );
  }
  const actorKey = actor.key;

  // Attestation Tokens are verified with the keys of the applied bundle, by Shield's clock, and cached by jti.
  const attestation = createAttestationChecker();
  // Request signatures (slice 04): verified against the binding of the request's valid token, nonces per instance.
  const signatures = createSignatureChecker();
  // Virtual patches (slice 20): evaluated per request after the Rules; body conditions completed by `verifyBody`.
  const patchChecker = createPatchChecker();
  /** The binding of each request's token, from `attest` to `signature` of the same request. */
  const bindings = new WeakMap<object, SessionBinding>();

  let internalErrors = 0;
  let middleware: ShieldMiddleware | undefined;

  function policyStale(): boolean {
    try {
      return store.isStale(now());
    } catch {
      return false; // the host's clock threw
    }
  }

  const shield: Shield = {
    decide: (input) => decide(store.current(), input),
    express() {
      middleware ??= createExpressMiddleware({
        // Looked up on the Shield at call time, so the Decision always comes from the public `decide`.
        decide: (input) => shield.decide(input),
        signals: (request, path) => canarySignals(store.current(), request, path),
        client: (address) => describeClient(actorKey, address),
        contain: (client) => containmentOf(store.current(), client, now),
        attest: (request) => {
          const { result, binding } = attestation.checkBound(
            store.current(),
            request.headers?.[HEADER_NAME],
            Math.floor(now() / 1000),
          );
          if (binding !== null) bindings.set(request, binding);
          return result;
        },
        signature: (request) => signatures.check(request, bindings.get(request) ?? null, now()),
        patches: (request, method, recordMonitor) =>
          patchChecker.evaluate(store.current(), request, method, hasBody(request), recordMonitor),
        ...(bodyTypes === null ? {} : { bodyTypes }),
        routeOf: routeOfDecision,
        record: (event) => emitter.record(event),
        now,
        clientAddress: typeof config.clientAddress === "function" ? config.clientAddress : undefined,
        onInternalError: () => {
          internalErrors += 1;
        },
      });
      return middleware;
    },
    // A plain function, so that `express.json({ verify: shield.verifyBody })` works unbound. Only the fixed 403 error
    // of a body mismatch is thrown; anything else is contained and the parser goes on: fail open.
    // The patches' body conditions follow the signature (Rules before patches), on whatever body the hook sees —
    // `bodyVerified.types` governs signature requirements only; an enforced match throws the same 403 error. A
    // failure in them is contained.
    verifyBody: (req, _res, buf) => {
      try {
        signatures.verifyBody(req, buf);
      } catch (error) {
        if (error instanceof BodyMismatchError) throw error;
        internalErrors += 1;
      }
      let refuse = false;
      try {
        refuse = patchChecker.verifyBody(req, buf);
      } catch {
        internalErrors += 1;
        refuse = false;
      }
      if (refuse) throw new BodyMismatchError();
    },
    errorHandler: () => createErrorHandler(isRefusal),
    flush: () => emitter.flush(),
    refreshPolicy: () => poller?.refresh() ?? Promise.resolve(),
    close() {
      poller?.close();
      if (inventoryTimer !== undefined) clearTimeout(inventoryTimer);
      inventoryTimer = undefined;
      inventory?.close();
      return emitter.close().then(() => {
        ownTransport?.close();
      });
    },
    stats() {
      const policy = store.current();
      return {
        ...emitter.stats(),
        internalErrors,
        disabledReason: null,
        policyVersion: policy.version,
        policyStale: policyStale(),
        policyRules: policy.rules.length + policy.signatureRules.length,
        lastPolicyError: poller?.lastError() ?? policyConfigError,
        actorHashing: actorKey !== null,
        inventory: inventory?.state() ?? "off",
      };
    },
  };
  return shield;
}

/** The emitter brings nonsense numbers back to its defaults itself; the poller is given a usable timeout. */
function positiveOr(value: number, fallback: number): number {
  return Number.isFinite(value) && value >= 1 ? Math.min(Math.floor(value), 600_000) : fallback;
}

/**
 * Creates a Shield. A configuration that cannot run gives a disabled Shield that logs one warning, lets every
 * request through untouched and records nothing. The one exception: a malformed `bodyVerified` throws a TypeError
 * here, at startup, disabled or not (review F1) — it is a programming error, not a deployment condition.
 */
export function createShield(config: ShieldConfig): Shield {
  const bodyTypes = bodyTypesOf(config);
  let warn: (condition: string, message: string) => void = () => {};
  try {
    const given: ShieldConfig | null | undefined = config;
    const logger = given?.logger;
    warn = createOnceLogger(typeof logger?.warn === "function" ? logger : undefined);
    if (given === null || typeof given !== "object") return disabledShield("no configuration was given", warn);
    const reason = reasonToDisable(given);
    return reason === null ? activeShield(given, warn, bodyTypes) : disabledShield(reason, warn);
  } catch {
    return disabledShield("the configuration could not be read", warn);
  }
}
