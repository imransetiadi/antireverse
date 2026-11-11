import type { IncomingMessage, ServerResponse } from "node:http";
import type { ShieldEvent } from "@antireverse/protocol";
import { type AttestationResult, INVALID_RESULT } from "./attestation.ts";
import type { Signal } from "./canary.ts";
import { type Client, type ContainmentHit, UNKNOWN_CLIENT } from "./containment.ts";
import { truncateIp } from "./ip.ts";
import { type PatchBody, type PatchState, recordedPatch } from "./patches.ts";
import { trackRoute } from "./route.ts";
import type { SignatureState } from "./signature.ts";
import type { DecideInput, Decision, ShieldErrorHandler, ShieldMiddleware } from "./types.ts";
import { uuidv7 } from "./uuidv7.ts";

export interface AdapterDeps {
  /** Synchronous, no I/O. Called once per request, when the request arrives. */
  decide(input: DecideInput): Decision;
  /**
   * The Canary signals of the request (`canarySignals` under the applied Policy). Synchronous, no I/O. Called once
   * per request, when it arrives, with the path `decide` is given. Left out: no signals.
   */
  signals?(request: IncomingMessage, path: string): Signal[];
  /**
   * The client of the request from its address: the parsed address and the actor hash. Synchronous, no I/O.
   * Called once per request, when it arrives. Left out: every client is unknown.
   */
  client?(address: string | undefined): Client;
  /**
   * The Containment that blocks this client now, or null (`containmentOf` under the applied Policy). Synchronous,
   * no I/O. Called once per request, before `decide`. Left out: nothing is contained.
   */
  contain?(client: Client): ContainmentHit | null;
  /**
   * The attestation of the request (`ar-attestation` verified under the applied Policy). Synchronous, no I/O.
   * Called once per request, when it arrives. Left out: the Event's `attestation` is null. A throw is counted and
   * recorded as `invalid`: the request proceeds.
   */
  attest?(request: IncomingMessage): AttestationResult;
  /**
   * The request signature (slice 04), verified after `attest` and before `decide`. Synchronous, no I/O. The state is
   * read again when the response closes, so that the body hook's result (`checked`, `mismatch`) is recorded. Left
   * out: the Event's `signature` is null and the requirement is never met. A throw is counted and recorded as
   * `invalid`, and the requirement counts as not met (owner's decision, slice 04): an Enforce requirement Rule
   * blocks the request (fail closed there only); everywhere else the request proceeds as before.
   */
  signature?(request: IncomingMessage): SignatureState;
  /**
   * The media types (lower case, without parameters) whose parser carries `verifyBody` (`bodyVerified.types`). A
   * validly signed body of a listed type defers an Enforce requirement to the hook. Left out: none.
   */
  bodyTypes?: ReadonlySet<string>;
  /**
   * The Virtual patches of the request (slice 20), evaluated after Containments and Rules, when neither blocked it.
   * `recordMonitor` is false when a Rule in monitor already decided: only an enforced patch can still change the
   * outcome. Synchronous, no I/O. The state is read again when the response closes, so that the body hook's result
   * is recorded. Left out, or null: no patches. A throw is counted and the request proceeds (fail open).
   */
  patches?(request: IncomingMessage, method: string, recordMonitor: boolean): PatchState | null;
  /** The path pattern of the Rule behind a block Decision of `decide`, if it is one of Shield's own. */
  routeOf(decision: Decision): string | undefined;
  /** Buffers the Event. Synchronous, no I/O. */
  record(event: ShieldEvent): void;
  /** Milliseconds since the epoch. */
  now(): number;
  clientAddress: ((req: unknown) => string | undefined) | undefined;
  /** Counts an error that was contained. */
  onInternalError(): void;
}

/** `request.route` of a request that matched no route. Equal to `UNMATCHED_ROUTE` of the protocol (pinned by a test). */
const UNMATCHED_ROUTE = "(unmatched)";
/** The whole body of a block response. Equal to `BLOCK_RESPONSE_BODY` of the protocol (pinned by a test). */
export const BLOCK_BODY = '{"error":"request_blocked"}';
/** Every method `node:http` can parse; the protocol accepts nothing else. */
const METHOD = /^[A-Z-]{1,16}$/;
const LATENCY_MAX_MS = 600_000;
/** When no Decision could be made the request proceeds: fail open. */
const FAIL_OPEN: Decision = Object.freeze({ action: "allow", mode: "monitor", ruleId: null, policyVersion: 0 });

/** The media type of a request: its `content-type` before any `;`, trimmed, lower case; "" without one. */
function mediaTypeOf(request: IncomingMessage): string {
  const value = request.headers?.["content-type"];
  if (typeof value !== "string") return "";
  const end = value.indexOf(";");
  return (end === -1 ? value : value.slice(0, end)).trim().toLowerCase();
}

/**
 * Whether a request meets the signature requirement now: `valid` with body `none` or `checked`. A `valid` request
 * whose body is still `unchecked` meets it provisionally only when its media type is one whose parser carries the
 * hook (`bodyVerified.types`): the hook decides. Any other body cannot be bound in time: not met.
 */
function requirementMet(
  state: SignatureState,
  request: IncomingMessage,
  types: ReadonlySet<string> | undefined,
): boolean {
  if (state.status !== "valid") return false;
  if (state.body === "none" || state.body === "checked") return true;
  return state.body === "unchecked" && types !== undefined && types.size > 0 && types.has(mediaTypeOf(request));
}

/** A CORS preflight: `OPTIONS` with an `access-control-request-method` header (review F3). */
function isPreflight(request: IncomingMessage, method: string): boolean {
  return method === "OPTIONS" && request.headers?.["access-control-request-method"] !== undefined;
}

/** What an Event records of a state, at the time the response closes. */
function signatureOf(state: SignatureState): { status: SignatureState["status"]; body: SignatureState["body"] } {
  return { status: state.status, body: state.body };
}

function methodOf(request: IncomingMessage): string {
  const method = typeof request.method === "string" ? request.method.toUpperCase() : "";
  return METHOD.test(method) ? method : "UNKNOWN";
}

/**
 * The path Rules are matched against: the full path of the request, as the application routes on it.
 *
 * Under Express that is `req.baseUrl + req.path`. `req.path` is the pathname the router itself matches (the same
 * parse, cached on the request), so whatever spelling of a request target Express would route to a handler — a
 * query string, a fragment, the absolute form `http://host/path`, a backslash its parser turns into a slash —
 * Shield matches the same text. `req.baseUrl` is the part a mount point has stripped: together they are the whole
 * path wherever the middleware is installed, on the application or on a mounted router. `decide` matches this text
 * and also its canonical forms (decoded, dot segments resolved), which a middleware after Shield such as
 * `express.static` may act on.
 *
 * Without Express (`node:http` alone) it is the request URL; `decide` drops the query string.
 * A request without a URL has no path, and no Rule matches it.
 */
function pathOf(request: IncomingMessage): string {
  const req = request as IncomingMessage & { baseUrl?: unknown; path?: unknown; originalUrl?: unknown };
  const path = req.path;
  if (typeof path === "string") return (typeof req.baseUrl === "string" ? req.baseUrl : "") + path;
  const url = typeof req.originalUrl === "string" ? req.originalUrl : req.url;
  return typeof url === "string" ? url : "";
}

/** A Decision as `decide` promises it. Anything else is treated as a failure to decide. */
function isDecision(value: Decision): boolean {
  return (
    (value.action === "allow" || value.action === "block") &&
    (value.mode === "monitor" || value.mode === "enforce") &&
    (value.ruleId === null || typeof value.ruleId === "string") &&
    Number.isInteger(value.policyVersion) &&
    value.policyVersion >= 0
  );
}

/** Node sends status codes up to 999; the protocol stops at 599. */
function statusOf(response: ServerResponse): number {
  const status = response.statusCode;
  if (!Number.isInteger(status)) throw new TypeError("the response has no status code");
  return Math.min(Math.max(status, 100), 599);
}

/** Answers a blocked request: 403, `content-type: application/json`, the block body. Nothing else is added. */
function block(response: ServerResponse): void {
  if (response.headersSent) throw new Error("the response has already started");
  response.statusCode = 403;
  response.setHeader("content-type", "application/json");
  response.end(BLOCK_BODY);
}

/**
 * The Express adapter. For every request it:
 * - reads the client address once, when the request arrives, and derives its actor hash. The address stays in the
 *   process: only its network prefix and its hash are recorded;
 * - checks the Containments first: a request from a contained client (its actor hash or its network prefix is
 *   blocked, it is in no allowlist range, the block has not expired) is answered as a Rule block is, and its Event
 *   names the Containment. Rules are not consulted for it;
 * - otherwise decides once, on the method and the path. The path is used for that and nothing else: it is never
 *   recorded;
 * - answers a request that a Rule in Enforce mode blocks with 403 and the block body, and calls neither `next()`
 *   nor anything of the application. Every other request it leaves alone: the response is never touched;
 * - never throws and fails open: everything that can fail is inside try/catch, and when no Decision can be made,
 *   or the block response cannot be written, the request proceeds and the error is counted;
 * - records exactly one Event, on the response's 'close' — the only event that also fires when the client aborts;
 * - records only the allowlist: method, route, status, latency, network prefix, actor hash, Decision, Containment
 *   id, signals, attestation status with verdict and risk (never the token), signature status and body state (never
 *   the signature, nonce, content hash or body). The route is the route template, or, for a request a Rule blocked, the path pattern of the Rule,
 *   and `(unmatched)` for a request a Containment blocked. A signal names a Canary the request used by its id,
 *   never by its value.
 */
export function createExpressMiddleware(deps: AdapterDeps): ShieldMiddleware {
  /** Requests already seen: mounting the middleware twice still gives one Decision and one Event per request. */
  const observed = new WeakSet<IncomingMessage>();

  function contained(): void {
    try {
      deps.onInternalError();
    } catch {
      // nothing left to do
    }
  }

  /**
   * Registers the Event of this request. `blockedBy` is the route recorded for a blocked request: the path pattern
   * of the Rule, or `(unmatched)` for a Containment. `containmentId` names the Containment that blocked it, if any.
   */
  function observe(
    request: IncomingMessage,
    response: ServerResponse,
    started: number,
    decision: Decision,
    blockedBy: string | undefined,
    containmentId: string | null,
    signals: Signal[],
    ipPrefix: string | null,
    client: Client,
    attestation: AttestationResult | null,
    signature: SignatureState | null,
    patches: PatchState | null,
  ): void {
    const startedAt = deps.now();
    const eventId = uuidv7(startedAt);
    // A blocked request never reaches the router: there is no route to track.
    const routeOf = blockedBy === undefined ? trackRoute(request) : undefined;

    response.once("close", () => {
      try {
        const latency = performance.now() - started;
        // A requirement deferred to the body hook and not met after all — the hook refused the body, or never ran
        // (review F1: an honest record; the response has already gone out) — names the requirement Rule.
        let recorded = decision;
        let route = blockedBy;
        let patchId: string | null = null;
        let patchBody: PatchBody | null = null;
        const deferred = signature?.deferred as Decision | undefined;
        if (patches !== null && patches.blocked !== null) {
          // An enforced patch refused the request, when it arrived or in the body hook.
          recorded = patches.blocked.decision;
          patchId = patches.blocked.id;
          patchBody = patches.blockedBody;
        } else if (
          signature !== null &&
          deferred !== undefined &&
          (signature.body === "mismatch" || signature.body === "unchecked")
        ) {
          recorded = deferred;
          route = deps.routeOf(deferred) ?? route;
        } else if (patches !== null && recorded.action === "allow") {
          // Nothing before the patches decided: a monitor patch that matched, else one whose body was never checked
          // (recorded, never blocking).
          const patch = recordedPatch(patches);
          if (patch !== null) {
            recorded = patch.decision;
            patchId = patch.patch.id;
            patchBody = patch.body;
          }
        }
        deps.record({
          event_id: eventId,
          ts: new Date(startedAt).toISOString(),
          type: "request.decision",
          surface: "api",
          request: {
            method: methodOf(request),
            route: route ?? routeOf?.() ?? UNMATCHED_ROUTE,
            status: statusOf(response),
            latency_ms: latency > 0 ? Math.min(Math.round(latency * 1000) / 1000, LATENCY_MAX_MS) : 0,
          },
          decision: {
            action: recorded.action,
            mode: recorded.mode,
            rule_id: recorded.ruleId,
            policy_version: recorded.policyVersion,
            containment_id: containmentId,
            patch_id: patchId,
            patch_body: patchBody,
          },
          actor: { ip_prefix: ipPrefix, ip_hash: client.hash },
          signals,
          attestation:
            attestation === null
              ? null
              : { status: attestation.status, verdict: attestation.verdict, risk: attestation.risk },
          signature: signature === null ? null : signatureOf(signature),
        });
      } catch {
        contained();
      }
    });
  }

  /** Decides, blocks if a Rule says so, and registers the Event. True when the request was answered here. */
  function handle(request: IncomingMessage, response: ServerResponse): boolean {
    const started = performance.now();
    let decision = FAIL_OPEN;
    let blockedBy: string | undefined;
    let containmentId: string | null = null;
    let path: string | undefined;
    let signals: Signal[] = [];
    // The address is read once, now: at 'close' the socket may be gone. It never leaves the process.
    let ipPrefix: string | null = null;
    let client = UNKNOWN_CLIENT;
    try {
      const address = deps.clientAddress ? deps.clientAddress(request) : request.socket?.remoteAddress;
      ipPrefix = truncateIp(address);
      if (deps.client !== undefined) client = deps.client(address);
    } catch {
      contained();
      ipPrefix = null;
      client = UNKNOWN_CLIENT;
    }
    try {
      path = pathOf(request);
      // Observe only: a Canary adds a signal to the Event and changes nothing else.
      if (deps.signals !== undefined) signals = deps.signals(request, path);
    } catch {
      contained();
      signals = [];
    }
    // Observe only: the attestation is recorded and decides nothing. A failure records `invalid` (a token that could
    // not be verified is not a valid one) and the request proceeds.
    let attestation: AttestationResult | null = null;
    try {
      if (deps.attest !== undefined) attestation = deps.attest(request);
    } catch {
      contained();
      attestation = INVALID_RESULT;
    }
    // The signature, after the attestation (its token backs the signature). Recorded on the Event; it decides only
    // through requirement Rules. A failure records `invalid` and does not meet the requirement: only an Enforce
    // requirement Rule then blocks (fail closed there, by the owner's decision); every other request proceeds.
    let signature: SignatureState | null = null;
    let signed = false;
    try {
      if (deps.signature !== undefined) {
        signature = deps.signature(request);
        signed = requirementMet(signature, request, deps.bodyTypes);
      }
    } catch {
      contained();
      signature = { status: "invalid", body: "none", deferred: undefined, refuse: false };
      signed = false;
    }
    // Containments before Rules. Whatever fails here contains nothing: the Rules still decide.
    let hit: ContainmentHit | null = null;
    try {
      if (deps.contain !== undefined && client.address !== null) hit = deps.contain(client);
    } catch {
      contained();
      hit = null;
    }
    try {
      if (hit !== null) {
        decision = hit.decision;
        block(response);
        blockedBy = UNMATCHED_ROUTE; // the request never reached a route
        containmentId = hit.id;
      } else {
        if (path === undefined) throw new TypeError("the path of the request could not be read");
        const method = methodOf(request);
        const preflight = isPreflight(request, method);
        const decided = deps.decide({ method, path, signed, preflight });
        if (!isDecision(decided)) throw new TypeError("decide did not return a Decision");
        decision = decided;
        // Met only provisionally (body still unchecked, a listed type): what applies if the hook refuses the body
        // or never runs.
        if (signed && signature !== null && signature.body === "unchecked") {
          const unmet = deps.decide({ method, path, signed: false, preflight });
          if (isDecision(unmet) && unmet !== decided && unmet.action === "block") {
            signature.deferred = unmet;
            // Only an enforced requirement refuses a mismatching body; a Monitor one records it.
            signature.refuse = unmet.mode === "enforce";
          }
        }
        if (decision.action === "block" && decision.mode === "enforce") {
          const route = deps.routeOf(decision) ?? UNMATCHED_ROUTE;
          block(response);
          blockedBy = route;
        }
      }
    } catch {
      // No Decision, or no way to answer 403 any more: the request proceeds, and the Event says so.
      contained();
      decision = FAIL_OPEN;
      blockedBy = undefined;
      containmentId = null;
    }
    // The Virtual patches, after Containments and Rules, unless one of them refused the request already. Whatever
    // fails here fails open: the request proceeds as the Rules decided.
    let patches: PatchState | null = null;
    if (blockedBy === undefined && deps.patches !== undefined) {
      const ruled = decision;
      try {
        patches = deps.patches(request, methodOf(request), decision.action === "allow");
        if (patches !== null && patches.blocked !== null) {
          decision = patches.blocked.decision;
          block(response);
          blockedBy = UNMATCHED_ROUTE; // the request never reached a route
        }
      } catch {
        contained();
        patches = null;
        decision = ruled;
        blockedBy = undefined;
      }
    }
    try {
      observe(
        request,
        response,
        started,
        decision,
        blockedBy,
        containmentId,
        signals,
        ipPrefix,
        client,
        attestation,
        signature,
        patches,
      );
    } catch {
      contained(); // the Event is lost; the Decision stands
    }
    return blockedBy !== undefined;
  }

  return function shieldMiddleware(request, response, next) {
    let answered = false;
    try {
      if (!observed.has(request)) {
        observed.add(request);
        answered = handle(request, response);
      }
    } catch {
      contained();
    }
    if (!answered) next();
  };
}

/**
 * `shield.errorHandler()` (review F6): an Express error middleware (four arguments) that answers the error
 * `verifyBody` throws on a refused body with exactly the response of any Shield block — 403,
 * `content-type: application/json`, the block body — and passes every other error, and this one once the response
 * has started, to `next(err)` unchanged. Never throws.
 */
export function createErrorHandler(isRefusal: (error: unknown) => boolean): ShieldErrorHandler {
  // Four declared parameters: Express recognises an error middleware by its arity.
  return function shieldErrorHandler(error, _request, response, next) {
    let answered = false;
    try {
      if (isRefusal(error) && !response.headersSent) {
        block(response);
        answered = true;
      }
    } catch {
      answered = false;
    }
    if (!answered) next(error);
  };
}
