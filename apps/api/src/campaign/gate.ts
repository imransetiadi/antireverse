import { createHash } from "node:crypto";
import {
  type AuthorizeResult,
  CAMPAIGN_END_REASONS,
  CAMPAIGN_LIMITS,
  CAMPAIGN_METHODS,
  type CampaignEndReason,
  type CampaignEvidence,
  type CampaignExchange,
  type CampaignIntensity,
  type CampaignLocation,
  type CampaignMethod,
  type CampaignRefusalReason,
  type CampaignSendFailure,
  canonicalCampaignPath,
  canonicalCampaignQuery,
  FATAL_CAMPAIGN_REFUSALS,
  TARGET_LIMITS,
  VERIFICATION_FILE_PATH,
} from "@antireverse/protocol";
import { type PinnedResponse, RESPONSE_HEADER_BYTES_MAX, TLS_OVERHEAD_BYTES_MAX } from "../prove/verify.ts";
import { BODY_WITHHELD, excerptAround, locationOf, redactBody, redactHeaders } from "./redact.ts";

// The request gate of a Pentest Campaign (slice 15a, D-105): the only code that sends Campaign traffic. An engine can
// ask for `{ method, path, query }` and nothing else; the gate decides, in a fixed order, whether that becomes a
// request to the Campaign's own Target:
//
//   1. the kill switch, the Organization's suspension, a stop request, a pending deletion;
//   2. the probe's shape;
//   3. the method: GET or HEAD;
//   4. the path and query: canonical, so that the form authorised is exactly the form sent;
//   5. `authorize`, read from the database: the Target still verified, in scope, the path not excluded, the intensity,
//      the window;
//   6. the Rules of Engagement are still the version bound at creation;
//   7. the request, time and byte budgets, charged before the call;
//   8. the spacing of one request per second, one at a time.
//
// The ownership check at the start goes through the gate too (`ownership`): it is authorised, budgeted, spaced and
// logged like any request, so that at most 60 requests in all reach a target.
//
// The log row of a request is written BEFORE the request goes out (`sending`) and settled afterwards: whatever fails
// later, a request that reached the target is in the log. If the row cannot be written, nothing is sent.
//
// A refused probe is never sent: it is logged with a fixed reason, and 20 refusals end the Campaign. The gate holds no
// host and no address: the transport it is given is bound to the Campaign's Target and its pinned address by the
// runner. It sets three request headers and no others: no body, no cookie, no credential can leave through it. What
// comes back is redacted here, before the engine, a Finding or the log sees it.

export const CAMPAIGN_USER_AGENT = "Airverse-Campaign/1";
export const CAMPAIGN_ID_HEADER = "x-airverse-campaign";

/** What the gate reads before every request, from the database. */
export interface GateControl {
  /** The operator's global kill switch. */
  killed: boolean;
  /** The operator suspended this Organization's Campaigns. */
  suspended: boolean;
  /** The owner asked to stop this Campaign. */
  stopRequested: boolean;
  /** The Organization's deletion is pending. */
  deletionPending: boolean;
}

/** One request as the gate hands it to the transport. The host and the address are the transport's, not the gate's. */
export interface GateSend {
  method: CampaignMethod;
  /** `path` or `path?query`, canonical. */
  target: string;
  headers: Readonly<Record<string, string>>;
  /** Bytes of the response read at most. */
  bodyBytesMax: number;
  /** Aborted at the request's deadline and when the Campaign is stopped. */
  signal: AbortSignal;
}

/** One row of the request log. Never a body. */
export interface GateRecord {
  seq: number;
  method: string | null;
  target: string | null;
  outcome: "sending" | "sent" | "not_sent" | "refused";
  reason: CampaignRefusalReason | null;
  status: number | null;
  failure: CampaignSendFailure | null;
  bytes: number;
  ms: number;
}

export interface GateDeps {
  campaign: { id: string; host: string; roeId: string; intensity: CampaignIntensity };
  control(): Promise<GateControl>;
  /** The API's `authorize` for the Campaign's Organization: read from the database on every call. */
  authorize(request: { host: string; path: string; intensity: CampaignIntensity }): Promise<AuthorizeResult>;
  transport(send: GateSend): Promise<PinnedResponse>;
  /** Writes a new row of the log: a refused probe, or a request about to go out (`sending`). */
  record(entry: GateRecord): Promise<void>;
  /** Settles the `sending` row of `entry.seq` with the request's result. */
  settle(entry: GateRecord): Promise<void>;
  /**
   * Whether the Rules' window still holds `aheadMs` from now, for `path`: asked with the time a request may still be
   * running at, so that none is started that could cross the window's end. Default: not asked.
   */
  windowHolds?(path: string, aheadMs: number): Promise<boolean>;
  /**
   * What is in this Campaign's log already (an earlier process started it and did not get to run it): the log and the
   * budgets go on from there, so that they hold per Campaign, not per attempt.
   */
  already?: { seq: number; sent: number; refused: number; bytes: number } | undefined;
  /** When the last request to this host or address went out (on `now`'s clock), whichever Campaign sent it. */
  previousSendAt?: number | null | undefined;
  /** Told the time (on `now`'s clock) each request goes out. */
  onSend?(at: number): void;
  /**
   * Milliseconds of a clock that only moves forward: the spacing, the time budget and the durations are measured on
   * it. (The API's wall clock, which `authorize` judges the window by, is not the gate's.)
   */
  now(): number;
  /** Resolves after `ms`, or rejects when the signal aborts. */
  sleep(ms: number, signal: AbortSignal): Promise<void>;
  /** Aborted when the Campaign is stopped; its reason, when it is an end reason, is how the Campaign ended. */
  signal: AbortSignal;
  /** Told once, when the gate ends the Campaign. */
  onEnd(reason: CampaignEndReason): void;
  /** Tests only: a shorter spacing or request deadline. Production passes none, so the protocol's limits hold. */
  limits?: { minSpacingMs?: number; requestTimeoutMs?: number } | undefined;
}

/** What the ownership check came to. `sent`: whether its request went out. */
export type OwnershipOutcome = { ok: true; body: string } | { ok: false; reason: CampaignEndReason; sent: boolean };

export interface Gate {
  /**
   * The start check's GET of the verification file from the pinned address, judged like a probe (authorize for its
   * path, the Rules bound at creation, the budgets, the window, the spacing) and logged as the first request. Not
   * for an engine: it hands back the file's body, unredacted, for the comparison with the token only. A whole 200 is
   * the only answer that counts. It does not end the Campaign: the runner writes the refusal.
   */
  ownership(): Promise<OwnershipOutcome>;
  /** Judges one probe and, if it passes, sends it. Never rejects. */
  request(probe: unknown): Promise<CampaignExchange>;
  /** The evidence of the sent request `seq`, with an excerpt of its redacted body around `at`; null if unknown. */
  evidence(seq: number, at: number): CampaignEvidence | null;
  counters(): { sent: number; refused: number; bytes: number };
  /** Why the gate ended the Campaign, or null while it has not. */
  ended(): CampaignEndReason | null;
}

interface Held {
  method: CampaignMethod;
  target: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  sha256: string;
  truncated: boolean;
  location: CampaignLocation | null;
}

/**
 * Bytes kept back before a request may start, beside its body: its headers (16 KB), the connection's TLS share
 * (16 KB) and two late socket reads (128 KB) that can arrive before a connection over its cap is dropped. What the
 * connections read is counted exactly; the reserve is what keeps the count inside the 2 MB. (It is not a hard bound
 * on the wire: a socket that delivered more than two reads after its cap would pass it; the next request is then
 * refused.)
 */
const READ_RESERVE = RESPONSE_HEADER_BYTES_MAX + TLS_OVERHEAD_BYTES_MAX + 131_072;

const PROBE_KEYS = new Set(["method", "path", "query"]);
const FATAL = new Set<string>(FATAL_CAMPAIGN_REFUSALS);
const LOG_TARGET_MAX = 256;

function plainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** What a refused probe asked for, for the log: bounded, printable ASCII only. Null when it had no such member. */
function printable(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  return value.slice(0, max).replace(/[^\x21-\x7e]/g, "?");
}

function loggedMethod(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return /^[A-Z]{1,16}$/.test(value) ? value : "OTHER";
}

export function createGate(deps: GateDeps): Gate {
  const { campaign } = deps;
  const minSpacingMs = deps.limits?.minSpacingMs ?? CAMPAIGN_LIMITS.minSpacingMs;
  const requestTimeoutMs = deps.limits?.requestTimeoutMs ?? CAMPAIGN_LIMITS.requestTimeoutMs;
  const wallMs = CAMPAIGN_LIMITS.wallTimeS * 1000;
  const startedAt = deps.now();
  const held = new Map<number, Held>();
  let seq = deps.already?.seq ?? 0;
  let sent = deps.already?.sent ?? 0;
  let refused = deps.already?.refused ?? 0;
  let bytes = deps.already?.bytes ?? 0;
  let failures = 0;
  let lastSentAt: number | null = deps.previousSendAt ?? null;
  let inFlight = false;
  let end: CampaignEndReason | null = null;

  function finish(reason: CampaignEndReason): void {
    if (end !== null) return;
    end = reason;
    deps.onEnd(reason);
  }

  function abortReason(): CampaignEndReason {
    const reason = deps.signal.reason as unknown;
    return (CAMPAIGN_END_REASONS as readonly unknown[]).includes(reason) ? (reason as CampaignEndReason) : "owner_stop";
  }

  async function refuse(reason: CampaignRefusalReason, probe: unknown): Promise<CampaignExchange> {
    refused += 1;
    const asked = plainObject(probe) ? probe : {};
    if (seq < CAMPAIGN_LIMITS.storedRequestsMax) {
      seq += 1;
      try {
        await deps.record({
          seq,
          method: loggedMethod(asked.method),
          target: printable(asked.path, LOG_TARGET_MAX),
          outcome: "refused",
          reason,
          status: null,
          failure: null,
          bytes: 0,
          ms: 0,
        });
      } catch {
        // A log that cannot be written ends the Campaign.
        finish("engine_error");
      }
    } else finish("refusal_limit");
    let fatal = FATAL.has(reason);
    if (fatal) finish(reason as CampaignEndReason);
    else if (refused >= CAMPAIGN_LIMITS.refusalsMax) {
      fatal = true;
      finish("refusal_limit");
    }
    return { ok: false, refused: reason, fatal: fatal || end !== null };
  }

  /** How long the next request must wait for the spacing. */
  const spacingWait = (): number => (lastSentAt === null ? 0 : Math.max(0, lastSentAt + minSpacingMs - deps.now()));

  /**
   * The budgets, for a request that would start after `wait`: the first that is spent, or null. A request is not
   * started when its own deadline would cross the 300th second, or when no room is left for its headers.
   */
  function overBudget(wait: number): "request_budget" | "time_budget" | "byte_budget" | null {
    if (sent >= CAMPAIGN_LIMITS.requestsMax) return "request_budget";
    if (deps.now() + wait + requestTimeoutMs - startedAt > wallMs) return "time_budget";
    if (CAMPAIGN_LIMITS.responseBytesMax - bytes - READ_RESERVE <= 0) return "byte_budget";
    return null;
  }

  type Dispatched =
    | { kind: "unsent" }
    | { kind: "unsettled" }
    | { kind: "done"; seq: number; response: PinnedResponse; failure: CampaignSendFailure | null; read: number };

  /**
   * Sends one judged request: waits for the spacing, charges the budget, writes the `sending` row, sends, and settles
   * the row. `unsent`: the wait was cut by a stop, or the row could not be written (the Campaign then ends) — nothing
   * went out. `unsettled`: it went out, and its result could not be recorded (the row stays `sending`; the Campaign
   * ends).
   */
  async function dispatch(
    method: CampaignMethod,
    target: string,
    accept: string,
    bodyCap: number,
  ): Promise<Dispatched> {
    const wait = spacingWait();
    if (wait > 0) {
      try {
        await deps.sleep(wait, deps.signal);
      } catch {
        // Only an abort ends the wait early.
      }
    }
    if (deps.signal.aborted || end !== null) return { kind: "unsent" };
    if (seq >= CAMPAIGN_LIMITS.storedRequestsMax) {
      finish("engine_error");
      return { kind: "unsent" };
    }

    // Charged before the call: whatever happens from here on, this request is spent.
    sent += 1;
    seq += 1;
    const number = seq;
    const row: GateRecord = {
      seq: number,
      method,
      target,
      outcome: "sending",
      reason: null,
      status: null,
      failure: null,
      bytes: 0,
      ms: 0,
    };
    try {
      await deps.record(row);
    } catch {
      // Nothing is sent unrecorded.
      finish("engine_error");
      return { kind: "unsent" };
    }
    if (deps.signal.aborted) {
      // Stopped while the row was being written: the request never left. The row says so, and it is not counted.
      sent -= 1;
      await deps.settle({ ...row, outcome: "not_sent" }).catch(() => finish("engine_error"));
      return { kind: "unsent" };
    }

    const started = deps.now();
    lastSentAt = started;
    deps.onSend?.(started);
    const deadline = new AbortController();
    const onAbort = () => deadline.abort();
    deps.signal.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => deadline.abort(), requestTimeoutMs);
    timer.unref?.();
    let response: PinnedResponse;
    try {
      response = await deps.transport({
        method,
        target,
        headers: { "user-agent": CAMPAIGN_USER_AGENT, [CAMPAIGN_ID_HEADER]: campaign.id, accept },
        bodyBytesMax: bodyCap,
        signal: deadline.signal,
      });
    } catch {
      response = { ok: false, reason: "connect_failed" };
    } finally {
      clearTimeout(timer);
      deps.signal.removeEventListener("abort", onAbort);
    }
    const ms = Math.max(0, deps.now() - started);

    // A status that is not one is not handed on: the request failed.
    if (response.ok && !(Number.isInteger(response.status) && response.status >= 100 && response.status <= 599)) {
      response = { ok: false, reason: "invalid_response" };
    }
    let failure: CampaignSendFailure | null = null;
    let read = 0;
    if (!response.ok) {
      failure = deps.signal.aborted
        ? "aborted"
        : response.reason === "address_mismatch"
          ? "connect_failed"
          : response.reason;
    }
    // What the connection read, whatever came of it: the handshake, 1xx responses, a response that then failed.
    read = Math.max(0, Math.round(response.bytesRead ?? 0));
    bytes += read;
    try {
      await deps.settle({
        ...row,
        outcome: "sent",
        status: response.ok ? response.status : null,
        failure,
        bytes: read,
        ms,
      });
    } catch {
      // The row stays `sending`: the request is in the log, its result is not. The Campaign ends.
      finish("engine_error");
      return { kind: "unsettled" };
    }
    return { kind: "done", seq: number, response, failure, read };
  }

  /** Bytes of a body that may be read now: at most 64 KB, and never more than is left after the headers' share. */
  const bodyCap = (max: number): number =>
    Math.max(0, Math.min(max, CAMPAIGN_LIMITS.responseBytesMax - bytes - READ_RESERVE));

  async function ownership(): Promise<OwnershipOutcome> {
    const unsent = (reason: CampaignEndReason): OwnershipOutcome => ({ ok: false, reason, sent: false });
    if (deps.signal.aborted) return unsent(abortReason());
    if (end !== null || inFlight) return unsent("engine_error");
    inFlight = true;
    try {
      const path = VERIFICATION_FILE_PATH;
      // Authorised like any other request: a path the Rules exclude is not fetched, the ownership file included.
      const authorized = await deps.authorize({ host: campaign.host, path, intensity: campaign.intensity });
      if (!authorized.allowed) {
        return unsent(authorized.reason === "path_excluded" ? "verification_path_excluded" : authorized.reason);
      }
      if (authorized.roe_id !== campaign.roeId) return unsent("rules_replaced");
      const wait = spacingWait();
      const spent = overBudget(wait);
      if (spent !== null) return unsent(spent);
      if (deps.windowHolds !== undefined && !(await deps.windowHolds(path, wait + requestTimeoutMs))) {
        return unsent("outside_window");
      }
      const dispatched = await dispatch("GET", path, "text/plain", bodyCap(TARGET_LIMITS.fetchBodyBytesMax));
      if (deps.signal.aborted) return { ok: false, reason: abortReason(), sent: dispatched.kind !== "unsent" };
      if (dispatched.kind === "unsent") return unsent("engine_error");
      if (dispatched.kind === "unsettled") return { ok: false, reason: "engine_error", sent: true };
      const { response } = dispatched;
      if (!response.ok || response.status !== 200 || response.truncated) {
        return { ok: false, reason: "target_not_verified", sent: true };
      }
      return { ok: true, body: response.body.toString("utf8") };
    } catch {
      return unsent("engine_error");
    } finally {
      inFlight = false;
    }
  }

  async function request(probe: unknown): Promise<CampaignExchange> {
    if (end === null && deps.signal.aborted) finish(abortReason());
    if (end !== null) return { ok: false, refused: "campaign_ended", fatal: true };
    if (inFlight) return refuse("concurrent_request", probe);
    inFlight = true;
    try {
      return await judge(probe);
    } catch {
      // Nothing above is expected to throw; if a dependency does, the Campaign ends rather than going on unjudged.
      finish("engine_error");
      return { ok: false, refused: "campaign_ended", fatal: true };
    } finally {
      inFlight = false;
    }
  }

  async function judge(probe: unknown): Promise<CampaignExchange> {
    // 1. The switches, read from the database now.
    const control = await deps.control();
    if (control.killed) return refuse("operator_kill", probe);
    if (control.suspended) return refuse("organization_suspended", probe);
    if (control.stopRequested) return refuse("owner_stop", probe);
    if (control.deletionPending) return refuse("deletion_pending", probe);

    // 2. The shape: method, path and an optional query, and no other member.
    if (!plainObject(probe)) return refuse("malformed_probe", probe);
    if (Object.keys(probe).some((key) => !PROBE_KEYS.has(key))) return refuse("malformed_probe", probe);
    if (typeof probe.method !== "string" || typeof probe.path !== "string") return refuse("malformed_probe", probe);
    if ("query" in probe && !plainObject(probe.query)) return refuse("malformed_probe", probe);

    // 3. The method.
    if (!(CAMPAIGN_METHODS as readonly string[]).includes(probe.method)) return refuse("method_not_allowed", probe);
    const method = probe.method as CampaignMethod;

    // 4. The path and the query, canonical: what is authorised below is exactly what is sent. The whole request
    // target is at most 1,024 characters.
    const path = canonicalCampaignPath(probe.path);
    if (path === null) return refuse("path_not_canonical", probe);
    const query = canonicalCampaignQuery(probe.query);
    if (query === null) return refuse("query_not_canonical", probe);
    const target = query === "" ? path : `${path}?${query}`;
    if (target.length > CAMPAIGN_LIMITS.requestTargetMax) return refuse("query_not_canonical", probe);

    // 5. Authorization, from the database.
    const authorized = await deps.authorize({ host: campaign.host, path, intensity: campaign.intensity });
    if (!authorized.allowed) return refuse(authorized.reason, probe);

    // 6. The Rules of Engagement bound at creation.
    if (authorized.roe_id !== campaign.roeId) return refuse("rules_replaced", probe);

    // 7. The budgets, and the window for as long as this request may run.
    const wait = spacingWait();
    const spent = overBudget(wait);
    if (spent !== null) return refuse(spent, probe);
    if (deps.windowHolds !== undefined && !(await deps.windowHolds(path, wait + requestTimeoutMs))) {
      return refuse("outside_window", probe);
    }

    // 8. The spacing, then the send.
    const dispatched = await dispatch(method, target, "*/*", bodyCap(CAMPAIGN_LIMITS.responseReadBytesMax));
    if (dispatched.kind !== "done") {
      if (deps.signal.aborted) finish(abortReason());
      return { ok: false, refused: "campaign_ended", fatal: true };
    }
    const { response, failure } = dispatched;
    const number = dispatched.seq;

    if (!response.ok || failure !== null) {
      if (deps.signal.aborted) finish(abortReason());
      else if (++failures >= CAMPAIGN_LIMITS.consecutiveFailuresMax) finish("target_unhealthy");
      return { ok: false, seq: number, error: failure ?? "connect_failed" };
    }

    const status = response.status;
    const headers = redactHeaders(response.headers, campaign.host);
    const location = locationOf(
      Array.isArray(response.headers.location) ? response.headers.location[0] : response.headers.location,
      campaign.host,
    );
    // Redacted here, before the engine, a Finding or a hash can hold it; a body that is not text is withheld whole.
    const body = redactBody(response.body);
    const withheld = body === BODY_WITHHELD;
    held.set(number, {
      method,
      target,
      status,
      headers,
      body,
      // Of the redacted body: the hash cannot be used to test guesses of what was removed.
      sha256: createHash("sha256").update(body, "utf8").digest("hex"),
      truncated: response.truncated,
      location,
    });

    // Target health: a 429, or a 503 that says when to come back, ends the Campaign; so do five failures in a row.
    if (status === 429) finish("target_rate_limited");
    else if (status === 503 && response.headers["retry-after"] !== undefined) finish("target_unavailable");
    else if (status >= 500) {
      if (++failures >= CAMPAIGN_LIMITS.consecutiveFailuresMax) finish("target_unhealthy");
    } else failures = 0;

    return { ok: true, seq: number, status, headers, body, truncated: response.truncated, location, withheld };
  }

  return {
    ownership,
    request,
    evidence(number, at) {
      const exchange = held.get(number);
      if (exchange === undefined) return null;
      return {
        method: exchange.method,
        target: exchange.target,
        status: exchange.status,
        headers: exchange.headers,
        excerpt: excerptAround(exchange.body, at),
        body_sha256: exchange.sha256,
        truncated: exchange.truncated,
        location: exchange.location,
      };
    },
    counters: () => ({ sent, refused, bytes }),
    ended: () => end,
  };
}
