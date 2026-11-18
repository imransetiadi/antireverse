import {
  type AuthorizeResult,
  CAMPAIGN_END_REASONS,
  CAMPAIGN_LIMITS,
  CAMPAIGN_METHODS,
  type CampaignCatalogProbe,
  type CampaignEndReason,
  type CampaignEvidence,
  type CampaignExchange,
  type CampaignIntensity,
  type CampaignLocation,
  type CampaignMethod,
  type CampaignRefusalReason,
  type CampaignSendFailure,
  campaignAskedBucket,
  campaignCatalog,
  campaignCatalogTarget,
  canonicalCampaignPath,
  canonicalCampaignQuery,
  FATAL_CAMPAIGN_REFUSALS,
  TARGET_LIMITS,
  VERIFICATION_FILE_PATH,
} from "@antireverse/protocol";
import {
  FRAMING_OVERHEAD_BYTES_MAX,
  type PinnedResponse,
  READ_OVERSHOOT_BYTES_MAX,
  RESPONSE_HEADER_BYTES_MAX,
  TLS_OVERHEAD_BYTES_MAX,
} from "../prove/verify.ts";
import { BODY_WITHHELD, evidenceWindow, locationOf, redactBody, redactHeaders } from "./redact.ts";

// The request gate of a Pentest Campaign (slice 15a, D-105): the only code that sends Campaign traffic. An engine can
// ask for `{ method, path, query }` and nothing else; the gate decides, in a fixed order, whether that becomes a
// request to the Campaign's own Target:
//
//   1. the kill switch, the Organization's suspension, a stop request, a pending deletion;
//   2. the probe's shape;
//   3. the method: GET or HEAD;
//   4. the path and query: canonical, so that the form authorised is exactly the form sent — and one of the probes
//      the engine's catalog declares (D-110): exact method and path, each query value of its declared shape;
//   5. `authorize`, read from the database: the Target still verified, in scope, the path not excluded, the intensity,
//      the window;
//   6. the Rules of Engagement are still the version bound at creation;
//   7. the request, time and byte budgets, charged before the call;
//   8. the spacing of one request per second, one at a time;
//   9. the authorization (5, 6) and then the switches (1) once more, after the wait and after the log row is written:
//      the switches are the last thing read, and nothing is awaited between that read and the send.
//
// The ownership check at the start goes through the gate too (`ownership`): it is judged by the switches, authorised,
// budgeted, spaced and logged like any request, so that at most 60 requests in all reach a target.
//
// The log row of a request is written BEFORE the request goes out (`sending`) and settled afterwards: whatever fails
// later, a request that reached the target is in the log. If the row cannot be written, nothing is sent.
//
// A refused probe is never sent: it is logged with a fixed reason and with how much it asked for — never with what it
// asked for (a probe outside the catalog is text an engine chose, perhaps out of a response) — and a probe that is not
// one of the catalog ends the Campaign at once; 20 refusals of other kinds end it too. The gate holds no
// host and no address: the transport it is given is bound to the Campaign's Target and its pinned address by the
// runner. It sets three request headers and no others: no body, no cookie, no credential can leave through it. What
// comes back is redacted here, before the engine, a Finding or the log sees it. Of a body, a Finding keeps a window of
// at most 200 characters around what its check matched, and nothing else is kept anywhere (D-107).

export const CAMPAIGN_USER_AGENT = "Airverse-Campaign/1";
export const CAMPAIGN_ID_HEADER = "x-airverse-campaign";

/** What the gate reads before every request, from the database. */
export interface GateControl {
  /** The operator's global kill switch. */
  killed: boolean;
  /** The operator suspended this Organization's Campaigns. */
  suspended: boolean;
  /**
   * The owner asked to stop this Campaign, or it is not in the state its phase expects: running for a probe, queued
   * for the ownership request of the start checks.
   */
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

/** One row of the request log. Never a body, and never text an engine chose (D-110). */
export interface GateRecord {
  seq: number;
  /** `GET` or `HEAD`; for a refused probe that asked for anything else the fixed label `OTHER`, or null for none. */
  method: string | null;
  /** The target of a catalog probe (or the ownership file); null for a refused probe that is not of the catalog. */
  target: string | null;
  /** For a refused probe: how much its path and query held, as a bucket (0, 256, 1024, 1000000; D-113). Else null. */
  asked: number | null;
  outcome: "sending" | "sent" | "not_sent" | "refused";
  reason: CampaignRefusalReason | null;
  status: number | null;
  failure: CampaignSendFailure | null;
  bytes: number;
  ms: number;
}

export interface GateDeps {
  campaign: { id: string; host: string; roeId: string; intensity: CampaignIntensity };
  /**
   * The probes the engine may send (D-110), from the engine's definition on the host side — never from a running
   * engine. Validated here (`campaignCatalog`: a TypeError otherwise) and copied: the gate judges by its own copy.
   */
  catalog: readonly CampaignCatalogProbe[];
  /**
   * The switches, read from the database now. `start`: for the ownership request, while the Campaign is still queued
   * (`campaign_start_control`); `run`: for a probe of a running Campaign (`campaign_control`).
   */
  control(phase: "start" | "run"): Promise<GateControl>;
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
   * The start check's GET of the verification file from the pinned address, judged like a probe (the switches,
   * authorize for its path, the Rules bound at creation, the budgets, the window, the spacing — and the switches and
   * the authorization once more right before it leaves) and logged as the first request. Not for an engine: it hands
   * back the file's body, unredacted, for the comparison with the token only. A whole 200 is the only answer that
   * counts. It does not end the Campaign: the runner writes the refusal.
   */
  ownership(): Promise<OwnershipOutcome>;
  /** Judges one probe and, if it passes, sends it. Never rejects. */
  request(probe: unknown): Promise<CampaignExchange>;
  /**
   * The evidence of the sent request `seq` (D-107): its status, its kept headers and `window` — what the engine says
   * its check matched. The window is the engine's word and is treated as such: it must be a string of at most 200
   * characters that occurs in the redacted body the gate holds for that request (empty for a check that reads no
   * body), and it is redacted again on its own. `check`: the check the Finding is of — the request must have been a
   * catalog probe declared for it. Null for an unknown request, another check's request or a window that does not
   * pass.
   */
  evidence(seq: number, window: unknown, check: unknown): CampaignEvidence | null;
  counters(): { sent: number; refused: number; bytes: number };
  /** Why the gate ended the Campaign, or null while it has not. */
  ended(): CampaignEndReason | null;
}

interface Held {
  method: CampaignMethod;
  target: string;
  /** The checks the catalog declares this request's probe for: a Finding of another check does not rest on it. */
  checks: readonly string[];
  status: number;
  headers: Record<string, string>;
  /** The redacted body, in this process's memory for the run only: an evidence window must occur in it. */
  body: string;
  withheld: boolean;
  truncated: boolean;
  location: CampaignLocation | null;
}

/**
 * Bytes kept back before a request may start, beside its body: its headers (16 KB), the connection's TLS share
 * (16 KB), its framing allowance (64 KB) — together with the body cap, what the transport lets one socket read — and
 * the one TCP read (64 KB) by which a connection can pass that cap before it is cut (`READ_OVERSHOOT_BYTES_MAX`:
 * the transport counts raw reads, so the bound is one read, whatever the bytes are). What the connections read is
 * counted exactly; the reserve is that bound, so the count stays inside the 2 MB.
 */
const READ_RESERVE =
  RESPONSE_HEADER_BYTES_MAX + TLS_OVERHEAD_BYTES_MAX + FRAMING_OVERHEAD_BYTES_MAX + READ_OVERSHOOT_BYTES_MAX;

const PROBE_KEYS = new Set(["method", "path", "query"]);
const FATAL = new Set<string>(FATAL_CAMPAIGN_REFUSALS);

function plainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * How much a refused probe asked for: the characters of its path and of its query's names and values, counted up to
 * `askedCharsMax`. A number is all that is kept of it.
 */
function askedChars(probe: unknown): number {
  if (!plainObject(probe)) return 0;
  const max = CAMPAIGN_LIMITS.askedCharsMax;
  let count = typeof probe.path === "string" ? probe.path.length : 0;
  if (plainObject(probe.query)) {
    for (const name in probe.query) {
      if (count >= max) break;
      const value = probe.query[name];
      count += name.length + (typeof value === "string" ? value.length : 0);
    }
  }
  return Math.min(count, max);
}

/** The method of a refused probe as the log holds it: one of the two a gate sends, or a fixed label. */
function loggedMethod(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return (CAMPAIGN_METHODS as readonly string[]).includes(value) ? value : "OTHER";
}

export function createGate(deps: GateDeps): Gate {
  const { campaign } = deps;
  const catalog = campaignCatalog(deps.catalog);
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

  type FatalSwitch = "operator_kill" | "organization_suspended" | "owner_stop" | "deletion_pending";

  /** A refusal read right before the ownership request, as the reason the Campaign is refused for. */
  function startReason(reason: CampaignRefusalReason | "verification_path_excluded"): CampaignEndReason {
    return (CAMPAIGN_END_REASONS as readonly string[]).includes(reason)
      ? (reason as CampaignEndReason)
      : "engine_error";
  }

  function abortReason(): CampaignEndReason {
    const reason = deps.signal.reason as unknown;
    return (CAMPAIGN_END_REASONS as readonly unknown[]).includes(reason) ? (reason as CampaignEndReason) : "owner_stop";
  }

  /**
   * Refuses a probe and logs the refusal. `target`: the target of a probe that is in the catalog, in the catalog's
   * words — with a token's value masked: a refused probe was never sent, and the value is the engine's choice.
   * Without it nothing the probe asked for is kept but its size.
   */
  async function refuse(
    reason: CampaignRefusalReason,
    probe: unknown,
    target: string | null = null,
  ): Promise<CampaignExchange> {
    refused += 1;
    const asked = plainObject(probe) ? probe : {};
    // The end comes first, before anything is awaited (sixth review): a refusal that ends the Campaign — a probe
    // outside the catalog, the twentieth refusal — ends it in the same turn it is judged in. Probes asked for in the
    // same tick then find the Campaign ended and write nothing: one row is all a burst can leave.
    let fatal = FATAL.has(reason);
    if (fatal) finish(reason as CampaignEndReason);
    else if (refused >= CAMPAIGN_LIMITS.refusalsMax) {
      fatal = true;
      finish("refusal_limit");
    }
    if (seq < CAMPAIGN_LIMITS.storedRequestsMax) {
      seq += 1;
      try {
        await deps.record({
          seq,
          method: loggedMethod(asked.method),
          target,
          asked: campaignAskedBucket(askedChars(probe)),
          outcome: "refused",
          reason,
          status: null,
          failure: null,
          bytes: 0,
          ms: 0,
        });
      } catch {
        // A log that cannot be written ends the Campaign (if this refusal has not ended it already).
        finish("engine_error");
      }
    } else finish("refusal_limit");
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

  /** The switches, as a refusal: the first that is on, or null. */
  function switchedOff(control: GateControl): FatalSwitch | null {
    if (control.killed) return "operator_kill";
    if (control.suspended) return "organization_suspended";
    if (control.stopRequested) return "owner_stop";
    if (control.deletionPending) return "deletion_pending";
    return null;
  }

  /**
   * Read again right before a request leaves: the authorization for the path with the Rules bound at creation, and
   * then the switches — last, so that a kill, a suspension or a stop committed while the authorization was read is
   * seen. Whatever was true when the request was judged — up to a second of spacing ago — is not enough.
   */
  async function stale(phase: "start" | "run", path: string): Promise<CampaignRefusalReason | null> {
    const authorized = await deps.authorize({ host: campaign.host, path, intensity: campaign.intensity });
    const off = switchedOff(await deps.control(phase));
    if (off !== null) return off;
    if (!authorized.allowed) return authorized.reason;
    if (authorized.roe_id !== campaign.roeId) return "rules_replaced";
    return null;
  }

  /**
   * Settles the row of a request that never left. `not_sent` while the Campaign has not ended; once it has, the
   * database takes `sent` only (D-108), and the row is settled as sent and cut off: the log may then hold more than
   * the target saw, never less. True when the row says `not_sent`.
   */
  async function settleUnsent(row: GateRecord): Promise<boolean> {
    try {
      await deps.settle({ ...row, outcome: "not_sent" });
      return true;
    } catch {
      // Refused: the Campaign has ended meanwhile.
    }
    try {
      await deps.settle({ ...row, outcome: "sent", failure: "aborted" });
    } catch {
      finish(deps.signal.aborted ? abortReason() : "engine_error");
    }
    return false;
  }

  type Dispatched =
    | { kind: "unsent" }
    | { kind: "stale"; reason: CampaignRefusalReason }
    | { kind: "unsettled" }
    | { kind: "done"; seq: number; response: PinnedResponse; failure: CampaignSendFailure | null; read: number };

  /**
   * Sends one judged request: waits for the spacing, charges the budget, writes the `sending` row, reads the switches
   * and the authorization once more, sends, and settles the row. `unsent`: the wait was cut by a stop, or the row
   * could not be written (the Campaign then ends) — nothing went out. `stale`: what was read right before the send
   * no longer allows the request — nothing went out, and its row says so. `unsettled`: it went out, and its result
   * could not be recorded (the row stays `sending`; the Campaign ends).
   */
  async function dispatch(
    phase: "start" | "run",
    method: CampaignMethod,
    target: string,
    path: string,
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
      asked: null,
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
    // The last read before the send: a stop, a kill or a lapse committed while this request waited for its turn or
    // for its row holds it back. Between this read and the send nothing is awaited.
    let refused: CampaignRefusalReason | null = null;
    let unread = false;
    if (!deps.signal.aborted) {
      try {
        refused = await stale(phase, path);
      } catch {
        unread = true;
      }
    }
    if (deps.signal.aborted || unread || refused !== null) {
      // Stopped or withdrawn while the row was being written: the request never left. The row says so, and it is
      // not counted.
      if (await settleUnsent(row)) sent -= 1;
      // The switches could not be read: nothing goes out unjudged, and the Campaign ends.
      if (unread && !deps.signal.aborted) finish("engine_error");
      return refused !== null && !deps.signal.aborted ? { kind: "stale", reason: refused } : { kind: "unsent" };
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
      // The row stays `sending`: the request is in the log, its result is not. The Campaign ends — as stopped when a
      // stop is what cut the request, as an error of ours otherwise.
      finish(deps.signal.aborted ? abortReason() : "engine_error");
      return { kind: "unsettled" };
    }
    // A connection that read more than one request may: the target is sending what no response holds. The row says
    // what was read; the Campaign ends on its byte budget.
    if (failure === "read_limit") finish("byte_budget");
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
      // The switches, read from the database now, as for a probe: a kill, a suspension, a stop or a pending deletion
      // that is committed holds the ownership request back too.
      const off = switchedOff(await deps.control("start"));
      if (off !== null) return unsent(off);
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
      const dispatched = await dispatch(
        "start",
        "GET",
        path,
        path,
        "text/plain",
        bodyCap(TARGET_LIMITS.fetchBodyBytesMax),
      );
      const left = dispatched.kind === "done" || dispatched.kind === "unsettled";
      // The connection read more than one request may: refused on the byte budget, whatever else is true.
      if (dispatched.kind === "done" && dispatched.failure === "read_limit") {
        return { ok: false, reason: "byte_budget", sent: true };
      }
      if (deps.signal.aborted) return { ok: false, reason: abortReason(), sent: left };
      if (dispatched.kind === "stale") {
        const reason = dispatched.reason === "path_excluded" ? "verification_path_excluded" : dispatched.reason;
        return unsent(startReason(reason));
      }
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
    if (inFlight) {
      // Asked for while another request is in flight. It is judged against the catalog first (D-113): a probe that
      // is not one of the engine's ends the Campaign whenever it is asked for — it is not a refusal the engine may
      // repeat. A catalog probe is refused for this turn only, with the catalog's target.
      const asked = classify(probe);
      if (!asked.ok) return refuse(asked.reason, probe);
      return refuse("concurrent_request", probe, asked.masked);
    }
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

  type Classified =
    | { ok: false; reason: CampaignRefusalReason }
    | {
        ok: true;
        method: CampaignMethod;
        path: string;
        /** The target as it is sent. */
        target: string;
        /** The target as a refused row keeps it: a token's value masked. */
        masked: string;
        checks: readonly string[];
      };

  /**
   * What a probe is, without asking anyone: malformed, of another method, not canonical, not in the catalog — or one
   * of the catalog's probes, with the request target in the catalog's own name order (the order an engine lists its
   * query names in is its choice, and is neither sent nor kept) and the checks that probe serves.
   */
  function classify(probe: unknown): Classified {
    // 2. The shape: method, path and an optional query, and no other member.
    if (!plainObject(probe)) return { ok: false, reason: "malformed_probe" };
    if (Object.keys(probe).some((key) => !PROBE_KEYS.has(key))) return { ok: false, reason: "malformed_probe" };
    if (typeof probe.method !== "string" || typeof probe.path !== "string") {
      return { ok: false, reason: "malformed_probe" };
    }
    if ("query" in probe && !plainObject(probe.query)) return { ok: false, reason: "malformed_probe" };

    // 3. The method.
    if (!(CAMPAIGN_METHODS as readonly string[]).includes(probe.method)) {
      return { ok: false, reason: "method_not_allowed" };
    }
    const method = probe.method as CampaignMethod;

    // 4. The path and the query, canonical: what is authorised is exactly what is sent. The whole request target is
    // at most 1,024 characters.
    const path = canonicalCampaignPath(probe.path);
    if (path === null) return { ok: false, reason: "path_not_canonical" };
    const query = canonicalCampaignQuery(probe.query);
    if (query === null) return { ok: false, reason: "query_not_canonical" };
    if (path.length + (query === "" ? 0 : 1 + query.length) > CAMPAIGN_LIMITS.requestTargetMax) {
      return { ok: false, reason: "query_not_canonical" };
    }
    // The catalog (D-110): the engine declared what it may ask for. From here on `target` is text of the catalog,
    // in the catalog's order, not of the engine.
    const declared = campaignCatalogTarget(catalog, probe);
    if (declared === null) return { ok: false, reason: "not_in_catalog" };
    return {
      ok: true,
      method,
      path,
      target: declared.target,
      masked: declared.masked,
      checks: declared.entry.checks ?? [],
    };
  }

  async function judge(probe: unknown): Promise<CampaignExchange> {
    // 1. The switches, read from the database now.
    const off = switchedOff(await deps.control("run"));
    // Ended while the switches were read (a probe of the same tick was outside the catalog): nothing more is judged
    // or written.
    if (end !== null) return { ok: false, refused: "campaign_ended", fatal: true };
    if (off !== null) return refuse(off, probe);

    // 2, 3, 4. The shape, the method, the canonical path and query, and the catalog.
    const asked = classify(probe);
    if (!asked.ok) return refuse(asked.reason, probe);
    const { method, path, target, masked, checks } = asked;

    // 5. Authorization, from the database.
    const authorized = await deps.authorize({ host: campaign.host, path, intensity: campaign.intensity });
    if (!authorized.allowed) return refuse(authorized.reason, probe, masked);

    // 6. The Rules of Engagement bound at creation.
    if (authorized.roe_id !== campaign.roeId) return refuse("rules_replaced", probe, masked);

    // 7. The budgets, and the window for as long as this request may run.
    const wait = spacingWait();
    const spent = overBudget(wait);
    if (spent !== null) return refuse(spent, probe, masked);
    if (deps.windowHolds !== undefined && !(await deps.windowHolds(path, wait + requestTimeoutMs))) {
      return refuse("outside_window", probe, masked);
    }

    // 8. The spacing; 9. the switches and the authorization once more; then the send.
    const dispatched = await dispatch(
      "run",
      method,
      target,
      path,
      "*/*",
      bodyCap(CAMPAIGN_LIMITS.responseReadBytesMax),
    );
    if (dispatched.kind === "stale") return refuse(dispatched.reason, probe, masked);
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
    // Redacted here, before the engine or a Finding can hold it; a body that cannot be read as UTF-8 text (encoded,
    // another charset, invalid bytes, a NUL) is withheld whole.
    const body = redactBody(response.body, {
      contentEncoding: response.headers["content-encoding"],
      contentType: response.headers["content-type"],
      truncated: response.truncated,
    });
    const withheld = body === BODY_WITHHELD;
    held.set(number, {
      method,
      target,
      checks,
      status,
      headers,
      body,
      withheld,
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
    evidence(number, window, check) {
      const exchange = held.get(number);
      if (exchange === undefined) return null;
      // The request must have been a probe the catalog declares for this check.
      if (typeof check !== "string" || !exchange.checks.includes(check)) return null;
      // The window is the engine's word: bounded, and a piece of the body the gate itself holds for this request.
      if (typeof window !== "string" || window.length > CAMPAIGN_LIMITS.evidenceWindowMax) return null;
      if (window !== "" && (exchange.withheld || !exchange.body.includes(window))) return null;
      return {
        method: exchange.method,
        target: exchange.target,
        status: exchange.status,
        headers: exchange.headers,
        excerpt: evidenceWindow(window),
        truncated: exchange.truncated,
        location: exchange.location,
      };
    },
    counters: () => ({ sent, refused, bytes }),
    ended: () => end,
  };
}
