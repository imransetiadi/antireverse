import {
  CAMPAIGN_END_REASONS,
  CAMPAIGN_LIMITS,
  type Campaign,
  type CampaignCatalogProbe,
  type CampaignChecks,
  type CampaignEndReason,
  campaignCatalog,
  campaignChecksSentence,
  canonicalCampaignPath,
  matchesFileChallenge,
  statusOfEndReason,
  VERIFICATION_FILE_PATH,
} from "@antireverse/protocol";
import { type RunCampaignEngineOptions, runCampaignEngine, standInEngine } from "@antireverse/prove";
import { z } from "zod";
import { audit, operatorActor, systemActor } from "../audit.ts";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import { type Authorize, evaluateAuthorization } from "../prove/authorize.ts";
import {
  type GuardedFetcherTesting,
  pinnedRequest,
  type Resolver,
  resolvePinned,
  sameAddress,
} from "../prove/verify.ts";
import {
  campaignControl,
  campaignQueue,
  claimCampaign,
  endCampaign,
  findCampaign,
  insertCampaignRequest,
  interruptRunningCampaigns,
  lastRequestSeq,
  type QueuedCampaign,
  reportFinding,
  settleCampaignRequest,
  startControl,
} from "../stores/campaigns.ts";
import { currentVersion } from "../stores/rules-of-engagement.ts";
import { findTarget } from "../stores/targets.ts";
import { createGate } from "./gate.ts";

// The Campaign queue and runner (slice 15a, D-105). Queued Campaigns are taken oldest first: one per Organization (the
// database's index), one per host across Organizations and two in all. A Campaign stays queued until every start
// check passed again — Campaigns on, no kill switch or suspension, the Rules of Engagement bound at creation still
// current and at most 90 days old, `authorize` from the database, the host resolved once to public addresses and
// pinned, and the Organization's ownership file served from the pinned address itself. Only then does it run: the
// engine in a worker thread, every probe through the request gate (gate.ts), which is the only code that sends.
//
// A stop — by the owner, the operator's kill switch or suspension, or the API closing — aborts the request in flight
// (its socket is destroyed), terminates the worker and ends the Campaign; the durable flag is what the gate reads
// before every request — the ownership request of the start checks included — and what the claim itself is
// conditional on, so a stop holds even if this process's memory did not. On start, a Campaign left running by a
// previous process becomes interrupted and is never resumed; queued ones are taken again and pass every check again.
//
// Single-process assumption, as the Assessment runner: the per-host and in-all limits live in this process's memory.

/** The engine run: `runCampaignEngine` of packages/prove (a worker thread). Tests pass a scripted one. */
export type CampaignEngineRunner = (options: RunCampaignEngineOptions) => Promise<void>;

/**
 * Test-only settings of the Campaign transport: the guarded fetcher's (a local TLS server with a test CA, loopback
 * allowed) and a shorter spacing and request deadline. Never set by production configuration — no environment
 * variable, request field or `startApi` default reads it; only a test constructs it. The budgets are not here: no
 * option changes them.
 */
export interface CampaignTesting extends GuardedFetcherTesting {
  minSpacingMs?: number;
  requestTimeoutMs?: number;
}

export interface CampaignRunnerOptions {
  db: Db;
  /** Whether the service has Campaigns on (`AR_PROVE_CAMPAIGNS=1`). Off: none is created and none starts. */
  enabled: boolean;
  resolver: Resolver;
  authorize: Authorize;
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  engine?: CampaignEngineRunner | undefined;
  /**
   * The probe catalog of the engine given (D-110). Default: the stand-in's own (`standInEngine.probes`). Only a test
   * that passes a scripted `engine` passes the catalog of what that script may send; no environment variable,
   * request field or message of a running engine reaches it.
   */
  probes?: readonly CampaignCatalogProbe[] | undefined;
  /** For tests only (see `CampaignTesting`). */
  testing?: CampaignTesting | undefined;
  /** Queue entries read per page. Default 1,000; tests pass a small one. */
  queuePage?: number | undefined;
}

/** What the routes need of the runner. */
export interface CampaignService {
  readonly enabled: boolean;
  /** Told that a Campaign was queued. */
  wake(): void;
  /**
   * Stops a Campaign this process is starting or running: aborts its request in flight, terminates its engine and
   * waits until its end is written. Resolves at once for a Campaign that is not active here.
   */
  abort(campaignId: string, reason: CampaignEndReason): Promise<void>;
  /** Whether this process is starting or running the Campaign now. */
  isActive(campaignId: string): boolean;
  /**
   * Aborts, at once and without awaiting anything, every Campaign of the Organization that this process is starting
   * or running: its request in flight is cut and nothing more is sent. For the moment something is committed that
   * the gate would only see at its next read — a deletion that was requested. A running Campaign then ends with
   * `reason`; one still in its start checks stays queued (and starts nothing while the reason holds).
   */
  cut(organizationId: string, reason: CampaignEndReason): void;
  /**
   * The operator's stop: ends every queued or running Campaign (of one Organization, or of all), writing one operator
   * entry per affected Organization's audit chain. Answers how many Campaigns it ended.
   */
  operatorStop(input: {
    reason: "operator_kill" | "organization_suspended";
    organizationId?: string;
    requestId: string;
    operatorReason: string;
  }): Promise<number>;
  /** Campaigns queued or running now, across Organizations. */
  activeCount(): Promise<number>;
}

export interface CampaignRunner extends CampaignService {
  /** Interrupts Campaigns left running by a previous process, then takes the queued ones. */
  start(): Promise<void>;
  /** Resolves once no Campaign is starting or running here and the queue has nothing this runner can take. */
  idle(): Promise<void>;
  /** Takes nothing more and ends running Campaigns as interrupted (`api_shutdown`). */
  stop(): Promise<void>;
}

const QUEUE_READ = 1000;
/** Queue entries read in all per pass, page by page. */
const QUEUE_MAX = 100_000;
/** Milliseconds of the start checks' network part: the one resolution and the ownership file. */
const START_TIMEOUT_MS = 5000;
/** Milliseconds before a Campaign whose start checks returned without an end may be taken again by this process. */
const RELAUNCH_AFTER_MS = 60_000;

const EngineCheckSchema = z.object({
  id: z.string(),
  result: z.enum(["reported", "clean", "inconclusive", "skipped"]),
});
// What an engine may say of a Finding: which check, which path, which sent request, and the evidence window (D-107:
// at most 200 characters; the gate then requires it to be a piece of the body it holds for that request). A title or
// a severity an engine adds is not read: both are the catalog's.
const EngineFindingSchema = z.object({
  check_id: z.string().regex(/^[A-Z]{2}-[0-9]{2}$/),
  path: z.string().max(CAMPAIGN_LIMITS.pathMax),
  seq: z.int().min(1).max(CAMPAIGN_LIMITS.storedRequestsMax),
  window: z.string().max(CAMPAIGN_LIMITS.evidenceWindowMax),
});

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal.aborted) return reject(new Error("aborted"));
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Error("aborted"));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    timer.unref?.();
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function endReasonOf(value: unknown): CampaignEndReason | null {
  return (CAMPAIGN_END_REASONS as readonly unknown[]).includes(value) ? (value as CampaignEndReason) : null;
}

/** The reasons that are a stop: someone decided that the Campaign must not go on. */
const STOPS = new Set<CampaignEndReason>(["owner_stop", "operator_kill", "organization_suspended", "deletion_pending"]);

interface Active {
  organizationId: string;
  host: string;
  /** The pinned address, once resolved. */
  address: string | null;
  controller: AbortController;
  done: Promise<void>;
}

export function createCampaignRunner(options: CampaignRunnerOptions): CampaignRunner {
  const { db, enabled, resolver, authorize, testing } = options;
  const now = options.now ?? (() => new Date());
  const logger = redacting(options.logger ?? consoleLogger);
  const engine = options.engine ?? runCampaignEngine;
  // Validated once, here: a catalog that is not one never reaches a gate.
  const probes = campaignCatalog(options.probes ?? standInEngine.probes);
  const queuePage = Math.min(Math.max(1, Math.floor(options.queuePage ?? QUEUE_READ)), QUEUE_READ);
  // The transport's part of the test-only option; the gate's part is its two timings.
  const transportTesting: GuardedFetcherTesting | undefined =
    testing === undefined
      ? undefined
      : {
          port: testing.port,
          ...(testing.ca === undefined ? {} : { ca: testing.ca }),
          ...(testing.allowLoopback === undefined ? {} : { allowLoopback: testing.allowLoopback }),
        };
  const gateLimits =
    testing === undefined
      ? undefined
      : {
          ...(testing.minSpacingMs === undefined ? {} : { minSpacingMs: testing.minSpacingMs }),
          ...(testing.requestTimeoutMs === undefined ? {} : { requestTimeoutMs: testing.requestTimeoutMs }),
        };

  const active = new Map<string, Active>();
  /**
   * Campaigns this process will not launch again: one whose run threw (a write that failed) is ended as failed if
   * that can be written, and otherwise stays queued — for the next process, which runs every start check again. Never
   * a retry loop: each retry would be another request to the target.
   */
  const parked = new Map<string, number>();
  /** Campaigns waiting because another one runs against the same address: taken again when that one ended. */
  const waiting = new Map<string, string>();
  /**
   * When the last request went out to a host and to an address (on the gate's clock), whichever Campaign sent it:
   * the spacing of one request per second holds across Campaigns and for the start checks too.
   */
  const lastSend = new Map<string, number>();
  let stopped = false;
  /**
   * Operator stops at work: while one is, nothing is launched. A Campaign that is still queued is then ended by the
   * stop itself — with the operator's entry and in its count — and not by start checks that the queue launched in
   * between and that would end it as the system's.
   */
  let held = 0;
  let pumping: Promise<void> | null = null;
  let again = false;

  function pump(): Promise<void> {
    if (pumping !== null) {
      again = true;
      return pumping;
    }
    pumping = (async () => {
      do {
        again = false;
        try {
          await pass();
        } catch (error) {
          logger.warn(`campaign queue failed: ${(error as Error).name}`);
        }
      } while (again && !stopped);
    })().finally(() => {
      pumping = null;
    });
    return pumping;
  }

  /** The whole queue, read page by page: however many Campaigns cannot start now, the ones behind them are seen. */
  async function readQueue(): Promise<QueuedCampaign[]> {
    const all: QueuedCampaign[] = [];
    for (let offset = 0; offset < QUEUE_MAX; offset += queuePage) {
      const page = await db.tx("none", (q) => campaignQueue(q, queuePage, offset));
      all.push(...page);
      if (page.length < queuePage) break;
    }
    return all;
  }

  async function pass(): Promise<void> {
    if (stopped || held > 0 || active.size >= CAMPAIGN_LIMITS.runningInAll) return;
    for (const entry of await readQueue()) {
      if (stopped || held > 0 || active.size >= CAMPAIGN_LIMITS.runningInAll) return;
      if (entry.status !== "queued" || active.has(entry.campaignId)) continue;
      if ((parked.get(entry.campaignId) ?? 0) > performance.now()) continue;
      // An Organization whose deletion is pending starts nothing: its Campaign stays queued until the purge.
      if (entry.deletionPending) continue;
      const busy = [...active.values()];
      if (busy.some((other) => other.organizationId === entry.organizationId || other.host === entry.host)) continue;
      // One Campaign per address too: two names of one server do not run at once. Addresses are compared as
      // addresses, whatever their spelling.
      const address = waiting.get(entry.campaignId);
      if (
        address !== undefined &&
        busy.some((other) => other.address !== null && sameAddress(other.address, address))
      ) {
        continue;
      }
      waiting.delete(entry.campaignId);
      launch(entry.organizationId, entry.campaignId, entry.host);
    }
  }

  function launch(organizationId: string, campaignId: string, host: string): void {
    const controller = new AbortController();
    const entry: Active = { organizationId, host, address: null, controller, done: Promise.resolve() };
    active.set(campaignId, entry);
    entry.done = execute(organizationId, campaignId, entry)
      .then(() => {
        // Returned without an error. If that left the Campaign queued (its Organization's deletion became pending
        // meanwhile, a stop cut its start checks), it is not taken again at once: never a loop of start checks.
        if (!waiting.has(campaignId) && !parked.has(campaignId)) {
          parked.set(campaignId, performance.now() + RELAUNCH_AFTER_MS);
        }
      })
      .catch(async (error: unknown) => {
        // Something of ours failed (a write, most likely). Not again in this process, and nothing more is sent.
        parked.set(campaignId, Number.POSITIVE_INFINITY);
        controller.abort("engine_error");
        logger.warn(`campaign run failed id=${campaignId} ${(error as Error).name}`);
        try {
          await finish(organizationId, { id: campaignId }, { reason: "engine_error", started: false, checks: null });
        } catch (failure) {
          logger.warn(`campaign left queued until a restart id=${campaignId} ${(failure as Error).name}`);
        }
      })
      .finally(() => {
        active.delete(campaignId);
        if (!stopped) void pump();
      });
  }

  /** Writes the end of a Campaign and its audit entry, once: false when it had already ended. */
  async function finish(
    organizationId: string,
    campaign: Pick<Campaign, "id">,
    end: { reason: CampaignEndReason; started: boolean; checks: CampaignChecks | null; findingsDropped?: number },
  ): Promise<boolean> {
    const at = now();
    const written = await db.tx({ organizationId }, async (q) => {
      const before = await findCampaign(q, campaign.id);
      if (before === null) return null;
      // What the Campaign was when it ended, not what the caller believed: it ran if the database says so.
      const started = before.status === "running";
      // A stop the owner asked for, recorded before this end is written, is final: a Campaign whose stop arrived
      // while its last check was being finished does not end as completed.
      const reason = before.stop !== null && end.reason === "checks_complete" ? "owner_stop" : end.reason;
      if (!(await endCampaign(q, campaign.id, { ...end, reason, started, at }))) return null;
      const status = statusOfEndReason(reason, started);
      const sent = before.requests_sent;
      const dropped = end.findingsDropped ?? 0;
      const lost = dropped === 0 ? "" : ` ${dropped} ${dropped === 1 ? "Finding" : "Findings"} could not be stored.`;
      // Exactly what was sent, counted from the request log (every request is in it before it goes out).
      const summary = started
        ? `The Campaign ended: ${status} (${reason}); ${sent} ${sent === 1 ? "request" : "requests"} sent (the ownership check included), ${before.requests_refused} refused. ${
            end.checks === null ? "" : campaignChecksSentence(end.checks)
          }${lost}`
        : `The Campaign did not start: ${status} (${reason}). ${
            sent === 0 ? "Nothing was sent." : "The ownership check was requested; no probe was sent."
          }`;
      await audit(q, systemActor(organizationId), {
        action: started ? "campaign.end" : "campaign.refuse",
        target: { kind: "campaign", id: campaign.id },
        summary,
        at,
      });
      return status;
    });
    logger.info(
      `campaign ${written === null ? "already ended" : "ended"} id=${campaign.id} status=${written ?? "-"} reason=${end.reason}`,
    );
    return written !== null;
  }

  async function execute(organizationId: string, campaignId: string, entry: Active): Promise<void> {
    const { controller } = entry;
    const { signal } = controller;
    const refuse = (reason: CampaignEndReason) =>
      finish(organizationId, { id: campaignId }, { reason, started: false, checks: null });

    // --- The start checks, every one of them again, whatever was true when the Campaign was created. -------------
    // A stop while they run writes nothing here: the owner's stop and the operator's write the end themselves, and
    // at shutdown the Campaign stays queued — the next process runs every check again.
    const facts = await db.tx({ organizationId }, async (q) => {
      const campaign = await findCampaign(q, campaignId);
      if (campaign === null || campaign.status !== "queued") return null;
      return {
        campaign,
        control: await campaignControl(q, campaignId),
        current: await currentVersion(q),
        token: (await findTarget(q, campaign.target_id))?.token ?? null,
        lastSeq: await lastRequestSeq(q, campaignId),
      };
    });
    if (facts === null || signal.aborted) return;
    const { campaign, control, current } = facts;
    if (!enabled) return void (await refuse("campaigns_disabled"));
    if (control.killed) return void (await refuse("operator_kill"));
    if (control.suspended) return void (await refuse("organization_suspended"));
    if (control.deletionPending) return;
    if (current === null) return void (await refuse("no_rules_of_engagement"));
    if (current.id !== campaign.roe_id) return void (await refuse("rules_replaced"));
    const ageMs = now().getTime() - Date.parse(current.signed_at);
    if (!(ageMs <= CAMPAIGN_LIMITS.roeMaxAgeDays * 86_400_000)) return void (await refuse("rules_too_old"));
    // The first request will be the ownership file's: authorised like any other, before anything is resolved.
    const authorized = await authorize(organizationId, {
      host: campaign.host,
      path: VERIFICATION_FILE_PATH,
      intensity: campaign.intensity,
    });
    if (!authorized.allowed) {
      return void (await refuse(
        authorized.reason === "path_excluded" ? "verification_path_excluded" : authorized.reason,
      ));
    }
    if (authorized.roe_id !== campaign.roe_id) return void (await refuse("rules_replaced"));
    if (facts.token === null) return void (await refuse("target_unknown"));

    // The one resolution of the run: every address must be public, and the first is pinned.
    const starting = AbortSignal.any([signal, AbortSignal.timeout(START_TIMEOUT_MS)]);
    let pinned: Awaited<ReturnType<typeof resolvePinned>>;
    try {
      pinned = await resolvePinned(campaign.host, { resolver, signal: starting, testing: transportTesting });
    } catch {
      pinned = { ok: false, reason: "resolve_failed" };
    }
    if (signal.aborted) return;
    if (!pinned.ok) return void (await refuse("target_not_reachable"));
    const address = pinned.address;
    // Another Campaign runs against this address under another name: wait for it, without asking anything.
    if (
      [...active.values()].some(
        (other) => other !== entry && other.address !== null && sameAddress(other.address, address),
      )
    ) {
      waiting.set(campaign.id, address);
      return;
    }
    entry.address = address;

    const gate = createGate({
      campaign: { id: campaign.id, host: campaign.host, roeId: campaign.roe_id, intensity: campaign.intensity },
      // What the engine may ask for: its declared catalog, read on this side from its definition.
      catalog: probes,
      // An earlier process may have started this Campaign's checks: its log and its budgets go on from there.
      already: {
        seq: facts.lastSeq,
        sent: campaign.requests_sent,
        refused: campaign.requests_refused,
        bytes: campaign.response_bytes,
      },
      // The switches, from the database on every call: as a queued Campaign for the ownership request, as a running
      // one for a probe.
      control: (phase) =>
        db.tx({ organizationId }, (q) =>
          phase === "start" ? startControl(q, campaign.id) : campaignControl(q, campaign.id),
        ),
      authorize: (request) => authorize(organizationId, request),
      // The window, for as long as a request may still be running; freshness is judged now, as always.
      async windowHolds(path, aheadMs) {
        const at = now();
        const later = await evaluateAuthorization(
          db,
          organizationId,
          {
            host: campaign.host,
            path,
            intensity: campaign.intensity,
            at: new Date(at.getTime() + aheadMs).toISOString(),
          },
          at,
        );
        return later.allowed || later.reason !== "outside_window";
      },
      transport: (send) =>
        pinnedRequest({
          host: campaign.host,
          address,
          method: send.method,
          path: send.target,
          headers: send.headers,
          signal: send.signal,
          bodyBytesMax: send.bodyBytesMax,
          testing: transportTesting,
        }),
      record: (row) =>
        db.tx({ organizationId }, (q) => insertCampaignRequest(q, organizationId, campaign.id, row, now())),
      settle: async (row) => {
        const settled = await db.tx({ organizationId }, (q) => settleCampaignRequest(q, campaign.id, row));
        if (!settled) throw new Error("The request log row was not settled.");
      },
      now: () => performance.now(),
      sleep,
      signal,
      previousSendAt: Math.max(lastSend.get(campaign.host) ?? -Infinity, lastSend.get(address) ?? -Infinity),
      onSend(at) {
        lastSend.set(campaign.host, at);
        lastSend.set(address, at);
      },
      // The gate ended the Campaign: the engine is terminated at once.
      onEnd: (reason) => controller.abort(reason),
      limits: gateLimits,
    });

    // Ownership, now, from the pinned address itself, through the gate: the well-known file must hold this
    // Organization's token. It is the Campaign's first request: logged, spaced and counted like the others.
    const file = await gate.ownership();
    // The gate could not write its log: nothing more is sent, and this process does not try this Campaign again.
    if (gate.ended() === "engine_error" || (!file.ok && file.reason === "engine_error")) {
      throw new Error("The ownership check could not be recorded.");
    }
    // The target answered the ownership request with more than a response may hold: refused, on the byte budget.
    if (!file.ok && file.reason === "byte_budget") return void (await refuse("byte_budget"));
    if (signal.aborted) return;
    // An Organization whose deletion became pending starts nothing: its Campaign stays queued until the purge.
    if (!file.ok && file.reason === "deletion_pending") return;
    if (!file.ok) return void (await refuse(file.reason));
    if (!matchesFileChallenge(file.body, facts.token)) return void (await refuse("target_not_verified"));

    // --- Running. ------------------------------------------------------------------------------------------------
    const startedAt = now();
    const claimed = await db.tx({ organizationId }, async (q) => {
      if (!(await claimCampaign(q, campaign.id, startedAt, address))) return false;
      await audit(q, systemActor(organizationId), {
        action: "campaign.start",
        target: { kind: "campaign", id: campaign.id },
        summary: `The Campaign started: every start check passed, the target's address was resolved once and pinned, and the ownership file was served from it (engine ${campaign.engine.name} ${campaign.engine.version}, ${campaign.intensity}).`,
        at: startedAt,
      });
      return true;
    });
    if (!claimed) {
      // Not claimed: it is no longer queued (stopped while the start checks ran; its end is already written), or a
      // stop, the kill switch or a suspension was committed before the claim. Then its end is written here, unless
      // the one who stopped it already did (an end is written once).
      if (signal.aborted) return;
      const late = await db.tx({ organizationId }, (q) => startControl(q, campaign.id));
      if (late.killed) return void (await refuse("operator_kill"));
      if (late.suspended) return void (await refuse("organization_suspended"));
      if (late.deletionPending) return;
      if (late.stopRequested) return void (await refuse("owner_stop"));
      return;
    }
    logger.info(`campaign started id=${campaign.id}`);

    const known = new Set(standInEngine.checks);
    const catalog = standInEngine.findings;
    const checks = new Map<string, "reported" | "clean" | "inconclusive" | "skipped">();
    let dropped = 0;
    let outcome: "done" | "TimeoutError" | "other" = "done";
    try {
      await engine({
        intensity: campaign.intensity,
        request: (probe) => gate.request(probe),
        onCheck(value) {
          const parsed = EngineCheckSchema.safeParse(value);
          if (parsed.success && known.has(parsed.data.id) && !checks.has(parsed.data.id)) {
            checks.set(parsed.data.id, parsed.data.result);
          }
        },
        async onFinding(value) {
          // What an engine reports is checked like anything else it says: a known check, a canonical path, and
          // evidence that is the gate's own record of a request it really sent to that path, with a window that is
          // a piece of what the gate holds. A report that does not pass is never swallowed either: whatever the
          // reason, it is counted (`findings_dropped`), and the Campaign does not end as completed.
          const parsed = EngineFindingSchema.safeParse(value);
          const described = parsed.success ? catalog[parsed.data.check_id] : undefined;
          if (!parsed.success || described === undefined || !known.has(parsed.data.check_id)) return void dropped++;
          const finding = parsed.data;
          if (canonicalCampaignPath(finding.path) !== finding.path) return void dropped++;
          const evidence = gate.evidence(finding.seq, finding.window);
          if (evidence === null || evidence.target.split("?")[0] !== finding.path) return void dropped++;
          // A Finding that cannot be stored is counted too.
          try {
            const stored = await db.tx({ organizationId }, (q) =>
              reportFinding(q, organizationId, campaign.id, {
                checkId: finding.check_id,
                path: finding.path,
                // The catalog's words, not the engine's: a title is never text made up from a response.
                title: described.title.slice(0, CAMPAIGN_LIMITS.titleMax),
                severity: described.severity,
                evidence,
                at: now(),
              }),
            );
            if (stored === null) dropped++;
          } catch (error) {
            dropped++;
            logger.warn(`campaign finding not stored id=${campaign.id} ${(error as Error).name}`);
          }
        },
        signal,
      });
    } catch (error) {
      outcome = (error as { name?: unknown } | null)?.name === "TimeoutError" ? "TimeoutError" : "other";
    }
    // A stop that reached this Campaign — the owner's, the operator's kill or suspension, a deletion — before its end
    // is written: a stop is final. Even when the engine was done and only its last Finding was still being stored,
    // the Campaign ends as stopped, never as completed.
    const stop = signal.aborted ? endReasonOf(signal.reason) : null;
    // However the engine ended, nothing more may be sent.
    if (!signal.aborted) controller.abort(outcome === "done" ? "checks_complete" : "engine_error");
    let reason: CampaignEndReason =
      stop !== null && STOPS.has(stop)
        ? stop
        : (gate.ended() ??
          (outcome === "done"
            ? "checks_complete"
            : outcome === "TimeoutError"
              ? "time_budget"
              : (endReasonOf(signal.reason) ?? "engine_error")));
    if (dropped > 0 && reason === "checks_complete") reason = "engine_error";
    const results = [...checks.values()];
    // Ran: got an answer it could judge. Inconclusive: got one it could not read. Everything else was skipped.
    const ran = results.filter((result) => result === "reported" || result === "clean").length;
    const inconclusive = results.filter((result) => result === "inconclusive").length;
    await finish(organizationId, campaign, {
      reason,
      started: true,
      checks: {
        ran,
        reported: results.filter((result) => result === "reported").length,
        inconclusive,
        skipped: standInEngine.checks.length - ran - inconclusive,
      },
      findingsDropped: dropped,
    });
  }

  async function abort(campaignId: string, reason: CampaignEndReason): Promise<void> {
    const entry = active.get(campaignId);
    if (entry === undefined) return;
    entry.controller.abort(reason);
    await entry.done;
  }

  return {
    enabled,
    async start() {
      const at = now();
      const interrupted = await db.tx("none", (q) => interruptRunningCampaigns(q, at));
      for (const { organizationId, campaignId } of interrupted) {
        await db.tx({ organizationId }, (q) =>
          audit(q, systemActor(organizationId), {
            action: "campaign.end",
            target: { kind: "campaign", id: campaignId },
            summary:
              "The Campaign ended: interrupted (api_restart). The API restarted while it was running; it is not resumed.",
            at,
          }),
        );
      }
      if (interrupted.length > 0) logger.warn(`campaigns interrupted count=${interrupted.length}`);
      void pump();
    },
    wake() {
      if (!stopped) void pump();
    },
    abort,
    isActive: (campaignId) => active.has(campaignId),
    cut(organizationId, reason) {
      for (const entry of active.values()) {
        if (entry.organizationId === organizationId) entry.controller.abort(reason);
      }
    },
    async operatorStop(input) {
      // First, before anything is awaited: every Campaign this process is starting or running (of the Organization,
      // or of all) is aborted — its request in flight is cut and nothing more is sent. The kill is committed when
      // this is called; the audit entries and the ends below take several transactions.
      const cut = new Map<string, string>();
      for (const [campaignId, entry] of active) {
        if (input.organizationId === undefined || entry.organizationId === input.organizationId) {
          entry.controller.abort(input.reason);
          cut.set(campaignId, entry.organizationId);
        }
      }
      // And nothing is launched while this stop is at work: a Campaign still queued is ended below, by the operator.
      held++;
      try {
        const at = now();
        // The Campaigns cut above (one of them may have written its end before the queue is read), and every other
        // queued or running one.
        const affected = new Map(cut);
        for (const entry of await readQueue()) {
          if (input.organizationId === undefined || entry.organizationId === input.organizationId) {
            affected.set(entry.campaignId, entry.organizationId);
          }
        }
        let ended = 0;
        for (const [campaignId, organizationId] of affected) {
          // Its request in flight is cut, its engine terminated, and its end written: by the Campaign itself if it
          // was running here, else here.
          await abort(campaignId, input.reason);
          await finish(organizationId, { id: campaignId }, { reason: input.reason, started: false, checks: null });
          // The operator's own entry, in the Organization's chain, for every Campaign this stop ended — one that
          // ended in the same moment for a reason of its own gets none and is not counted. (A running Campaign's
          // end is the system's entry, and stands before this one.)
          const stopped = await db.tx({ organizationId }, async (q) => {
            const campaign = await findCampaign(q, campaignId);
            if (campaign === null || campaign.end_reason !== input.reason) return false;
            await audit(q, operatorActor(organizationId, input.requestId, input.operatorReason), {
              action: "campaign.operator_kill",
              target: { kind: "campaign", id: campaignId },
              summary:
                input.reason === "operator_kill"
                  ? "The operator stopped all Campaigns: this Organization's Campaign was ended."
                  : "The operator suspended this Organization's Campaigns: its Campaign was ended.",
              at,
            });
            return true;
          });
          if (stopped) ended++;
        }
        return ended;
      } finally {
        held--;
        if (!stopped) void pump();
      }
    },
    async activeCount() {
      return (await readQueue()).length;
    },
    async idle() {
      for (;;) {
        if (pumping !== null) await pumping;
        const running = [...active.values()];
        if (running.length === 0 && pumping === null) return;
        await Promise.all(running.map((entry) => entry.done));
      }
    },
    async stop() {
      stopped = true;
      if (pumping !== null) await pumping;
      const running = [...active.values()];
      for (const entry of running) entry.controller.abort("api_shutdown");
      await Promise.all(running.map((entry) => entry.done));
    },
  };
}
