import {
  ASSESSMENT_CALL_LIMITS,
  type AssessmentCall,
  AssessmentCallSchema,
  type AssessmentTier,
  type Canary,
  type ObjectiveId,
  type ObjectiveResult,
  ObjectiveResultSchema,
  ScopeStatementSchema,
  scoreAssessment,
  TIER_IDS,
  TIERS,
  type TierLimits,
} from "@antireverse/protocol";
import { z } from "zod";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import type { SloSink } from "../slo/recorder.ts";
import {
  artifactFiles,
  assessmentQueue,
  buildCanaries,
  type ClaimedRun,
  claimAssessment,
  expireArtifacts,
  type Finish,
  finishAssessment,
  interruptRunning,
  type StoredCalls,
} from "../stores/assessments.ts";
import { findBuildLogic, findBuildRoutes, findManifest } from "../stores/builds.ts";
import { pendingDeletion } from "../stores/deletions.ts";
import type { Assessor, AssessorInput, AssessorOutcome } from "./assessor.ts";

// The Assessment queue and runner (slice 12a). Runs queued Assessments oldest first, one running per Organization and
// `concurrency` (2) at once in all, each through the Assessor with the Build's facts as verifier inputs. The runner
// scores a finished run itself with the protocol's `scoreAssessment` after validating every result and the scope
// statement; a run that rejects, returns something invalid, or outlives the tier's time budget plus a grace is failed
// with a fixed reason (never the engine's message, which could quote artifact content) and keeps the results decided
// before (`onResult`). On start, Assessments left running by a previous process become failed (interrupted) and the
// queued ones resume; on stop, running ones are aborted and failed (interrupted). A periodic job deletes artifacts 30
// days after their last Assessment finished. Log lines carry ids, counts and statuses only.
//
// Single-process assumption: the one-running-per-Organization rule, the two-in-all limit and the interrupt-on-start
// recovery hold only while exactly one API process runs Assessments on the database — the PGlite deployment, whose
// data-directory lock admits one process. The limits are kept in this process's memory (beside a per-Organization
// guard in the claim), and `start()` fails every running Assessment as interrupted: a second process on the same
// database would exceed the global limit and would fail the first process's live runs. Several API processes need a
// shared lease (claim with an owner and a heartbeat) before they may run Assessments.

/** Fixed failure reasons: an Assessment never carries an engine's own message. */
export const FAILURE_REASONS = Object.freeze({
  engine: "The assessment engine stopped with an error.",
  invalid: "The assessment engine returned results that could not be scored.",
  timeout: "The run exceeded its time budget.",
  interrupted: "Interrupted: the API stopped while the Assessment was running.",
  agent: "The adversary agent stopped with an error; the results decided are kept, without a score.",
  artifact: "The artifact of this Assessment is no longer available.",
});

export const RUNNER_DEFAULTS = Object.freeze({
  /** Assessments running at once, across Organizations. */
  concurrency: 2,
  /**
   * Added to the tier's seconds before the runner gives up on a run the engine did not end itself. It outlasts
   * the engine's own grace (prove's 60 s judging budget plus margin, 90 s), so the engine ends a run first.
   */
  graceMs: 120_000,
  /** Between runs of the artifact expiry. */
  expiryIntervalMs: 3_600_000,
  /** Queue entries read per pass. */
  queueRead: 1000,
});

export interface AssessmentRunnerOptions {
  db: Db;
  assessor: Assessor;
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  concurrency?: number;
  /** Overrides of the tier limits (tests), passed to the Assessor and used for the runner's own deadline. */
  budgets?: Partial<Record<AssessmentTier, TierLimits>>;
  graceMs?: number;
  expiryIntervalMs?: number;
  /** Slice 18d: told each T1 Assessment that ends (SLO-10). */
  slo?: SloSink | undefined;
}

/** SLO-10's bound (PB-22): a T1 result within 30 min of the Assessment's creation. */
export const PROVE_GOOD_MS = 1_800_000;

/** What the routes need: told when an Assessment was queued. */
export interface AssessmentQueue {
  wake(): void;
}

export interface AssessmentRunner extends AssessmentQueue {
  /** Fails Assessments left running, then takes queued ones and schedules the artifact expiry. */
  start(): Promise<void>;
  /** One run of the artifact expiry now. Returns how many artifacts were deleted. */
  expireOnce(): Promise<number>;
  /** Resolves once no run is in progress and the queue has nothing this runner can take. */
  idle(): Promise<void>;
  /** Takes nothing more, aborts running Assessments and marks them failed (interrupted), and stops the expiry. */
  stop(): Promise<void>;
}

const ResultsSchema = z.array(ObjectiveResultSchema);

/**
 * The calls of the engine's call log that some Objective's evidence references (fork 5, Jev "store_referenced_calls"):
 * valid entries only, ascending index, at most `ASSESSMENT_CALL_LIMITS.storedMax`; an index the cap (or an invalid
 * entry) left out is dropped from the evidence, so every stored index resolves to a stored call. A summary that
 * contains a planted Canary value is withheld (summaries name paths and counts only; this is the backstop). Without a
 * call log from the engine, nothing is stored and the evidence is left as it is.
 */
export function referencedCalls(
  results: readonly ObjectiveResult[],
  outcome: AssessorOutcome,
  canaries: readonly Canary[],
): { results: ObjectiveResult[]; log: StoredCalls | null } {
  if (outcome.calls === undefined) return { results: [...results], log: null };
  const referenced = new Set(results.flatMap((result) => result.evidence.calls));
  const byIndex = new Map<number, AssessmentCall>();
  for (const entry of outcome.calls) {
    const parsed = AssessmentCallSchema.safeParse(entry);
    if (!parsed.success || !referenced.has(parsed.data.index) || byIndex.has(parsed.data.index)) continue;
    const call = parsed.data;
    const leaks = canaries.some((canary) => canary.value.length > 0 && call.summary.includes(canary.value));
    byIndex.set(call.index, leaks ? { ...call, summary: `${call.tool}: summary withheld` } : call);
  }
  const calls = [...byIndex.values()].sort((a, b) => a.index - b.index).slice(0, ASSESSMENT_CALL_LIMITS.storedMax);
  const kept = new Set(calls.map((call) => call.index));
  const last = outcome.calls.at(-1);
  const total = outcome.cost ?? (last === undefined ? { calls: 0, seconds: 0 } : last.cost);
  return {
    results: results.map((result) => ({
      ...result,
      evidence: { ...result.evidence, calls: result.evidence.calls.filter((index) => kept.has(index)) },
    })),
    log: { calls, totals: { count: outcome.calls.length, calls: total.calls, seconds: total.seconds } },
  };
}

interface Active {
  organizationId: string;
  controller: AbortController;
  done: Promise<void>;
}

export function createAssessmentRunner(options: AssessmentRunnerOptions): AssessmentRunner {
  const { db, assessor } = options;
  const now = options.now ?? (() => new Date());
  const logger = redacting(options.logger ?? consoleLogger);
  const concurrency = Math.max(1, options.concurrency ?? RUNNER_DEFAULTS.concurrency);
  const graceMs = options.graceMs ?? RUNNER_DEFAULTS.graceMs;
  const expiryIntervalMs = options.expiryIntervalMs ?? RUNNER_DEFAULTS.expiryIntervalMs;
  const budgets = options.budgets ?? {};
  const limitsOf = (tier: AssessmentTier): TierLimits => budgets[tier] ?? TIERS[tier];

  const active = new Map<string, Active>();
  let stopped = false;
  let pumping: Promise<void> | null = null;
  let again = false;
  let expiryTimer: ReturnType<typeof setInterval> | undefined;

  /** Takes queued Assessments while there is room. One pass at a time; a wake during a pass runs one more. */
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
          logger.warn(`assessment queue failed: ${(error as Error).name}`);
        }
      } while (again && !stopped);
    })().finally(() => {
      pumping = null;
    });
    return pumping;
  }

  async function pass(): Promise<void> {
    if (stopped || active.size >= concurrency) return;
    const queue = await db.tx("none", (q) => assessmentQueue(q, RUNNER_DEFAULTS.queueRead));
    const busy = new Set(queue.filter((entry) => entry.status === "running").map((entry) => entry.organizationId));
    for (const entry of active.values()) busy.add(entry.organizationId);
    for (const entry of queue) {
      if (stopped || active.size >= concurrency) return;
      if (entry.status !== "queued" || busy.has(entry.organizationId)) continue;
      const { organizationId } = entry;
      // Slice 18b: an Organization whose deletion is pending runs nothing more (the queue leaves it out too; this
      // closes the race with a request made after the queue was read). Its Assessments stay queued until the purge.
      const claimed = await db.tx({ organizationId }, async (q) =>
        (await pendingDeletion(q)) !== null ? null : claimAssessment(q, entry.assessmentId, now()),
      );
      busy.add(organizationId);
      if (claimed === null) continue;
      launch(organizationId, claimed);
    }
  }

  function launch(organizationId: string, claimed: ClaimedRun): void {
    const controller = new AbortController();
    const entry: Active = { organizationId, controller, done: Promise.resolve() };
    active.set(claimed.id, entry);
    logger.info(`assessment started id=${claimed.id} tier=${claimed.tier}`);
    entry.done = execute(organizationId, claimed, controller)
      .catch((error: unknown) => logger.warn(`assessment run failed id=${claimed.id} ${(error as Error).name}`))
      .finally(() => {
        active.delete(claimed.id);
        if (!stopped) void pump();
      });
  }

  async function finish(organizationId: string, claimed: ClaimedRun, result: Finish): Promise<void> {
    const { id } = claimed;
    const finishedAt = now();
    const written = await db.tx({ organizationId }, (q) => finishAssessment(q, id, result, finishedAt));
    logger.info(`assessment ${written ? "finished" : "already ended"} id=${id} status=${result.status}`);
    // Slice 18d, SLO-10: a T1 Assessment with a result (scored or inconclusive) within 30 min of its creation.
    if (written && claimed.tier === "T1" && options.slo !== undefined) {
      const ms = finishedAt.getTime() - claimed.createdAt.getTime();
      options.slo.record("SLO-10", result.status !== "failed" && ms <= PROVE_GOOD_MS, ms);
    }
  }

  async function execute(organizationId: string, claimed: ClaimedRun, controller: AbortController): Promise<void> {
    const partial = new Map<ObjectiveId, ObjectiveResult>();
    const failWith = (reason: string): Finish => ({ status: "failed", results: [...partial.values()], reason });
    const target = { organizationId, appId: claimed.appId };

    const facts = await db.tx({ organizationId }, async (q) => {
      if (claimed.artifactId === null) return null;
      const artifact = await artifactFiles(q, claimed.artifactId);
      if (artifact.size === 0) return null;
      return {
        artifact,
        canaries: await buildCanaries(q, target, claimed.buildId),
        routes: await findBuildRoutes(q, target, claimed.buildId),
        logic: await findBuildLogic(q, target, claimed.buildId),
        integrity: (await findManifest(q, target, claimed.buildId))?.transform.integrity ?? false,
      };
    });
    if (facts === null) {
      await finish(organizationId, claimed, failWith(FAILURE_REASONS.artifact));
      return;
    }

    const input: AssessorInput = {
      tier: claimed.tier,
      artifact: facts.artifact,
      // Verifier inputs only: the Assessor keeps them out of the agent's context.
      build: {
        canaries: facts.canaries,
        leakFindings: [],
        routes: facts.routes,
        logic: facts.logic,
        integrity: facts.integrity,
      },
      budgets,
      signal: controller.signal,
      onResult: (result) => {
        const parsed = ObjectiveResultSchema.safeParse(result);
        if (!parsed.success || partial.has(parsed.data.objective)) return;
        if (parsed.data.result === "achieved" && TIER_IDS.indexOf(parsed.data.tier) > TIER_IDS.indexOf(claimed.tier)) {
          return;
        }
        partial.set(parsed.data.objective, parsed.data);
      },
    };

    // The runner's own deadline: the tier's seconds plus a grace, whatever the engine does about its budget.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), limitsOf(claimed.tier).seconds * 1000 + graceMs);
      timer.unref?.();
    });
    const aborted = new Promise<"aborted">((resolve) => {
      controller.signal.addEventListener("abort", () => resolve("aborted"), { once: true });
    });
    const run = assessor.assess(input).then(
      (outcome) => ({ kind: "outcome" as const, outcome }),
      (error: unknown) => ({ kind: "error" as const, name: (error as { name?: unknown } | null)?.name }),
    );
    const ended = await Promise.race([run, deadline, aborted]).finally(() => clearTimeout(timer));

    if (ended === "timeout") {
      controller.abort();
      await finish(organizationId, claimed, failWith(FAILURE_REASONS.timeout));
      return;
    }
    if (ended === "aborted") {
      await finish(organizationId, claimed, failWith(FAILURE_REASONS.interrupted));
      return;
    }
    if (ended.kind === "error") {
      // By the error's name only (the engine's own deadline, its abort, anything else); never its message.
      const reason =
        ended.name === "TimeoutError"
          ? FAILURE_REASONS.timeout
          : ended.name === "AbortError"
            ? FAILURE_REASONS.interrupted
            : FAILURE_REASONS.engine;
      await finish(organizationId, claimed, failWith(reason));
      return;
    }

    const results = ResultsSchema.safeParse(ended.outcome.results);
    const scope = ScopeStatementSchema.safeParse(ended.outcome.scope);
    if (!results.success || !scope.success || scope.data.tier !== claimed.tier) {
      await finish(organizationId, claimed, failWith(FAILURE_REASONS.invalid));
      return;
    }
    // Stored in Objective order, as the protocol lists them, with the referenced calls of the call log (fork 5).
    const { results: ordered, log } = referencedCalls(
      [...results.data].sort((a, b) => a.objective.localeCompare(b.objective)),
      ended.outcome,
      facts.canaries,
    );
    if (ended.outcome.end === "agent_error") {
      // A failed run keeps its results as partial ones, never a score; an achieved tier beyond the run's is dropped.
      const kept = ordered.filter(
        (result, index) =>
          ordered.findIndex((other) => other.objective === result.objective) === index &&
          (result.result !== "achieved" || TIER_IDS.indexOf(result.tier) <= TIER_IDS.indexOf(claimed.tier)),
      );
      await finish(organizationId, claimed, {
        status: "failed",
        results: kept,
        reason: FAILURE_REASONS.agent,
        log,
      });
      return;
    }
    let score: ReturnType<typeof scoreAssessment>;
    try {
      score = scoreAssessment(results.data, claimed.tier);
    } catch {
      await finish(organizationId, claimed, failWith(FAILURE_REASONS.invalid));
      return;
    }
    await finish(
      organizationId,
      claimed,
      score.status === "scored"
        ? {
            status: "scored",
            results: ordered,
            rrs: score.rrs,
            renormalised: score.renormalised,
            scope: scope.data,
            log,
          }
        : {
            status: "inconclusive",
            results: ordered,
            reason: score.reason,
            code: score.code,
            scope: scope.data,
            log,
          },
    );
  }

  async function expireOnce(): Promise<number> {
    const deleted = await db.tx("none", (q) => expireArtifacts(q, now()));
    if (deleted > 0) logger.info(`assessment artifacts expired count=${deleted}`);
    return deleted;
  }

  return {
    async start() {
      const interrupted = await db.tx("none", (q) => interruptRunning(q, now(), FAILURE_REASONS.interrupted));
      if (interrupted > 0) logger.warn(`assessments interrupted count=${interrupted}`);
      await expireOnce().catch((error: unknown) => logger.warn(`assessment expiry failed: ${(error as Error).name}`));
      expiryTimer = setInterval(() => {
        void expireOnce().catch((error: unknown) => logger.warn(`assessment expiry failed: ${(error as Error).name}`));
      }, expiryIntervalMs);
      expiryTimer.unref?.();
      void pump();
    },
    wake() {
      if (!stopped) void pump();
    },
    expireOnce,
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
      clearInterval(expiryTimer);
      if (pumping !== null) await pumping;
      const running = [...active.values()];
      for (const entry of running) entry.controller.abort();
      await Promise.all(running.map((entry) => entry.done));
    },
  };
}
