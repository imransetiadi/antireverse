// Pentest Campaigns of the stand-in API (slice 15a), in memory, in the shape of the protocol (checked by
// test/stub-campaigns.test.ts): `/v1/campaigns…` per Organization and the operator's switches `/v1/ops/prove…`.
// Nothing is ever sent anywhere: a "run" is a script that advances with the clock, read lazily.
//
// Creation checks what the API checks, in the API's order, and answers with the API's problem documents:
//   400 validation (target_id, intensity, confirm, staging) → 400 reason-required → 403 campaigns-disabled →
//   403 campaigns-stopped → 403 campaigns-suspended → 400 target_id (not a target of the Organization) →
//   400 confirm (not `I authorise a test of <host>`) → 409 campaign-target-not-verified → campaign-no-rules →
//   campaign-target-out-of-scope → campaign-rules-too-old → campaign-intensity-exceeds →
//   campaign-verification-path-excluded → campaign-active →
//   429 with Retry-After (5 per Organization and 3 per target in 24 hours) → 202.
//
// A run: queued for 2 s, then one scripted request per second — the six checks of the stand-in catalog (RW-01 to
// RW-06; the safe-active ones are skipped by a passive Campaign), each Finding repeated once to confirm it — then
// completed. The first label of the target's host picks another end, so that every state can be looked at:
//   unreachable.<…>  refused at start (target_not_reachable)   unowned.<…>  refused at start (target_not_verified)
//   limited.<…>      runs three requests, then fails (target_rate_limited)
// A stop is final: queued or running → stopped, and nothing follows it. `seed: true` adds four ended Campaigns older
// than a day (completed, stopped with a refused probe in its log, refused, failed).
//
// The operator's switches need the operator token (as stub-ops.mjs): 404 without one configured, 401 for any other
// bearer. Kill ends every active Campaign of every Organization; suspend those of one. `AR_STUB_CAMPAIGNS=off`
// (stub-api.mjs) starts the stub with Campaigns switched off.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  CAMPAIGN_LIMITS,
  CAMPAIGN_REPORT_LIMITS,
  CAMPAIGN_STAND_IN_NOTICE,
  CreateCampaignRequestSchema,
  campaignAuthorisationPhrase,
  campaignChecksSentence,
  ID_PATTERNS,
  isPathExcluded,
  ProveOperatorRequestSchema,
  STAND_IN_ENGINE,
  toProblemErrors,
  VERIFICATION_FILE_PATH,
} from "@antireverse/protocol";

const PROBLEMS = "https://antireverse.dev/problems/";
const DAY_MS = 86_400_000;
const FRESHNESS_MS = 93_600_000;
const SKEW_MS = 300_000;
const QUEUED_MS = 2_000;
const INTENSITIES = ["passive", "safe-active", "full"];

const newId = (prefix) => `${prefix}_${randomBytes(12).toString("hex")}`;
const iso = (ms) => new Date(ms).toISOString();
const digest = (text) => createHash("sha256").update(text, "utf8").digest();

// The API's own problem documents (apps/api/src/problem.ts), word for word.
const problem = (status, kind, title, detail, extra = {}, headers = undefined) => ({
  status,
  body: { type: `${PROBLEMS}${kind}`, title, status, ...(detail === undefined ? {} : { detail }), ...extra },
  ...(headers === undefined ? {} : { headers }),
});
const NOT_FOUND = () => problem(404, "not-found", "Not found", "The resource does not exist.");
const UNAUTHORIZED = () =>
  problem(
    401,
    "unauthorized",
    "Unauthorized",
    "A valid key is required. Send it as: Authorization: Bearer <key>.",
    {},
    { "www-authenticate": "Bearer" },
  );
const invalid = (errors) => problem(400, "validation", "Invalid request", undefined, { errors });
const REASON_REQUIRED = () =>
  problem(
    400,
    "reason-required",
    "Reason required",
    "This change needs a reason. Send it as: X-Airverse-Reason: <1 to 500 characters>.",
  );
const UNAVAILABLE = {
  disabled: () =>
    problem(
      403,
      "campaigns-disabled",
      "Campaigns are not enabled",
      "Pentest Campaigns are not enabled on this service. The operator turns them on by setting AR_PROVE_CAMPAIGNS=1.",
    ),
  stopped: () =>
    problem(
      403,
      "campaigns-stopped",
      "Campaigns are stopped",
      "The operator has stopped all Pentest Campaigns. None can be created until they are re-enabled.",
    ),
  suspended: () =>
    problem(
      403,
      "campaigns-suspended",
      "Campaigns are suspended",
      "The operator has suspended Pentest Campaigns for this Organization.",
    ),
};
const CONFLICT_DETAILS = {
  "campaign-active": "This Organization already has a queued or running Campaign. Wait for it to end, or stop it.",
  "campaign-target-not-verified":
    "The target is not verified, or its last ownership check is older than 26 hours. Verify it again first.",
  "campaign-no-rules": "There are no signed Rules of Engagement. Sign them first.",
  "campaign-target-out-of-scope":
    "The target is not in the scope of the current Rules of Engagement. Sign a version that names it first.",
  "campaign-rules-too-old": `The current Rules of Engagement were signed more than ${CAMPAIGN_LIMITS.roeMaxAgeDays} days ago. Sign them again first.`,
  "campaign-intensity-exceeds": "The current Rules of Engagement allow less than the intensity asked for.",
  "campaign-verification-path-excluded":
    "The current Rules of Engagement exclude the ownership file's path (/.well-known/airverse-verification.txt), which every Campaign fetches at its start. Sign Rules that do not exclude it.",
  "campaign-ended": "The Campaign has ended or is already being stopped. A stop is final.",
};
const conflict = (reason) => problem(409, "conflict", "Conflict", CONFLICT_DETAILS[reason], { reason });
const tooMany = (retryAfterS) =>
  problem(
    429,
    "too-many-requests",
    "Too many requests",
    `At most ${CAMPAIGN_LIMITS.createdPerOrganizationPerDay} Campaigns per Organization and ${CAMPAIGN_LIMITS.createdPerTargetPerDay} per target in 24 hours. Try again after the time in Retry-After.`,
    {},
    { "retry-after": String(retryAfterS) },
  );
const ok = (body, status = 200) => ({ status, body });

// The stand-in catalog (plan 15a): what each check asks for and what the reference target answers, already redacted.
const CATALOG = [
  {
    id: "RW-01",
    intensity: "passive",
    path: "/",
    title: "Missing security headers",
    severity: "low",
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    // A check that reads no body keeps no text of the response (the evidence window, D-107).
    excerpt: "",
    bytes: 1820,
  },
  {
    id: "RW-02",
    intensity: "safe-active",
    path: "/api/orders/x",
    title: "Error with a stack trace",
    severity: "medium",
    status: 500,
    headers: { "content-type": "text/plain; charset=utf-8" },
    excerpt: "TypeError: order id must be a number\n    at readOrder (/srv/shop/orders.js:41:11)",
    bytes: 412,
  },
  {
    id: "RW-03",
    intensity: "passive",
    path: "/api/admin/reports",
    title: "Admin data without authentication",
    severity: "high",
    status: 200,
    headers: { "content-type": "application/json" },
    excerpt: '{"reports":[{"owner":"[redacted-email]","api_key":"[redacted-key]","total":1299}]}',
    bytes: 960,
  },
  {
    id: "RW-04",
    intensity: "safe-active",
    path: "/api/orders/1001",
    title: "Synthetic order readable by a guessable id",
    severity: "high",
    status: 200,
    headers: { "content-type": "application/json" },
    excerpt: '{"order":1001,"customer":"[redacted-email]","card":"[redacted-card]"}',
    bytes: 388,
  },
  {
    id: "RW-05",
    intensity: "safe-active",
    path: "/search",
    query: "q=airverse-marker-7f3a",
    title: "Marker reflected unencoded",
    severity: "medium",
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    excerpt: "<p>No results for <b>airverse-marker-7f3a</b></p>",
    bytes: 640,
  },
  {
    id: "RW-06",
    intensity: "safe-active",
    path: "/go",
    query: "to=elsewhere",
    title: "Redirect to another host",
    severity: "low",
    status: 302,
    headers: {},
    excerpt: "",
    bytes: 0,
    location: "other-host",
  },
];
const targetOf = (check) => (check.query === undefined ? check.path : `${check.path}?${check.query}`);

/** The scripted steps of a run: every check the intensity allows once, then each once more to confirm its Finding. */
function scriptOf(intensity) {
  const allowed = CATALOG.filter((check) => INTENSITIES.indexOf(check.intensity) <= INTENSITIES.indexOf(intensity));
  return [
    ...allowed.map((check) => ({ check, confirms: false })),
    ...allowed.map((check) => ({ check, confirms: true })),
  ];
}

/** The switches the operator holds, shared by every Organization of the stub. */
export function createProveSwitch({ enabled = true } = {}) {
  /** @type {Map<string, string>} Organization id → when it was suspended (ISO) */
  const suspended = new Map();
  return {
    enabled,
    killed: false,
    /** @type {string | null} */
    killedAt: null,
    kill(ms) {
      if (!this.killed) this.killedAt = iso(ms);
      this.killed = true;
    },
    enable() {
      this.killed = false;
      this.killedAt = null;
    },
    /** True when it changed something. */
    suspend(organizationId, ms) {
      if (suspended.has(organizationId)) return false;
      suspended.set(organizationId, iso(ms));
      return true;
    },
    resume(organizationId) {
      return suspended.delete(organizationId);
    },
    isSuspended: (organizationId) => suspended.has(organizationId),
    suspendedList: () => [...suspended].map(([organization_id, suspended_at]) => ({ organization_id, suspended_at })),
  };
}

/**
 * @typedef {{ actor: "admin_key" | "system" | "operator", action: string, target: { kind: string, id: string }, reason?: string, summary: string }} CampaignAuditEntry
 * @typedef {{ handle: (method: string, path: string, body?: unknown) => { status: number, body: any } | null }} ProveStore
 * @typedef {ReturnType<typeof createProveSwitch>} ProveSwitch
 */

/**
 * The Campaigns of one Organization. `prove` is its Prove store (targets and Rules of Engagement are read through
 * its own routes), `control` the operator's switches, `record` receives every audit entry
 * (`{ actor: "admin_key" | "system" | "operator", action, target, reason?, summary }`), `now` is the clock (ms).
 * `handle(method, path, body, reason)` answers a request under `/v1/campaigns`, or returns null for any other path.
 * @param {{ organizationId: string, keyId: string, prove: ProveStore, control: ProveSwitch, record?: (entry: CampaignAuditEntry) => void, now?: () => number, seed?: boolean }} options
 */
export function createCampaignStore({
  organizationId,
  keyId,
  prove,
  control,
  record = (_entry) => {},
  now = () => Date.now(),
  seed = false,
}) {
  /** @type {Array<{ campaign: any, requests: any[], findings: any[], script: any[], outcome: string }>} oldest first */
  const entries = [];

  const targets = () => prove.handle("GET", "/v1/targets")?.body.targets ?? [];
  const currentRules = () => prove.handle("GET", "/v1/rules-of-engagement/current")?.body.version ?? null;
  // The seed writes no audit entries: the chain of a new Organization starts with its own changes.
  let seeding = false;
  const write = (entry) => {
    if (!seeding) record(entry);
  };
  const system = (action, id, summary) => write({ actor: "system", action, target: { kind: "campaign", id }, summary });

  function evidenceOf(check) {
    return {
      method: "GET",
      target: targetOf(check),
      status: check.status,
      headers: { ...check.headers },
      excerpt: check.excerpt,
      truncated: false,
      location: check.location ?? null,
    };
  }

  /** Runs step `index` of the script at `at`: one sent request, and the Finding it reports or confirms. */
  function step(entry, index, at) {
    const { check, confirms } = entry.script[index];
    const seq = entry.requests.length + 1;
    entry.requests.push({
      seq,
      at: iso(at),
      method: "GET",
      target: targetOf(check),
      outcome: "sent",
      reason: null,
      status: check.status,
      failure: null,
      bytes: check.bytes,
      ms: 20 + ((seq * 7) % 30),
      asked_chars: null,
    });
    entry.campaign.requests_sent += 1;
    entry.campaign.response_bytes += check.bytes;
    const finding = entry.findings.find((one) => one.check_id === check.id);
    if (confirms && finding) {
      finding.state = "confirmed";
      finding.last_seen_at = iso(at);
    } else if (!finding) {
      entry.findings.push({
        check_id: check.id,
        path: check.path,
        title: check.title,
        severity: check.severity,
        state: "unverified",
        evidence: evidenceOf(check),
        first_seen_at: iso(at),
        last_seen_at: iso(at),
      });
    }
  }

  function checksOf(entry) {
    const ran = new Set(entry.requests.filter((row) => row.outcome === "sent").map((row) => row.target)).size;
    return { ran, reported: entry.findings.length, inconclusive: 0, skipped: CATALOG.length - ran };
  }

  function end(entry, reason, status, at, started) {
    const { campaign } = entry;
    campaign.status = status;
    campaign.end_reason = reason;
    campaign.finished_at = iso(at);
    campaign.checks = started ? checksOf(entry) : null;
    system(
      started ? "campaign.end" : "campaign.refuse",
      campaign.id,
      started
        ? `The Campaign ended: ${status} (${reason}); ${campaign.requests_sent} requests sent, ${campaign.requests_refused} refused. ${campaignChecksSentence(campaign.checks)}`
        : `The Campaign did not start: ${status} (${reason}). No request was sent.`,
    );
  }

  /** Brings a Campaign to where the clock says it is. An ended Campaign never moves again. */
  function advance(entry) {
    const { campaign } = entry;
    if (campaign.status !== "queued" && campaign.status !== "running") return;
    const at = now();
    const created = Date.parse(campaign.created_at);
    if (at - created < QUEUED_MS) return;
    const startAt = created + QUEUED_MS;
    if (campaign.status === "queued") {
      if (entry.outcome === "unreachable") return end(entry, "target_not_reachable", "refused", startAt, false);
      if (entry.outcome === "unowned") return end(entry, "target_not_verified", "refused", startAt, false);
      campaign.status = "running";
      campaign.started_at = iso(startAt);
      system("campaign.start", campaign.id, `The Campaign started against ${campaign.host}. Engine: stand-in 1.`);
    }
    const limit = entry.outcome === "limited" ? 3 : entry.script.length;
    const due = Math.min(limit, Math.floor((at - startAt) / CAMPAIGN_LIMITS.minSpacingMs) + 1);
    for (let index = campaign.requests_sent; index < due; index++) {
      step(entry, index, startAt + index * CAMPAIGN_LIMITS.minSpacingMs);
    }
    if (campaign.requests_sent < limit) return;
    const endAt = startAt + limit * CAMPAIGN_LIMITS.minSpacingMs;
    if (entry.outcome === "limited") return end(entry, "target_rate_limited", "failed", endAt, true);
    end(entry, "checks_complete", "completed", endAt, true);
  }

  const active = () => {
    for (const entry of entries) advance(entry);
    return entries.filter(({ campaign }) => campaign.status === "queued" || campaign.status === "running");
  };

  function insert(target, rules, intensity, createdAt) {
    const first = target.host.split(".")[0];
    const entry = {
      campaign: {
        id: newId("cmp"),
        target_id: target.id,
        host: target.host,
        roe_id: rules.id,
        roe_sha256: rules.content_sha256,
        intensity,
        engine: { ...STAND_IN_ENGINE },
        notice: CAMPAIGN_STAND_IN_NOTICE,
        status: "queued",
        end_reason: null,
        staging_declared: true,
        created_by: keyId,
        requests_sent: 0,
        requests_refused: 0,
        response_bytes: 0,
        checks: null,
        findings_dropped: 0,
        stop: null,
        created_at: iso(createdAt),
        started_at: null,
        finished_at: null,
      },
      requests: [],
      findings: [],
      script: scriptOf(intensity),
      outcome: ["unreachable", "unowned", "limited"].includes(first) ? first : "complete",
    };
    entries.push(entry);
    return entry;
  }

  /** Ends an active Campaign as stopped. `refusedProbe`: the probe the engine asked for after the stop, refused. */
  function stopEntry(entry, reason, at) {
    const { campaign } = entry;
    const started = campaign.status === "running";
    if (started) {
      entry.requests.push({
        seq: entry.requests.length + 1,
        at: iso(at),
        method: "GET",
        // A probe of the catalog, refused: its target is the catalog's text, and the row says how much was asked.
        target: targetOf(entry.script[Math.min(campaign.requests_sent, entry.script.length - 1)].check),
        outcome: "refused",
        reason,
        status: null,
        failure: null,
        bytes: 0,
        ms: 0,
        // A bucket, as the API keeps it: at most 256 characters.
        asked_chars: 256,
      });
      campaign.requests_refused += 1;
    }
    end(entry, reason, "stopped", at, started);
  }

  if (seed) {
    const start = now();
    const rules = currentRules();
    const shop = targets().find((target) => target.host === "shop.acme-shop.io");
    const api = targets().find((target) => target.host === "api.acme-shop.io");
    if (rules && shop && api) {
      seeding = true;
      const past = (target, intensity, daysAgo) => {
        const created = start - daysAgo * DAY_MS;
        const entry = insert(target, rules, intensity, created);
        return { entry, created };
      };
      const done = past(shop, "safe-active", 5);
      done.entry.campaign.status = "running";
      done.entry.campaign.started_at = iso(done.created + QUEUED_MS);
      for (let index = 0; index < done.entry.script.length; index++) {
        step(done.entry, index, done.created + QUEUED_MS + index * 1000);
      }
      end(done.entry, "checks_complete", "completed", done.created + QUEUED_MS + done.entry.script.length * 1000, true);

      const halted = past(api, "passive", 4);
      halted.entry.campaign.status = "running";
      halted.entry.campaign.started_at = iso(halted.created + QUEUED_MS);
      step(halted.entry, 0, halted.created + QUEUED_MS);
      halted.entry.campaign.stop = {
        requested_at: iso(halted.created + QUEUED_MS + 1500),
        requested_by: keyId,
        reason: "The staging system is being deployed to",
      };
      stopEntry(halted.entry, "owner_stop", halted.created + QUEUED_MS + 1500);

      const never = past(shop, "passive", 3);
      end(never.entry, "target_not_reachable", "refused", never.created + QUEUED_MS, false);

      const limited = past(api, "safe-active", 2);
      limited.entry.campaign.status = "running";
      limited.entry.campaign.started_at = iso(limited.created + QUEUED_MS);
      for (let index = 0; index < 3; index++) step(limited.entry, index, limited.created + QUEUED_MS + index * 1000);
      end(limited.entry, "target_rate_limited", "failed", limited.created + QUEUED_MS + 3000, true);
      seeding = false;
    }
  }

  function create(body, reason) {
    const parsed = CreateCampaignRequestSchema.safeParse(body);
    if (!parsed.success) return invalid(toProblemErrors(parsed.error));
    if (reason === undefined) return REASON_REQUIRED();
    if (!control.enabled) return UNAVAILABLE.disabled();
    if (control.killed) return UNAVAILABLE.stopped();
    if (control.isSuspended(organizationId)) return UNAVAILABLE.suspended();
    const at = now();
    const request = parsed.data;
    const target = targets().find((one) => one.id === request.target_id);
    if (!target) return invalid([{ path: "target_id", message: "Must be a target of the Organization." }]);
    if (request.confirm !== campaignAuthorisationPhrase(target.host)) {
      return invalid([
        { path: "confirm", message: "Type the exact phrase: I authorise a test of <the target's host>." },
      ]);
    }
    const verifiedAt = target.verified_at === null ? Number.NaN : Date.parse(target.verified_at);
    if (target.status !== "verified" || !(verifiedAt <= at + SKEW_MS && at - verifiedAt <= FRESHNESS_MS)) {
      return conflict("campaign-target-not-verified");
    }
    const rules = currentRules();
    if (rules === null) return conflict("campaign-no-rules");
    if (!rules.scope.includes(target.id)) return conflict("campaign-target-out-of-scope");
    if (!(at - Date.parse(rules.signed_at) <= CAMPAIGN_LIMITS.roeMaxAgeDays * DAY_MS)) {
      return conflict("campaign-rules-too-old");
    }
    if (INTENSITIES.indexOf(request.intensity) > INTENSITIES.indexOf(rules.intensity)) {
      return conflict("campaign-intensity-exceeds");
    }
    if (isPathExcluded(VERIFICATION_FILE_PATH, rules.exclusions)) {
      return conflict("campaign-verification-path-excluded");
    }
    if (active().length > 0) return conflict("campaign-active");
    const recent = entries
      .map(({ campaign }) => ({ created: Date.parse(campaign.created_at), targetId: campaign.target_id }))
      .filter(({ created }) => at - created < DAY_MS);
    const ofTarget = recent.filter(({ targetId }) => targetId === target.id);
    const waits = [];
    if (recent.length >= CAMPAIGN_LIMITS.createdPerOrganizationPerDay) {
      waits.push(Math.min(...recent.map(({ created }) => created)) + DAY_MS - at);
    }
    if (ofTarget.length >= CAMPAIGN_LIMITS.createdPerTargetPerDay) {
      waits.push(Math.min(...ofTarget.map(({ created }) => created)) + DAY_MS - at);
    }
    if (waits.length > 0) return tooMany(Math.max(1, Math.ceil(Math.max(...waits) / 1000)));
    const { campaign } = insert(target, rules, request.intensity, at);
    write({
      actor: "admin_key",
      action: "campaign.create",
      target: { kind: "campaign", id: campaign.id },
      reason,
      summary: `Queued a ${request.intensity} Campaign against the target ${target.id} under the Rules of Engagement ${rules.id}. The creator declared the target a staging system and typed the authorisation phrase. Engine: stand-in 1.`,
    });
    return ok({ campaign: { ...campaign } }, 202);
  }

  function stop(entry, reason) {
    if (reason === undefined) return REASON_REQUIRED();
    advance(entry);
    const { campaign } = entry;
    if (campaign.status !== "queued" && campaign.status !== "running") return conflict("campaign-ended");
    const at = now();
    campaign.stop = { requested_at: iso(at), requested_by: keyId, reason };
    write({
      actor: "admin_key",
      action: "campaign.stop",
      target: { kind: "campaign", id: campaign.id },
      reason,
      summary: `Stopped the Campaign while it was ${campaign.status}. A stop is final.`,
    });
    stopEntry(entry, "owner_stop", at);
    return ok({ campaign: { ...campaign } });
  }

  function handle(method, path, body, reason) {
    if (path === "/v1/campaigns") {
      if (method === "POST") return create(body, reason);
      if (method !== "GET") return null;
      for (const entry of entries) advance(entry);
      const newest = [...entries].reverse().slice(0, CAMPAIGN_LIMITS.listed);
      return ok({
        campaigns: newest.map(({ campaign }) => ({ ...campaign })),
        enabled: control.enabled,
        blocked: control.killed
          ? "operator_kill"
          : control.isSuspended(organizationId)
            ? "organization_suspended"
            : null,
        notice: CAMPAIGN_STAND_IN_NOTICE,
      });
    }
    const one = /^\/v1\/campaigns\/([^/]+)(?:\/(requests|findings|report|stop))?$/.exec(path);
    if (!one) return null;
    const entry = ID_PATTERNS.cmp.test(one[1]) ? entries.find(({ campaign }) => campaign.id === one[1]) : undefined;
    if (!entry) return NOT_FOUND();
    if (one[2] === "stop") return method === "POST" ? stop(entry, reason) : null;
    if (method !== "GET") return null;
    advance(entry);
    const campaign = { ...entry.campaign };
    const findings = entry.findings.map((finding) => ({ ...finding, evidence: { ...finding.evidence } }));
    if (one[2] === undefined) return ok({ campaign });
    if (one[2] === "requests") return ok({ requests: entry.requests.map((row) => ({ ...row })) });
    if (one[2] === "findings") return ok({ findings, engine: campaign.engine, notice: campaign.notice });
    return ok({
      report: {
        campaign,
        engine: campaign.engine,
        notice: campaign.notice,
        summary: campaign.checks === null ? null : campaignChecksSentence(campaign.checks),
        checks: campaign.checks,
        findings,
        findings_dropped: campaign.findings_dropped,
        limits: [...CAMPAIGN_REPORT_LIMITS],
      },
    });
  }

  return {
    handle,
    /** How many Campaigns are queued or running now. */
    activeCount: () => active().length,
    /** The operator's stop of every active Campaign: one operator entry and the end of each. Answers how many. */
    operatorStop(endReason, operatorReason) {
      const at = now();
      const stopping = active();
      for (const entry of stopping) {
        write({
          actor: "operator",
          action: "campaign.operator_kill",
          target: { kind: "campaign", id: entry.campaign.id },
          reason: operatorReason,
          summary:
            endReason === "operator_kill"
              ? "The operator stopped all Campaigns: this Organization's Campaign was ended."
              : "The operator suspended this Organization's Campaigns: its Campaign was ended.",
        });
        stopEntry(entry, endReason, at);
      }
      return stopping.length;
    },
    /** One operator entry in this Organization's chain: its Campaigns were suspended, or the suspension lifted. */
    recordSuspension(suspended, operatorReason) {
      write({
        actor: "operator",
        action: suspended ? "campaign.operator_suspend" : "campaign.operator_resume",
        target: { kind: "organization", id: organizationId },
        reason: operatorReason,
        summary: suspended
          ? "The operator suspended this Organization's Campaigns: none can be created or started."
          : "The operator lifted the suspension of this Organization's Campaigns.",
      });
    },
  };
}

/**
 * The operator's routes of Campaigns: `GET /v1/ops/prove`, `POST …/kill`, `…/enable`,
 * `…/organizations/:id/suspend` and `…/resume`, each change with `{ reason }`. `stores()` gives the Campaign store of
 * every Organization (id → store); `isOrganization(id)` says whether the stub knows the Organization.
 */
export function createProveOperator({ token, control, stores, isOrganization, now = () => Date.now() }) {
  const expected = token ? digest(token) : undefined;
  const state = (stopped) => {
    let activeCount = 0;
    for (const store of stores().values()) activeCount += store.activeCount();
    return ok({
      enabled: control.enabled,
      killed: control.killed,
      killed_at: control.killedAt,
      suspended: control.suspendedList(),
      active: activeCount,
      stopped,
    });
  };
  return {
    /** The answer to `method path`, or null when it is not one of these routes. */
    handle(method, path, authorization, body) {
      if (!path.startsWith("/v1/ops/prove")) return null;
      const organization = /^\/v1\/ops\/prove\/organizations\/([^/]+)\/(suspend|resume)$/.exec(path);
      const change = path === "/v1/ops/prove/kill" || path === "/v1/ops/prove/enable" || organization !== null;
      if (!(method === "GET" && path === "/v1/ops/prove") && !(method === "POST" && change)) return null;
      if (expected === undefined) return NOT_FOUND();
      const presented = /^Bearer (\S+)$/i.exec(authorization ?? "")?.[1];
      if (presented === undefined || !timingSafeEqual(digest(presented), expected)) return UNAUTHORIZED();
      if (method === "GET") return state(0);
      const parsed = ProveOperatorRequestSchema.safeParse(body);
      if (!parsed.success) return invalid(toProblemErrors(parsed.error));
      const { reason } = parsed.data;
      if (path === "/v1/ops/prove/kill") {
        control.kill(now());
        let stopped = 0;
        for (const store of stores().values()) stopped += store.operatorStop("operator_kill", reason);
        return state(stopped);
      }
      if (path === "/v1/ops/prove/enable") {
        control.enable();
        return state(0);
      }
      const [, organizationId, verb] = organization;
      if (!ID_PATTERNS.org.test(organizationId)) return NOT_FOUND();
      const suspend = verb === "suspend";
      const known = isOrganization(organizationId);
      const changed = known && (suspend ? control.suspend(organizationId, now()) : control.resume(organizationId));
      let stopped = 0;
      if (changed) {
        const store = stores().get(organizationId);
        store?.recordSuspension(suspend, reason);
        if (suspend) stopped = store?.operatorStop("organization_suspended", reason) ?? 0;
      } else if (suspend !== control.isSuspended(organizationId)) {
        // Nothing changed and it is not so already: there is no such Organization.
        return NOT_FOUND();
      }
      return state(stopped);
    },
  };
}
