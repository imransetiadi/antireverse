// Reverse Assessments of the stand-in API (slice 12a): plausible, made-up runs in the shape of the protocol's
// `AssessmentSchema` (assessment.ts), per Organization, in memory. A test parses every answer with the protocol.
// Only node:crypto is imported, so that the test can load this module as it is.
//
// Seed of each Organization's App, Builds newest first:
//   newest  an inconclusive T1 run of the stand-in agent (W2 achieved through the Build's decoy key Canary, W3
//           and W4 not supported), and an older failed T1 run that kept its W2 result;
//   next    a scored, renormalised T2 run (W4 not attempted) and an older scored T1 run, both by a model agent,
//           so that the RRS meter can be looked at before 12b makes a score reachable;
//   oldest  a running T1 run.
// Every run keeps its artifact for 30 days after it finished (`artifact_kept_until`, null once deleted); the older
// run of the next Build has had its artifact deleted already.
// `POST …/assessments` takes the tier and, optionally, the artifact's files (nothing is decoded). Without files it
// reassesses the Build's kept artifact, or answers 409 `artifact-required` when none is kept. It answers 202 with a
// queued run, which runs 2 s after it was created and turns inconclusive 30 s later.

import { randomBytes } from "node:crypto";

const TIERS = ["T1", "T2", "T3"];
const OBJECTIVES = [
  ["W1", 15],
  ["W2", 20],
  ["W3", 25],
  ["W4", 20],
  ["W5", 20],
];
const NAMES = { W1: "Map", W2: "Secrets", W3: "Logic", W4: "Tamper", W5: "Replay" };
const REASONS = {
  not_supported: "not supported",
  refused: "refused",
  tool_failure: "tool failure",
  sandbox_error: "sandbox error",
  budget_exhausted_before_attempt: "budget exhausted before the attempt",
  no_inventory: "no route inventory",
};
const R_TENTHS = { achieved: { T1: 0, T2: 4, T3: 7 }, not_achieved: { T1: 4, T2: 7, T3: 10 } };
const QUEUED_MS = 2_000;
const RUN_MS = 30_000;
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const KEEP_MS = 30 * 24 * HOUR;

const STAND_IN = { agent: { name: "stand-in", version: "0.1.0" }, model: "stand-in", toolbelt: "0.1.0" };
const MODEL_AGENT = { agent: { name: "adversary", version: "0.2.0" }, model: "example-model-1", toolbelt: "0.1.0" };

const newId = () => `asm_${randomBytes(12).toString("hex")}`;
const iso = (ms) => new Date(ms).toISOString();

/** The score of a run as the protocol's `scoreAssessment` computes it: exact, half up, inconclusive over 20 %. */
function score(results, tier) {
  let excluded = 0;
  let attempted = 0;
  let weighted = 0;
  const missing = [];
  for (const [id, weight] of OBJECTIVES) {
    const result = results.find((one) => one.objective === id);
    if (result.result === "not_attempted") {
      excluded += weight;
      missing.push(`${id} ${NAMES[id]}: ${REASONS[result.reason]}`);
      continue;
    }
    attempted += weight;
    weighted += weight * (result.result === "achieved" ? R_TENTHS.achieved[result.tier] : R_TENTHS.not_achieved[tier]);
  }
  if (excluded > 20) {
    return {
      status: "inconclusive",
      rrs: null,
      renormalised: false,
      inconclusive_code: "excluded_over_limit",
      inconclusive_reason: `${excluded}% of the Objective weight was not attempted (${missing.join("; ")}); a score needs at most 20%.`,
    };
  }
  return {
    status: "scored",
    rrs: Math.floor((20 * weighted + attempted) / (2 * attempted)),
    renormalised: excluded > 0,
    inconclusive_code: null,
    inconclusive_reason: null,
  };
}

const notSupported = (objective) => ({
  objective,
  result: "not_attempted",
  reason: "not_supported",
  evidence: { summary: `${NAMES[objective]} is not assessed in this version.`, recovered: [], calls: [] },
});

/** What the stand-in agent finds on a Build: W2 through its decoy key Canary (or a leak), W3 and W4 unsupported. */
function standInResults(build) {
  const key = (build.canaries ?? []).find((canary) => canary.kind === "key");
  const secret = key
    ? {
        summary: `Found the decoy key ${key.id} as a string literal in ${build.artifacts?.[0]?.path ?? "the bundle"}.`,
        recovered: [{ kind: "canary", canary_id: key.id }],
      }
    : {
        summary: "Found a string the leak scan had reported, by its fingerprint.",
        recovered: [{ kind: "leak", rule: "aws-access-key", fingerprint: "9f2c4e7a1b3d5f60718293a4b5c6d7e8" }],
      };
  return [
    {
      objective: "W1",
      result: "not_achieved",
      cost: { calls: 41, seconds: 12.5 },
      evidence: {
        summary: "Extracted 5 path literals from fetch calls; 3 of the 8 registered routes matched (below 60 %).",
        recovered: [{ kind: "routes", matched: 3, submitted: 5, inventory: 8 }],
        calls: [2, 5, 9],
      },
    },
    {
      objective: "W2",
      result: "achieved",
      tier: "T1",
      cost: { calls: 12, seconds: 3.2 },
      evidence: { ...secret, calls: [1, 11] },
    },
    notSupported("W3"),
    notSupported("W4"),
    {
      objective: "W5",
      result: "not_achieved",
      cost: { calls: 63, seconds: 20.4 },
      evidence: {
        summary: "Replayed POST /api/checkout without a signature; the replica refused it.",
        recovered: [{ kind: "replay", status: 401 }],
        calls: [40, 41],
      },
    },
  ];
}

/** A model agent's T2 run: Map achieved within T2 limits, Tamper not attempted, the rest held. */
function modelResultsT2() {
  return [
    {
      objective: "W1",
      result: "achieved",
      tier: "T2",
      cost: { calls: 412, seconds: 1830 },
      evidence: {
        summary: "Recovered 14 route templates from the router table; 7 of the 8 registered routes matched.",
        recovered: [{ kind: "routes", matched: 7, submitted: 14, inventory: 8 }],
        calls: [118, 240, 411],
      },
    },
    {
      objective: "W2",
      result: "not_achieved",
      cost: { calls: 1500, seconds: 6900 },
      evidence: { summary: "No planted Canary and no leak scan finding was submitted.", recovered: [], calls: [] },
    },
    {
      objective: "W3",
      result: "not_achieved",
      cost: { calls: 1500, seconds: 6900 },
      evidence: {
        summary: "The lifted price function gave different answers from the reference.",
        recovered: [],
        calls: [902],
      },
    },
    {
      objective: "W4",
      result: "not_attempted",
      reason: "tool_failure",
      evidence: { summary: "The code runner failed before the tamper attempt.", recovered: [], calls: [1201] },
    },
    {
      objective: "W5",
      result: "not_achieved",
      cost: { calls: 1500, seconds: 6900 },
      evidence: {
        summary: "Replayed POST /api/checkout with a copied signature; the replica refused it.",
        recovered: [{ kind: "replay", status: 403 }],
        calls: [1310, 1311],
      },
    },
  ];
}

/** A model agent's earlier T1 run, before the strings were encrypted: Map and Secrets achieved within T1 limits. */
function modelResultsT1(build) {
  const key = (build.canaries ?? []).find((canary) => canary.kind === "key");
  return [
    {
      objective: "W1",
      result: "achieved",
      tier: "T1",
      cost: { calls: 88, seconds: 410 },
      evidence: {
        summary: "Extracted 9 path literals; 6 of the 8 registered routes matched.",
        recovered: [{ kind: "routes", matched: 6, submitted: 9, inventory: 8 }],
        calls: [12, 40, 87],
      },
    },
    {
      objective: "W2",
      result: "achieved",
      tier: "T1",
      cost: { calls: 20, seconds: 61 },
      evidence: key
        ? {
            summary: `Found the decoy key ${key.id} in a configuration object.`,
            recovered: [{ kind: "canary", canary_id: key.id }],
            calls: [19],
          }
        : { summary: "Found a string the leak scan had reported.", recovered: [], calls: [19] },
    },
    ...["W3", "W4", "W5"].map((objective) => ({
      objective,
      result: "not_achieved",
      cost: { calls: 150, seconds: 880 },
      evidence: {
        summary: `The ${NAMES[objective]} Objective was not reached within the budget.`,
        recovered: [],
        calls: [],
      },
    })),
  ];
}

/**
 * The Assessments of the stand-in API. `seed(organizationId, builds)` plants the seed on an App's Builds (newest
 * first); `handle(organizationId, method, path, body, findBuild)` answers a request under
 * `/v1/apps/:appId/builds/:buildId/assessments` or `/v1/assessments/:id`, or returns null for any other path.
 * `findBuild(appId, buildId)` gives the Organization's Build or null.
 */
export function createAssessmentStore({ now = () => Date.now() } = {}) {
  /** @type {Map<string, { organizationId: string, record: object }>} */
  const records = new Map();

  function add(organizationId, record) {
    records.set(record.id, { organizationId, record });
    return record;
  }

  /** A record as the API returns it at `now()`: an artifact past its date is deleted, and a requested run moves from
   * queued to running to finished. */
  function view(stored) {
    const expired = stored.artifact_kept_until !== null && Date.parse(stored.artifact_kept_until) <= now();
    const record = expired ? { ...stored, artifact_kept_until: null } : stored;
    if (!record.lifecycle) return record;
    const created = Date.parse(record.created_at);
    const at = now();
    const base = { ...record };
    delete base.lifecycle;
    delete base.build;
    if (at < created + QUEUED_MS) return base;
    if (at < created + QUEUED_MS + RUN_MS) return { ...base, status: "running", started_at: iso(created + QUEUED_MS) };
    const results = standInResults(record.build);
    return {
      ...base,
      ...score(results, record.tier),
      results,
      started_at: iso(created + QUEUED_MS),
      finished_at: iso(created + QUEUED_MS + RUN_MS),
      artifact_kept_until: record.artifact_kept_until === null ? null : iso(created + QUEUED_MS + RUN_MS + KEEP_MS),
    };
  }

  function finished(build, tier, scope, results, createdMs, runMs) {
    return {
      id: newId(),
      build_id: build.build_id,
      app_id: build.app_id,
      ...(build.environment ? { environment: build.environment } : {}),
      tier,
      ...score(results, tier),
      results,
      scope: { ...scope, tier },
      created_at: iso(createdMs),
      started_at: iso(createdMs + 1_000),
      finished_at: iso(createdMs + 1_000 + runMs),
      failure_reason: null,
      artifact_kept_until: iso(createdMs + 1_000 + runMs + KEEP_MS),
    };
  }

  function empty(build, tier, scope, createdMs) {
    return {
      id: newId(),
      build_id: build.build_id,
      app_id: build.app_id,
      ...(build.environment ? { environment: build.environment } : {}),
      tier,
      status: "queued",
      results: [],
      rrs: null,
      inconclusive_reason: null,
      inconclusive_code: null,
      renormalised: false,
      scope: { ...scope, tier },
      created_at: iso(createdMs),
      started_at: null,
      finished_at: null,
      failure_reason: null,
      // The run's own time is added once it finished; until then, 30 days from its creation.
      artifact_kept_until: iso(createdMs + KEEP_MS),
    };
  }

  function seed(organizationId, builds) {
    const at = now();
    const [newest, next, oldest] = builds;
    if (newest) {
      add(organizationId, {
        ...empty(newest, "T1", STAND_IN, at - 3 * HOUR),
        status: "failed",
        started_at: iso(at - 3 * HOUR + 1_000),
        finished_at: iso(at - 3 * HOUR + 41_000),
        failure_reason: "The code runner stopped: the worker ran out of memory.",
        artifact_kept_until: iso(at - 3 * HOUR + 41_000 + KEEP_MS),
        // A failed run keeps the results reached before the failure (amendment A1), never a score.
        results: standInResults(newest).slice(1, 2),
      });
      add(organizationId, finished(newest, "T1", STAND_IN, standInResults(newest), at - 40 * MINUTE, 118_000));
    }
    if (next) {
      add(organizationId, {
        ...finished(next, "T1", MODEL_AGENT, modelResultsT1(next), at - 30 * HOUR, 890_000),
        artifact_kept_until: null,
      });
      add(organizationId, finished(next, "T2", MODEL_AGENT, modelResultsT2(), at - 25 * HOUR, 6_950_000));
    }
    if (oldest) {
      add(organizationId, {
        ...empty(oldest, "T1", STAND_IN, at - 2 * MINUTE),
        status: "running",
        started_at: iso(at - MINUTE),
      });
    }
  }

  const answer = (status, body) => ({ status, body });
  const problem = (status, title, extra = {}) => answer(status, { type: "about:blank", title, status, ...extra });

  function listFor(organizationId, buildId) {
    return [...records.values()]
      .filter((entry) => entry.organizationId === organizationId && entry.record.build_id === buildId)
      .map((entry) => view(entry.record))
      .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
      .slice(0, 50);
  }

  function handle(organizationId, method, path, body, findBuild) {
    const one = /^\/v1\/assessments\/([^/]+)$/.exec(path);
    if (one) {
      if (method !== "GET") return problem(405, "Method Not Allowed");
      const entry = records.get(one[1]);
      if (!entry || entry.organizationId !== organizationId) return problem(404, "Not Found");
      return answer(200, { assessment: view(entry.record) });
    }
    const match = /^\/v1\/apps\/([^/]+)\/builds\/([^/]+)\/assessments$/.exec(path);
    if (!match) return null;
    const build = findBuild(match[1], match[2]);
    if (!build) return problem(404, "Not Found");
    if (method === "GET") return answer(200, { assessments: listFor(organizationId, build.build_id) });
    if (method !== "POST") return problem(405, "Method Not Allowed");
    const errors = [];
    if (!TIERS.includes(body?.tier)) errors.push({ path: "tier", message: "Invalid option" });
    const files = body?.files;
    if (files === undefined) {
      // No files: the Build's most recent kept artifact is assessed again, if there is one.
      const kept = listFor(organizationId, build.build_id).some((one) => one.artifact_kept_until !== null);
      if (errors.length === 0 && !kept) {
        return problem(409, "Conflict", {
          detail: "No uploaded artifact is kept for this Build.",
          reason: "artifact-required",
        });
      }
    } else if (!Array.isArray(files) || files.length === 0) {
      errors.push({ path: "files", message: "Must list the artifact's files" });
    } else if (files.some((file) => typeof file?.path !== "string" || typeof file?.base64 !== "string")) {
      errors.push({ path: "files", message: "Each file has a path and base64 content" });
    }
    if (errors.length > 0) return problem(400, "Bad Request", { errors });
    const record = add(organizationId, { ...empty(build, body.tier, STAND_IN, now()), lifecycle: true, build });
    return answer(202, { assessment: view(record) });
  }

  return { seed, handle };
}
