// A stand-in for the Airverse API, for looking at the Console without the real API.
// It implements the responses of contracts C2 and P2 in memory, with well-formed identifiers and keys, a
// live stream that emits one synthetic Event per second for every App, and Policies: every new App starts
// with two published versions in development, one in production and none in staging. Slice 06: the first
// App of an Organization gets three Incidents (open, acknowledged, resolved) with Detections and evidence,
// and every Organization starts with a webhook and a Slack alert channel. A test alert to a host under
// example.com fails with 503, to a host under .invalid gets no response, and is delivered anywhere else.
// Slice 06b: every Organization also has an email channel with a confirmed and a pending recipient; resend, the
// daily cap, the public confirmation and `smtp_configured` work as in the API (stub-alerts.mjs, checked by a test
// against the protocol). No mail is sent: `GET /__stub/confirmation-link/<recipient id>` (with the admin key) gives
// the link of a pending recipient's latest confirmation mail. `AR_STUB_SMTP=off` answers as an API without SMTP.
// Slice 07: the newest Build has a clean leak scan and three Canaries, the next one a scan with two suppressed
// findings and three Canaries, the oldest neither; the first App also gets an open "Canary used" Incident
// naming the newest Build's decoy key. Canaries are returned as id and kind only, never a value.
// Slice 09: every Incident lists the Actors of its evidence (keyed hashes, never an address) and its blocks;
// blocks can be created from an Incident (Actor or network, 15 min / 1 h / 24 h), lifted, and listed; the
// Organization has a never-block list. Each 409 carries the API's `reason`: incident-resolved, actor-unknown,
// prefix-allowlisted (IPv4 overlap only in this stub), containment-limit (150 active per App and
// Environment), containment-ended, containment-not-applicable (slice 10), allowlist-duplicate, allowlist-limit.
// Slice 10: the newest Build has a Clone Beacon with two allowed origins (origins only, never the token); the
// first App also gets an open "Clone detected" Incident for https://clone.example naming that Build, with two
// Detections — one reporter network known, one unknown. Every Incident and Detection carries `origin`.
// Slice 19: the newest Build lists 412 components, the next 398, the oldest none. Every App has Findings in
// every state — open (build and runtime), fixed, ignored, withdrawn (D-060) — with severities critical, high,
// medium, low and unknown, against six synthetic advisories (one without a fix, one rated by nothing); the first App also gets
// an open "Vulnerable component" Incident for the high build Finding's advisory. Ignore (reason 1–200, until in
// the future and at most 90 days ahead) and reopen work as in the API, as do the list filters advisory_id (id or
// alias) and build_id; an ignore past its date is open again.
// Every Incident carries `advisory_id`.
// Slice 20: a three-entry virtual patch catalog. A patch is active for an App and Environment with an open or
// ignored Finding for one of its advisories in its package (so the high build Finding's patch is active, the
// ignored one's too, and the third never); the ignored Finding's patch is reported as not shipped (bundle
// budget). Modes are kept per App, Environment and patch; enforcing needs `confirm` equal to the patch id (400
// otherwise). Every fifth streamed Event names an active patch, alternating body checked and unchecked, and the
// first App also gets an open "Exploit attempt" Incident for the high Finding's advisory.
// Slice 08: a Rule may carry a limit (action throttle; requests 1–100,000 per window of 1–3,600 s, per ip or
// device, counting requests or failures; never beside `requires`), checked as the API checks it. The current
// development Policy has a "Login protection" limit Rule in monitor mode and the production Policy an enforced
// "API rate" limit Rule. Every eighth streamed Event is a throttle decision of the App's limit Rule (429 on the
// Rule's pattern when enforced; the response unchanged in monitor), and the first App also gets an open
// "Credential stuffing" Incident whose evidence mixes failed logins (401) and throttled requests (429).
// Slice 11: `POST /v1/apps/:appId/policy/simulate` answers with made-up figures derived from each Rule's pattern
// (stub-simulation.mjs, whose shape a test checks against the protocol); it refuses what a publish refuses (400)
// and a seventh simulation of an Organization within a minute (429 with Retry-After). Nothing is stored.
// Slice 14: every Organization has Verified Targets in each status and two signed Rules of Engagement versions;
// targets can be added, verified (the outcome follows the host's first label, see stub-prove.mjs) and removed
// (409 while in the current scope), versions signed with the exact phrase, and tests checked by authorize.
// Verification tokens are never logged.
// Slice 12a: every App's Builds carry Reverse Assessments (stub-assessments.mjs, checked by a test against the
// protocol): the newest an inconclusive stand-in run and a failed one, the next two scored runs, the oldest a running
// one. `POST …/builds/:buildId/assessments` takes the tier (and optionally the files) and queues a stand-in run.
// Slice 12b: the newest Build designates two protected functions (`logic_count` 2), and its latest run is scored.
// Channel URLs, signing secrets and confirmation tokens are never logged; URLs and secrets never returned after
// creation. The server is not used by any test.
//
//   PORT=39201 node apps/console/scripts/stub-api.mjs
//   AR_API_URL=http://127.0.0.1:39201 PORT=39200 npm run dev -w @antireverse/console
//
// `POST /__stub/outage?ms=6000` simulates an API restart. It never logs a key.
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import http from "node:http";
import { createAlertStore } from "./stub-alerts.mjs";
import { createAssessmentStore } from "./stub-assessments.mjs";
import { createProveStore } from "./stub-prove.mjs";
import { stubSimulation } from "./stub-simulation.mjs";

const port = Number(process.env.PORT ?? 39201);
const host = process.env.HOST ?? "127.0.0.1";

/** @type {Map<string, { id: string, name: string, created_at: string }>} admin key → Organization */
const organizations = new Map();
/** @type {Map<string, Array<{ id: string, name: string, created_at: string, environment: string }>>} Organization id → Apps, newest first */
const apps = new Map();
/** @type {Map<string, object[]>} App id → Events, newest first */
const events = new Map();
/** @type {Set<http.ServerResponse>} */
const streams = new Set();
/** @type {Map<string, Array<{ version: number, published_at: string, rules: object[] }>>} "<App id>/<Environment>" → versions, oldest first */
const policies = new Map();
/** @type {Map<string, object[]>} App id → Builds, newest first */
const builds = new Map();
/** @type {Map<string, Array<{ incident: object, detections: object[], evidence: object[] }>>} Organization id → Incidents */
const incidents = new Map();
/** Alert channels of every Organization (slices 06 and 06b): stub-alerts.mjs. `AR_STUB_SMTP=off` answers as an API
 * without SMTP settings. */
const alerts = createAlertStore({ smtpConfigured: process.env.AR_STUB_SMTP !== "off" });
/** @type {Map<string, string>} admin key → its key id (`created_by` of blocks and ranges) */
const adminKeyIds = new Map();
/** @type {Map<string, object[]>} Organization id → blocks without their computed status, newest first */
const containments = new Map();
/** @type {Map<string, object[]>} Organization id → never-block ranges, oldest first */
const allowlists = new Map();
/** @type {Map<string, object[]>} Organization id → Findings as stored, newest first */
const findings = new Map();
/** @type {Map<string, number[]>} Organization id → when its simulations of the last minute ran (ms) */
const simulations = new Map();
const SIMULATIONS_PER_MINUTE = 6;
/** @type {Map<string, ReturnType<typeof createProveStore>>} Organization id → its Prove state (slice 14) */
const proveStores = new Map();
/** Reverse Assessments of every Organization (slice 12a): stub-assessments.mjs. */
const assessments = createAssessmentStore();

// The signing key of contract P2: a real Ed25519 key pair, of which only the public half is ever served.
const publicKeyRaw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x, "base64url");
const signingKey = {
  key_id: createHash("sha256").update(publicKeyRaw).digest("hex").slice(0, 16),
  algorithm: "Ed25519",
  public_key: publicKeyRaw.toString("base64url"),
};

const newId = (prefix) => `${prefix}_${randomBytes(12).toString("hex")}`;
const TAGS = { production: "prod", staging: "stg", development: "dev" };

function newKey(scheme) {
  const secret = randomBytes(32).toString("base64url");
  const key = scheme + secret;
  return { key, prefix: scheme + secret.slice(0, 6), last4: key.slice(-4) };
}

function uuidv7(ms) {
  const time = ms.toString(16).padStart(12, "0");
  const random = randomBytes(10).toString("hex");
  return `${time.slice(0, 8)}-${time.slice(8)}-7${random.slice(0, 3)}-8${random.slice(3, 6)}-${random.slice(6, 18)}`;
}

const ROUTES = [
  ["GET", "/api/products/:id", 200],
  ["GET", "/", 200],
  ["POST", "/api/login", 401],
  ["GET", "(unmatched)", 404],
  ["GET", "/api/orders/:orderId/items/:itemId", 500],
];

const PATH_PATTERN = /^(?=.{1,256}$)(?:\/|(?:\/(?:[A-Za-z0-9._~-]+|\*))*\/(?:[A-Za-z0-9._~-]+|\*|\*\*))$/;
const policyKey = (appId, environment) => `${appId}/${environment}`;
const currentPolicy = (appId, environment) => {
  const latest = (policies.get(policyKey(appId, environment)) ?? []).at(-1);
  return {
    app_id: appId,
    environment,
    version: latest?.version ?? 0,
    rules: latest?.rules ?? [],
    published_at: latest?.published_at ?? null,
  };
};

function publish(appId, environment, rules, at = new Date()) {
  const versions = policies.get(policyKey(appId, environment)) ?? [];
  const stored = rules.map((rule) => ({ ...rule, id: rule.id ?? newId("rul") }));
  versions.push({ version: versions.length + 1, published_at: at.toISOString(), rules: stored });
  policies.set(policyKey(appId, environment), versions);
  return currentPolicy(appId, environment);
}

/** The limit of a Rule as stored (`count` defaults to requests), or null when there is none or it is refused. */
function checkLimit(limit, at) {
  if (limit === undefined) return null;
  if (limit === null || typeof limit !== "object") {
    at("limit", "Expected an object");
    return null;
  }
  const whole = (value, max) => Number.isInteger(value) && value >= 1 && value <= max;
  const count = limit.count ?? "requests";
  let ok = true;
  const refuse = (member, message) => {
    ok = false;
    at(`limit.${member}`, message);
  };
  if (!whole(limit.requests, 100_000)) refuse("requests", "Expected a whole number from 1 to 100000");
  if (!whole(limit.window_s, 3_600)) refuse("window_s", "Expected a whole number from 1 to 3600");
  if (limit.key !== "ip" && limit.key !== "device") refuse("key", "Invalid option");
  if (count !== "requests" && count !== "failures") refuse("count", "Invalid option");
  return ok ? { requests: limit.requests, window_s: limit.window_s, key: limit.key, count } : null;
}

/** The problems of a publish request as `errors[]`, or the Rules ready to store. */
function checkRules(body) {
  if (!Array.isArray(body?.rules)) return { errors: [{ path: "rules", message: "Expected an array" }] };
  if (body.rules.length > 50) return { errors: [{ path: "rules", message: "Too big: at most 50 Rules" }] };
  const errors = [];
  const rules = body.rules.map((rule, index) => {
    const at = (field, message) => errors.push({ path: `rules.${index}.${field}`, message });
    const name = typeof rule?.name === "string" ? rule.name.trim() : "";
    const methods = rule?.methods ?? [];
    const mode = rule?.mode ?? "monitor";
    if (rule?.id !== undefined && !/^rul_[0-9a-f]{24}$/.test(rule.id)) at("id", "Invalid identifier");
    if (name.length < 1 || name.length > 80) at("name", "Invalid name");
    if (typeof rule?.path !== "string" || !PATH_PATTERN.test(rule.path)) at("path", "Must be a path pattern");
    if (!Array.isArray(methods) || methods.length > 8) at("methods", "Invalid methods");
    else {
      methods.forEach((method, n) => {
        if (typeof method !== "string" || !/^[A-Z-]{1,16}$/.test(method)) at(`methods.${n}`, "Invalid method");
      });
    }
    // Slice 08: a limit makes the action throttle, and the reverse; without an action a limit implies throttle.
    const limit = checkLimit(rule?.limit, at);
    const action = rule?.action ?? (limit ? "throttle" : "block");
    if (action !== "block" && action !== "throttle") at("action", "Invalid option");
    else if (limit && action !== "throttle") at("action", "A Rule with a limit must have the action throttle.");
    else if (!limit && action === "throttle" && rule?.limit === undefined)
      at("limit", "A Rule with the action throttle must have a limit.");
    if (limit && rule?.requires !== undefined) at("requires", "A Rule must not have both a requirement and a limit.");
    if (mode !== "monitor" && mode !== "enforce") at("mode", "Invalid option");
    else if (mode === "enforce" && rule?.path === "/**")
      at("mode", "A Rule on /** in Enforce mode would block every request");
    // Slice 04: the one requirement a Rule may carry; absent means none.
    if (rule?.requires !== undefined && rule.requires !== "signature") at("requires", "Invalid option");
    const stored = { id: rule?.id, name, path: rule?.path, methods, action, mode };
    if (limit) return { ...stored, limit };
    return rule?.requires === "signature" ? { ...stored, requires: "signature" } : stored;
  });
  return errors.length > 0 ? { errors } : { rules };
}

/** Like the API: an Enforce Rule whose first segment is a wildcard needs `allow_broad: true`. */
function broadErrors(rules, allowBroad) {
  if (allowBroad === true) return [];
  return rules.flatMap((rule, index) => {
    const first = String(rule.path).split("/")[1];
    const broad = rule.mode === "enforce" && rule.path !== "/**" && (first === "*" || first === "**");
    return broad ? [{ path: `rules.${index}.mode`, message: "Broad pattern: send allow_broad: true" }] : [];
  });
}

/**
 * Two versions in development, one in production, none in staging: every state of the Policy screen. The current
 * development version has a Rule that requires a signed request and a limit Rule in monitor mode (the Login
 * protection preset); production has an enforced limit Rule.
 */
function seedPolicies(appId) {
  const hour = 3_600_000;
  const admin = { name: "Admin area", path: "/api/admin/**", methods: [], action: "block", mode: "monitor" };
  const exports = {
    name: "User export",
    path: "/api/users/*/export",
    methods: ["GET", "POST"],
    action: "block",
    mode: "monitor",
  };
  // Slice 04: a Rule that blocks checkout requests without a valid signature.
  const checkout = {
    name: "Checkout",
    path: "/api/checkout",
    methods: ["POST"],
    action: "block",
    mode: "monitor",
    requires: "signature",
  };
  // Slice 08: what the Login protection preset fills in, on the stub's login route.
  const login = {
    name: "Login protection",
    path: "/api/login",
    methods: ["POST"],
    action: "throttle",
    mode: "monitor",
    limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
  };
  const rate = {
    name: "API rate",
    path: "/api/**",
    methods: [],
    action: "throttle",
    mode: "enforce",
    limit: { requests: 100, window_s: 60, key: "device", count: "requests" },
  };
  const first = publish(appId, "development", [admin], new Date(Date.now() - 2 * hour));
  publish(
    appId,
    "development",
    [{ ...first.rules[0], mode: "enforce" }, exports, checkout, login],
    new Date(Date.now() - hour),
  );
  publish(appId, "production", [{ ...admin, mode: "enforce" }, rate], new Date(Date.now() - hour));
}

const sha256Hex = (value) => createHash("sha256").update(value).digest("hex");

/** One Build Manifest as the API returns it (contract P1/P2), with deterministic-looking digests. */
function makeBuild(app, spec) {
  const created = new Date(Date.now() - spec.createdOffsetMs);
  const artifacts = spec.artifactPaths.map((path, index) => ({
    path,
    sha256: sha256Hex(`${app.id}:${spec.version}:${path}:${index}`),
    bytes: 1024 * (index + 1) + spec.version.length,
  }));
  return {
    format: 1,
    build_id: newId("bld"),
    app_id: app.id,
    environment: app.environment,
    version: spec.version,
    profile: spec.profile,
    seed_id: randomBytes(8).toString("hex"),
    artifacts,
    transform: spec.transform,
    costs: spec.costs,
    equivalence: spec.equivalence,
    created_at: created.toISOString(),
    registered_at: new Date(created.getTime() + 1_000).toISOString(),
    ...(spec.leakScan ? { leak_scan: spec.leakScan } : {}),
    ...(spec.canaries ? { canaries: makeCanaries() } : {}),
    ...(spec.beacon ? { beacon: { origins: spec.beacon } } : {}),
    // Slice 12b: protected functions designated with `harden --logic`, in summary only.
    ...(spec.logic ? { logic_digest: sha256Hex(`${app.id}:${spec.version}:logic`), logic_count: spec.logic } : {}),
    ...(spec.components
      ? { component_count: spec.components, components_digest: sha256Hex(`${app.id}:${spec.version}:components`) }
      : {}),
  };
}

/** The Canaries of one Build as the API returns them (slice 07, contract P3): one decoy key, two decoy routes. */
function makeCanaries() {
  return [
    { id: newId("cny"), kind: "key" },
    { id: newId("cny"), kind: "route" },
    { id: newId("cny"), kind: "route" },
  ];
}

/** Three Builds per App, newest first: within budget, over budget (both costs), and a light run-null/skipped one. */
function seedBuilds(app) {
  const hour = 3_600_000;
  builds.set(app.id, [
    makeBuild(app, {
      version: "1.4.0",
      profile: "balanced",
      costs: { size_overhead_pct: 12.5, run_overhead_pct: 3.2 },
      equivalence: "passed",
      transform: { mangled: 42, strings_encrypted: 12, files_mangle_only: 1, integrity: false },
      artifactPaths: ["dist/index.js", "dist/vendor.js"],
      createdOffsetMs: 3 * hour,
      leakScan: { status: "clean", suppressed: 0 },
      canaries: true,
      beacon: ["https://shop.example", "https://www.shop.example"],
      components: 412,
      logic: 2,
    }),
    makeBuild(app, {
      version: "1.3.0",
      profile: "balanced",
      costs: { size_overhead_pct: 41.8, run_overhead_pct: 18.4 },
      equivalence: "passed",
      transform: { mangled: 51, strings_encrypted: 0, files_mangle_only: 3, integrity: true },
      artifactPaths: ["dist/index.js"],
      createdOffsetMs: 26 * hour,
      leakScan: { status: "suppressed", suppressed: 2 },
      canaries: true,
      components: 398,
    }),
    makeBuild(app, {
      version: "1.2.0",
      profile: "light",
      costs: { size_overhead_pct: 4.1, run_overhead_pct: null },
      equivalence: "skipped",
      transform: { mangled: 33, strings_encrypted: 0, files_mangle_only: 0, integrity: false },
      artifactPaths: ["dist/index.js"],
      createdOffsetMs: 72 * hour,
    }),
  ]);
}

/** The Decision the stub's Policy would take: the Rule's pattern and 403 when it blocks, as Shield reports it. */
function decide(app, n, route, status) {
  const policy = currentPolicy(app.id, app.environment);
  const allow = {
    action: "allow",
    mode: policy.version === 0 ? "monitor" : "enforce",
    rule_id: null,
    policy_version: policy.version,
  };
  // Slice 08: every eighth request is over the limit of the Policy's limit Rule. Enforced, Shield answers 429
  // on the Rule's pattern; in monitor the response is unchanged and the Event records the throttle.
  const limited = policy.rules.find((rule) => rule.action === "throttle");
  if (limited && n % 8 === 6) {
    const decision = { action: "throttle", mode: limited.mode, rule_id: limited.id, policy_version: policy.version };
    const method = limited.methods[0] ?? "GET";
    return limited.mode === "enforce"
      ? { method, route: limited.path, status: 429, decision }
      : { method, route: limited.path, status: limited.limit.count === "failures" ? 401 : 200, decision };
  }
  const enforced = policy.rules.find((rule) => rule.mode === "enforce" && rule.action === "block");
  const monitored = policy.rules.find((rule) => rule.mode === "monitor" && rule.action === "block");
  if (enforced && n % 3 === 1) {
    const decision = { action: "block", mode: "enforce", rule_id: enforced.id, policy_version: policy.version };
    return { route: enforced.path, status: 403, decision };
  }
  if (monitored && n % 3 === 2) {
    return {
      route,
      status,
      decision: { action: "block", mode: "monitor", rule_id: monitored.id, policy_version: policy.version },
    };
  }
  return { route, status, decision: allow };
}

// The Guard attestation Shield verified for a request (slice 03): every status and verdict in turn, and an
// older Shield that does not report it (null). Verdicts and risks follow the verdict table of the protocol.
const ATTESTATIONS = [
  { status: "valid", verdict: "trusted", risk: 5 },
  { status: "missing", verdict: null, risk: null },
  { status: "valid", verdict: "suspect", risk: 70 },
  { status: "invalid", verdict: null, risk: null },
  { status: "valid", verdict: "hostile", risk: 100 },
  { status: "expired", verdict: null, risk: null },
  null,
];
const attestationFor = (n) => ATTESTATIONS[n % ATTESTATIONS.length];

// The request signature Shield verified (slice 04): every status with the body states the protocol allows, and an
// older Shield that does not report it (null). Nine entries against seven attestations, so the pairs vary.
const SIGNATURES = [
  { status: "valid", body: "checked" },
  { status: "missing", body: null },
  { status: "valid", body: "none" },
  { status: "invalid", body: "mismatch" },
  { status: "valid", body: "unchecked" },
  { status: "stale", body: "none" },
  { status: "replayed", body: "checked" },
  { status: "invalid", body: "unchecked" },
  null,
];
const signatureFor = (n) => SIGNATURES[n % SIGNATURES.length];

function makeEvent(organizationId, app, n) {
  const now = Date.now();
  const [templateMethod, template, templateStatus] = ROUTES[n % ROUTES.length];
  const decided = decide(app, n, template, templateStatus);
  const method = decided.method ?? templateMethod;
  // Every fifth Event matched an active, shipped virtual patch (slice 20).
  const patched = n % 5 === 3 ? patchDecision(organizationId, app, n, decided.decision.policy_version) : null;
  const { route, status, decision } = patched
    ? { route: "/api/search", status: patched.mode === "enforce" ? 403 : 200, decision: patched }
    : decided;
  const iso = new Date(now).toISOString();
  return {
    event_id: uuidv7(now),
    ts: iso,
    type: "request.decision",
    surface: "api",
    request: { method, route, status, latency_ms: n % 7 === 0 ? 1234.5 : (n % 5) + 0.4 },
    decision,
    actor: { ip_prefix: n % 4 === 0 ? null : "203.0.113.0/24" },
    signals: [],
    attestation: attestationFor(n),
    signature: signatureFor(n),
    organization_id: organizationId,
    app_id: app.id,
    environment: app.environment,
    received_at: iso,
  };
}

// ── Incidents (slice 06) ──────────────────────────────────────────────────────────────────────────────

const RULES = {
  "blocked-burst": { title: "Blocked burst", severity: "high", threshold: 20 },
  "failed-signin-burst": { title: "Failed sign-in burst", severity: "medium", threshold: 30 },
  "credential-stuffing": { title: "Credential stuffing", severity: "high", threshold: 50 },
  "canary-touched": { title: "Canary used", severity: "high", threshold: 1 },
  "clone-origin": { title: "Clone detected", severity: "high", threshold: 1 },
};

/** One stored Event of an Incident's evidence: what the rule counted, from the Incident's network. */
function evidenceEvent(organizationId, app, rule, prefix, at, canary, ipHash = null) {
  if (canary) {
    // A request that used the decoy key: Shield observed it (allowed) and added the Canary's signal, never the key.
    return {
      event_id: uuidv7(at),
      ts: new Date(at).toISOString(),
      type: "request.decision",
      surface: "api",
      request: { method: "GET", route: "/api/orders", status: 401, latency_ms: 2.1 },
      decision: { action: "allow", mode: "monitor", rule_id: null, policy_version: 2 },
      actor: { ip_prefix: prefix },
      signals: [{ id: `canary.touched:${canary.id}`, confidence: 1 }],
      attestation: { status: "missing", verdict: null, risk: null },
      signature: { status: "missing", body: null },
      organization_id: organizationId,
      app_id: app.id,
      environment: app.environment,
      received_at: new Date(at + 150).toISOString(),
    };
  }
  if (rule === "credential-stuffing") {
    // Slice 08: failed logins on the limit-protected route, and every third request refused by the limit Rule.
    const limited = currentPolicy(app.id, app.environment).rules.find((one) => one.action === "throttle");
    const step = Math.floor(at / 14_000);
    const throttled = step % 3 === 0;
    return {
      event_id: uuidv7(at),
      ts: new Date(at).toISOString(),
      type: "request.decision",
      surface: "api",
      request: {
        method: "POST",
        route: limited?.path ?? "/api/login",
        status: throttled ? 429 : 401,
        latency_ms: throttled ? 0.4 : 38.7,
      },
      decision: throttled
        ? { action: "throttle", mode: "enforce", rule_id: limited?.id ?? newId("rul"), policy_version: 2 }
        : { action: "allow", mode: "enforce", rule_id: null, policy_version: 2 },
      actor: { ip_prefix: prefix, ip_hash: ipHash },
      signals: [],
      attestation: attestationFor(step),
      signature: signatureFor(step),
      organization_id: organizationId,
      app_id: app.id,
      environment: app.environment,
      received_at: new Date(at + 150).toISOString(),
    };
  }
  const blocked = rule === "blocked-burst";
  return {
    event_id: uuidv7(at),
    ts: new Date(at).toISOString(),
    type: "request.decision",
    surface: "api",
    request: blocked
      ? { method: "GET", route: "/api/admin/**", status: 403, latency_ms: 0.6 }
      : { method: "POST", route: "/api/login", status: 401, latency_ms: 41.2 },
    decision: blocked
      ? { action: "block", mode: "enforce", rule_id: newId("rul"), policy_version: 2 }
      : { action: "allow", mode: "enforce", rule_id: null, policy_version: 2 },
    actor: { ip_prefix: prefix, ip_hash: ipHash },
    signals: [],
    // Evidence Events of a burst are 14 s apart: one step per Event, so a burst shows every state.
    attestation: attestationFor(Math.floor(at / 14_000)),
    signature: signatureFor(Math.floor(at / 14_000)),
    organization_id: organizationId,
    app_id: app.id,
    environment: app.environment,
    received_at: new Date(at + 150).toISOString(),
  };
}

/** A synthetic actor hash: `iph_` and 32 hex characters. The stub never sees an address. */
const newActorHash = () => `iph_${randomBytes(16).toString("hex")}`;

/** The Actors of an Incident's evidence: distinct hashes with their counts, most first, then by hash; at most 10. */
function actorsOf(evidence) {
  const counts = new Map();
  for (const event of evidence) {
    const hash = event.actor.ip_hash;
    if (hash) counts.set(hash, (counts.get(hash) ?? 0) + 1);
  }
  return [...counts]
    .map(([ip_hash, events]) => ({ ip_hash, events }))
    .sort((a, b) => b.events - a.events || a.ip_hash.localeCompare(b.ip_hash))
    .slice(0, 10);
}

/** A block as the API returns it: its status computed from the clock. */
function withStatus(stored) {
  const status = stored.lifted_at ? "lifted" : Date.parse(stored.expires_at) <= Date.now() ? "expired" : "active";
  return { ...stored, status };
}

/** An IPv4 text as a 32-bit number, or null. */
function ipv4(text) {
  const parts = text.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255))
    return null;
  return parts.reduce((value, part) => value * 256 + Number(part), 0);
}

/** `{ start, size }` of a canonical IPv4 CIDR /8–/32 with host bits zero, or null (IPv6 is accepted unchecked). */
function ipv4Range(cidr) {
  const [address, length] = cidr.split("/");
  const start = address === undefined ? null : ipv4(address);
  if (start === null || !/^[1-9][0-9]?$/.test(length ?? "") || Number(length) < 8 || Number(length) > 32) return null;
  const size = 2 ** (32 - Number(length));
  return start % size === 0 ? { start, size } : null;
}

/** Whether two IPv4 ranges share an address. Ranges of another version never overlap in this stub. */
function overlaps(a, b) {
  const x = ipv4Range(a);
  const y = ipv4Range(b);
  return x !== null && y !== null && x.start < y.start + y.size && y.start < x.start + x.size;
}

/** An Incident with `bursts` Detections, each `threshold` Events within 2 minutes, `gapMs` apart, the last one ending at `endMs`. */
function makeIncident(
  organizationId,
  app,
  { rule, prefix, status, bursts, endMs, gapMs, canary = null, build = null },
) {
  const { title, severity, threshold } = RULES[rule];
  const detections = [];
  const evidence = [];
  // Three clients of the network; the first sends most of the requests. A Canary use comes from one.
  const hashes = [newActorHash(), newActorHash(), newActorHash()];
  for (let n = bursts - 1; n >= 0; n--) {
    const end = endMs - n * gapMs;
    const start = canary ? end : end - 119_000;
    detections.push({
      id: newId("dtc"),
      rule,
      app_id: app.id,
      environment: app.environment,
      ip_prefix: prefix,
      count: threshold,
      window_start: new Date(start).toISOString(),
      window_end: new Date(end).toISOString(),
      detected_at: new Date(end + 1_000).toISOString(),
      canary_id: canary?.id ?? null,
      origin: null,
    });
    const perBurst = canary ? 1 : 8;
    for (let i = 0; i < perBurst; i++) {
      const hash = hashes[i % 4 === 3 ? 1 + ((i >> 2) % 2) : 0];
      evidence.push(evidenceEvent(organizationId, app, rule, prefix, end - i * 14_000, canary, hash));
    }
  }
  evidence.sort((a, b) => b.ts.localeCompare(a.ts));
  const first = detections[0];
  const last = detections.at(-1);
  const incident = {
    id: newId("inc"),
    app_id: app.id,
    environment: app.environment,
    rule,
    severity,
    title,
    status,
    ip_prefix: prefix,
    first_seen: first.window_start,
    last_seen: last.window_end,
    detection_count: detections.length,
    created_at: first.detected_at,
    updated_at: last.detected_at,
    canary_id: canary?.id ?? null,
    build_id: build?.build_id ?? null,
    origin: null,
    advisory_id: null,
  };
  const listed = evidence.slice(0, 20);
  return { incident, detections, evidence: listed, actors: actorsOf(listed) };
}

/**
 * A clone Incident (slice 10): `reports` Clone Beacon reports of `origin` for `build`, `gapMs` apart, the last
 * at `endMs`. Each report is one Detection with the reporter's network (null when unknown); the Incident has no
 * network, no evidence and no Actors.
 */
function makeCloneIncident(app, { origin, build, status, reporters, endMs, gapMs }) {
  const { title, severity } = RULES["clone-origin"];
  const detections = reporters.map((prefix, index) => {
    const at = endMs - (reporters.length - 1 - index) * gapMs;
    return {
      id: newId("dtc"),
      rule: "clone-origin",
      app_id: app.id,
      environment: app.environment,
      ip_prefix: prefix,
      count: 1,
      window_start: new Date(at).toISOString(),
      window_end: new Date(at).toISOString(),
      detected_at: new Date(at + 1_000).toISOString(),
      canary_id: null,
      origin,
    };
  });
  const first = detections[0];
  const last = detections.at(-1);
  const incident = {
    id: newId("inc"),
    app_id: app.id,
    environment: app.environment,
    rule: "clone-origin",
    severity,
    title,
    status,
    ip_prefix: null,
    first_seen: first.window_start,
    last_seen: last.window_end,
    detection_count: detections.length,
    created_at: first.detected_at,
    updated_at: last.detected_at,
    canary_id: null,
    build_id: build?.build_id ?? null,
    origin,
    advisory_id: null,
  };
  return { incident, detections, evidence: [], actors: [] };
}

/** Open, acknowledged and resolved: every state of the Incident screens. */
function seedIncidents(organizationId, app) {
  const now = Date.now();
  const minute = 60_000;
  // The newest Build's decoy key (seedBuilds runs first).
  const build = (builds.get(app.id) ?? [])[0] ?? null;
  const canary = build?.canaries?.find((one) => one.kind === "key") ?? null;
  incidents.set(organizationId, [
    ...vulnerableIncident(organizationId, app, now),
    ...exploitIncident(organizationId, app, now),
    makeCloneIncident(app, {
      origin: "https://clone.example",
      build,
      status: "open",
      reporters: ["198.51.100.0/24", null],
      endMs: now - minute,
      gapMs: 6 * minute,
    }),
    ...(canary
      ? [
          makeIncident(organizationId, app, {
            rule: "canary-touched",
            prefix: "192.0.2.0/24",
            status: "open",
            bursts: 1,
            endMs: now - 2 * minute,
            gapMs: 0,
            canary,
            build,
          }),
        ]
      : []),
    makeIncident(organizationId, app, {
      rule: "credential-stuffing",
      prefix: "198.51.100.0/24",
      status: "open",
      bursts: 2,
      endMs: now - 3 * minute,
      gapMs: 7 * minute,
    }),
    makeIncident(organizationId, app, {
      rule: "blocked-burst",
      prefix: "203.0.113.0/24",
      status: "open",
      bursts: 3,
      endMs: now - 4 * minute,
      gapMs: 9 * minute,
    }),
    makeIncident(organizationId, app, {
      rule: "failed-signin-burst",
      prefix: "198.51.100.0/24",
      status: "acknowledged",
      bursts: 1,
      endMs: now - 47 * minute,
      gapMs: 0,
    }),
    makeIncident(organizationId, app, {
      rule: "blocked-burst",
      prefix: "2001:db8:42::/48",
      status: "resolved",
      bursts: 2,
      endMs: now - 26 * 60 * minute,
      gapMs: 15 * minute,
    }),
  ]);
}

// ── Findings (slice 19) ───────────────────────────────────────────────────────────────────────────────

/** Six synthetic advisories (an OSV subset): rated by GHSA, by CVSS v3 only, and by nothing; one withdrawn. */
const ADVISORIES = new Map(
  [
    {
      id: "GHSA-2c3m-4p5q-6r7v",
      aliases: ["CVE-2026-10001"],
      summary: "Denial of service in example-parser",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
      database_specific: { severity: "HIGH" },
      affected: [
        {
          package: { ecosystem: "npm", name: "example-parser" },
          ranges: [
            {
              type: "SEMVER",
              events: [{ introduced: "0" }, { fixed: "1.2.4" }, { introduced: "2.0.0" }, { fixed: "2.1.1" }],
            },
          ],
        },
      ],
      published: "2026-10-01T00:00:00Z",
      modified: "2026-10-02T00:00:00Z",
    },
    {
      id: "GHSA-8f2x-9q4w-c5vr",
      aliases: ["CVE-2026-20001", "GHSA-zzzz-yyyy-xxxx", "CVE-2026-20002", "CVE-2026-20003"],
      summary: "Prototype pollution in @example/ui allows remote code execution",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      affected: [
        {
          package: { ecosystem: "npm", name: "@example/ui" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        },
      ],
      published: "2026-11-01T00:00:00Z",
      modified: "2026-11-02T00:00:00Z",
    },
    {
      id: "GHSA-3j7k-m2p9-w4xh",
      aliases: ["CVE-2026-30001"],
      summary: "Regular expression denial of service in example-yaml",
      severity: [],
      database_specific: { severity: "MODERATE" },
      affected: [
        {
          package: { ecosystem: "npm", name: "example-yaml" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "3.0.0" }, { fixed: "3.1.1" }] }],
          versions: ["2.9.9"],
        },
      ],
      published: "2026-09-01T00:00:00Z",
      modified: "2026-09-03T00:00:00Z",
    },
    {
      id: "GHSA-6v4c-h8rt-q2nm",
      aliases: [],
      summary: "Path traversal in example-test-runner fixtures",
      severity: [],
      database_specific: { severity: "LOW" },
      affected: [
        {
          package: { ecosystem: "npm", name: "example-test-runner" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "9.0.0" }, { last_affected: "9.1.0" }] }],
        },
      ],
      published: "2026-08-01T00:00:00Z",
      modified: "2026-08-01T00:00:00Z",
    },
    {
      id: "GHSA-9w5r-t7yb-k3dc",
      aliases: ["CVE-2026-40001"],
      summary: "Information exposure in example-legacy",
      severity: [],
      affected: [
        {
          package: { ecosystem: "npm", name: "example-legacy" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0.5.0" }, { fixed: "1.0.0" }] }],
        },
      ],
      published: "2026-07-01T00:00:00Z",
      modified: "2026-07-01T00:00:00Z",
    },
    {
      id: "GHSA-5p8d-r3xq-v6jw",
      aliases: ["CVE-2026-50001"],
      summary: "Withdrawn: incorrect report against example-date",
      severity: [],
      database_specific: { severity: "MODERATE" },
      affected: [
        {
          package: { ecosystem: "npm", name: "example-date" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "2.0.0" }, { fixed: "2.5.0" }] }],
        },
      ],
      published: "2026-06-01T00:00:00Z",
      modified: "2026-11-05T00:00:00Z",
      withdrawn: "2026-11-05T00:00:00Z",
    },
  ].map((advisory) => [advisory.id, advisory]),
);

const fixedOf = (advisoryId, name) =>
  ADVISORIES.get(advisoryId)
    .affected.filter((entry) => entry.package.name === name)
    .flatMap((entry) => entry.ranges.flatMap((range) => range.events.flatMap((event) => event.fixed ?? [])));

/** One stored Finding of `app` (the API's shape); `ageMs` back from now for first seen, `seenMs` for last seen. */
function makeFinding(app, spec) {
  const advisory = ADVISORIES.get(spec.advisory);
  const now = Date.now();
  return {
    id: newId("fnd"),
    app_id: app.id,
    environment: app.environment,
    source: spec.build ? "build" : "runtime",
    build_id: spec.build?.build_id ?? null,
    package: spec.name,
    version: spec.version,
    dev: spec.dev ?? false,
    advisory_id: advisory.id,
    aliases: advisory.aliases,
    summary: advisory.summary,
    severity: spec.severity,
    fixed_versions: fixedOf(advisory.id, spec.name),
    status: spec.status,
    ignore: spec.ignore ?? null,
    first_seen: new Date(now - spec.ageMs).toISOString(),
    last_seen: new Date(now - spec.seenMs).toISOString(),
  };
}

/** Findings in every state for a new App: open build and runtime, fixed, ignored, withdrawn; every severity. */
function seedFindings(organizationId, keyId, app) {
  const hour = 3_600_000;
  const [newest, older] = builds.get(app.id) ?? [];
  const list = findings.get(organizationId) ?? [];
  list.unshift(
    makeFinding(app, {
      advisory: "GHSA-8f2x-9q4w-c5vr",
      name: "@example/ui",
      version: "4.0.0-rc.1",
      severity: "critical",
      status: "open",
      ageMs: 20 * hour,
      seenMs: 0.2 * hour,
    }),
    makeFinding(app, {
      advisory: "GHSA-2c3m-4p5q-6r7v",
      build: newest,
      name: "example-parser",
      version: "1.2.3",
      severity: "high",
      status: "open",
      ageMs: 3 * hour,
      seenMs: 3 * hour,
    }),
    makeFinding(app, {
      advisory: "GHSA-9w5r-t7yb-k3dc",
      name: "example-legacy",
      version: "0.9.0",
      severity: "unknown",
      status: "open",
      ageMs: 30 * hour,
      seenMs: 0.5 * hour,
    }),
    makeFinding(app, {
      advisory: "GHSA-6v4c-h8rt-q2nm",
      build: newest,
      name: "example-test-runner",
      version: "9.1.0",
      dev: true,
      severity: "low",
      status: "ignored",
      ignore: {
        reason: "Development dependency, never shipped to users",
        until: new Date(Date.now() + 20 * 24 * hour).toISOString(),
        by: keyId,
      },
      ageMs: 3 * hour,
      seenMs: 3 * hour,
    }),
    makeFinding(app, {
      advisory: "GHSA-3j7k-m2p9-w4xh",
      build: older,
      name: "example-yaml",
      version: "3.1.0",
      severity: "medium",
      status: "fixed",
      ageMs: 26 * hour,
      seenMs: 26 * hour,
    }),
    // D-060: the advisory was withdrawn after it matched; never open, no actions (ignore and reopen answer 409).
    makeFinding(app, {
      advisory: "GHSA-5p8d-r3xq-v6jw",
      name: "example-date",
      version: "2.4.1",
      severity: "medium",
      status: "withdrawn",
      ageMs: 40 * hour,
      seenMs: 1 * hour,
    }),
  );
  findings.set(organizationId, list);
}

/** An open "Vulnerable component" Incident for the first App's high build Finding (seedFindings runs first). */
function vulnerableIncident(organizationId, app, now) {
  const finding = (findings.get(organizationId) ?? []).find(
    (one) => one.app_id === app.id && one.severity === "high" && one.status === "open",
  );
  if (!finding) return [];
  const at = new Date(now - 3 * 3_600_000).toISOString();
  const detection = {
    id: newId("dtc"),
    rule: "vulnerable-component",
    app_id: app.id,
    environment: app.environment,
    ip_prefix: null,
    count: 1,
    window_start: at,
    window_end: at,
    detected_at: at,
    canary_id: null,
    origin: null,
  };
  const incident = {
    id: newId("inc"),
    app_id: app.id,
    environment: app.environment,
    rule: "vulnerable-component",
    severity: finding.severity,
    title: "Vulnerable component",
    status: "open",
    ip_prefix: null,
    first_seen: at,
    last_seen: at,
    detection_count: 1,
    created_at: at,
    updated_at: at,
    canary_id: null,
    build_id: finding.build_id,
    origin: null,
    advisory_id: finding.advisory_id,
  };
  return [{ incident, detections: [detection], evidence: [], actors: [] }];
}

/** A Finding as the API returns it: an ignore past its date is open again. */
function currentFinding(stored) {
  if (stored.status === "ignored" && Date.parse(stored.ignore.until) <= Date.now()) {
    stored.status = "open";
    stored.ignore = null;
  }
  return stored;
}

const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "unknown"];
const FINDING_STATUSES = ["open", "fixed", "ignored"];
const FINDING_SOURCES = ["build", "runtime"];
const IGNORE_MAX_MS = 90 * 86_400_000;

const INCIDENT_STATUSES = ["open", "acknowledged", "resolved"];
const TRANSITIONS = { open: ["acknowledged", "resolved"], acknowledged: ["resolved"], resolved: [] };

// ── Virtual patches (slice 20) ────────────────────────────────────────────────────────────────────────

const PATCH_CATALOG = [
  {
    id: "vp_example_parser_proto",
    title: "Prototype pollution through query keys in example-parser",
    advisories: ["GHSA-2c3m-4p5q-6r7v"],
    package: "example-parser",
  },
  {
    id: "vp_test_runner_path",
    title: "Path traversal in the example-test-runner report server",
    advisories: ["GHSA-6v4c-h8rt-q2nm"],
    package: "example-test-runner",
    // Stands for an active patch the signed bundle had no room for.
    shipped: false,
  },
  {
    id: "vp_unused_xml_proto",
    title: "Prototype pollution through XML elements in example-xml",
    advisories: ["GHSA-0000-1111-2222"],
    package: "example-xml",
  },
];
/** @type {Map<string, "monitor" | "enforce">} "<App id>/<Environment>/<patch id>" → mode */
const patchModes = new Map();
/** @type {Map<string, number[]>} "<App id>/<Environment>/<patch id>" → hit times in ms, newest first */
const patchHits = new Map();

/** The catalog as `GET /v1/apps/:appId/patches?environment=` returns it for one App and Environment. */
function patchesFor(organizationId, appId, environment) {
  const now = Date.now();
  const live = (findings.get(organizationId) ?? [])
    .map(currentFinding)
    .filter(
      (finding) =>
        finding.app_id === appId &&
        finding.environment === environment &&
        (finding.status === "open" || finding.status === "ignored"),
    );
  return PATCH_CATALOG.map((entry) => {
    const slot = `${appId}/${environment}/${entry.id}`;
    const matched = live.filter(
      (finding) =>
        finding.package === entry.package &&
        [finding.advisory_id, ...finding.aliases].some((id) => entry.advisories.includes(id)),
    );
    const hits = (patchHits.get(slot) ?? []).filter((at) => at > now - 86_400_000);
    return {
      id: entry.id,
      title: entry.title,
      advisories: entry.advisories,
      package: entry.package,
      mode: patchModes.get(slot) ?? "monitor",
      active: matched.length > 0,
      shipped: matched.length > 0 && entry.shipped !== false,
      findings: matched.map((finding) => finding.id),
      hits_24h: hits.length,
      last_hit: hits.length === 0 ? null : new Date(hits[0]).toISOString(),
    };
  });
}

/** Records a hit and returns the patch decision of a request that matched an active, shipped patch. */
function patchDecision(organizationId, app, n, policyVersion) {
  const shipped = patchesFor(organizationId, app.id, app.environment).filter((patch) => patch.shipped);
  const patch = shipped[n % Math.max(shipped.length, 1)];
  if (!patch) return null;
  const slot = `${app.id}/${app.environment}/${patch.id}`;
  patchHits.set(slot, [Date.now(), ...(patchHits.get(slot) ?? [])].slice(0, 1000));
  return {
    action: "block",
    mode: patch.mode,
    rule_id: null,
    policy_version: policyVersion,
    containment_id: null,
    patch_id: patch.id,
    patch_body: n % 2 === 0 ? "checked" : "unchecked",
  };
}

/** An open "Exploit attempt" Incident for the first App's high build Finding, with one monitored Event. */
function exploitIncident(organizationId, app, now) {
  const finding = (findings.get(organizationId) ?? []).find(
    (one) => one.app_id === app.id && one.severity === "high" && one.status === "open",
  );
  const patch = PATCH_CATALOG.find((entry) => finding && entry.advisories.includes(finding.advisory_id));
  if (!finding || !patch) return [];
  const atMs = now - 40 * 60_000;
  const at = new Date(atMs).toISOString();
  const prefix = "198.51.100.0/24";
  const slot = `${app.id}/${app.environment}/${patch.id}`;
  patchHits.set(slot, [atMs, ...(patchHits.get(slot) ?? [])]);
  const evidence = [
    {
      event_id: uuidv7(atMs),
      ts: at,
      type: "request.decision",
      surface: "api",
      request: { method: "GET", route: "/api/search", status: 200, latency_ms: 3.4 },
      decision: {
        action: "block",
        mode: "monitor",
        rule_id: null,
        policy_version: currentPolicy(app.id, app.environment).version,
        containment_id: null,
        patch_id: patch.id,
        patch_body: "unchecked",
      },
      actor: { ip_prefix: prefix },
      signals: [],
      attestation: null,
      signature: null,
      organization_id: organizationId,
      app_id: app.id,
      environment: app.environment,
      received_at: at,
    },
  ];
  const detection = {
    id: newId("dtc"),
    rule: "exploit-attempt",
    app_id: app.id,
    environment: app.environment,
    ip_prefix: prefix,
    count: 1,
    window_start: at,
    window_end: at,
    detected_at: at,
    canary_id: null,
    origin: null,
  };
  const incident = {
    id: newId("inc"),
    app_id: app.id,
    environment: app.environment,
    rule: "exploit-attempt",
    severity: "high",
    title: "Exploit attempt",
    status: "open",
    ip_prefix: prefix,
    first_seen: at,
    last_seen: at,
    detection_count: 1,
    created_at: at,
    updated_at: at,
    canary_id: null,
    build_id: null,
    origin: null,
    advisory_id: finding.advisory_id,
  };
  return [{ incident, detections: [detection], evidence, actors: actorsOf(evidence) }];
}

function json(res, status, body, contentType = "application/json") {
  res.writeHead(status, { "content-type": contentType });
  res.end(JSON.stringify(body));
}

/** Writes an answer of a store module: a body, nothing for 204, a problem document with its headers otherwise. */
function send(res, answer) {
  if (answer.status === 204) {
    res.writeHead(204);
    return res.end();
  }
  if (answer.status >= 400) {
    const { type: _type, title, status: _status, ...extra } = answer.body;
    return problem(res, answer.status, title, extra, answer.headers ?? {});
  }
  return json(res, answer.status, answer.body);
}

function problem(res, status, title, extra = {}, more = {}) {
  const headers = status === 401 ? { "www-authenticate": "Bearer" } : more;
  res.writeHead(status, { "content-type": "application/problem+json", ...headers });
  res.end(JSON.stringify({ type: "about:blank", title, status, ...extra }));
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return undefined;
  }
}

function validName(body) {
  const name = typeof body?.name === "string" ? body.name.trim() : "";
  return name.length >= 1 && name.length <= 80 ? name : null;
}

const publicApp = ({ id, name, created_at }) => ({ id, name, created_at });

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${host}`);
  const path = url.pathname;
  console.log(`${new Date().toISOString()} ${req.method} ${path}${url.search}`);

  if (req.method === "GET" && path === "/healthz") return json(res, 200, { status: "ok" });

  // Needs no key: the public key Shield verifies a Policy with.
  if (req.method === "GET" && path === "/v1/signing-key") return json(res, 200, signingKey);

  // Simulates a restart that keeps its data: every stream ends and connections are refused for `ms`.
  //   curl -X POST 'http://127.0.0.1:39201/__stub/outage?ms=6000'
  if (req.method === "POST" && path === "/__stub/outage") {
    const ms = Math.min(Math.max(Number(url.searchParams.get("ms")) || 5_000, 100), 60_000);
    json(res, 202, { outage_ms: ms });
    setTimeout(() => {
      for (const stream of streams) stream.end();
      server.close(() => setTimeout(() => server.listen(port, host), ms));
      server.closeAllConnections();
      console.log(`${new Date().toISOString()} outage for ${ms} ms`);
    }, 50);
    return;
  }

  if (req.method === "POST" && path === "/v1/organizations") {
    const name = validName(await readBody(req));
    if (!name) return problem(res, 400, "Bad Request", { errors: [{ path: "name", message: "Invalid name" }] });
    const organization = { id: newId("org"), name, created_at: new Date().toISOString() };
    const adminKey = newKey("aro_");
    organizations.set(adminKey.key, organization);
    adminKeyIds.set(adminKey.key, newId("key"));
    apps.set(organization.id, []);
    proveStores.set(organization.id, createProveStore({ keyId: adminKeyIds.get(adminKey.key) }));
    alerts.seed(organization.id);
    return json(res, 201, { organization, admin_key: adminKey });
  }

  // Public (slice 06b): the Console posts the token of a confirmation link here from its server. Never logged.
  if (req.method === "POST" && path === "/v1/alert-recipients/confirm")
    return send(res, alerts.confirm(await readBody(req)));

  // Everything below needs an admin key.
  const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
  if (bearer?.startsWith("ark_")) return problem(res, 403, "Forbidden");
  const organization = bearer ? organizations.get(bearer) : undefined;
  if (!organization) return problem(res, 401, "Unauthorized");
  const ownApps = apps.get(organization.id) ?? [];

  // Prove (slice 14): targets, Rules of Engagement and the dry authorization check.
  if (path.startsWith("/v1/targets") || path.startsWith("/v1/rules-of-engagement") || path === "/v1/prove/authorize") {
    const prove = proveStores.get(organization.id);
    const answer = prove?.handle(req.method, path, req.method === "POST" ? await readBody(req) : undefined);
    if (answer) {
      if (answer.status === 204) {
        res.writeHead(204);
        return res.end();
      }
      if (answer.status >= 400) {
        const { type: _type, title, status: _status, ...extra } = answer.body;
        return problem(res, answer.status, title, extra, answer.headers ?? {});
      }
      return json(res, answer.status, answer.body);
    }
  }

  if (req.method === "GET" && path === "/v1/organization") return json(res, 200, { organization });

  if (req.method === "POST" && path === "/v1/apps") {
    const body = await readBody(req);
    const name = validName(body);
    const environment = body?.environment ?? "development";
    if (!name) return problem(res, 400, "Bad Request", { errors: [{ path: "name", message: "Invalid name" }] });
    if (!Object.hasOwn(TAGS, environment)) {
      return problem(res, 400, "Bad Request", { errors: [{ path: "environment", message: "Invalid option" }] });
    }
    const app = { id: newId("app"), name, created_at: new Date().toISOString(), environment };
    ownApps.unshift(app);
    events.set(app.id, []);
    seedPolicies(app.id);
    seedBuilds(app);
    assessments.seed(organization.id, builds.get(app.id) ?? []);
    seedFindings(organization.id, adminKeyIds.get(bearer) ?? newId("key"), app);
    if (!incidents.has(organization.id)) seedIncidents(organization.id, app);
    return json(res, 201, { app: publicApp(app), shield_key: { ...newKey(`ark_${TAGS[environment]}_`), environment } });
  }

  if (req.method === "GET" && path === "/v1/apps") return json(res, 200, { apps: ownApps.map(publicApp) });

  // Slice 11: an estimate for draft Rules. Checked as a publish, limited per Organization, and nothing is stored.
  const simulateMatch = /^\/v1\/apps\/([^/]+)\/policy\/simulate$/.exec(path);
  if (simulateMatch) {
    if (!ownApps.some((candidate) => candidate.id === simulateMatch[1])) return problem(res, 404, "Not Found");
    if (req.method !== "POST") return problem(res, 405, "Method Not Allowed");
    const now = Date.now();
    const recent = (simulations.get(organization.id) ?? []).filter((at) => now - at < 60_000);
    simulations.set(organization.id, recent);
    if (recent.length >= SIMULATIONS_PER_MINUTE) {
      const wait = Math.max(1, Math.ceil((recent[0] + 60_000 - now) / 1000));
      return problem(res, 429, "Too Many Requests", {}, { "retry-after": String(wait) });
    }
    const body = await readBody(req);
    if (!Object.hasOwn(TAGS, body?.environment ?? "")) {
      return problem(res, 400, "Bad Request", { errors: [{ path: "environment", message: "Invalid option" }] });
    }
    const checked = checkRules(body);
    if (checked.errors) return problem(res, 400, "Bad Request", { errors: checked.errors });
    recent.push(now);
    return json(res, 200, { simulation: stubSimulation(checked.rules, now) });
  }

  const policyMatch = /^\/v1\/apps\/([^/]+)\/policies\/([^/]+)(\/versions(?:\/[^/]+)?|\/rollback)?$/.exec(path);
  if (policyMatch) {
    const [, appId, environment, sub] = policyMatch;
    const app = ownApps.find((candidate) => candidate.id === appId);
    if (!app || !Object.hasOwn(TAGS, environment)) return problem(res, 404, "Not Found");
    const versions = policies.get(policyKey(appId, environment)) ?? [];

    if (req.method === "GET" && !sub) return json(res, 200, { policy: currentPolicy(appId, environment) });

    // Like the API: a change based on a version that is no longer current stores nothing.
    const outdated = (body) =>
      body?.expected_version !== undefined && body.expected_version !== currentPolicy(appId, environment).version;

    if (req.method === "PUT" && !sub) {
      const body = await readBody(req);
      if (outdated(body)) return problem(res, 409, "Policy changed");
      const checked = checkRules(body);
      if (checked.errors) return problem(res, 400, "Bad Request", { errors: checked.errors });
      const broad = broadErrors(checked.rules, body?.allow_broad);
      if (broad.length > 0) return problem(res, 400, "Bad Request", { errors: broad });
      return json(res, 201, { policy: publish(appId, environment, checked.rules) });
    }

    if (req.method === "GET" && sub === "/versions") {
      const listed = versions
        .slice(-20)
        .reverse()
        .map(({ version, published_at, rules }) => ({
          version,
          published_at,
          rule_count: rules.length,
          enforced_count: rules.filter((rule) => rule.mode === "enforce").length,
        }));
      return json(res, 200, { versions: listed });
    }

    if (req.method === "GET" && sub?.startsWith("/versions/")) {
      const one = versions.find((candidate) => String(candidate.version) === sub.slice("/versions/".length));
      if (!one) return problem(res, 404, "Not Found");
      return json(res, 200, { policy: { app_id: appId, environment, ...one } });
    }

    if (req.method === "POST" && sub === "/rollback") {
      const body = await readBody(req);
      if (!Number.isInteger(body?.version) || body.version < 1) {
        return problem(res, 400, "Bad Request", { errors: [{ path: "version", message: "Invalid version" }] });
      }
      if (outdated(body)) return problem(res, 409, "Policy changed");
      const earlier = versions.find((candidate) => candidate.version === body.version);
      if (!earlier) return problem(res, 404, "Not Found");
      const broad = broadErrors(earlier.rules, body?.allow_broad);
      if (broad.length > 0) return problem(res, 400, "Bad Request", { errors: broad });
      return json(res, 201, { policy: publish(appId, environment, earlier.rules) });
    }

    return problem(res, 405, "Method Not Allowed");
  }

  // Incidents (slice 06, contract P2): the list newest first by last seen, one Incident, a status change.
  if (path === "/v1/incidents" && req.method === "GET") {
    const status = url.searchParams.get("status");
    const appId = url.searchParams.get("app_id");
    if (status !== null && !INCIDENT_STATUSES.includes(status)) {
      return problem(res, 400, "Bad Request", { errors: [{ path: "status", message: "Invalid option" }] });
    }
    const listed = (incidents.get(organization.id) ?? [])
      .map((entry) => entry.incident)
      .filter(
        (incident) => (status === null || incident.status === status) && (appId === null || incident.app_id === appId),
      )
      .sort((a, b) => b.last_seen.localeCompare(a.last_seen))
      .slice(0, 50);
    return json(res, 200, { incidents: listed });
  }
  const incidentMatch = /^\/v1\/incidents\/([^/]+)$/.exec(path);
  if (incidentMatch) {
    const entry = (incidents.get(organization.id) ?? []).find((one) => one.incident.id === incidentMatch[1]);
    if (!entry) return problem(res, 404, "Not Found");
    if (req.method === "GET") {
      const own = (containments.get(organization.id) ?? []).filter((one) => one.incident_id === entry.incident.id);
      return json(res, 200, { ...entry, containments: own.map(withStatus) });
    }
    if (req.method === "PATCH") {
      const body = await readBody(req);
      if (body?.status !== "acknowledged" && body?.status !== "resolved") {
        return problem(res, 400, "Bad Request", { errors: [{ path: "status", message: "Invalid option" }] });
      }
      if (!TRANSITIONS[entry.incident.status].includes(body.status)) return problem(res, 409, "Conflict");
      entry.incident = { ...entry.incident, status: body.status, updated_at: new Date().toISOString() };
      return json(res, 200, { incident: entry.incident });
    }
    return problem(res, 405, "Method Not Allowed");
  }

  // Findings (slice 19): the list newest first with its filters, one Finding with its advisory, ignore, reopen.
  if (path === "/v1/findings" && req.method === "GET") {
    const filters = {
      app_id: [url.searchParams.get("app_id"), null],
      environment: [url.searchParams.get("environment"), Object.keys(TAGS)],
      status: [url.searchParams.get("status"), FINDING_STATUSES],
      severity: [url.searchParams.get("severity"), FINDING_SEVERITIES],
      source: [url.searchParams.get("source"), FINDING_SOURCES],
    };
    for (const [name, [value, allowed]] of Object.entries(filters)) {
      if (value !== null && allowed !== null && !allowed.includes(value)) {
        return problem(res, 400, "Bad Request", { errors: [{ path: name, message: "Invalid option" }] });
      }
    }
    // Like the API: advisory_id matches the advisory id or any alias; build_id the build Findings of that Build.
    const advisoryId = url.searchParams.get("advisory_id");
    const buildId = url.searchParams.get("build_id");
    const listed = (findings.get(organization.id) ?? [])
      .map(currentFinding)
      .filter(
        (finding) =>
          Object.entries(filters).every(([name, [value]]) => value === null || finding[name] === value) &&
          (advisoryId === null || finding.advisory_id === advisoryId || finding.aliases.includes(advisoryId)) &&
          (buildId === null || finding.build_id === buildId),
      )
      .sort((a, b) => b.last_seen.localeCompare(a.last_seen))
      .slice(0, 200);
    return json(res, 200, { findings: listed });
  }
  const findingMatch = /^\/v1\/findings\/([^/]+)(\/ignore|\/reopen)?$/.exec(path);
  if (findingMatch) {
    const stored = (findings.get(organization.id) ?? []).find((one) => one.id === findingMatch[1]);
    if (!stored) return problem(res, 404, "Not Found");
    const finding = currentFinding(stored);
    if (req.method === "GET" && !findingMatch[2]) {
      return json(res, 200, { finding, advisory: ADVISORIES.get(finding.advisory_id) });
    }
    if (req.method === "POST" && findingMatch[2] === "/ignore") {
      const body = await readBody(req);
      const reason = typeof body?.reason === "string" ? body.reason.trim() : "";
      const until = typeof body?.until === "string" ? Date.parse(body.until) : Number.NaN;
      const errors = [];
      if (reason.length < 1 || reason.length > 200) errors.push({ path: "reason", message: "Invalid reason" });
      if (!(until > Date.now() && until <= Date.now() + IGNORE_MAX_MS)) {
        errors.push({ path: "until", message: "Must lie in the next 90 days" });
      }
      if (errors.length > 0) return problem(res, 400, "Bad Request", { errors });
      if (finding.status !== "open") return problem(res, 409, "Conflict");
      finding.status = "ignored";
      finding.ignore = { reason, until: new Date(until).toISOString(), by: adminKeyIds.get(bearer) ?? newId("key") };
      return json(res, 200, { finding });
    }
    if (req.method === "POST" && findingMatch[2] === "/reopen") {
      if (finding.status !== "ignored") return problem(res, 409, "Conflict");
      finding.status = "open";
      finding.ignore = null;
      return json(res, 200, { finding });
    }
    return problem(res, 405, "Method Not Allowed");
  }

  // Containment (slice 09, contract P2): create from an Incident, lift, list; the never-block list.
  const keyId = adminKeyIds.get(bearer) ?? newId("key");
  const ownBlocks = containments.get(organization.id) ?? [];
  containments.set(organization.id, ownBlocks);
  const ownRanges = allowlists.get(organization.id) ?? [];
  allowlists.set(organization.id, ownRanges);
  const createMatch = /^\/v1\/incidents\/([^/]+)\/containments$/.exec(path);
  if (createMatch && req.method === "POST") {
    const entry = (incidents.get(organization.id) ?? []).find((one) => one.incident.id === createMatch[1]);
    if (!entry) return problem(res, 404, "Not Found");
    const body = await readBody(req);
    const { incident } = entry;
    const ttl = body?.ttl_s;
    if (![900, 3600, 86400].includes(ttl)) {
      return problem(res, 400, "Invalid request", { errors: [{ path: "ttl_s", message: "Invalid option" }] });
    }
    // A clone Incident, or any Incident without a network prefix, cannot be contained (slice 10).
    if (incident.rule === "clone-origin" || incident.ip_prefix === null) {
      return problem(res, 409, "Conflict", { reason: "containment-not-applicable" });
    }
    let target;
    if (body?.target?.kind === "actor" && typeof body.target.ip_hash === "string") {
      target = { kind: "actor", ip_hash: body.target.ip_hash };
    } else if (
      body?.target?.kind === "prefix" &&
      incident.ip_prefix !== null &&
      body?.confirm_prefix === incident.ip_prefix
    ) {
      target = { kind: "prefix", ip_prefix: incident.ip_prefix };
    } else {
      return problem(res, 400, "Invalid request", { errors: [{ path: "target", message: "Not in this Incident" }] });
    }
    if (incident.status === "resolved") return problem(res, 409, "Conflict", { reason: "incident-resolved" });
    if (target.kind === "actor" && !entry.actors.some((actor) => actor.ip_hash === target.ip_hash)) {
      return problem(res, 409, "Conflict", { reason: "actor-unknown" });
    }
    if (target.kind === "prefix" && ownRanges.some((range) => overlaps(range.cidr, target.ip_prefix))) {
      return problem(res, 409, "Conflict", { reason: "prefix-allowlisted" });
    }
    const active = ownBlocks
      .map(withStatus)
      .filter(
        (one) => one.status === "active" && one.app_id === incident.app_id && one.environment === incident.environment,
      );
    const same = active.find((one) => JSON.stringify(one.target) === JSON.stringify(target));
    if (same) return json(res, 200, { containment: same });
    if (active.length >= 150) return problem(res, 409, "Conflict", { reason: "containment-limit" });
    const now = Date.now();
    const stored = {
      id: newId("cnt"),
      app_id: incident.app_id,
      environment: incident.environment,
      incident_id: incident.id,
      target,
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + ttl * 1000).toISOString(),
      created_by: keyId,
      lifted_at: null,
      lifted_by: null,
    };
    ownBlocks.unshift(stored);
    return json(res, 201, { containment: withStatus(stored) });
  }
  const liftMatch = /^\/v1\/containments\/([^/]+)\/lift$/.exec(path);
  if (liftMatch && req.method === "POST") {
    const stored = ownBlocks.find((one) => one.id === liftMatch[1]);
    if (!stored) return problem(res, 404, "Not Found");
    if (withStatus(stored).status !== "active") return problem(res, 409, "Conflict", { reason: "containment-ended" });
    stored.lifted_at = new Date().toISOString();
    stored.lifted_by = keyId;
    return json(res, 200, { containment: withStatus(stored) });
  }
  if (path === "/v1/containments" && req.method === "GET") {
    const appId = url.searchParams.get("app_id");
    const environment = url.searchParams.get("environment");
    const status = url.searchParams.get("status");
    const listed = ownBlocks
      .map(withStatus)
      .filter(
        (one) =>
          (appId === null || one.app_id === appId) &&
          (environment === null || one.environment === environment) &&
          (status === null || one.status === status),
      );
    return json(res, 200, { containments: listed });
  }
  if (path === "/v1/allowlist") {
    if (req.method === "GET") return json(res, 200, { entries: ownRanges });
    if (req.method === "POST") {
      const body = await readBody(req);
      const cidr = typeof body?.cidr === "string" ? body.cidr : "";
      const note = typeof body?.note === "string" ? body.note.trim() : "";
      const errors = [];
      const v6 = cidr.includes(":") && /^[0-9a-f:]+\/[1-9][0-9]{1,2}$/.test(cidr);
      if (!v6 && ipv4Range(cidr) === null) errors.push({ path: "cidr", message: "Must be a normalised CIDR" });
      if (note.length > 80) errors.push({ path: "note", message: "Too long" });
      if (errors.length > 0) return problem(res, 400, "Invalid request", { errors });
      if (ownRanges.some((range) => range.cidr === cidr)) {
        return problem(res, 409, "Conflict", { reason: "allowlist-duplicate" });
      }
      if (ownRanges.length >= 100) return problem(res, 409, "Conflict", { reason: "allowlist-limit" });
      const entry = { id: newId("alw"), cidr, note, created_at: new Date().toISOString(), created_by: keyId };
      ownRanges.push(entry);
      return json(res, 201, { entry });
    }
    return problem(res, 405, "Method Not Allowed");
  }
  const rangeMatch = /^\/v1\/allowlist\/([^/]+)$/.exec(path);
  if (rangeMatch && req.method === "DELETE") {
    const index = ownRanges.findIndex((range) => range.id === rangeMatch[1]);
    if (index === -1) return problem(res, 404, "Not Found");
    ownRanges.splice(index, 1);
    res.writeHead(204);
    return res.end();
  }

  // Alert channels (slices 06 and 06b). The URL and the signing secret never leave after creation; no token ever does.
  if (path.startsWith("/v1/alert-channels")) {
    const answer = alerts.handle(
      organization.id,
      req.method,
      path,
      req.method === "POST" ? await readBody(req) : undefined,
    );
    if (answer) return send(res, answer);
  }
  // Stub only: the link of the latest confirmation mail of a pending recipient, since the stub sends no mail. The
  // token travels in this response alone and is never logged.
  const linkMatch = /^\/__stub\/confirmation-link\/([^/]+)$/.exec(path);
  if (linkMatch && req.method === "GET") {
    const token = alerts.confirmationToken(organization.id, linkMatch[1]);
    if (token === null) return problem(res, 404, "Not Found");
    const consoleUrl = process.env.AR_CONSOLE_URL ?? "http://127.0.0.1:39200";
    return json(res, 200, { url: `${consoleUrl}/alerts/confirm?token=${token}` });
  }

  // Reverse Assessments (slice 12a): of a Build of the Organization's App, and one by its id.
  if (/^\/v1\/(?:assessments\/[^/]+|apps\/[^/]+\/builds\/[^/]+\/assessments)$/.test(path)) {
    const answer = assessments.handle(
      organization.id,
      req.method,
      path,
      req.method === "POST" ? await readBody(req) : undefined,
      (appId, buildId) =>
        ownApps.some((candidate) => candidate.id === appId)
          ? ((builds.get(appId) ?? []).find((candidate) => candidate.build_id === buildId) ?? null)
          : null,
    );
    if (answer) return send(res, answer);
  }

  // The Builds of an App (contract P4): the list newest first, and one Build by its id.
  const buildsMatch = /^\/v1\/apps\/([^/]+)\/builds(?:\/([^/]+))?$/.exec(path);
  if (req.method === "GET" && buildsMatch) {
    const [, appId, buildId] = buildsMatch;
    const app = ownApps.find((candidate) => candidate.id === appId);
    if (!app) return problem(res, 404, "Not Found");
    const list = builds.get(appId) ?? [];
    if (!buildId) return json(res, 200, { builds: list });
    const build = list.find((candidate) => candidate.build_id === buildId);
    if (!build) return problem(res, 404, "Not Found");
    return json(res, 200, { build });
  }

  // Virtual patches (slice 20): the catalog per App and Environment, and the mode change.
  const patchMatch = /^\/v1\/apps\/([^/]+)\/patches(?:\/([^/]+)\/mode)?$/.exec(path);
  if (patchMatch) {
    const app = ownApps.find((candidate) => candidate.id === patchMatch[1]);
    if (!app) return problem(res, 404, "Not Found");
    if (req.method === "GET" && !patchMatch[2]) {
      const environment = url.searchParams.get("environment");
      if (!Object.keys(TAGS).includes(environment ?? "")) {
        return problem(res, 400, "Bad Request", { errors: [{ path: "environment", message: "Invalid option" }] });
      }
      return json(res, 200, { patches: patchesFor(organization.id, app.id, environment) });
    }
    if (req.method === "POST" && patchMatch[2]) {
      const entry = PATCH_CATALOG.find((one) => one.id === patchMatch[2]);
      if (!entry) return problem(res, 404, "Not Found");
      const body = await readBody(req);
      const errors = [];
      if (!Object.keys(TAGS).includes(body?.environment)) errors.push({ path: "environment", message: "Invalid" });
      if (!["monitor", "enforce"].includes(body?.mode)) errors.push({ path: "mode", message: "Invalid" });
      if (body?.mode === "enforce" && body?.confirm !== entry.id) {
        errors.push({ path: "confirm", message: "Must equal the patch id" });
      }
      if (errors.length > 0) return problem(res, 400, "Bad Request", { errors });
      patchModes.set(`${app.id}/${body.environment}/${entry.id}`, body.mode);
      const patch = patchesFor(organization.id, app.id, body.environment).find((one) => one.id === entry.id);
      return json(res, 200, { patch });
    }
    return problem(res, 405, "Method Not Allowed");
  }

  const match = /^\/v1\/apps\/([^/]+)(\/events(\/stream)?)?$/.exec(path);
  if (req.method === "GET" && match) {
    const app = ownApps.find((candidate) => candidate.id === match[1]);
    if (!app) return problem(res, 404, "Not Found");
    if (!match[2]) return json(res, 200, { app: publicApp(app) });

    if (!match[3]) {
      const limit = url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : 50;
      if (!Number.isInteger(limit) || limit < 1 || limit > 200) return problem(res, 400, "Bad Request");
      return json(res, 200, { events: (events.get(app.id) ?? []).slice(0, limit) });
    }

    // The live stream: a comment at once, then one Event per second until the client leaves.
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    res.write(": connected\n\n");
    streams.add(res);
    let n = 0;
    const timer = setInterval(() => {
      const event = makeEvent(organization.id, app, n++);
      const stored = events.get(app.id) ?? [];
      stored.unshift(event);
      stored.length = Math.min(stored.length, 500);
      res.write(`id: ${event.event_id}\nevent: security-event\ndata: ${JSON.stringify(event)}\n\n`);
    }, 1_000);
    console.log(`${new Date().toISOString()} stream OPEN ${app.id}`);
    req.on("close", () => {
      clearInterval(timer);
      streams.delete(res);
      console.log(`${new Date().toISOString()} stream CLOSE ${app.id} after ${n} events`);
    });
    return;
  }

  return problem(res, 404, "Not Found");
});

server.listen(port, host, () => console.log(`stub API on http://${host}:${port}`));

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    for (const stream of streams) stream.end();
    server.close(() => process.exit(0));
    server.closeAllConnections();
  });
}
