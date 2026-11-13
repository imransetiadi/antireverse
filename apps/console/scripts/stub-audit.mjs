// The audit log of the stand-in API (slice 18a): one entry per change made with an admin key, hash-chained per
// Organization as the API chains it — `hash = sha256(prev_hash ‖ canonicalJson(entry without hash))`, the first
// `prev_hash` 64 zeros, `seq` from 1 without gaps — listed newest first with the API's filters and cursor, verified,
// and exported as NDJSON. The reason header is decoded (percent-encoded UTF-8) and checked as the API checks it.
// `verify` and the first line of the export carry the chain head signed with the stub's own Ed25519 audit key.
// The reason is checked with the protocol's own `AuditReasonSchema` and `holdsSecretShape`, and refused with the API's
// `code`; times outside the years 2000 to 2099 are refused as the API refuses them. The protocol is TypeScript, so the
// stub runs with tsx (see stub-api.mjs). A test checks every shape against the protocol and every hash against
// `auditHash`.
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { AUDIT_LIMITS, AuditReasonSchema, holdsSecretShape } from "@antireverse/protocol";

const GENESIS = "0".repeat(64);
const REASON_PATH = "headers.x-airverse-reason";
const PROBLEMS = "https://antireverse.dev/problems/";
const LIST_DEFAULT = 50;
const LIST_MAX = 200;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/** An ISO time the API takes: `Date#toISOString` form, in the years 2000 to 2099. */
const isApiTime = (value) => {
  if (!ISO.test(value)) return false;
  const time = Date.parse(value);
  return time >= Date.UTC(2000, 0, 1) && time < Date.UTC(2100, 0, 1);
};

/** Keys sorted, no whitespace: the protocol's canonical JSON. */
function canonicalJson(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const hashOf = (entry) => {
  const { hash: _hash, ...rest } = entry;
  return createHash("sha256")
    .update(rest.prev_hash + canonicalJson(rest), "utf8")
    .digest("hex");
};

const problem = (status, kind, title, extra = {}) => ({
  status,
  body: { type: `${PROBLEMS}${kind}`, title, status, ...extra },
});
const invalid = (path, message) => problem(400, "validation", "Invalid request", { errors: [{ path, message }] });
/** A refused reason header: a validation problem on the header's path, with the API's `code`. */
const refusedReason = (code, message) =>
  problem(400, "validation", "Invalid request", { code, errors: [{ path: REASON_PATH, message }] });

export function createAuditStore({ now = () => Date.now() } = {}) {
  // The stub's audit key: a real Ed25519 key pair, generated per process; only signatures leave.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicRaw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const keyId = createHash("sha256").update(publicRaw).digest("hex").slice(0, 16);
  /** @type {Map<string, object[]>} Organization id → entries, oldest first */
  const chains = new Map();
  const chainOf = (organizationId) => {
    const chain = chains.get(organizationId) ?? [];
    chains.set(organizationId, chain);
    return chain;
  };

  /** The Organization's chain head, signed over the canonical JSON of the head. */
  const signedHead = (organizationId) => {
    const last = chainOf(organizationId).at(-1);
    const head = {
      organization_id: organizationId,
      seq: last?.seq ?? 0,
      hash: last?.hash ?? GENESIS,
      at: new Date(now()).toISOString(),
    };
    const signature = sign(null, Buffer.from(canonicalJson(head), "utf8"), privateKey).toString("base64url");
    return { head, key_id: keyId, signature };
  };

  return {
    /** The Organization's chain head, signed (slice 18b: the head the Organization export is cut at). */
    signedHead,

    /** `GET /v1/audit/public-key`: the public half of the stub's audit key. */
    publicKey: () => ({ key_id: keyId, algorithm: "Ed25519", public_key: publicRaw.toString("base64url") }),

    /**
     * The reason of a request from its header: `{ reason }` (undefined without a header), or `{ error }`, the 400 the
     * API answers for a header that is not percent-encoded UTF-8 or whose text is not 1 to 500 characters on one line.
     */
    parseReason(raw) {
      if (raw === undefined) return { reason: undefined };
      if (!PRINTABLE_ASCII.test(raw)) {
        return {
          error: refusedReason("reason-not-ascii", "Must be printable ASCII: percent-encode any other character."),
        };
      }
      let text;
      try {
        text = decodeURIComponent(raw);
      } catch {
        return {
          error: refusedReason("reason-bad-encoding", "Must be percent-encoded UTF-8; send a literal % as %25."),
        };
      }
      const reason = text.trim();
      if (reason.length === 0)
        return { error: refusedReason("reason-empty", "Too small: expected 1 character or more.") };
      if (reason.length > AUDIT_LIMITS.reasonMax) {
        return {
          error: refusedReason("reason-too-long", `Too big: expected at most ${AUDIT_LIMITS.reasonMax} characters.`),
        };
      }
      if (!AuditReasonSchema.safeParse(reason).success) {
        return { error: refusedReason("reason-unsafe-characters", "Must not contain unsafe characters.") };
      }
      if (holdsSecretShape(reason)) {
        return {
          error: refusedReason("reason-holds-secret", "Must not contain a key, a token, a secret or an email address."),
        };
      }
      return { reason };
    },

    /** The 400 of a sensitive change sent without a reason. */
    reasonRequired() {
      return problem(400, "reason-required", "Reason required", {
        detail: "This change needs a reason. Send it as: X-Airverse-Reason: <1 to 500 characters>.",
      });
    },

    /**
     * Appends one entry to the Organization's chain and returns it.
     * @param {string} organizationId
     * @param {{ keyId: string, action: string, appId?: string, target: { kind: string, id: string }, reason?: string, summary: string }} change
     * @returns {any} the entry, in the shape of the protocol's `AuditEntry`
     */
    record(organizationId, { keyId, action, appId, target, reason, summary }) {
      const chain = chainOf(organizationId);
      const last = chain.at(-1);
      const entry = {
        id: `aud_${randomBytes(12).toString("hex")}`,
        organization_id: organizationId,
        seq: chain.length + 1,
        at: new Date(now()).toISOString(),
        actor: { kind: "admin_key", key_id: keyId },
        action,
        ...(appId === undefined ? {} : { app_id: appId }),
        target,
        ...(reason === undefined ? {} : { reason }),
        summary: summary.slice(0, 500),
        request_id: randomUUID(),
        prev_hash: last?.hash ?? GENESIS,
      };
      entry.hash = hashOf(entry);
      chain.push(entry);
      return entry;
    },

    /** Stub only: changes a stored entry without rehashing it, as an attacker with database access would. */
    tamper(organizationId, seq, changes) {
      const entry = chainOf(organizationId).find((one) => one.seq === seq);
      if (entry) Object.assign(entry, changes);
    },

    /** `GET /v1/audit`, `/v1/audit/verify`, `/v1/audit/export`; null for any other request. */
    handle(organizationId, method, path, query) {
      if (!path.startsWith("/v1/audit")) return null;
      if (method !== "GET") return problem(405, "method-not-allowed", "Method Not Allowed");
      const chain = chainOf(organizationId);

      if (path === "/v1/audit") {
        const action = query.get("action");
        const appId = query.get("app_id");
        const targetId = query.get("target_id");
        const from = query.get("from");
        const to = query.get("to");
        const cursor = query.get("cursor");
        const limitText = query.get("limit");
        if (action !== null && !/^[a-z_]+(?:\.[a-z_]+)+$/.test(action)) return invalid("action", "Invalid option");
        if (appId !== null && !/^app_[0-9a-f]{24}$/.test(appId)) return invalid("app_id", "Expected an App id.");
        if (from !== null && !isApiTime(from)) return invalid("from", "Must be a time in the years 2000 to 2099.");
        if (to !== null && !isApiTime(to)) return invalid("to", "Must be a time in the years 2000 to 2099.");
        if (cursor !== null && !/^[1-9][0-9]{0,15}$/.test(cursor)) return invalid("cursor", "Expected a cursor.");
        if (
          limitText !== null &&
          (!/^[0-9]{1,9}$/.test(limitText) || Number(limitText) < 1 || Number(limitText) > LIST_MAX)
        ) {
          return invalid("limit", `Expected an integer from 1 to ${LIST_MAX}.`);
        }
        const limit = limitText === null ? LIST_DEFAULT : Number(limitText);
        const matching = chain
          .filter(
            (entry) =>
              (action === null || entry.action === action) &&
              (appId === null || entry.app_id === appId) &&
              (targetId === null || entry.target.id === targetId) &&
              (from === null || entry.at >= new Date(from).toISOString()) &&
              (to === null || entry.at < new Date(to).toISOString()) &&
              (cursor === null || entry.seq < Number(cursor)),
          )
          .reverse();
        const entries = matching.slice(0, limit);
        const next = matching.length > limit ? String(entries.at(-1).seq) : null;
        return { status: 200, body: { entries, next_cursor: next } };
      }

      if (path === "/v1/audit/verify") {
        let prev = GENESIS;
        let broken = null;
        chain.forEach((entry, index) => {
          if (broken !== null) return;
          if (entry.seq !== index + 1 || entry.prev_hash !== prev || hashOf(entry) !== entry.hash) broken = index + 1;
          else prev = entry.hash;
        });
        return {
          status: 200,
          body: {
            verify: { valid: broken === null, entries: chain.length, last_seq: chain.length, first_broken_seq: broken },
            signed_head: signedHead(organizationId),
          },
        };
      }

      if (path === "/v1/audit/export") {
        return {
          status: 200,
          contentType: "application/x-ndjson",
          // The signed head first, then every entry up to it, oldest first.
          body: [{ type: "audit_head", ...signedHead(organizationId) }, ...chain]
            .map((line) => `${JSON.stringify(line)}\n`)
            .join(""),
        };
      }
      return problem(404, "not-found", "Not Found");
    },
  };
}

/** What an Enforce Rule enforces, as the API compares it: path, methods in any order, action, requirement, limit. */
const enforcement = (rule) =>
  canonicalJson({
    path: rule?.path,
    methods: [...(rule?.methods ?? [])].sort(),
    action: rule?.action,
    requires: rule?.requires ?? null,
    limit: rule?.limit ?? null,
  });

/**
 * The ids of the Rules of `after` that promote: enforced, and not enforced in `before` or enforced there on other
 * traffic. As the API decides it.
 */
export function promotedRules(before, after) {
  const enforcedBefore = new Map(
    (before ?? []).filter((rule) => rule?.mode === "enforce").map((rule) => [rule.id, enforcement(rule)]),
  );
  return (after ?? [])
    .filter((rule) => rule?.mode === "enforce" && enforcedBefore.get(rule.id) !== enforcement(rule))
    .map((rule) => rule.id);
}

/** The changes the stub records: method, path pattern, and what the entry says, from the path's match. */
const CHANGES = [
  [
    "POST",
    /^\/v1\/apps$/,
    (_m, _q, r) => ({
      action: "app.create",
      appId: r?.app?.id,
      target: { kind: "app", id: r?.app?.id },
      summary: `Created App ${r?.app?.id}.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/apps\/([^/]+)\/patches\/([^/]+)\/mode$/,
    ([, appId, patchId], q) => ({
      action: q?.mode === "enforce" ? "patch.promote" : "patch.demote",
      appId,
      target: { kind: "patch", id: patchId },
      summary: `${q?.mode === "enforce" ? "Enforced" : "Put back to monitor"} ${patchId} in ${q?.environment}.`,
    }),
  ],
  [
    "PATCH",
    /^\/v1\/incidents\/([^/]+)$/,
    ([, id], q) => ({
      action: q?.status === "resolved" ? "incident.resolve" : "incident.acknowledge",
      target: { kind: "incident", id },
      summary: `${q?.status === "resolved" ? "Resolved" : "Acknowledged"} ${id}.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/incidents\/([^/]+)\/containments$/,
    ([, id], _q, r) => ({
      action: "containment.create",
      appId: r?.containment?.app_id,
      target: { kind: "containment", id: r?.containment?.id },
      summary: `Blocked ${r?.containment?.target?.kind ?? "a target"} of ${id} until ${r?.containment?.expires_at}.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/containments\/([^/]+)\/lift$/,
    ([, id], _q, r) => ({
      action: "containment.lift",
      appId: r?.containment?.app_id,
      target: { kind: "containment", id },
      summary: `Lifted ${id}.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/allowlist$/,
    (_m, _q, r) => ({
      action: "allowlist_entry.create",
      target: { kind: "allowlist_entry", id: r?.entry?.id },
      summary: `Added ${r?.entry?.cidr}.`,
    }),
  ],
  [
    "DELETE",
    /^\/v1\/allowlist\/([^/]+)$/,
    ([, id]) => ({
      action: "allowlist_entry.delete",
      target: { kind: "allowlist_entry", id },
      summary: `Removed ${id}.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/alert-channels$/,
    (_m, _q, r) => ({
      action: "alert_channel.create",
      target: { kind: "alert_channel", id: r?.channel?.id },
      summary: `Added ${r?.channel?.kind} channel ${r?.channel?.id}.`,
    }),
  ],
  [
    "DELETE",
    /^\/v1\/alert-channels\/([^/]+)$/,
    ([, id]) => ({ action: "alert_channel.delete", target: { kind: "alert_channel", id }, summary: `Removed ${id}.` }),
  ],
  [
    "POST",
    /^\/v1\/alert-channels\/([^/]+)\/test$/,
    ([, id]) => ({
      action: "alert_channel.test",
      target: { kind: "alert_channel", id },
      summary: `Sent a test alert to ${id}.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/alert-channels\/[^/]+\/recipients\/([^/]+)\/resend$/,
    ([, id]) => ({
      action: "alert_recipient.resend",
      target: { kind: "alert_recipient", id },
      summary: `Sent ${id} a new confirmation email.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/findings\/([^/]+)\/(ignore|reopen)$/,
    ([, id, verb], q, r) => ({
      action: verb === "ignore" ? "finding.ignore" : "finding.reopen",
      appId: r?.finding?.app_id,
      target: { kind: "finding", id },
      summary: verb === "ignore" ? `Ignored ${id} until ${q?.until}.` : `Reopened ${id}.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/apps\/([^/]+)\/builds\/[^/]+\/assessments$/,
    ([, appId], _q, r) => ({
      action: "assessment.create",
      appId,
      target: { kind: "assessment", id: r?.assessment?.id },
      summary: `Requested ${r?.assessment?.id}.`,
    }),
  ],
  [
    "POST",
    /^\/v1\/targets$/,
    (_m, _q, r) => ({
      action: "target.create",
      target: { kind: "target", id: r?.target?.id },
      summary: `Added ${r?.target?.host}.`,
    }),
  ],
  [
    "DELETE",
    /^\/v1\/targets\/([^/]+)$/,
    ([, id]) => ({ action: "target.delete", target: { kind: "target", id }, summary: `Removed ${id}.` }),
  ],
  [
    "POST",
    /^\/v1\/targets\/([^/]+)\/verify$/,
    ([, id]) => ({ action: "target.verify", target: { kind: "target", id }, summary: `Checked ${id}.` }),
  ],
  [
    "POST",
    /^\/v1\/rules-of-engagement$/,
    (_m, q, r) => ({
      action: "rules_of_engagement.sign",
      target: { kind: "rules_of_engagement", id: r?.version?.id },
      summary: `Signed ${r?.version?.id} at ${r?.version?.intensity ?? q?.intensity} intensity, ${r?.version?.scope?.length ?? 0} targets in scope.`,
    }),
  ],
];

/** A publish (PUT) or a rollback (POST …/rollback) of a Policy: promotes when it enforces a Rule anew. */
function policyChange(method, path, request, response, rulesBefore) {
  const match = /^\/v1\/apps\/([^/]+)\/policies\/([^/]+)(\/rollback)?$/.exec(path);
  if (match === null) return null;
  const [, appId, environment, rollback] = match;
  if (!((method === "PUT" && !rollback) || (method === "POST" && rollback))) return null;
  const promoted = promotedRules(rulesBefore, response?.policy?.rules ?? request?.rules ?? []);
  const version = response?.policy?.version;
  const base = rollback
    ? `Rolled back to the Rules of version ${request?.version} as version ${version}`
    : `Published version ${version}`;
  const action = rollback ? "policy.rollback" : promoted.length > 0 ? "policy.rule.promote" : "policy.publish";
  const summary = promoted.length > 0 ? `${base}; promoted to enforce: ${promoted.join(", ")}.` : `${base}.`;
  return { action, appId, target: { kind: "policy", id: `${appId}/${environment}` }, summary };
}

/**
 * What a successful change records: the action, the App, the target and a summary without secrets, from the method,
 * the path, the request body and the response body (and, for a publish or rollback, the Rules before it). Null for a
 * request that changes nothing.
 */
export function auditOf(method, path, request, response, rulesBefore = []) {
  const policy = policyChange(method, path, request, response, rulesBefore);
  if (policy !== null) return policy;
  for (const [verb, pattern, describe] of CHANGES) {
    if (verb !== method) continue;
    const match = pattern.exec(path);
    if (match !== null) return describe(match, request, response);
  }
  return null;
}
