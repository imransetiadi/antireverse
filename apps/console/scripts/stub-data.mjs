// Data controls of the stand-in API (slice 18b), in the shape of the protocol (checked by test/stub-data.test.ts):
// the Organization export (NDJSON: a manifest, the rows, an end line with the row counts, a SHA-256 over the
// preceding lines and an Ed25519 signature), the Organization deletion with its 7-day grace period and its
// cancellation, the gate that refuses every other route of an Organization pending deletion (403
// organization-deletion-pending), and subject requests by actor hash. No purge runs here: a deletion report is never
// found. Each answer that changes or exports something carries the audit entry the caller records. As in the API:
// bodies are validated with the protocol's schemas before the reason is checked; manifests carry `consistency` and
// the Organization export the signed audit head; audit entries name a subject by `auditSubjectRef`, never by its
// hash; the Organization export takes from a per-Organization budget of 20 a minute that audit verification and the
// audit export share (`takeRead`), answering 429 too-many-requests with Retry-After when it is spent.
// Slice 18c: the Event retention (`GET`/`PUT /v1/organization/retention`), 30 days for a new Organization; the body is
// validated first, then a shortening needs the reason, as in the API. No retention job runs here: the last run is the
// one given to `recordRetentionRun`, else null.
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import {
  DEFAULT_EVENT_RETENTION_DAYS,
  EXPORT_CONSISTENCY,
  RETENTION_FIXED_DAYS,
  RequestDeletionRequestSchema,
  SubjectRequestSchema,
  UpdateRetentionRequestSchema,
} from "@antireverse/protocol";
import { auditSubjectRef } from "@antireverse/protocol/server";

const PROBLEMS = "https://antireverse.dev/problems/";
const GRACE_DAYS = 7;
const DAY_MS = 86_400_000;
const NDJSON = "application/x-ndjson";
/** The API's `AUDIT_READS_PER_MINUTE`: audit verifications and exports and Organization exports, per Organization. */
const READS_PER_MINUTE = 20;
const MINUTE_MS = 60_000;

const problem = (status, kind, title, extra = {}) => ({
  status,
  body: { type: `${PROBLEMS}${kind}`, title, status, ...extra },
});
const invalid = (path, message) => problem(400, "validation", "Invalid request", { errors: [{ path, message }] });
/** The body as `schema` reads it, or the validation problem the API answers with. */
function validated(schema, body) {
  const parsed = schema.safeParse(body);
  if (parsed.success) return { data: parsed.data };
  return {
    error: problem(400, "validation", "Invalid request", {
      errors: parsed.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })),
    }),
  };
}
const reasonRequired = () =>
  problem(400, "reason-required", "Reason required", {
    detail: "This change needs a reason. Send it as: X-Airverse-Reason: <1 to 500 characters>.",
  });

/** JSON with sorted keys at every depth: the text the end line signs. */
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** The routes an Organization pending deletion may still use. */
const OPEN_DURING_DELETION = new Set([
  "GET /v1/organization/deletion",
  "DELETE /v1/organization/deletion",
  "GET /v1/organization/export",
]);

/**
 * @param {{
 *   now?: () => number,
 *   auditHead?: (organizationId: string) => object,
 *   tables: (organizationId: string) => Record<string, object[]>,
 *   subject: {
 *     rows: (organizationId: string, ipHash: string) => { events: object[], containments: object[] },
 *     erase: (organizationId: string, ipHash: string, atMs: number) =>
 *       { events_erased: number, containments_erased: number, active_containments: { id: string, expires_at: string }[] },
 *   },
 * }} deps
 */
export function createDataStore({ now = () => Date.now(), auditHead, tables, subject }) {
  // The stub's own Ed25519 key for export end lines, generated per process; only signatures leave.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicRaw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const keyId = createHash("sha256").update(publicRaw).digest("hex").slice(0, 16);
  /** @type {Map<string, object>} Organization id → its pending deletion */
  const pendingByOrg = new Map();
  /** @type {Map<string, { start: number, count: number }>} Organization id → its read budget of this minute */
  const reads = new Map();
  /** @type {Map<string, number>} Organization id → its Event retention in days (slice 18c) */
  const retentionDays = new Map();
  /** @type {Map<string, { ran_at: string, complete: boolean, counts: Record<string, number> }>} last run per Organization */
  const lastRuns = new Map();

  /** The Organization's retention and its last run: the body of `GET /v1/organization/retention`. */
  const retentionBody = (organizationId) => ({
    retention: {
      event_retention_days: retentionDays.get(organizationId) ?? DEFAULT_EVENT_RETENTION_DAYS,
      ...RETENTION_FIXED_DAYS,
    },
    last_run: lastRuns.get(organizationId) ?? null,
  });

  /** Takes one read from the Organization's budget of this minute. */
  function takeRead(organizationId) {
    const at = now();
    let window = reads.get(organizationId);
    if (!window || at - window.start >= MINUTE_MS) {
      window = { start: at, count: 0 };
      reads.set(organizationId, window);
    }
    if (window.count >= READS_PER_MINUTE) {
      return { allowed: false, retryAfterS: Math.max(1, Math.ceil((window.start + MINUTE_MS - at) / 1000)) };
    }
    window.count += 1;
    return { allowed: true, retryAfterS: 0 };
  }

  /** NDJSON of a manifest, the rows of `rowsByTable`, and the signed end line. */
  function ndjson(manifest, rowsByTable) {
    const lines = [
      JSON.stringify({
        kind: "manifest",
        ...manifest,
        consistency: EXPORT_CONSISTENCY,
        tables: Object.keys(rowsByTable),
      }),
    ];
    const counts = {};
    for (const [table, rows] of Object.entries(rowsByTable)) {
      counts[table] = rows.length;
      for (const row of rows) lines.push(JSON.stringify({ kind: "row", table, row }));
    }
    const before = `${lines.join("\n")}\n`;
    const sha256 = createHash("sha256").update(before, "utf8").digest("hex");
    const signature = sign(null, Buffer.from(canonicalJson({ counts, sha256 }), "utf8"), privateKey).toString(
      "base64url",
    );
    return `${before}${JSON.stringify({ kind: "end", counts, sha256, signature, key_id: keyId })}\n`;
  }

  return {
    takeRead,

    /** The Organization's Event retention in days (slice 17a: usage reports it). */
    eventRetentionDays: (organizationId) => retentionBody(organizationId).retention.event_retention_days,

    /** The public half of the key that signs export end lines. */
    publicKey: () => ({ key_id: keyId, algorithm: "Ed25519", public_key: publicRaw.toString("base64url") }),

    /** Records a run of the retention job for the Organization (the stub runs none itself). */
    recordRetentionRun(organizationId, run) {
      lastRuns.set(organizationId, { ran_at: run.ran_at, complete: run.complete, counts: { ...run.counts } });
    },

    /** The pending deletion of an Organization, or null. */
    pending: (organizationId) => pendingByOrg.get(organizationId) ?? null,

    /** The API's gate: a 403 answer for a route closed while the Organization's deletion is pending, else null. */
    gate(organizationId, method, path) {
      if (!pendingByOrg.has(organizationId) || OPEN_DURING_DELETION.has(`${method} ${path}`)) return null;
      return problem(403, "organization-deletion-pending", "Organization deletion pending", {
        detail:
          "This Organization is scheduled for deletion. Until the deletion is cancelled, only its status, its cancellation and the export are available.",
      });
    },

    /**
     * The data-control routes; null for any other request. `reason` is the decoded reason header, if any. A 2xx
     * answer that changes or exports something carries `audit`, the entry the caller records.
     */
    handle(organization, method, path, body, reason) {
      const organizationId = organization.id;
      const at = now();
      const iso = new Date(at).toISOString();
      const day = iso.slice(0, 10);

      if (/^\/v1\/deletions\/[^/]+\/report$/.test(path) && method === "GET") {
        return problem(404, "not-found", "Not found");
      }
      if (path === "/v1/organization/deletion") {
        if (method === "GET") return { status: 200, body: { deletion: pendingByOrg.get(organizationId) ?? null } };
        if (method === "POST") {
          const read = validated(RequestDeletionRequestSchema, body);
          if (read.error) return read.error;
          if (reason === undefined) return reasonRequired();
          const name = read.data.confirm_name;
          if (name !== organization.name) {
            return invalid("confirm_name", "Must be the Organization's name, exactly as it is shown.");
          }
          if (pendingByOrg.has(organizationId)) return problem(409, "conflict", "Conflict");
          const deletion = {
            id: `del_${randomBytes(12).toString("hex")}`,
            organization_id: organizationId,
            status: "pending",
            requested_at: iso,
            purge_after: new Date(at + GRACE_DAYS * DAY_MS).toISOString(),
            cancelled_at: null,
            purged_at: null,
          };
          pendingByOrg.set(organizationId, deletion);
          return {
            status: 201,
            body: { deletion },
            audit: {
              action: "organization.deletion.request",
              target: { kind: "organization_deletion", id: deletion.id },
              summary: `Requested the deletion of the Organization ${organizationId}; its data is erased after ${deletion.purge_after}.`,
            },
          };
        }
        if (method === "DELETE") {
          if (reason === undefined) return reasonRequired();
          const pending = pendingByOrg.get(organizationId);
          if (!pending) return problem(404, "not-found", "Not found");
          pendingByOrg.delete(organizationId);
          const deletion = { ...pending, status: "cancelled", cancelled_at: iso };
          return {
            status: 200,
            body: { deletion },
            audit: {
              action: "organization.deletion.cancel",
              target: { kind: "organization_deletion", id: deletion.id },
              summary: `Cancelled the deletion ${deletion.id} of the Organization ${organizationId}.`,
            },
          };
        }
        return problem(405, "method-not-allowed", "Method Not Allowed");
      }
      if (path === "/v1/organization/retention") {
        if (method === "GET") return { status: 200, body: retentionBody(organizationId) };
        if (method === "PUT") {
          const read = validated(UpdateRetentionRequestSchema, body);
          if (read.error) return read.error;
          const days = read.data.event_retention_days;
          const before = retentionBody(organizationId).retention.event_retention_days;
          if (days < before && reason === undefined) return reasonRequired();
          retentionDays.set(organizationId, days);
          return {
            status: 200,
            body: {
              ...retentionBody(organizationId),
              events_removed_before: new Date(at - days * DAY_MS).toISOString(),
            },
            audit: {
              action: "organization.retention.update",
              target: { kind: "organization", id: organizationId },
              summary: `Changed the Event retention from ${before} to ${days} days.`,
            },
          };
        }
        return problem(405, "method-not-allowed", "Method Not Allowed");
      }
      if (path === "/v1/organization/export" && method === "GET") {
        const taken = takeRead(organizationId);
        if (!taken.allowed) {
          return {
            ...problem(429, "too-many-requests", "Too many requests", {
              detail: "Too many reads for this Organization. Try again after the time in Retry-After.",
            }),
            headers: { "retry-after": String(taken.retryAfterS) },
          };
        }
        const rows = tables(organizationId);
        return {
          status: 200,
          contentType: NDJSON,
          headers: { "content-disposition": `attachment; filename="airverse-${organizationId}-${day}.ndjson"` },
          body: ndjson(
            {
              format: "airverse.export.v1",
              organization_id: organizationId,
              generated_at: iso,
              ...(auditHead ? { audit_head: auditHead(organizationId) } : {}),
            },
            rows,
          ),
          audit: {
            action: "organization.export",
            target: { kind: "organization", id: organizationId },
            summary: `Exported the Organization's data (${Object.keys(rows).length} tables).`,
          },
        };
      }
      if (path === "/v1/subjects/export" && method === "POST") {
        const read = validated(SubjectRequestSchema, body);
        if (read.error) return read.error;
        const ipHash = read.data.ip_hash;
        const rows = subject.rows(organizationId, ipHash);
        return {
          status: 200,
          contentType: NDJSON,
          headers: { "content-disposition": `attachment; filename="airverse-subject-${ipHash}-${day}.ndjson"` },
          body: ndjson(
            {
              format: "airverse.subject.v1",
              organization_id: organizationId,
              generated_at: iso,
              subject: { ip_hash: ipHash },
            },
            rows,
          ),
          audit: {
            action: "subject.export",
            target: { kind: "subject", id: auditSubjectRef(organizationId, ipHash) },
            summary: `Exported the subject's data: ${rows.events.length} Events, ${rows.containments.length} blocks.`,
          },
        };
      }
      if (path === "/v1/subjects/erase" && method === "POST") {
        const read = validated(SubjectRequestSchema, body);
        if (read.error) return read.error;
        if (reason === undefined) return reasonRequired();
        const ipHash = read.data.ip_hash;
        const erased = subject.erase(organizationId, ipHash, at);
        const report = { ip_hash: ipHash, ...erased };
        return {
          status: 200,
          body: { report },
          audit: {
            action: "subject.erase",
            target: { kind: "subject", id: auditSubjectRef(organizationId, ipHash) },
            summary: `Erased the subject's data: ${report.events_erased} Events, ${report.containments_erased} ended blocks; ${report.active_containments.length} active blocks kept until they end.`,
          },
        };
      }
      return null;
    },
  };
}
