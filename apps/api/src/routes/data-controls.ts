import {
  canonicalJson,
  DATA_EXPORT_CONTENT_TYPE,
  DATA_EXPORT_FORMAT,
  DELETION_GRACE_DAYS,
  type DeletionResponse,
  type DeletionStatusResponse,
  ID_PATTERNS,
  RequestDeletionRequestSchema,
  type RetentionResponse,
  type SignedAuditHead,
  SUBJECT_EXPORT_FORMAT,
  type SubjectEraseResponse,
  SubjectRequestSchema,
  UpdateRetentionRequestSchema,
  type UpdateRetentionResponse,
} from "@antireverse/protocol";
import { auditSubjectRef, newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import type { WindowLimiter } from "../attestation/limiter.ts";
import { audit, auditActor, reasonMissing } from "../audit.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import { EXPORT_TABLES, type ExportSource, exportStream } from "../data/export.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import type { Signer } from "../signer.ts";
import { auditHead } from "../stores/audit.ts";
import { cancelDeletion, deletionReport, insertDeletion, pendingDeletion } from "../stores/deletions.ts";
import { findOrganization } from "../stores/organizations.ts";
import { lastRetentionRun, lockedRetention, organizationRetention, setEventRetention } from "../stores/retention.ts";
import { validateJson } from "../validate.ts";

// Data controls (slice 18b): the Organization export, the Organization deletion with a grace period, the signed
// deletion report, and subject requests by actor hash; and the Event retention (slice 18c). Admin keys only. While a deletion is pending, the deletion
// status, its cancellation and the export stay open to the Organization's keys; every other route refuses them
// (`requireKey`). The deletion report is public by its id, which only the Organization was given.

const DAY_MS = 86_400_000;
/** SQL state of a unique violation: a second pending deletion. */
const UNIQUE_VIOLATION = "23505";

/** Which rows of a subject: the Events and the blocks of one actor hash. */
function subjectSources(ipHash: string): ExportSource[] {
  return [
    { table: "events", where: "payload->'actor'->>'ip_hash' = $2", params: [ipHash] },
    { table: "containments", where: "ip_hash = $2", params: [ipHash] },
  ];
}

export function dataControlRoutes(deps: {
  db: Db;
  /** The audit key: signs the export's end line. */
  signer: Signer;
  /** The per-Organization budget shared with audit verification and export. */
  reads: WindowLimiter;
  now?: (() => Date) | undefined;
}): Hono<AppEnv> {
  const { db, signer, reads } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");
  const adminDuringDeletion = requireKey(db, "admin", { duringDeletion: true });

  routes.get("/v1/organization/export", adminDuringDeletion, async (c) => {
    const { organizationId } = c.var.principal;
    const taken = reads.take(organizationId, now().getTime());
    if (!taken.allowed) {
      c.header("Retry-After", String(taken.retryAfterS));
      return problem(c, "too-many-audit-reads");
    }
    const at = now();
    const actor = auditActor(c);
    // The entry first, so that the export holds it too; then the chain head the export is cut at, in the same
    // transaction: the audit tables are exported up to exactly this head, whatever is written while the rest streams.
    const head = await db.tx({ organizationId }, async (q) => {
      await audit(q, actor, {
        action: "organization.export",
        target: { kind: "organization", id: organizationId },
        summary: `Exported the Organization's data (${EXPORT_TABLES.length} tables).`,
        at,
      });
      return auditHead(q);
    });
    const signedHead: SignedAuditHead = {
      head: { organization_id: organizationId, seq: head.seq, hash: head.hash, at: at.toISOString() },
      key_id: signer.keyId,
      signature: "",
    };
    signedHead.signature = signer.sign(new TextEncoder().encode(canonicalJson(signedHead.head)));
    const sources: ExportSource[] = EXPORT_TABLES.map((table) => {
      if (table === "audit_heads") {
        return { table, rows: [{ organization_id: organizationId, seq: head.seq, hash: head.hash }] };
      }
      if (table === "audit_entries") return { table, where: "seq <= $2", params: [head.seq], key: ["seq"] };
      return { table };
    });
    const body = exportStream({
      db,
      organizationId,
      signer,
      manifest: {
        format: DATA_EXPORT_FORMAT,
        organization_id: organizationId,
        generated_at: at.toISOString(),
        audit_head: signedHead,
      },
      sources,
    });
    return c.body(body, 200, {
      "Content-Type": DATA_EXPORT_CONTENT_TYPE,
      "Content-Disposition": `attachment; filename="airverse-${organizationId}-${at.toISOString().slice(0, 10)}.ndjson"`,
    });
  });

  routes.get("/v1/organization/deletion", adminDuringDeletion, async (c) => {
    const { organizationId } = c.var.principal;
    const deletion = await db.tx({ organizationId }, (q) => pendingDeletion(q));
    return c.json({ deletion } satisfies DeletionStatusResponse);
  });

  // Typed confirmation of the Organization's name and a reason; purge after DELETION_GRACE_DAYS. A second request
  // never reaches this handler: the gate refuses every key of an Organization pending deletion.
  routes.post(
    "/v1/organization/deletion",
    admin,
    limitBody(),
    validateJson(RequestDeletionRequestSchema),
    async (c) => {
      const { organizationId } = c.var.principal;
      const missing = reasonMissing(c);
      if (missing !== null) return missing;
      const { confirm_name } = c.req.valid("json");
      const actor = auditActor(c);
      const at = now();
      const purgeAfter = new Date(at.getTime() + DELETION_GRACE_DAYS * DAY_MS);
      try {
        const outcome = await db.tx({ organizationId }, async (q) => {
          const organization = await findOrganization(q, organizationId);
          if (organization === null) return "not-found" as const;
          if (organization.name !== confirm_name) return "mismatch" as const;
          const deletion = await insertDeletion(q, {
            id: newId("del"),
            requestedBy: actor.keyId,
            reason: actor.reason ?? "",
            at,
            purgeAfter,
          });
          await audit(q, actor, {
            action: "organization.deletion.request",
            target: { kind: "organization_deletion", id: deletion.id },
            summary: `Requested the deletion of the Organization ${organizationId}; its data is erased after ${deletion.purge_after}.`,
            at,
          });
          return deletion;
        });
        if (outcome === "not-found") return problem(c, "not-found");
        if (outcome === "mismatch") {
          return problem(c, "validation", [
            { path: "confirm_name", message: "Must be the Organization's name, exactly as it is shown." },
          ]);
        }
        return c.json({ deletion: outcome } satisfies DeletionResponse, 201);
      } catch (error) {
        if ((error as { code?: unknown }).code === UNIQUE_VIOLATION) return problem(c, "conflict");
        throw error;
      }
    },
  );

  routes.delete("/v1/organization/deletion", adminDuringDeletion, async (c) => {
    const { organizationId } = c.var.principal;
    const missing = reasonMissing(c);
    if (missing !== null) return missing;
    const actor = auditActor(c);
    const at = now();
    const deletion = await db.tx({ organizationId }, async (q) => {
      const cancelled = await cancelDeletion(q, at);
      if (cancelled === null) return null;
      await audit(q, actor, {
        action: "organization.deletion.cancel",
        target: { kind: "organization_deletion", id: cancelled.id },
        summary: `Cancelled the deletion ${cancelled.id} of the Organization ${organizationId}.`,
        at,
      });
      return cancelled;
    });
    if (deletion === null) return problem(c, "not-found");
    return c.json({ deletion } satisfies DeletionResponse);
  });

  // The Event retention, the fixed periods and the Organization's last retention run.
  routes.get("/v1/organization/retention", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const body = await db.tx({ organizationId }, async (q) => {
      const retention = await organizationRetention(q, organizationId);
      if (retention === null) return null;
      return { retention, last_run: await lastRetentionRun(q) } satisfies RetentionResponse;
    });
    if (body === null) return problem(c, "not-found");
    return c.json(body);
  });

  // Changes the Event retention. Shortening it removes Events at the next run: it needs a reason.
  routes.put(
    "/v1/organization/retention",
    admin,
    limitBody(),
    validateJson(UpdateRetentionRequestSchema),
    async (c) => {
      const { organizationId } = c.var.principal;
      const { event_retention_days: days } = c.req.valid("json");
      const at = now();
      const outcome = await db.tx({ organizationId }, async (q) => {
        // Locked: a concurrent change waits, so the reason check and the audit use the value replaced here.
        const before = await lockedRetention(q, organizationId);
        if (before === null) return "not-found" as const;
        if (days < before.event_retention_days && reasonMissing(c) !== null) return "reason-required" as const;
        await setEventRetention(q, organizationId, days);
        await audit(q, auditActor(c), {
          action: "organization.retention.update",
          target: { kind: "organization", id: organizationId },
          summary: `Changed the Event retention from ${before.event_retention_days} to ${days} days.`,
          at,
        });
        return {
          retention: { ...before, event_retention_days: days },
          last_run: await lastRetentionRun(q),
          events_removed_before: new Date(at.getTime() - days * DAY_MS).toISOString(),
        } satisfies UpdateRetentionResponse;
      });
      if (outcome === "not-found") return problem(c, "not-found");
      if (outcome === "reason-required") return problem(c, "reason-required");
      return c.json(outcome);
    },
  );

  // Public: the signed report of a purged deletion, by the id the Organization was given at request time.
  routes.get("/v1/deletions/:deletionId/report", async (c) => {
    const deletionId = c.req.param("deletionId");
    if (!ID_PATTERNS.del.test(deletionId)) return problem(c, "not-found");
    const signed = await db.tx("none", (q) => deletionReport(q, deletionId));
    if (signed === null) return problem(c, "not-found");
    return c.json(signed);
  });

  // The Events and blocks of one actor hash, as NDJSON in the export's line format.
  routes.post("/v1/subjects/export", admin, limitBody(), validateJson(SubjectRequestSchema), async (c) => {
    const { organizationId } = c.var.principal;
    const { ip_hash } = c.req.valid("json");
    const actor = auditActor(c);
    const at = now();
    await db.tx({ organizationId }, async (q) => {
      const { rows } = await q.query<{ events: number; containments: number }>(
        `SELECT (SELECT count(*)::int FROM events WHERE payload->'actor'->>'ip_hash' = $1) AS events,
           (SELECT count(*)::int FROM containments WHERE ip_hash = $1) AS containments`,
        [ip_hash],
      );
      const counts = rows[0] ?? { events: 0, containments: 0 };
      await audit(q, actor, {
        action: "subject.export",
        target: { kind: "subject", id: auditSubjectRef(organizationId, ip_hash) },
        summary: `Exported the subject's data: ${counts.events} Events, ${counts.containments} blocks.`,
        at,
      });
    });
    const body = exportStream({
      db,
      organizationId,
      signer,
      manifest: {
        format: SUBJECT_EXPORT_FORMAT,
        organization_id: organizationId,
        generated_at: at.toISOString(),
        subject: { ip_hash },
      },
      sources: subjectSources(ip_hash),
    });
    return c.body(body, 200, {
      "Content-Type": DATA_EXPORT_CONTENT_TYPE,
      "Content-Disposition": `attachment; filename="airverse-subject-${ip_hash}-${at.toISOString().slice(0, 10)}.ndjson"`,
    });
  });

  // Erases the Events and ended blocks of one actor hash; active blocks are kept until they end and listed.
  routes.post("/v1/subjects/erase", admin, limitBody(), validateJson(SubjectRequestSchema), async (c) => {
    const { organizationId } = c.var.principal;
    const missing = reasonMissing(c);
    if (missing !== null) return missing;
    const { ip_hash } = c.req.valid("json");
    const actor = auditActor(c);
    const at = now();
    const report = await db.tx({ organizationId }, async (q) => {
      const erased = await q.query<{ events_erased: number; containments_erased: number }>(
        "SELECT * FROM subject_erase($1, $2)",
        [ip_hash, at.toISOString()],
      );
      const active = await q.query<{ id: string; expires_at: Date }>(
        `SELECT id, expires_at FROM containments
         WHERE ip_hash = $1 AND lifted_at IS NULL AND expires_at > $2 ORDER BY expires_at, id`,
        [ip_hash, at.toISOString()],
      );
      const counts = erased.rows[0] ?? { events_erased: 0, containments_erased: 0 };
      const result: SubjectEraseResponse["report"] = {
        ip_hash,
        events_erased: counts.events_erased,
        containments_erased: counts.containments_erased,
        active_containments: active.rows.map((row) => ({ id: row.id, expires_at: row.expires_at.toISOString() })),
      };
      await audit(q, actor, {
        action: "subject.erase",
        target: { kind: "subject", id: auditSubjectRef(organizationId, ip_hash) },
        summary: `Erased the subject's data: ${result.events_erased} Events, ${result.containments_erased} ended blocks; ${result.active_containments.length} active blocks kept until they end.`,
        at,
      });
      return result;
    });
    return c.json({ report } satisfies SubjectEraseResponse);
  });

  return routes;
}
