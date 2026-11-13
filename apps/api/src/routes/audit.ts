import {
  AUDIT_EXPORT_CONTENT_TYPE,
  AUDIT_GENESIS_HASH,
  type AuditEntry,
  type AuditExportHeadLine,
  type AuditHead,
  type AuditPublicKeyResponse,
  AuditQuerySchema,
  type AuditVerifyResponse,
  canonicalJson,
  type ListAuditResponse,
  type SignedAuditHead,
} from "@antireverse/protocol";
import { auditHash } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { createWindowLimiter, type WindowLimiter } from "../attestation/limiter.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import type { Signer } from "../signer.ts";
import { auditEntriesAfter, auditHead, countAuditEntriesAfter, listAuditEntries } from "../stores/audit.ts";
import { validateQuery } from "../validate.ts";

// The audit log (slice 18a), for admins only and tenant-isolated by row-level security: the list (newest first,
// filters, cursor), the chain verification, and the NDJSON export that lets a third party recompute the chain. Both
// verification and export read the head first, sign it with the audit key, and read the chain up to it in pages of
// AUDIT_PAGE, one transaction each, yielding between pages: a long chain never holds the database (one lock for every
// tenant) for long. The audit key's public half is public at /v1/audit/public-key.

/** Entries read per transaction while verifying or exporting. */
export const AUDIT_PAGE = 500;

/** Verifications and exports per Organization per minute, together. */
export const AUDIT_READS_PER_MINUTE = 20;

/** Organizations whose minute windows are tracked at once. */
const AUDIT_READ_KEYS_MAX = 10_000;

/** True when the stored entry's hash is the hash of its members. An entry that no longer validates is broken. */
function hashHolds(entry: AuditEntry): boolean {
  const { hash, ...rest } = entry;
  try {
    return auditHash(rest) === hash;
  } catch {
    return false;
  }
}

/**
 * The per-Organization budget of audit verifications and exports, which the Organization export shares (slice 18b).
 */
export function createAuditReadLimiter(perMinute: number = AUDIT_READS_PER_MINUTE): WindowLimiter {
  return createWindowLimiter({ limit: perMinute, windowMs: 60_000, maxKeys: AUDIT_READ_KEYS_MAX });
}

/** Lets other requests run between two pages. */
const yieldToOthers = () => new Promise<void>((resolve) => setImmediate(resolve));

export function auditRoutes(deps: {
  db: Db;
  /** The audit key (never the Policy key): signs the heads that verification and export hand out. */
  signer: Signer;
  now?: (() => Date) | undefined;
  /** Default `AUDIT_READS_PER_MINUTE`. */
  readsPerMinute?: number | undefined;
  /** The budget to take from, shared with the Organization export. Default: one of `readsPerMinute`. */
  reads?: WindowLimiter | undefined;
}): Hono<AppEnv> {
  const { db, signer } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");
  const reads = deps.reads ?? createAuditReadLimiter(deps.readsPerMinute);

  /** The Organization's head now, signed. */
  async function signedHead(organizationId: string): Promise<SignedAuditHead> {
    const stored = await db.tx({ organizationId }, (q) => auditHead(q));
    const head: AuditHead = {
      organization_id: organizationId,
      seq: stored.seq,
      hash: stored.hash,
      at: now().toISOString(),
    };
    return {
      head,
      key_id: signer.keyId,
      signature: signer.sign(new TextEncoder().encode(canonicalJson(head))),
    };
  }

  routes.get("/v1/audit/public-key", (c) =>
    c.json({
      key_id: signer.keyId,
      algorithm: "Ed25519",
      public_key: signer.publicKey,
    } satisfies AuditPublicKeyResponse),
  );

  routes.get("/v1/audit", admin, validateQuery(AuditQuerySchema), async (c) => {
    const { organizationId } = c.var.principal;
    const query = c.req.valid("query");
    const page = await db.tx({ organizationId }, (q) =>
      listAuditEntries(q, {
        action: query.action,
        appId: query.app_id,
        targetId: query.target_id,
        from: query.from === undefined ? undefined : new Date(query.from),
        to: query.to === undefined ? undefined : new Date(query.to),
        beforeSeq: query.cursor,
        // One more than asked: its presence says that another page follows.
        limit: query.limit + 1,
      }),
    );
    const entries = page.slice(0, query.limit);
    const last = entries.at(-1);
    const nextCursor = page.length > query.limit && last !== undefined ? String(last.seq) : null;
    return c.json({ entries, next_cursor: nextCursor } satisfies ListAuditResponse);
  });

  // Recomputes the chain from the first entry up to the head read first: the first seq at which it no longer holds
  // (an entry missing, altered or out of chain, or a head beyond the last entry), or null.
  routes.get("/v1/audit/verify", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const taken = reads.take(organizationId, now().getTime());
    if (!taken.allowed) {
      c.header("Retry-After", String(taken.retryAfterS));
      return problem(c, "too-many-audit-reads");
    }
    const signed = await signedHead(organizationId);
    const head = signed.head;
    let expected = 1;
    let prev = AUDIT_GENESIS_HASH;
    let entries = 0;
    let broken: number | null = null;
    let after = 0;
    while (after < head.seq) {
      await yieldToOthers();
      const page = await db.tx({ organizationId }, (q) => auditEntriesAfter(q, after, AUDIT_PAGE, head.seq));
      for (const entry of page) {
        entries++;
        if (broken !== null) continue;
        if (entry.seq === expected && entry.prev_hash === prev && hashHolds(entry)) {
          prev = entry.hash;
          expected++;
        } else {
          broken = expected;
        }
      }
      const last = page.at(-1);
      if (page.length < AUDIT_PAGE || last === undefined) break;
      after = last.seq;
    }
    // Entries beyond the head: only the owner could have written them, past the trigger.
    const beyond = await db.tx({ organizationId }, (q) => countAuditEntriesAfter(q, head.seq));
    entries += beyond;
    const verified = expected - 1;
    if (broken === null) {
      if (head.seq > verified) broken = verified + 1;
      else if (head.hash !== prev) broken = verified === 0 ? 1 : verified;
      else if (beyond > 0) broken = head.seq + 1;
    }
    const verify = { valid: broken === null, entries, last_seq: head.seq, first_broken_seq: broken };
    return c.json({ verify, signed_head: signed } satisfies AuditVerifyResponse);
  });

  // The signed head as the first line, then every entry up to it, oldest first, one JSON object per line, hashes
  // included. Read in pages of AUDIT_PAGE, one transaction each.
  routes.get("/v1/audit/export", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const taken = reads.take(organizationId, now().getTime());
    if (!taken.allowed) {
      c.header("Retry-After", String(taken.retryAfterS));
      return problem(c, "too-many-audit-reads");
    }
    const signed = await signedHead(organizationId);
    const upTo = signed.head.seq;
    const encoder = new TextEncoder();
    const first: AuditExportHeadLine = { type: "audit_head", ...signed };
    let after = 0;
    let started = false;
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (!started) {
          started = true;
          controller.enqueue(encoder.encode(`${JSON.stringify(first)}\n`));
          if (upTo === 0) controller.close();
          return;
        }
        await yieldToOthers();
        const page = await db.tx({ organizationId }, (q) => auditEntriesAfter(q, after, AUDIT_PAGE, upTo));
        if (page.length > 0) {
          controller.enqueue(encoder.encode(page.map((entry) => `${JSON.stringify(entry)}\n`).join("")));
          after = page.at(-1)?.seq ?? after;
        }
        if (page.length < AUDIT_PAGE || after >= upTo) controller.close();
      },
    });
    return c.body(body, 200, {
      "Content-Type": AUDIT_EXPORT_CONTENT_TYPE,
      "Content-Disposition": 'attachment; filename="audit.ndjson"',
    });
  });

  return routes;
}
