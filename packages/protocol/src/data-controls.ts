// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { SignedAuditHeadSchema } from "./audit.ts";
import { ID_PATTERNS } from "./constants.ts";
import { ActorHashSchema } from "./containment.ts";
import { canonicalJson } from "./prove.ts";
import { deepFreeze, isoDateTime, text } from "./shared.ts";

// Data controls (slice 18b, FR-CON-11, SECURITY §8, OPERATION §17): the Organization export, the Organization deletion
// with a grace period, and subject requests by actor hash. Every signature here is Ed25519 by the audit key
// (`GET /v1/audit/public-key`), over the UTF-8 bytes of the text the `…SignedText` helper returns.

/** Days between a deletion request and the purge; the request can be cancelled until then. */
export const DELETION_GRACE_DAYS = 7;

/** Media type of the Organization export and of the subject export: one JSON object per line. */
export const DATA_EXPORT_CONTENT_TYPE = "application/x-ndjson";
/** `format` of the Organization export's manifest line (`GET /v1/organization/export`). */
export const DATA_EXPORT_FORMAT = "airverse.export.v1";
/** `format` of the subject export's manifest line (`POST /v1/subjects/export`). */
export const SUBJECT_EXPORT_FORMAT = "airverse.subject.v1";

const HashSchema = z.string().regex(/^[0-9a-f]{64}$/);
const KeyIdSchema = z.string().regex(/^[0-9a-f]{16}$/);
const SignatureSchema = z.string().regex(/^[A-Za-z0-9_-]{86}$/);
const TableNameSchema = z.string().regex(/^[a-z_][a-z0-9_]{0,62}$/);
const CountsSchema = z.record(TableNameSchema, z.int().min(0));

/**
 * How consistent an export is: `per-page` — each page of a table is read in its own transaction, so a change made
 * while the export runs may be in one table and not in another. The audit chain is the exception: the Organization
 * export reads its head first (`audit_head`, signed), exports the audit tables first, and holds exactly the entries up
 * to that head, so the exported chain always verifies against the exported head.
 */
export const EXPORT_CONSISTENCY = "per-page";

/**
 * Line 1 of an export. `tables` lists the tables whose rows follow, in that order. The Organization export carries
 * the audit chain head it was cut at; a subject export names its subject.
 */
export const ExportManifestLineSchema = z.object({
  kind: z.literal("manifest"),
  format: z.enum([DATA_EXPORT_FORMAT, SUBJECT_EXPORT_FORMAT]),
  organization_id: z.string().regex(ID_PATTERNS.org),
  generated_at: isoDateTime(),
  consistency: z.literal(EXPORT_CONSISTENCY),
  tables: z.array(TableNameSchema),
  audit_head: SignedAuditHeadSchema.optional(),
  subject: z.object({ ip_hash: ActorHashSchema }).optional(),
});
export type ExportManifestLine = z.infer<typeof ExportManifestLineSchema>;

/**
 * One stored row, as its columns: timestamps as ISO 8601, binary content as base64, credentials as their hashes,
 * prefixes and last four characters only (a secret column `x` is exported as `x_sha256`).
 */
export const ExportRowLineSchema = z.object({
  kind: z.literal("row"),
  table: TableNameSchema,
  row: z.record(z.string(), z.unknown()),
});
export type ExportRowLine = z.infer<typeof ExportRowLineSchema>;

/**
 * The last line: rows per table, `sha256` (hex) over the bytes of every preceding line (newlines included), and the
 * audit key's signature of `dataExportSignedText`.
 */
export const ExportEndLineSchema = z.object({
  kind: z.literal("end"),
  counts: CountsSchema,
  sha256: HashSchema,
  signature: SignatureSchema,
  key_id: KeyIdSchema,
});
export type ExportEndLine = z.infer<typeof ExportEndLineSchema>;

export const ExportLineSchema = z.discriminatedUnion("kind", [
  ExportManifestLineSchema,
  ExportRowLineSchema,
  ExportEndLineSchema,
]);
export type ExportLine = z.infer<typeof ExportLineSchema>;

/** The text an export's end line signs: the canonical JSON of its counts and its sha256. */
export function dataExportSignedText(end: { counts: Record<string, number>; sha256: string }): string {
  return canonicalJson({ counts: { ...end.counts }, sha256: end.sha256 });
}

// --- Organization deletion ------------------------------------------------------------------------------------

/** `POST /v1/organization/deletion`: the Organization's name typed exactly. The reason goes in the reason header. */
export const RequestDeletionRequestSchema = z.strictObject({ confirm_name: text(200).min(1) });
export type RequestDeletionRequest = z.infer<typeof RequestDeletionRequestSchema>;

export const DELETION_STATUSES = deepFreeze(["pending", "cancelled", "purged"] as const);

/** A deletion request as its Organization sees it. */
export const OrganizationDeletionSchema = z.object({
  id: z.string().regex(ID_PATTERNS.del),
  organization_id: z.string().regex(ID_PATTERNS.org),
  status: z.enum(DELETION_STATUSES),
  requested_at: isoDateTime(),
  /** When the purge may run: `requested_at` plus `DELETION_GRACE_DAYS`. The data is erased at the first daily run after it. */
  purge_after: isoDateTime(),
  cancelled_at: isoDateTime().nullable(),
  purged_at: isoDateTime().nullable(),
});
export type OrganizationDeletion = z.infer<typeof OrganizationDeletionSchema>;

/** `POST /v1/organization/deletion` (201) and `DELETE /v1/organization/deletion` (200). */
export const DeletionResponseSchema = z.object({ deletion: OrganizationDeletionSchema });
export type DeletionResponse = z.infer<typeof DeletionResponseSchema>;

/** `GET /v1/organization/deletion`: the pending deletion, or null. */
export const DeletionStatusResponseSchema = z.object({ deletion: OrganizationDeletionSchema.nullable() });
export type DeletionStatusResponse = z.infer<typeof DeletionStatusResponseSchema>;

/** What the purge did: rows deleted per table (every table that held the Organization's rows, `organizations` last). */
export const DeletionReportSchema = z.object({
  deletion_id: z.string().regex(ID_PATTERNS.del),
  organization_id: z.string().regex(ID_PATTERNS.org),
  requested_at: isoDateTime(),
  purge_after: isoDateTime(),
  purged_at: isoDateTime(),
  rows: CountsSchema,
  total_rows: z.int().min(0),
});
export type DeletionReport = z.infer<typeof DeletionReportSchema>;

/** `GET /v1/deletions/:deletionId/report`: the report signed with the audit key over `deletionReportSignedText`. */
export const SignedDeletionReportSchema = z.object({
  report: DeletionReportSchema,
  key_id: KeyIdSchema,
  signature: SignatureSchema,
});
export type SignedDeletionReport = z.infer<typeof SignedDeletionReportSchema>;

/** The text a deletion report's signature signs: its canonical JSON. */
export function deletionReportSignedText(report: DeletionReport): string {
  return canonicalJson({ ...report, rows: { ...report.rows } });
}

export const EXAMPLE_DELETION_REPORT: DeletionReport = deepFreeze({
  deletion_id: "del_0123456789abcdef01234567",
  organization_id: "org_0123456789abcdef01234567",
  requested_at: "2026-11-13T09:00:00.000Z",
  purge_after: "2026-11-20T09:00:00.000Z",
  purged_at: "2026-11-21T03:00:00.000Z",
  rows: { api_keys: 2, apps: 1, audit_entries: 4, audit_heads: 1, events: 120, organizations: 1 },
  total_rows: 129,
});

// --- Subject requests -----------------------------------------------------------------------------------------

/**
 * How an audit entry names an end user (`auditSubjectRef` of the server entry): the target id of `subject.export` and
 * `subject.erase`, and the name of an Actor in the summary of `containment.create`. Never the actor hash itself.
 */
export const AUDIT_SUBJECT_REF_PATTERN = /^subj_[0-9a-f]{32}$/;

/**
 * `POST /v1/subjects/export` and `POST /v1/subjects/erase`: the end user's actor hash, computed by the customer with
 * the Shield key (`actorHash`). Airverse never receives the address.
 */
export const SubjectRequestSchema = z.strictObject({ ip_hash: ActorHashSchema });
export type SubjectRequest = z.infer<typeof SubjectRequestSchema>;

/** What an erasure did. Active blocks are kept until they end and listed here. */
export const SubjectEraseReportSchema = z.object({
  ip_hash: ActorHashSchema,
  events_erased: z.int().min(0),
  containments_erased: z.int().min(0),
  active_containments: z.array(z.object({ id: z.string().regex(ID_PATTERNS.cnt), expires_at: isoDateTime() })),
});
export type SubjectEraseReport = z.infer<typeof SubjectEraseReportSchema>;

export const SubjectEraseResponseSchema = z.object({ report: SubjectEraseReportSchema });
export type SubjectEraseResponse = z.infer<typeof SubjectEraseResponseSchema>;
