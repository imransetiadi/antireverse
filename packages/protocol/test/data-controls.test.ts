import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AUDIT_ACTIONS,
  AUDIT_SUBJECT_REF_PATTERN,
  AUDIT_TARGET_KINDS,
  canonicalJson,
  DATA_EXPORT_CONTENT_TYPE,
  DATA_EXPORT_FORMAT,
  DELETION_GRACE_DAYS,
  DeletionReportSchema,
  DeletionStatusResponseSchema,
  dataExportSignedText,
  deletionReportSignedText,
  EXAMPLE_DELETION_REPORT,
  EXAMPLE_SIGNED_AUDIT_HEAD,
  ExportEndLineSchema,
  ExportLineSchema,
  ExportManifestLineSchema,
  ID_PATTERNS,
  OrganizationDeletionSchema,
  RequestDeletionRequestSchema,
  SignedDeletionReportSchema,
  SUBJECT_EXPORT_FORMAT,
  SubjectEraseResponseSchema,
  SubjectRequestSchema,
} from "../src/index.ts";
import { auditSubjectRef } from "../src/server.ts";

// Slice 18b: the data-controls contract (export lines, deletion, subject requests).

const ORG = "org_0123456789abcdef01234567";
const DEL = "del_0123456789abcdef01234567";
const HASH = "iph_0123456789abcdef0123456789abcdef";

describe("data controls", () => {
  it("names the new audit actions and target kinds", () => {
    for (const action of [
      "organization.export",
      "organization.deletion.request",
      "organization.deletion.cancel",
      "subject.export",
      "subject.erase",
    ]) {
      expect(AUDIT_ACTIONS).toContain(action);
    }
    expect(AUDIT_TARGET_KINDS).toContain("organization_deletion");
    expect(AUDIT_TARGET_KINDS).toContain("subject");
  });

  it("has a deletion id pattern and a 7-day grace", () => {
    expect(ID_PATTERNS.del.test(DEL)).toBe(true);
    expect(DELETION_GRACE_DAYS).toBe(7);
    expect(DATA_EXPORT_CONTENT_TYPE).toBe("application/x-ndjson");
    expect(DATA_EXPORT_FORMAT).toBe("airverse.export.v1");
    expect(SUBJECT_EXPORT_FORMAT).toBe("airverse.subject.v1");
  });

  it("parses the three kinds of export line and refuses others", () => {
    const manifest = {
      kind: "manifest",
      format: DATA_EXPORT_FORMAT,
      organization_id: ORG,
      generated_at: "2026-11-13T09:00:00.000Z",
      consistency: "per-page",
      tables: ["apps", "events"],
      audit_head: EXAMPLE_SIGNED_AUDIT_HEAD,
    };
    expect(ExportManifestLineSchema.parse(manifest)).toEqual(manifest);
    // The manifest states how consistent the export is: each table page by page, the audit chain up to its head.
    const { consistency: _, ...without } = manifest;
    expect(ExportManifestLineSchema.safeParse(without).success).toBe(false);
    expect(ExportLineSchema.parse({ kind: "row", table: "apps", row: { id: "app_x" } }).kind).toBe("row");
    const end = {
      kind: "end",
      counts: { apps: 1, events: 0 },
      sha256: "a".repeat(64),
      signature: "A".repeat(86),
      key_id: "0123456789abcdef",
    };
    expect(ExportEndLineSchema.parse(end)).toEqual(end);
    expect(ExportLineSchema.safeParse({ kind: "other" }).success).toBe(false);
    expect(ExportLineSchema.safeParse({ ...end, sha256: "xyz" }).success).toBe(false);
    // The subject export uses the same lines; its manifest names the subject.
    const { audit_head: __, ...plain } = manifest;
    const subject = { ...plain, format: SUBJECT_EXPORT_FORMAT, subject: { ip_hash: HASH } };
    expect(ExportManifestLineSchema.parse(subject)).toEqual(subject);
  });

  it("signs the canonical JSON of the counts and the sha256 of an export", () => {
    expect(dataExportSignedText({ counts: { b: 2, a: 1 }, sha256: "f".repeat(64) })).toBe(
      canonicalJson({ counts: { a: 1, b: 2 }, sha256: "f".repeat(64) }),
    );
  });

  it("requires the typed name on a deletion request", () => {
    expect(RequestDeletionRequestSchema.parse({ confirm_name: "Acme" })).toEqual({ confirm_name: "Acme" });
    expect(RequestDeletionRequestSchema.safeParse({}).success).toBe(false);
    expect(RequestDeletionRequestSchema.safeParse({ confirm_name: "" }).success).toBe(false);
    expect(RequestDeletionRequestSchema.safeParse({ confirm_name: "Acme", extra: 1 }).success).toBe(false);
  });

  it("states a deletion and its status", () => {
    const deletion = {
      id: DEL,
      organization_id: ORG,
      status: "pending",
      requested_at: "2026-11-13T09:00:00.000Z",
      purge_after: "2026-11-20T09:00:00.000Z",
      cancelled_at: null,
      purged_at: null,
    };
    expect(OrganizationDeletionSchema.parse(deletion)).toEqual(deletion);
    expect(DeletionStatusResponseSchema.parse({ deletion: null })).toEqual({ deletion: null });
    expect(OrganizationDeletionSchema.safeParse({ ...deletion, status: "gone" }).success).toBe(false);
  });

  it("has a signed deletion report over its canonical JSON", () => {
    expect(DeletionReportSchema.parse(EXAMPLE_DELETION_REPORT)).toEqual(EXAMPLE_DELETION_REPORT);
    expect(deletionReportSignedText(EXAMPLE_DELETION_REPORT)).toBe(canonicalJson(EXAMPLE_DELETION_REPORT));
    const signed = { report: EXAMPLE_DELETION_REPORT, key_id: "0123456789abcdef", signature: "A".repeat(86) };
    expect(SignedDeletionReportSchema.parse(signed)).toEqual(signed);
    const total = Object.values(EXAMPLE_DELETION_REPORT.rows).reduce((sum, n) => sum + n, 0);
    expect(EXAMPLE_DELETION_REPORT.total_rows).toBe(total);
  });

  it("takes an actor hash for subject requests, never an address", () => {
    expect(SubjectRequestSchema.parse({ ip_hash: HASH })).toEqual({ ip_hash: HASH });
    expect(SubjectRequestSchema.safeParse({ ip_hash: "203.0.113.7" }).success).toBe(false);
    expect(SubjectRequestSchema.safeParse({ ip_hash: HASH, ip: "203.0.113.7" }).success).toBe(false);
    const report = {
      report: {
        ip_hash: HASH,
        events_erased: 3,
        containments_erased: 1,
        active_containments: [{ id: "cnt_0123456789abcdef01234567", expires_at: "2026-11-14T09:00:00.000Z" }],
      },
    };
    expect(SubjectEraseResponseSchema.parse(report)).toEqual(report);
  });

  it("names a subject in the audit log by a derived reference, never by its actor hash", () => {
    const ref = auditSubjectRef(ORG, HASH);
    expect(ref).toMatch(AUDIT_SUBJECT_REF_PATTERN);
    expect(ref).toBe(
      `subj_${createHash("sha256").update(`antireverse/audit-subject/v1\n${ORG}\n${HASH}`, "utf8").digest("hex").slice(0, 32)}`,
    );
    expect(ref).not.toContain(HASH.slice(4));
    // Per Organization: the same end user is another reference in another Organization.
    expect(auditSubjectRef("org_89abcdef0123456789abcdef", HASH)).not.toBe(ref);
    expect(() => auditSubjectRef(ORG, "203.0.113.7")).toThrow(TypeError);
  });
});
