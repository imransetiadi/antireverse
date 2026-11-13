import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AUDIT_ACTIONS,
  AUDIT_GENESIS_HASH,
  AUDIT_LIMITS,
  AUDIT_REASON_ERROR_CODES,
  AUDIT_REASON_HEADER,
  AUDIT_TARGET_KINDS,
  AUDIT_VERIFY_DOC,
  AuditEntrySchema,
  AuditExportHeadLineSchema,
  AuditExportLineSchema,
  AuditHeadSchema,
  AuditPublicKeyResponseSchema,
  AuditQuerySchema,
  AuditReasonSchema,
  AuditVerifyResponseSchema,
  canonicalJson,
  EXAMPLE_AUDIT_ENTRY,
  EXAMPLE_SIGNED_AUDIT_HEAD,
  encodeAuditReason,
  holdsSecretShape,
  ID_PATTERNS,
  ListAuditResponseSchema,
  ProblemSchema,
  SignedAuditHeadSchema,
  scrubSecretShapes,
} from "../src/index.ts";
import { auditHash } from "../src/server.ts";

const sha256 = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

describe("audit contract", () => {
  it("names every action <resource>.<verb> from a closed list", () => {
    expect(AUDIT_ACTIONS.length).toBeGreaterThan(20);
    for (const action of AUDIT_ACTIONS) expect(action).toMatch(/^[a-z_]+(\.[a-z_]+)+$/);
    expect(new Set(AUDIT_ACTIONS).size).toBe(AUDIT_ACTIONS.length);
    expect(AUDIT_ACTIONS).toContain("organization.create");
    expect(AUDIT_ACTIONS).toContain("policy.rule.promote");
    expect(AUDIT_ACTIONS).toContain("containment.create");
    expect(AUDIT_ACTIONS).toContain("alert_channel.delete");
    expect(Object.isFrozen(AUDIT_ACTIONS)).toBe(true);
  });

  it("has an aud_ identifier, the genesis hash and the reason header", () => {
    expect(ID_PATTERNS.aud.test("aud_0123456789abcdef01234567")).toBe(true);
    expect(AUDIT_GENESIS_HASH).toBe("0".repeat(64));
    expect(AUDIT_REASON_HEADER).toBe("X-Airverse-Reason");
    expect(AUDIT_LIMITS.reasonMax).toBe(500);
    expect(AUDIT_LIMITS.summaryMax).toBe(500);
  });

  it("accepts the example entry and refuses an unknown action, a long summary or a bad hash", () => {
    expect(AuditEntrySchema.parse(EXAMPLE_AUDIT_ENTRY)).toEqual(EXAMPLE_AUDIT_ENTRY);
    expect(AuditEntrySchema.safeParse({ ...EXAMPLE_AUDIT_ENTRY, action: "policy.delete_all" }).success).toBe(false);
    expect(AuditEntrySchema.safeParse({ ...EXAMPLE_AUDIT_ENTRY, summary: "x".repeat(501) }).success).toBe(false);
    expect(AuditEntrySchema.safeParse({ ...EXAMPLE_AUDIT_ENTRY, hash: "ABC" }).success).toBe(false);
    expect(AuditEntrySchema.safeParse({ ...EXAMPLE_AUDIT_ENTRY, seq: 0 }).success).toBe(false);
    expect(AuditEntrySchema.safeParse({ ...EXAMPLE_AUDIT_ENTRY, target: { kind: "planet", id: "x" } }).success).toBe(
      false,
    );
    expect(AUDIT_TARGET_KINDS).toContain(EXAMPLE_AUDIT_ENTRY.target.kind);
    expect(AuditExportLineSchema.parse(EXAMPLE_AUDIT_ENTRY)).toEqual(EXAMPLE_AUDIT_ENTRY);
  });

  it("reason: trimmed, 1 to 500 characters, no control characters", () => {
    expect(AuditReasonSchema.parse("  Incident 42 \t")).toBe("Incident 42");
    expect(AuditReasonSchema.safeParse("   ").success).toBe(false);
    expect(AuditReasonSchema.safeParse("x".repeat(501)).success).toBe(false);
    expect(AuditReasonSchema.safeParse("x".repeat(500)).success).toBe(true);
    expect(AuditReasonSchema.safeParse("one\u0007two").success).toBe(false);
  });

  it("encodeAuditReason: percent-encoded UTF-8, header-safe, a literal % as %25", () => {
    expect(encodeAuditReason("Incident-42_ok")).toBe("Incident-42_ok");
    expect(encodeAuditReason("Perbaikan darurat: blokir 100% IP")).toBe(
      "Perbaikan%20darurat%3A%20blokir%20100%25%20IP",
    );
    for (const text of ["Perbaikan darurat untuk serangan login", "日本語の理由", "Ünïcödé 🚀 ok"]) {
      const encoded = encodeAuditReason(text);
      expect(encoded).toMatch(/^[\x21-\x7e]*$/);
      expect(decodeURIComponent(encoded)).toBe(text);
    }
    expect(() => encodeAuditReason("lone \ud800 surrogate")).toThrow(TypeError);
  });

  it("holdsSecretShape: keys, secrets, Canary values, tokens and email addresses, wherever they sit", () => {
    const key = `aro_${"a".repeat(43)}`;
    for (const text of [
      `key ${key}`,
      `k_${key}`,
      "ark_prod_abcdefgh",
      `whsec_${"A".repeat(43)}`,
      "ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE",
      `beacon bcn_${"0".repeat(24)}`,
      "/api/internal/un539n4s/backup",
      `token ${"b".repeat(43)}`,
      `x${"b".repeat(43)}y`,
      "Asked by alice@corp.example",
    ]) {
      expect(holdsSecretShape(text), text).toBe(true);
    }
    for (const text of [
      "Incident 42: blocking the login wave",
      "Perbaikan darurat, 日本語",
      "karo_x",
      "aro_short",
      "ak_live_",
      "b".repeat(42),
      `key_${"0".repeat(24)} and rul_${"1".repeat(24)}`,
    ]) {
      expect(holdsSecretShape(text), text).toBe(false);
    }
    // Stateless: the same text answers the same twice (no global regex state).
    expect(holdsSecretShape(`k_${key}`)).toBe(true);
    expect(scrubSecretShapes(`App "k_${key}" for bob@x.io`)).toBe('App "k_[key]" for [email]');
  });

  it("names every reason refusal with a code, carried by a validation problem", () => {
    expect(AUDIT_REASON_ERROR_CODES).toEqual([
      "reason-not-ascii",
      "reason-bad-encoding",
      "reason-empty",
      "reason-too-long",
      "reason-unsafe-characters",
      "reason-holds-secret",
    ]);
    const problem = {
      type: "https://antireverse.dev/problems/validation",
      title: "Invalid request",
      status: 400,
      errors: [{ path: "headers.x-airverse-reason", message: "x" }],
      code: "reason-holds-secret",
    };
    expect(ProblemSchema.parse(problem)).toEqual(problem);
    expect(ProblemSchema.safeParse({ ...problem, code: "nope" }).success).toBe(false);
  });

  it("list query: filters optional, limit and cursor checked", () => {
    expect(AuditQuerySchema.parse({})).toEqual({ limit: AUDIT_LIMITS.listDefault });
    expect(
      AuditQuerySchema.parse({ action: "app.create", limit: "10", cursor: "42", from: "2026-11-13T00:00:00.000Z" }),
    ).toEqual({ action: "app.create", limit: 10, cursor: 42, from: "2026-11-13T00:00:00.000Z" });
    expect(AuditQuerySchema.safeParse({ action: "nope" }).success).toBe(false);
    expect(AuditQuerySchema.safeParse({ limit: "0" }).success).toBe(false);
    expect(AuditQuerySchema.safeParse({ limit: String(AUDIT_LIMITS.listMax + 1) }).success).toBe(false);
    expect(AuditQuerySchema.safeParse({ cursor: "-1" }).success).toBe(false);
    expect(AuditQuerySchema.safeParse({ app_id: "app_x" }).success).toBe(false);
  });

  it("list and verify responses; the signed head, the export head line and the public key", () => {
    expect(ListAuditResponseSchema.parse({ entries: [EXAMPLE_AUDIT_ENTRY], next_cursor: null }).entries).toHaveLength(
      1,
    );
    const signed_head = EXAMPLE_SIGNED_AUDIT_HEAD;
    expect(
      AuditVerifyResponseSchema.parse({
        verify: { valid: false, entries: 3, last_seq: 3, first_broken_seq: 2 },
        signed_head,
      }),
    ).toBeTruthy();
    expect(
      AuditVerifyResponseSchema.safeParse({
        verify: { valid: true, entries: 3, last_seq: 3, first_broken_seq: 2 },
        signed_head,
      }).success,
    ).toBe(false);
    expect(SignedAuditHeadSchema.safeParse({ ...signed_head, signature: "x" }).success).toBe(false);
    expect(AuditHeadSchema.safeParse({ ...signed_head.head, seq: -1 }).success).toBe(false);
    expect(AuditExportHeadLineSchema.parse({ type: "audit_head", ...signed_head })).toEqual({
      type: "audit_head",
      ...signed_head,
    });
    // An entry line is never mistaken for the head line, nor the other way round.
    expect(AuditExportHeadLineSchema.safeParse(EXAMPLE_AUDIT_ENTRY).success).toBe(false);
    expect(AuditExportLineSchema.safeParse({ type: "audit_head", ...signed_head }).success).toBe(false);
    expect(
      AuditPublicKeyResponseSchema.parse({
        key_id: "0123456789abcdef",
        algorithm: "Ed25519",
        public_key: "A".repeat(43),
      }),
    ).toBeTruthy();
    expect(AUDIT_VERIFY_DOC).toMatch(
      /first seq at which the chain no longer holds; the entry before it may be the altered one/,
    );
    expect(AuditVerifyResponseSchema.shape.verify.description).toBe(AUDIT_VERIFY_DOC);
  });

  it("reason: refuses bidi overrides, C1 controls, line separators and zero-width characters", () => {
    for (const bad of ["ok\u202etxt.exe", "a\u0085b", "a\u2028b", "a\u200bb", "a\ufeffb", "a\u2066b"]) {
      expect(AuditReasonSchema.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
    }
    expect(AuditReasonSchema.parse("Perbaikan darurat, 日本語")).toBe("Perbaikan darurat, 日本語");
  });
});

describe("auditHash", () => {
  const { hash, ...unhashed } = EXAMPLE_AUDIT_ENTRY;

  it("is sha256(prev_hash ‖ canonical JSON of the entry without its hash)", () => {
    expect(auditHash(unhashed)).toBe(sha256(unhashed.prev_hash + canonicalJson(unhashed)));
    expect(auditHash(unhashed)).toBe(hash);
  });

  it("does not depend on key order; any change of a member changes it", () => {
    const reversed = Object.fromEntries(Object.entries(unhashed).reverse()) as typeof unhashed;
    expect(auditHash(reversed)).toBe(hash);
    expect(auditHash({ ...unhashed, summary: "Other." })).not.toBe(hash);
    expect(auditHash({ ...unhashed, seq: 2 })).not.toBe(hash);
    expect(auditHash({ ...unhashed, prev_hash: "1".repeat(64) })).not.toBe(hash);
  });

  it("leaves absent optional members out, the same as undefined ones", () => {
    const { reason: _reason, app_id: _app, ...bare } = unhashed;
    expect(auditHash({ ...bare, reason: undefined, app_id: undefined })).toBe(auditHash(bare));
    expect(auditHash(bare)).toBe(sha256(bare.prev_hash + canonicalJson(bare)));
  });

  it("throws a TypeError for an entry that is not valid", () => {
    expect(() => auditHash({ ...unhashed, action: "nope" } as never)).toThrow(TypeError);
  });
});
