// @vitest-environment node
import { createHash, createPublicKey, verify } from "node:crypto";
import {
  DeletionResponseSchema,
  DeletionStatusResponseSchema,
  dataExportSignedText,
  EXPORT_CONSISTENCY,
  ExportLineSchema,
  ExportManifestLineSchema,
  ProblemSchema,
  SignedAuditHeadSchema,
  SubjectEraseResponseSchema,
} from "@antireverse/protocol";
import { auditSubjectRef } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { createDataStore } from "../scripts/stub-data.mjs";

// Slice 18b: the stand-in API answers the data-control routes in the shape of the protocol, and refuses every other
// route of an Organization pending deletion as the API does, so that the Console can be looked at against it.

const ORG = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };
const IP_HASH = "iph_0123456789abcdef0123456789abcdef";
const T0 = Date.parse("2026-11-13T09:00:00.000Z");
const REASON = "Contract ended";

interface Answer {
  status: number;
  body: unknown;
  contentType?: string;
  headers?: Record<string, string>;
  audit?: { action: string; target: { kind: string; id: string }; summary: string };
}

const HEAD = {
  head: { organization_id: ORG.id, seq: 3, hash: "a".repeat(64), at: "2026-11-13T09:00:00.000Z" },
  key_id: "0123456789abcdef",
  signature: "A".repeat(86),
};

/** Every line exactly as the protocol reads it: no member missing, none it does not know (review 18b, M3). */
function protocolLines(text: string) {
  return text
    .trimEnd()
    .split("\n")
    .map((line) => {
      const raw = JSON.parse(line);
      const parsed = ExportLineSchema.parse(raw);
      expect(parsed).toEqual(raw);
      return parsed;
    });
}

function store() {
  const clock = { ms: T0 };
  const erased: string[] = [];
  const data = createDataStore({
    now: () => clock.ms,
    auditHead: () => HEAD,
    tables: () => ({ apps: [{ id: "app_0123456789abcdef01234567", name: "shop-web" }], events: [{ id: 1 }] }),
    subject: {
      rows: (_organizationId: string, ipHash: string) => ({ events: [{ ip_hash: ipHash }], containments: [] }),
      erase: (_organizationId: string, ipHash: string) => {
        erased.push(ipHash);
        return {
          events_erased: 3,
          containments_erased: 1,
          active_containments: [{ id: "cnt_0123456789abcdef01234567", expires_at: "2026-11-13T10:00:00.000Z" }],
        };
      },
    },
  });
  const call = (method: string, path: string, body?: unknown, reason?: string): Answer => {
    const answer = data.handle(ORG, method, path, body, reason);
    if (answer === null) throw new Error(`no answer for ${method} ${path}`);
    return answer as Answer;
  };
  return { data, call, clock, erased };
}

const problemType = (answer: Answer) => ProblemSchema.parse(answer.body).type;

describe("stub data controls", () => {
  it("answers nothing for other routes", () => {
    expect(store().data.handle(ORG, "GET", "/v1/apps", undefined, undefined)).toBeNull();
  });

  it("requests a deletion with the exact name and a reason, purge after seven days", () => {
    const { call, data } = store();
    expect(DeletionStatusResponseSchema.parse(call("GET", "/v1/organization/deletion").body).deletion).toBeNull();
    let answer = call("POST", "/v1/organization/deletion", { confirm_name: "Acme" });
    expect(answer.status).toBe(400);
    expect(problemType(answer)).toMatch(/\/reason-required$/);
    answer = call("POST", "/v1/organization/deletion", { confirm_name: "acme" }, REASON);
    expect(answer.status).toBe(400);
    expect(ProblemSchema.parse(answer.body).errors?.[0]?.path).toBe("confirm_name");
    answer = call("POST", "/v1/organization/deletion", { confirm_name: "Acme" }, REASON);
    expect(answer.status).toBe(201);
    const { deletion } = DeletionResponseSchema.parse(answer.body);
    expect(deletion.status).toBe("pending");
    expect(deletion.purge_after).toBe("2026-11-20T09:00:00.000Z");
    expect(answer.audit?.action).toBe("organization.deletion.request");
    expect(data.pending(ORG.id)).toEqual(deletion);
    expect(DeletionStatusResponseSchema.parse(call("GET", "/v1/organization/deletion").body).deletion).toEqual(
      deletion,
    );
  });

  it("refuses every other route while pending, except the status, its cancellation and the export", () => {
    const { call, data } = store();
    call("POST", "/v1/organization/deletion", { confirm_name: "Acme" }, REASON);
    const refused = data.gate(ORG.id, "GET", "/v1/organization") as Answer;
    expect(refused.status).toBe(403);
    expect(problemType(refused)).toBe("https://antireverse.dev/problems/organization-deletion-pending");
    expect(data.gate(ORG.id, "POST", "/v1/subjects/erase")).not.toBeNull();
    for (const [method, path] of [
      ["GET", "/v1/organization/deletion"],
      ["DELETE", "/v1/organization/deletion"],
      ["GET", "/v1/organization/export"],
    ] as const) {
      expect(data.gate(ORG.id, method, path)).toBeNull();
    }
    let answer = call("DELETE", "/v1/organization/deletion");
    expect(problemType(answer)).toMatch(/\/reason-required$/);
    answer = call("DELETE", "/v1/organization/deletion", undefined, REASON);
    expect(answer.status).toBe(200);
    expect(DeletionResponseSchema.parse(answer.body).deletion.status).toBe("cancelled");
    expect(answer.audit?.action).toBe("organization.deletion.cancel");
    expect(data.gate(ORG.id, "GET", "/v1/organization")).toBeNull();
    expect(call("DELETE", "/v1/organization/deletion", undefined, REASON).status).toBe(404);
  });

  it("exports NDJSON: a manifest, the rows, and an end line whose hash and signature check", () => {
    const { call, data } = store();
    const answer = call("GET", "/v1/organization/export");
    expect(answer.status).toBe(200);
    expect(answer.contentType).toBe("application/x-ndjson");
    expect(answer.headers?.["content-disposition"]).toMatch(/^attachment; filename="airverse-org_[0-9a-f]{24}-/);
    const text = String(answer.body);
    const lines = text.trimEnd().split("\n");
    const parsed = protocolLines(text);
    const manifest = ExportManifestLineSchema.parse(parsed[0]);
    expect(manifest.consistency).toBe(EXPORT_CONSISTENCY);
    expect(SignedAuditHeadSchema.parse(manifest.audit_head)).toEqual(HEAD);
    const end = parsed.at(-1);
    if (end?.kind !== "end") throw new Error("no end line");
    expect(end.counts).toEqual({ apps: 1, events: 1 });
    const before = `${lines.slice(0, -1).join("\n")}\n`;
    expect(end.sha256).toBe(createHash("sha256").update(before, "utf8").digest("hex"));
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: data.publicKey().public_key },
      format: "jwk",
    });
    expect(
      verify(null, Buffer.from(dataExportSignedText(end), "utf8"), key, Buffer.from(end.signature, "base64url")),
    ).toBe(true);
    expect(answer.audit?.action).toBe("organization.export");
  });

  it("exports and erases a subject by actor hash; erasing needs a reason", () => {
    const { call, erased } = store();
    expect(call("POST", "/v1/subjects/export", { ip_hash: "203.0.113.7" }).status).toBe(400);
    const exported = call("POST", "/v1/subjects/export", { ip_hash: IP_HASH });
    expect(exported.status).toBe(200);
    const manifest = ExportManifestLineSchema.parse(protocolLines(String(exported.body))[0]);
    expect(manifest.subject?.ip_hash).toBe(IP_HASH);
    expect(manifest.consistency).toBe(EXPORT_CONSISTENCY);
    expect(manifest.audit_head).toBeUndefined();
    // The audit entry names the subject by its reference, never by the actor hash (as the API does).
    expect(exported.audit?.target).toEqual({ kind: "subject", id: auditSubjectRef(ORG.id, IP_HASH) });
    expect(problemType(call("POST", "/v1/subjects/erase", { ip_hash: IP_HASH }))).toMatch(/\/reason-required$/);
    expect(erased).toEqual([]);
    const answer = call("POST", "/v1/subjects/erase", { ip_hash: IP_HASH }, REASON);
    expect(answer.status).toBe(200);
    expect(SubjectEraseResponseSchema.parse(answer.body).report.events_erased).toBe(3);
    expect(answer.audit?.action).toBe("subject.erase");
    expect(answer.audit?.target.id).toBe(auditSubjectRef(ORG.id, IP_HASH));
    expect(answer.audit?.summary).not.toContain(IP_HASH);
    expect(erased).toEqual([IP_HASH]);
  });

  it("validates the body before the reason, as the API does (review 18b, L5)", () => {
    const { call } = store();
    let answer = call("POST", "/v1/organization/deletion", { confirm_name: "" });
    expect(problemType(answer)).toMatch(/\/validation$/);
    answer = call("POST", "/v1/organization/deletion", { confirm_name: "Acme", extra: 1 });
    expect(problemType(answer)).toMatch(/\/validation$/);
    answer = call("POST", "/v1/subjects/erase", { ip_hash: "nope" });
    expect(problemType(answer)).toMatch(/\/validation$/);
    // A valid body without a reason: reason-required.
    expect(problemType(call("POST", "/v1/subjects/erase", { ip_hash: IP_HASH }))).toMatch(/\/reason-required$/);
  });

  it("limits the export with the budget it shares with audit reads: 20 a minute, then 429 (review 18b, L4)", () => {
    const { call, data, clock } = store();
    for (let i = 0; i < 19; i += 1) expect(data.takeRead(ORG.id).allowed).toBe(true);
    expect(call("GET", "/v1/organization/export").status).toBe(200);
    const refused = call("GET", "/v1/organization/export");
    expect(refused.status).toBe(429);
    expect(problemType(refused)).toBe("https://antireverse.dev/problems/too-many-audit-reads");
    expect(Number(refused.headers?.["retry-after"])).toBeGreaterThanOrEqual(1);
    expect(refused.audit).toBeUndefined();
    expect(data.takeRead(ORG.id).allowed).toBe(false);
    // Another Organization has its own budget; the next minute starts afresh.
    expect(data.takeRead("org_fedcba9876543210fedcba98").allowed).toBe(true);
    clock.ms += 60_000;
    expect(call("GET", "/v1/organization/export").status).toBe(200);
  });

  it("serves no deletion report before a purge", () => {
    const { call } = store();
    expect(call("GET", "/v1/deletions/del_0123456789abcdef01234567/report").status).toBe(404);
  });
});
