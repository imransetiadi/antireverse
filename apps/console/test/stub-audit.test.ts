// @vitest-environment node

import { createPublicKey, verify } from "node:crypto";
import {
  AUDIT_ACTIONS,
  AUDIT_GENESIS_HASH,
  AuditEntrySchema,
  AuditExportHeadLineSchema,
  AuditPublicKeyResponseSchema,
  AuditReasonSchema,
  AuditVerifyResponseSchema,
  canonicalJson,
  encodeAuditReason,
  holdsSecretShape,
  ListAuditResponseSchema,
  ProblemSchema,
} from "@antireverse/protocol";
import { auditHash } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { auditOf, createAuditStore, promotedRules } from "../scripts/stub-audit.mjs";

// The stand-in API keeps an audit log (slice 18a) in the shape of the protocol, hash-chained as the API chains it,
// so that the Console's Audit log page can be looked at against the same contract the real API serves.

const ORG = "org_0123456789abcdef01234567";
const OTHER = "org_fedcba9876543210fedcba98";
const KEY_ID = "key_0123456789abcdef01234567";
const APP = "app_0123456789abcdef01234567";
const T0 = Date.parse("2026-11-13T09:00:00.000Z");

interface Answer {
  status: number;
  body: unknown;
  contentType?: string;
}

function store() {
  const clock = { ms: T0 };
  const audit = createAuditStore({ now: () => clock.ms });
  const call = (organizationId: string, path: string, query = ""): Answer => {
    const answer = audit.handle(organizationId, "GET", path, new URLSearchParams(query));
    if (answer === null) throw new Error(`no answer for ${path}`);
    return answer as Answer;
  };
  const write = (action: string, extra: Record<string, unknown> = {}) => {
    clock.ms += 60_000;
    return audit.record(ORG, {
      keyId: KEY_ID,
      action,
      appId: APP,
      target: { kind: "policy", id: `${APP}/production` },
      summary: `Did ${action}.`,
      ...extra,
    });
  };
  return { audit, call, write, clock };
}

function parsed<T>(
  schema: { safeParse(value: unknown): { success: boolean; data?: T; error?: unknown } },
  body: unknown,
) {
  const result = schema.safeParse(body);
  expect(result.success ? [] : (result.error as { issues: unknown[] }).issues).toEqual([]);
  expect(result.data).toEqual(body);
  return result.data as T;
}

describe("stub audit — entries and chain", () => {
  it("chains entries per Organization exactly as the protocol hashes them", () => {
    const { write } = store();
    const first = write("policy.rule.promote", { reason: "Stuffing on /login" });
    const second = write("target.create", {
      appId: undefined,
      target: { kind: "target", id: "tgt_0123456789abcdef01234567" },
    });
    for (const entry of [first, second]) {
      parsed(AuditEntrySchema, entry);
      const { hash, ...rest } = entry;
      expect(auditHash(rest)).toBe(hash);
    }
    expect(first.seq).toBe(1);
    expect(first.prev_hash).toBe(AUDIT_GENESIS_HASH);
    expect(second.seq).toBe(2);
    expect(second.prev_hash).toBe(first.hash);
    expect(first.reason).toBe("Stuffing on /login");
    expect("reason" in second).toBe(false);
    expect("app_id" in second).toBe(false);
  });

  it("lists newest first with the filters, a cursor and a limit, per Organization", () => {
    const { call, write } = store();
    write("policy.publish");
    write("policy.rule.promote");
    write("containment.create", {
      appId: undefined,
      target: { kind: "containment", id: "cnt_0123456789abcdef01234567" },
    });
    const all = parsed(ListAuditResponseSchema, call(ORG, "/v1/audit").body);
    expect(all.entries.map((entry) => entry.seq)).toEqual([3, 2, 1]);
    expect(all.next_cursor).toBeNull();

    const paged = parsed(ListAuditResponseSchema, call(ORG, "/v1/audit", "limit=2").body);
    expect(paged.entries.map((entry) => entry.seq)).toEqual([3, 2]);
    expect(paged.next_cursor).toBe("2");
    const rest = parsed(ListAuditResponseSchema, call(ORG, "/v1/audit", "limit=2&cursor=2").body);
    expect(rest.entries.map((entry) => entry.seq)).toEqual([1]);

    expect(
      parsed(ListAuditResponseSchema, call(ORG, "/v1/audit", "action=policy.rule.promote").body).entries.map(
        (e) => e.seq,
      ),
    ).toEqual([2]);
    expect(parsed(ListAuditResponseSchema, call(ORG, "/v1/audit", `app_id=${APP}`).body).entries).toHaveLength(2);
    // T0 + 2 min is the second entry: from is inclusive, to exclusive.
    const ranged = call(ORG, "/v1/audit", "from=2026-11-13T09:02:00.000Z&to=2026-11-13T09:03:00.000Z");
    expect((ranged.body as { entries: Array<{ seq: number }> }).entries.map((e) => e.seq)).toEqual([2]);
    expect(parsed(ListAuditResponseSchema, call(OTHER, "/v1/audit").body).entries).toEqual([]);
  });

  it("refuses a filter the API refuses", () => {
    const { call } = store();
    for (const query of ["action=nope", "limit=0", "limit=201", "cursor=abc", "app_id=x", "from=yesterday"]) {
      const answer = call(ORG, "/v1/audit", query);
      expect(answer.status).toBe(400);
      parsed(ProblemSchema, answer.body);
    }
  });

  it("verifies the chain, and names the first entry that was altered", () => {
    const { audit, call, write } = store();
    const empty = parsed(AuditVerifyResponseSchema, call(ORG, "/v1/audit/verify").body);
    expect(empty.verify).toEqual({ valid: true, entries: 0, last_seq: 0, first_broken_seq: null });
    expect(empty.signed_head.head).toMatchObject({ organization_id: ORG, seq: 0, hash: AUDIT_GENESIS_HASH });
    write("policy.publish");
    write("policy.rule.promote");
    write("policy.rollback");
    expect(parsed(AuditVerifyResponseSchema, call(ORG, "/v1/audit/verify").body).verify).toEqual({
      valid: true,
      entries: 3,
      last_seq: 3,
      first_broken_seq: null,
    });
    audit.tamper(ORG, 2, { summary: "Nothing happened." });
    expect(parsed(AuditVerifyResponseSchema, call(ORG, "/v1/audit/verify").body).verify).toEqual({
      valid: false,
      entries: 3,
      last_seq: 3,
      first_broken_seq: 2,
    });
  });

  it("exports the signed head, then every entry oldest first, as NDJSON", () => {
    const { audit, call, write } = store();
    write("policy.publish");
    const last = write("policy.rule.promote");
    const answer = call(ORG, "/v1/audit/export");
    expect(answer.status).toBe(200);
    expect(answer.contentType).toBe("application/x-ndjson");
    const [head, ...lines] = String(answer.body).trimEnd().split("\n");
    const signed = parsed(AuditExportHeadLineSchema, JSON.parse(head ?? ""));
    expect(signed.head).toMatchObject({ seq: 2, hash: last.hash });
    const key = parsed(AuditPublicKeyResponseSchema, audit.publicKey());
    expect(signed.key_id).toBe(key.key_id);
    const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.public_key }, format: "jwk" });
    expect(
      verify(null, Buffer.from(canonicalJson(signed.head)), publicKey, Buffer.from(signed.signature, "base64url")),
    ).toBe(true);
    expect(lines.map((line) => parsed(AuditEntrySchema, JSON.parse(line)).seq)).toEqual([1, 2]);
  });
});

describe("stub audit — the reason header", () => {
  it("decodes a percent-encoded reason as the API does, trimmed", () => {
    const { audit } = store();
    expect(audit.parseReason(undefined)).toEqual({ reason: undefined });
    expect(audit.parseReason(encodeAuditReason("  Stuffing — 100 % sure, café  "))).toEqual({
      reason: "Stuffing — 100 % sure, café",
    });
  });

  it.each([
    ["a bare percent sign", "100%"],
    ["an empty reason", "%20%20%20"],
    ["a control character", encodeAuditReason("a\nb")],
    ["more than 500 characters", "x".repeat(501)],
  ])("refuses %s with a 400 on the header's path", (_label, raw) => {
    const { audit } = store();
    const result = audit.parseReason(raw);
    expect("error" in result).toBe(true);
    const answer = (result as { error: Answer }).error;
    expect(answer.status).toBe(400);
    const problem = parsed(ProblemSchema, answer.body);
    expect(problem.errors?.[0]?.path).toBe("headers.x-airverse-reason");
  });

  it("answers reason-required with the API's problem type", () => {
    const { audit } = store();
    const answer = audit.reasonRequired() as Answer;
    expect(answer.status).toBe(400);
    expect(parsed(ProblemSchema, answer.body).type).toBe("https://antireverse.dev/problems/reason-required");
  });
});

describe("stub audit — the system and the operator as actors (slice 15a)", () => {
  it("records an entry of the system or the operator without a key id, in the same chain", () => {
    const { audit, write } = store();
    const first = write("campaign.create", { target: { kind: "campaign", id: "cmp_0123456789abcdef01234567" } });
    const system = audit.record(ORG, {
      actor: "system",
      action: "campaign.end",
      target: { kind: "campaign", id: "cmp_0123456789abcdef01234567" },
      summary: "The Campaign ended.",
    });
    const operator = audit.record(ORG, {
      actor: "operator",
      keyId: KEY_ID,
      action: "campaign.operator_kill",
      target: { kind: "campaign", id: "cmp_0123456789abcdef01234567" },
      reason: "Incident 42",
      summary: "The operator stopped all Campaigns.",
    });
    expect(first.actor).toEqual({ kind: "admin_key", key_id: KEY_ID });
    expect(system.actor).toEqual({ kind: "system" });
    expect(operator.actor).toEqual({ kind: "operator" });
    for (const entry of [first, system, operator]) {
      parsed(AuditEntrySchema, entry);
      const { hash, ...rest } = entry;
      expect(auditHash(rest)).toBe(hash);
    }
    expect(operator.prev_hash).toBe(system.hash);
  });
});

describe("stub audit — what each change records", () => {
  it("maps every mutating route of the stub to an action of the protocol, with its target", () => {
    const INC = "inc_0123456789abcdef01234567";
    const cases: Array<[string, string, unknown, unknown, string, string | undefined]> = [
      ["POST", "/v1/apps", {}, { app: { id: APP } }, "app.create", APP],
      [
        "PUT",
        `/v1/apps/${APP}/policies/production`,
        {},
        { policy: { version: 3 } },
        "policy.publish",
        `${APP}/production`,
      ],
      [
        "POST",
        `/v1/apps/${APP}/policies/production/rollback`,
        {},
        { policy: { version: 4 } },
        "policy.rollback",
        `${APP}/production`,
      ],
      [
        "POST",
        `/v1/apps/${APP}/patches/vp_example_parser_proto/mode`,
        { mode: "enforce" },
        {},
        "patch.promote",
        "vp_example_parser_proto",
      ],
      [
        "POST",
        `/v1/apps/${APP}/patches/vp_example_parser_proto/mode`,
        { mode: "monitor" },
        {},
        "patch.demote",
        "vp_example_parser_proto",
      ],
      ["PATCH", `/v1/incidents/${INC}`, { status: "resolved" }, {}, "incident.resolve", INC],
      [
        "POST",
        `/v1/incidents/${INC}/containments`,
        {},
        { containment: { id: "cnt_0123456789abcdef01234567", app_id: APP } },
        "containment.create",
        "cnt_0123456789abcdef01234567",
      ],
      [
        "POST",
        "/v1/containments/cnt_0123456789abcdef01234567/lift",
        {},
        { containment: { app_id: APP } },
        "containment.lift",
        "cnt_0123456789abcdef01234567",
      ],
      [
        "POST",
        "/v1/allowlist",
        {},
        { entry: { id: "alw_0123456789abcdef01234567" } },
        "allowlist_entry.create",
        "alw_0123456789abcdef01234567",
      ],
      [
        "DELETE",
        "/v1/allowlist/alw_0123456789abcdef01234567",
        undefined,
        undefined,
        "allowlist_entry.delete",
        "alw_0123456789abcdef01234567",
      ],
      [
        "POST",
        "/v1/targets",
        {},
        { target: { id: "tgt_0123456789abcdef01234567" } },
        "target.create",
        "tgt_0123456789abcdef01234567",
      ],
      [
        "DELETE",
        "/v1/targets/tgt_0123456789abcdef01234567",
        undefined,
        undefined,
        "target.delete",
        "tgt_0123456789abcdef01234567",
      ],
      [
        "POST",
        "/v1/rules-of-engagement",
        {},
        { version: { id: "roe_0123456789abcdef01234567" } },
        "rules_of_engagement.sign",
        "roe_0123456789abcdef01234567",
      ],
    ];
    for (const [method, path, request, response, action, targetId] of cases) {
      const audit = auditOf(method, path, request, response);
      expect(audit?.action, `${method} ${path}`).toBe(action);
      expect(AUDIT_ACTIONS).toContain(audit?.action);
      expect(audit?.target.id).toBe(targetId);
    }
    expect(auditOf("POST", "/v1/apps/x/policy/simulate", {}, {})).toBeNull();
    expect(auditOf("POST", "/v1/prove/authorize", {}, {})).toBeNull();
  });

  it("names a promotion when a publish enforces a Rule anew", () => {
    const before = [{ id: "rul_a", mode: "monitor" }];
    const after = [{ id: "rul_a", mode: "enforce" }];
    const audit = auditOf(
      "PUT",
      `/v1/apps/${APP}/policies/production`,
      { rules: after },
      { policy: { version: 3, rules: after } },
      before,
    );
    expect(audit?.action).toBe("policy.rule.promote");
    expect(audit?.summary).toContain("rul_a");
  });

  it("counts a Rule as promoted when it is enforced anew or enforced on other traffic, as the API does", () => {
    const rule = { id: "rul_a", mode: "enforce", path: "/login", methods: ["POST", "GET"], action: "block" };
    expect(promotedRules([rule], [{ ...rule, methods: ["GET", "POST"] }])).toEqual([]);
    expect(promotedRules([rule], [{ ...rule, path: "/admin" }])).toEqual(["rul_a"]);
    expect(promotedRules([rule], [{ ...rule, requires: "signature" }])).toEqual(["rul_a"]);
    expect(promotedRules([{ ...rule, mode: "monitor" }], [rule])).toEqual(["rul_a"]);
    expect(promotedRules([rule], [{ ...rule, mode: "monitor" }])).toEqual([]);
  });
});

describe("stub audit — review findings F1 and F5", () => {
  it("F1: refuses times outside the years 2000 to 2099, as the API does", () => {
    const { call } = store();
    for (const query of ["from=1999-12-31T00:00:00.000Z", "to=2100-01-01T00:00:00.000Z"]) {
      expect(call(ORG, "/v1/audit", query).status).toBe(400);
    }
    expect(call(ORG, "/v1/audit", "from=2000-01-01T00:00:00.000Z&to=2099-12-31T00:00:00.000Z").status).toBe(200);
  });

  it.each([
    ["raw non-ASCII", "café", "reason-not-ascii"],
    ["a bare percent sign", "100%", "reason-bad-encoding"],
    ["an empty reason", "%20%20", "reason-empty"],
    ["more than 500 characters", "x".repeat(501), "reason-too-long"],
    ["a bidi override", encodeAuditReason("\u202Eevil"), "reason-unsafe-characters"],
    ["a zero-width space", encodeAuditReason("a\u200Bb"), "reason-unsafe-characters"],
    ["an email address", encodeAuditReason("ops@oncall"), "reason-holds-secret"],
    ["a token-like run", "a".repeat(43), "reason-holds-secret"],
  ])("F5: refuses %s with the API's code", (_label, raw, code) => {
    const result = createAuditStore().parseReason(raw);
    expect("error" in result).toBe(true);
    const body = parsed(ProblemSchema, (result as { error: Answer }).error.body);
    expect(body.code).toBe(code);
    expect(body.errors?.[0]?.path).toBe("headers.x-airverse-reason");
  });

  it("F5: accepts what the API accepts, decoded and trimmed", () => {
    for (const reason of ["ticket aro_123456", "50% más — 中文 🚀", "right\u200Fto\u200Eleft"]) {
      expect(AuditReasonSchema.safeParse(reason).success && !holdsSecretShape(reason)).toBe(true);
      expect(createAuditStore().parseReason(encodeAuditReason(` ${reason} `))).toEqual({ reason });
    }
  });
});
