import { randomUUID } from "node:crypto";
import {
  AUDIT_EXPORT_CONTENT_TYPE,
  AUDIT_GENESIS_HASH,
  AUDIT_REASON_ERROR_CODES,
  AUDIT_REASON_HEADER,
  type AuditEntry,
  AuditExportHeadLineSchema,
  AuditExportLineSchema,
  AuditPublicKeyResponseSchema,
  type AuditReasonErrorCode,
  AuditVerifyResponseSchema,
  canonicalJson,
  encodeAuditReason,
  ListAppsResponseSchema,
  ListAuditResponseSchema,
  type SignedAuditHead,
} from "@antireverse/protocol";
import { auditHash } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { AUDIT_PAGE } from "../src/routes/audit.ts";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  policyPath,
  put,
  type TestApi,
  verifySignature,
} from "./helpers.ts";

// Slice 18a: the audit log's chain, storage, reading routes and failure behaviour. Which route writes which entry
// is the business of audit-coverage.test.ts.

const T0 = Date.parse("2026-11-13T09:00:00.000Z");

describe("audit log", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);

  beforeAll(async () => {
    api = await makeTestApi({ now, auditReadsPerMinute: 10_000 });
  });
  afterAll(async () => {
    expectNoKeyLogged(api);
    await api.close();
  });

  async function tenant(name = "Acme") {
    const created = await createOrganization(api, name);
    const keyId = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ id: string }>("SELECT id FROM api_keys WHERE organization_id = $1", [
        created.organization.id,
      ]);
      return rows[0]?.id ?? "";
    });
    return { organizationId: created.organization.id, admin: created.admin_key.key, keyId };
  }

  async function list(admin: string, query = ""): Promise<{ entries: AuditEntry[]; next_cursor: string | null }> {
    const res = await api.app.request(`/v1/audit${query}`, { headers: bearer(admin) });
    expect(res.status).toBe(200);
    return ListAuditResponseSchema.parse(await res.json());
  }

  async function verified(admin: string) {
    const res = await api.app.request("/v1/audit/verify", { headers: bearer(admin) });
    expect(res.status).toBe(200);
    return AuditVerifyResponseSchema.parse(await res.json());
  }

  async function verify(admin: string) {
    return (await verified(admin)).verify;
  }

  /** The export: its first line, the signed head, then the entries up to it. */
  async function exportedWithHead(admin: string): Promise<{ head: SignedAuditHead; entries: AuditEntry[] }> {
    const res = await api.app.request("/v1/audit/export", { headers: bearer(admin) });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe(AUDIT_EXPORT_CONTENT_TYPE);
    const text = await res.text();
    expect(text.endsWith("\n")).toBe(true);
    const [first, ...rest] = text.split("\n").filter((line) => line !== "");
    const { type: _type, ...head } = AuditExportHeadLineSchema.parse(JSON.parse(first ?? ""));
    return { head, entries: rest.map((line) => AuditExportLineSchema.parse(JSON.parse(line))) };
  }

  async function exported(admin: string): Promise<AuditEntry[]> {
    return (await exportedWithHead(admin)).entries;
  }

  async function auditPublicKey(): Promise<string> {
    const res = await api.app.request("/v1/audit/public-key");
    expect(res.status).toBe(200);
    return AuditPublicKeyResponseSchema.parse(await res.json()).public_key;
  }

  /** True when the head's signature verifies under the audit key. */
  function signedByAudit(signed: SignedAuditHead, publicKey: string): boolean {
    return verifySignature(publicKey, canonicalJson(signed.head), signed.signature);
  }

  /** The chain recomputed by a third party from the export alone. */
  function chainHolds(entries: AuditEntry[]): boolean {
    let prev = AUDIT_GENESIS_HASH;
    return entries.every((entry, index) => {
      const { hash, ...rest } = entry;
      const ok = entry.seq === index + 1 && entry.prev_hash === prev && auditHash(rest) === hash;
      prev = hash;
      return ok;
    });
  }

  it("records the creation of an Organization as its first entry, by its first admin key", async () => {
    const res = await api.app.request("/v1/organizations", json({ name: "First" }));
    expect(res.status).toBe(201);
    const body = (await res.json()) as { organization: { id: string }; admin_key: { key: string } };
    api.issuedKeys.push(body.admin_key.key);
    const { entries } = await list(body.admin_key.key);
    expect(entries).toHaveLength(1);
    const [first] = entries as [AuditEntry];
    expect(first).toMatchObject({
      organization_id: body.organization.id,
      seq: 1,
      at: new Date(T0).toISOString(),
      action: "organization.create",
      target: { kind: "organization", id: body.organization.id },
      prev_hash: AUDIT_GENESIS_HASH,
    });
    expect(first.actor.kind).toBe("admin_key");
    expect(first.request_id).toBe(res.headers.get("x-request-id"));
    const { hash, ...rest } = first;
    expect(auditHash(rest)).toBe(hash);
  });

  it("writes one entry per change with actor, request id, reason and a chained hash", async () => {
    const t = await tenant();
    const res = await api.app.request(
      "/v1/apps",
      json({ name: "Storefront" }, { ...bearer(t.admin), [AUDIT_REASON_HEADER]: "  New shop launch  " }),
    );
    expect(res.status).toBe(201);
    const { app } = (await res.json()) as { app: { id: string } };
    const { entries } = await list(t.admin);
    expect(entries.map((entry) => entry.seq)).toEqual([2, 1]);
    const [second, first] = entries as [AuditEntry, AuditEntry];
    expect(second).toMatchObject({
      action: "app.create",
      actor: { kind: "admin_key", key_id: t.keyId },
      app_id: app.id,
      target: { kind: "app", id: app.id },
      reason: "New shop launch",
      request_id: res.headers.get("x-request-id"),
      prev_hash: first.hash,
    });
    expect(first.reason).toBeUndefined();
  });

  it("refuses an invalid reason on any mutating route, and stores nothing", async () => {
    const t = await tenant();
    const invalid: [header: string, code: AuditReasonErrorCode][] = [
      ["x".repeat(501), "reason-too-long"],
      // Raw bytes outside printable ASCII: a tab, and the UTF-8 of "Café" sent unencoded (as Node sees it).
      ["one\ttwo", "reason-not-ascii"],
      ["CafÃ©", "reason-not-ascii"],
      // Malformed percent sequences: a literal % must be sent as %25.
      ["100% sure", "reason-bad-encoding"],
      ["bad %G1 escape", "reason-bad-encoding"],
      ["cut short %E6%97", "reason-bad-encoding"],
      // Invalid UTF-8: a lone continuation byte, an overlong encoding, an encoded surrogate.
      ["%80", "reason-bad-encoding"],
      ["%C0%AF", "reason-bad-encoding"],
      ["%ED%A0%80", "reason-bad-encoding"],
      // Control characters and length are judged after decoding.
      ["one%09two", "reason-unsafe-characters"],
      ["%0A", "reason-empty"], // whitespace only once decoded and trimmed
      [encodeAuditReason("日".repeat(501)), "reason-too-long"],
      ["%20%20%20", "reason-empty"],
      // Review F4: bidi override, C1 control, line separator, zero-width space.
      ["ok%E2%80%AEtxt.exe", "reason-unsafe-characters"],
      ["a%C2%85b", "reason-unsafe-characters"],
      ["a%E2%80%A8b", "reason-unsafe-characters"],
      ["a%E2%80%8Bb", "reason-unsafe-characters"],
      // Review F6: anything shaped like a key, a token, a secret or an email address.
      [encodeAuditReason("Asked by alice@corp.example"), "reason-holds-secret"],
      [encodeAuditReason(`key ${t.admin}`), "reason-holds-secret"],
      [encodeAuditReason(`k_${t.admin}`), "reason-holds-secret"],
      [encodeAuditReason(`whsec_${"A".repeat(43)}`), "reason-holds-secret"],
      [encodeAuditReason(`token ${"b".repeat(43)}`), "reason-holds-secret"],
      [encodeAuditReason("ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE"), "reason-holds-secret"],
    ];
    for (const [reason, code] of invalid) {
      const problem = await expectProblem(
        await api.app.request("/v1/apps", json({ name: "X" }, { ...bearer(t.admin), [AUDIT_REASON_HEADER]: reason })),
        400,
      );
      expect(problem.type, reason).toBe("https://antireverse.dev/problems/validation");
      expect(problem.code, reason).toBe(code);
      expect(problem.errors?.[0]?.path, reason).toBe("headers.x-airverse-reason");
    }
    expect(new Set(invalid.map(([, code]) => code))).toEqual(new Set(AUDIT_REASON_ERROR_CODES));
    const apps = await api.app.request("/v1/apps", { headers: bearer(t.admin) });
    expect(ListAppsResponseSchema.parse(await apps.json()).apps).toEqual([]);
    expect((await list(t.admin)).entries).toHaveLength(1);
  });

  it("decodes a percent-encoded UTF-8 reason and stores the Unicode text; plain ASCII is unchanged", async () => {
    const t = await tenant();
    const reasons: [sent: string, stored: string][] = [
      [encodeAuditReason("Perbaikan darurat: blokir serangan login"), "Perbaikan darurat: blokir serangan login"],
      [encodeAuditReason("日本語の理由です"), "日本語の理由です"],
      [encodeAuditReason("日".repeat(500)), "日".repeat(500)],
      ["Plain ASCII reason, no escapes", "Plain ASCII reason, no escapes"],
      ["Rate 100%25 confirmed", "Rate 100% confirmed"],
      ["a+b stays a plus", "a+b stays a plus"],
    ];
    for (const [sent] of reasons) {
      const res = await api.app.request(
        "/v1/apps",
        json({ name: "X" }, { ...bearer(t.admin), [AUDIT_REASON_HEADER]: sent }),
      );
      expect(res.status, sent).toBe(201);
    }
    const stored = (await exported(t.admin)).slice(1).map((entry) => entry.reason);
    expect(stored).toEqual(reasons.map(([, text]) => text));
    expect(chainHolds(await exported(t.admin))).toBe(true);
  });

  it("scrubs anything shaped like a key, token or secret from a summary, also glued to a word", async () => {
    const t = await tenant();
    const names = [
      `k_${t.admin}`,
      `whsec_${"A".repeat(43)}`,
      `x ${"c".repeat(43)} y`,
      "ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE",
    ];
    for (const name of names) await createAppFor(api, t.admin, { name });
    const summaries = (await exported(t.admin)).slice(1).map((entry) => entry.summary);
    expect(summaries).toHaveLength(names.length);
    for (const summary of summaries) {
      expect(summary).not.toContain(t.admin.slice(4));
      expect(summary).not.toMatch(/whsec_|ak_live_|[A-Za-z0-9_-]{43}/);
    }
  });

  it("lists newest first with filters and cursor paging", async () => {
    const t = await tenant();
    const one = await createAppFor(api, t.admin, { name: "One" });
    clock.ms = T0 + 60_000;
    const two = await createAppFor(api, t.admin, { name: "Two" });
    const added = await api.app.request("/v1/allowlist", json({ cidr: "10.0.0.0/8", note: "Office" }, bearer(t.admin)));
    expect(added.status).toBe(201);
    clock.ms = T0;

    const all = await list(t.admin);
    expect(all.entries.map((entry) => entry.action)).toEqual([
      "allowlist_entry.create",
      "app.create",
      "app.create",
      "organization.create",
    ]);
    expect(all.next_cursor).toBeNull();

    expect((await list(t.admin, "?action=app.create")).entries.map((entry) => entry.app_id)).toEqual([
      two.app.id,
      one.app.id,
    ]);
    expect((await list(t.admin, `?app_id=${one.app.id}`)).entries.map((entry) => entry.seq)).toEqual([2]);
    expect((await list(t.admin, `?target_id=${two.app.id}`)).entries.map((entry) => entry.seq)).toEqual([3]);
    const since = encodeURIComponent(new Date(T0 + 60_000).toISOString());
    expect((await list(t.admin, `?from=${since}`)).entries.map((entry) => entry.seq)).toEqual([4, 3]);
    expect((await list(t.admin, `?to=${since}`)).entries.map((entry) => entry.seq)).toEqual([2, 1]);

    const page1 = await list(t.admin, "?limit=3");
    expect(page1.entries.map((entry) => entry.seq)).toEqual([4, 3, 2]);
    expect(page1.next_cursor).toBe("2");
    const page2 = await list(t.admin, `?limit=3&cursor=${page1.next_cursor}`);
    expect(page2.entries.map((entry) => entry.seq)).toEqual([1]);
    expect(page2.next_cursor).toBeNull();

    await expectProblem(await api.app.request("/v1/audit?action=nope", { headers: bearer(t.admin) }), 400);
    await expectProblem(await api.app.request("/v1/audit?limit=0", { headers: bearer(t.admin) }), 400);
  });

  it("exports the whole chain as NDJSON, oldest first, verifiable by anyone", async () => {
    const t = await tenant();
    await createAppFor(api, t.admin);
    await createAppFor(api, t.admin);
    const entries = await exported(t.admin);
    expect(entries.map((entry) => entry.seq)).toEqual([1, 2, 3]);
    expect(chainHolds(entries)).toBe(true);
    expect(await verify(t.admin)).toEqual({ valid: true, entries: 3, last_seq: 3, first_broken_seq: null });
  });

  it("keeps seq gapless under concurrent changes", async () => {
    const t = await tenant();
    const responses = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        api.app.request("/v1/apps", json({ name: `App ${index}` }, bearer(t.admin))),
      ),
    );
    expect(responses.map((res) => res.status)).toEqual(Array(12).fill(201));
    const entries = await exported(t.admin);
    expect(entries.map((entry) => entry.seq)).toEqual(Array.from({ length: 13 }, (_, index) => index + 1));
    expect(chainHolds(entries)).toBe(true);
    expect((await verify(t.admin)).valid).toBe(true);
  });

  it("names the first altered entry when one is changed directly in storage", async () => {
    const t = await tenant();
    for (let index = 0; index < 3; index++) await createAppFor(api, t.admin);
    await api.db.owner((q) =>
      q.query("UPDATE audit_entries SET summary = 'Nothing happened.' WHERE organization_id = $1 AND seq = 3", [
        t.organizationId,
      ]),
    );
    expect(await verify(t.admin)).toEqual({ valid: false, entries: 4, last_seq: 4, first_broken_seq: 3 });

    // Re-hashing the altered entry does not help: the next entry's prev_hash no longer matches.
    const altered = (await exported(t.admin))[2] as AuditEntry;
    const { hash: _old, ...rest } = altered;
    await api.db.owner((q) =>
      q.query("UPDATE audit_entries SET hash = $1 WHERE organization_id = $2 AND seq = 3", [
        auditHash(rest),
        t.organizationId,
      ]),
    );
    expect((await verify(t.admin)).first_broken_seq).toBe(4);
  });

  it("names the gap when an entry is deleted directly, and the tail when the newest is", async () => {
    const t = await tenant();
    for (let index = 0; index < 3; index++) await createAppFor(api, t.admin);
    await api.db.owner((q) =>
      q.query("DELETE FROM audit_entries WHERE organization_id = $1 AND seq = 2", [t.organizationId]),
    );
    expect((await verify(t.admin)).first_broken_seq).toBe(2);

    const u = await tenant();
    for (let index = 0; index < 2; index++) await createAppFor(api, u.admin);
    await api.db.owner((q) =>
      q.query("DELETE FROM audit_entries WHERE organization_id = $1 AND seq = 3", [u.organizationId]),
    );
    expect(await verify(u.admin)).toEqual({ valid: false, entries: 2, last_seq: 3, first_broken_seq: 3 });
  });

  it("verifies and exports a chain longer than one page, and counts past the first break", async () => {
    const t = await tenant();
    const total = AUDIT_PAGE * 2 + 7;
    await api.db.tx({ organizationId: t.organizationId }, async (q) => {
      const actor = { organizationId: t.organizationId, keyId: t.keyId, requestId: randomUUID() };
      for (let index = 1; index < total; index++) {
        await audit(q, actor, {
          action: "allowlist_entry.create",
          target: { kind: "allowlist_entry", id: `alw_${index}` },
          summary: `Entry ${index}.`,
          at: now(),
        });
      }
    });
    const all = await exported(t.admin);
    expect(all.map((entry) => entry.seq)).toEqual(Array.from({ length: total }, (_, index) => index + 1));
    expect(chainHolds(all)).toBe(true);
    expect(await verify(t.admin)).toEqual({ valid: true, entries: total, last_seq: total, first_broken_seq: null });

    const at = AUDIT_PAGE - 3;
    await api.db.owner((q) =>
      q.query("UPDATE audit_entries SET summary = 'Altered.' WHERE organization_id = $1 AND seq = $2", [
        t.organizationId,
        at,
      ]),
    );
    expect(await verify(t.admin)).toEqual({ valid: false, entries: total, last_seq: total, first_broken_seq: at });
  });

  it("needs a reason for any publish or rollback that newly enforces a Rule, also a new Rule that starts enforced", async () => {
    const t = await tenant();
    const { app } = await createAppFor(api, t.admin);
    const path = policyPath(app.id, "development");
    const rule = (mode: "monitor" | "enforce") => ({ name: "Login", path: "/login", methods: ["POST"], mode });
    const reasoned = { ...bearer(t.admin), [AUDIT_REASON_HEADER]: "Tested in monitor" };
    const refused = async (res: Response) =>
      expect((await expectProblem(res, 400)).type).toBe("https://antireverse.dev/problems/reason-required");

    await refused(await api.app.request(path, put({ rules: [rule("enforce")] }, bearer(t.admin))));
    expect((await api.app.request(path, put({ rules: [rule("monitor")] }, bearer(t.admin)))).status).toBe(201);
    const v1 = (await (await api.app.request(path, { headers: bearer(t.admin) })).json()) as {
      policy: { rules: { id: string }[] };
    };
    const id = v1.policy.rules[0]?.id;
    expect((await api.app.request(path, put({ rules: [{ ...rule("enforce"), id }] }, reasoned))).status).toBe(201);
    // Already enforced: keeping it so needs no reason.
    expect((await api.app.request(path, put({ rules: [{ ...rule("enforce"), id }] }, bearer(t.admin)))).status).toBe(
      201,
    );
    expect((await api.app.request(path, put({ rules: [{ ...rule("monitor"), id }] }, bearer(t.admin)))).status).toBe(
      201,
    );
    const rollback = policyPath(app.id, "development", "/rollback");
    await refused(await api.app.request(rollback, json({ version: 2 }, bearer(t.admin))));
    expect((await api.app.request(rollback, json({ version: 2 }, reasoned))).status).toBe(201);

    const actions = (await list(t.admin)).entries.map((entry) => [entry.action, entry.reason ?? null]);
    expect(actions).toEqual([
      ["policy.rollback", "Tested in monitor"],
      ["policy.publish", null],
      ["policy.publish", null],
      ["policy.rule.promote", "Tested in monitor"],
      ["policy.publish", null],
      ["app.create", null],
      ["organization.create", null],
    ]);
  });

  it("needs a reason when an enforced Rule's id is reused for other traffic, on publish and on rollback", async () => {
    const t = await tenant();
    const { app } = await createAppFor(api, t.admin);
    const path = policyPath(app.id, "production");
    const reasoned = { ...bearer(t.admin), [AUDIT_REASON_HEADER]: "Reviewed" };
    const health = { name: "Health", path: "/health", methods: ["GET"], mode: "enforce" };
    const first = await api.app.request(path, put({ rules: [health] }, reasoned));
    expect(first.status).toBe(201);
    const id = ((await first.json()) as { policy: { rules: { id: string }[] } }).policy.rules[0]?.id;
    const refused = async (res: Response) =>
      expect((await expectProblem(res, 400)).type).toBe("https://antireverse.dev/problems/reason-required");
    const changed = [
      { ...health, id, path: "/login" },
      { ...health, id, methods: ["POST"] },
      { ...health, id, action: "throttle", limit: { requests: 10, window_s: 60, key: "ip" } },
      { ...health, id, requires: "signature" },
    ];
    for (const rule of changed) await refused(await api.app.request(path, put({ rules: [rule] }, bearer(t.admin))));
    // A new name only: the same traffic, no reason needed.
    expect((await api.app.request(path, put({ rules: [{ ...health, id, name: "Up" }] }, bearer(t.admin)))).status).toBe(
      201,
    );
    expect((await api.app.request(path, put({ rules: [{ ...health, id, path: "/login" }] }, reasoned))).status).toBe(
      201,
    );
    // Back to version 1 brings /health back under the same id: other traffic again.
    const rollback = policyPath(app.id, "production", "/rollback");
    await refused(await api.app.request(rollback, json({ version: 1 }, bearer(t.admin))));
    expect((await api.app.request(rollback, json({ version: 1 }, reasoned))).status).toBe(201);
    const actions = (await list(t.admin, `?app_id=${app.id}`)).entries.map((entry) => entry.action);
    expect(actions).toEqual([
      "policy.rollback",
      "policy.rule.promote",
      "policy.publish",
      "policy.rule.promote",
      "app.create",
    ]);
  });

  it("verifies in pages, one transaction each, so other tenants' requests run in between", async () => {
    const t = await tenant();
    const other = await tenant("Other");
    await api.db.tx({ organizationId: t.organizationId }, async (q) => {
      const actor = { organizationId: t.organizationId, keyId: t.keyId, requestId: randomUUID() };
      for (let index = 0; index < AUDIT_PAGE * 6; index++) {
        await audit(q, actor, {
          action: "allowlist_entry.create",
          target: { kind: "allowlist_entry", id: `alw_${index}` },
          summary: `Entry ${index}.`,
          at: now(),
        });
      }
    });
    const finished: string[] = [];
    const verifying = Promise.resolve(api.app.request("/v1/audit/verify", { headers: bearer(t.admin) })).then(
      (res: Response) => {
        finished.push("verify");
        return res;
      },
    );
    await new Promise((resolve) => setImmediate(resolve));
    const reading = Promise.resolve(api.app.request("/v1/apps", { headers: bearer(other.admin) })).then(
      (res: Response) => {
        finished.push("other");
        return res;
      },
    );
    const [verifyRes, otherRes] = await Promise.all([verifying, reading]);
    expect(otherRes.status).toBe(200);
    expect(AuditVerifyResponseSchema.parse(await verifyRes.json()).verify.valid).toBe(true);
    expect(finished).toEqual(["other", "verify"]);
  });

  it("limits verify and export per Organization, with Retry-After", async () => {
    const limited = await makeTestApi({ now, auditReadsPerMinute: 2 });
    try {
      const org = await createOrganization(limited);
      const other = await createOrganization(limited, "Other");
      const headers = bearer(org.admin_key.key);
      expect((await limited.app.request("/v1/audit/verify", { headers })).status).toBe(200);
      expect((await limited.app.request("/v1/audit/export", { headers })).status).toBe(200);
      for (const path of ["/v1/audit/verify", "/v1/audit/export"]) {
        const res = await limited.app.request(path, { headers });
        await expectProblem(res, 429);
        expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
      }
      // Another Organization has its own budget; the list is not limited.
      expect((await limited.app.request("/v1/audit/verify", { headers: bearer(other.admin_key.key) })).status).toBe(
        200,
      );
      expect((await limited.app.request("/v1/audit", { headers })).status).toBe(200);
    } finally {
      await limited.close();
    }
  });

  it("keeps the chain head out of the request role's reach: only the trigger moves it", async () => {
    const t = await tenant();
    await createAppFor(api, t.admin);
    const scope = { organizationId: t.organizationId };
    for (const sql of [
      "UPDATE audit_heads SET seq = seq - 1",
      "DELETE FROM audit_heads",
      `INSERT INTO audit_heads (organization_id, seq, hash) VALUES ('${t.organizationId}', 9, '${"0".repeat(64)}')`,
      "SELECT seq FROM audit_heads FOR UPDATE",
    ]) {
      await expect(
        api.db.tx(scope, (q) => q.query(sql)),
        sql,
      ).rejects.toMatchObject({ code: "42501" });
    }
    // Every later change still writes its entry.
    await createAppFor(api, t.admin);
    expect(await verify(t.admin)).toMatchObject({ valid: true, entries: 3, last_seq: 3 });
  });

  it("refuses an entry whose seq or prev_hash does not follow the head, whoever inserts it", async () => {
    const t = await tenant();
    await createAppFor(api, t.admin);
    const [, second] = (await exported(t.admin)) as [AuditEntry, AuditEntry];
    const insert = (seq: number, prevHash: string) =>
      `INSERT INTO audit_entries (id, organization_id, seq, at, actor_kind, actor_key_id, action, target_kind, target_id,
         summary, request_id, prev_hash, hash)
       VALUES ('aud_${"1".repeat(24)}', '${t.organizationId}', ${seq}, now(), 'admin_key', '${t.keyId}', 'app.create',
         'app', 'x', 'Forged.', '${randomUUID()}', '${prevHash}', '${"f".repeat(64)}')`;
    const scope = { organizationId: t.organizationId };
    for (const sql of [insert(4, second.hash), insert(2, second.hash), insert(3, "e".repeat(64))]) {
      await expect(api.db.tx(scope, (q) => q.query(sql))).rejects.toThrow(/audit chain/);
      await expect(api.db.owner((q) => q.query(sql))).rejects.toThrow(/audit chain/);
    }
    expect(await verify(t.admin)).toMatchObject({ valid: true, entries: 2, last_seq: 2 });
  });

  it("signs the head with the audit key, publishes the key, and leads the export with it", async () => {
    const t = await tenant();
    await createAppFor(api, t.admin);
    const publicKey = await auditPublicKey();
    expect(publicKey).not.toBe(api.signer.publicKey);
    const { signed_head } = await verified(t.admin);
    expect(signed_head.head).toEqual({
      organization_id: t.organizationId,
      seq: 2,
      hash: (await exported(t.admin))[1]?.hash,
      at: now().toISOString(),
    });
    expect(signedByAudit(signed_head, publicKey)).toBe(true);
    expect(signedByAudit({ ...signed_head, head: { ...signed_head.head, seq: 1 } }, publicKey)).toBe(false);
    const { head, entries } = await exportedWithHead(t.admin);
    expect(signedByAudit(head, publicKey)).toBe(true);
    expect(head.head.seq).toBe(entries.at(-1)?.seq);
    expect(head.head.hash).toBe(entries.at(-1)?.hash);
    expect(chainHolds(entries)).toBe(true);
  });

  it("lets a verifier holding a signed head see the owner truncate the chain and reset the head", async () => {
    const t = await tenant();
    await createAppFor(api, t.admin);
    await createAppFor(api, t.admin);
    const publicKey = await auditPublicKey();
    const held = (await verified(t.admin)).signed_head;
    expect(held.head.seq).toBe(3);
    const kept = (await exported(t.admin))[1] as AuditEntry;
    await api.db.owner(async (q) => {
      await q.query("DELETE FROM audit_entries WHERE organization_id = $1 AND seq = 3", [t.organizationId]);
      await q.query("UPDATE audit_heads SET seq = 2, hash = $2 WHERE organization_id = $1", [
        t.organizationId,
        kept.hash,
      ]);
    });
    // The chain alone looks whole again...
    const now2 = await verified(t.admin);
    expect(now2.verify).toEqual({ valid: true, entries: 2, last_seq: 2, first_broken_seq: null });
    // ...but the head the verifier kept is genuine, and the chain no longer reaches it.
    expect(signedByAudit(held, publicKey)).toBe(true);
    const { entries } = await exportedWithHead(t.admin);
    const reaches = entries.some((entry) => entry.seq === held.head.seq && entry.hash === held.head.hash);
    expect(reaches).toBe(false);
    expect(now2.signed_head.head.seq).toBeLessThan(held.head.seq);
  });

  it("does not let the request role update or delete entries, nor delete the chain head", async () => {
    const t = await tenant();
    const scope = { organizationId: t.organizationId };
    await expect(api.db.tx(scope, (q) => q.query("UPDATE audit_entries SET summary = 'x'"))).rejects.toMatchObject({
      code: "42501",
    });
    await expect(api.db.tx(scope, (q) => q.query("DELETE FROM audit_entries"))).rejects.toMatchObject({
      code: "42501",
    });
    await expect(api.db.tx(scope, (q) => q.query("DELETE FROM audit_heads"))).rejects.toMatchObject({
      code: "42501",
    });
    await expect(api.db.tx(scope, (q) => q.query("TRUNCATE audit_entries"))).rejects.toMatchObject({
      code: "42501",
    });
    expect((await verify(t.admin)).valid).toBe(true);
  });

  it("isolates tenants: rows, filters and verification see only the caller's Organization", async () => {
    const a = await tenant("A");
    const b = await tenant("B");
    const appA = await createAppFor(api, a.admin);
    expect((await list(b.admin)).entries.map((entry) => entry.action)).toEqual(["organization.create"]);
    expect((await list(b.admin, `?target_id=${appA.app.id}`)).entries).toEqual([]);
    expect((await list(b.admin, `?app_id=${appA.app.id}`)).entries).toEqual([]);
    expect(await verify(b.admin)).toEqual({ valid: true, entries: 1, last_seq: 1, first_broken_seq: null });
    expect((await exported(b.admin)).every((entry) => entry.organization_id === b.organizationId)).toBe(true);
    // Row-level security: without a tenant the table is empty, with another tenant only that tenant's rows.
    const unscoped = await api.db.tx("none", (q) => q.query("SELECT 1 FROM audit_entries"));
    expect(unscoped.rows).toEqual([]);
    const asB = await api.db.tx({ organizationId: b.organizationId }, (q) =>
      q.query<{ organization_id: string }>("SELECT DISTINCT organization_id FROM audit_entries"),
    );
    expect(asB.rows).toEqual([{ organization_id: b.organizationId }]);
  });

  it("answers 401 without a key and 403 to a Shield key", async () => {
    const t = await tenant();
    const shield = (await createAppFor(api, t.admin)).shield_key.key;
    for (const path of ["/v1/audit", "/v1/audit/verify", "/v1/audit/export"]) {
      await expectProblem(await api.app.request(path), 401);
      await expectProblem(await api.app.request(path, { headers: bearer(shield) }), 403);
    }
  });

  it("writes no entry for a change that fails", async () => {
    const t = await tenant();
    const add = () => api.app.request("/v1/allowlist", json({ cidr: "10.0.0.0/8", note: "Office" }, bearer(t.admin)));
    expect((await add()).status).toBe(201);
    await expectProblem(await add(), 409);
    await expectProblem(await api.app.request("/v1/apps", json({ name: "" }, bearer(t.admin))), 400);
    await expectProblem(
      await api.app.request("/v1/allowlist/alw_000000000000000000000000", {
        method: "DELETE",
        headers: bearer(t.admin),
      }),
      404,
    );
    expect((await list(t.admin)).entries.map((entry) => entry.action)).toEqual([
      "allowlist_entry.create",
      "organization.create",
    ]);
  });

  it("rolls the change back when its entry cannot be written", async () => {
    const t = await tenant();
    await api.db.owner((q) => q.query("REVOKE INSERT ON audit_entries FROM ar_app"));
    try {
      await expectProblem(await api.app.request("/v1/apps", json({ name: "Lost" }, bearer(t.admin))), 500);
    } finally {
      await api.db.owner((q) => q.query("GRANT INSERT ON audit_entries TO ar_app"));
    }
    const apps = await api.app.request("/v1/apps", { headers: bearer(t.admin) });
    expect(ListAppsResponseSchema.parse(await apps.json()).apps).toEqual([]);
    expect(await verify(t.admin)).toEqual({ valid: true, entries: 1, last_seq: 1, first_broken_seq: null });
    // The chain carries on from where it was.
    await createAppFor(api, t.admin);
    expect((await exported(t.admin)).map((entry) => entry.seq)).toEqual([1, 2]);
  });
});
