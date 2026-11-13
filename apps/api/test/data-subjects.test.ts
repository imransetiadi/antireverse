import { createHash } from "node:crypto";
import {
  AuditPublicKeyResponseSchema,
  DATA_EXPORT_CONTENT_TYPE,
  dataExportSignedText,
  type ExportEndLine,
  ExportLineSchema,
  type ExportManifestLine,
  type ExportRowLine,
  ListAuditResponseSchema,
  SUBJECT_EXPORT_FORMAT,
  SubjectEraseResponseSchema,
} from "@antireverse/protocol";
import { auditSubjectRef } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeDataApi, type Seeded, SUBJECT_ADDRESS, seedOrganization } from "./data-seed.ts";
import { bearer, expectNoKeyLogged, expectProblem, json, verifySignature, withReason } from "./helpers.ts";

// Slice 18b: subject requests by actor hash — export an end user's Events and blocks, erase them (ended blocks only;
// active blocks are kept until they end and listed).

const T0 = Date.parse("2026-11-13T09:00:00.000Z");
const DAY = 86_400_000;

describe("subject requests", () => {
  let api: Awaited<ReturnType<typeof makeDataApi>>;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let a: Seeded;
  let b: Seeded;

  beforeAll(async () => {
    api = await makeDataApi(now);
    a = await seedOrganization(api, "Acme", { now });
    b = await seedOrganization(api, "Bravo", { now });
  });
  afterAll(async () => {
    expectNoKeyLogged(api);
    await api.close();
  });

  const exportOf = (key: string, ipHash: string) =>
    api.app.request("/v1/subjects/export", json({ ip_hash: ipHash }, bearer(key)));
  const erase = (key: string, ipHash: string, headers: Record<string, string> = withReason()) =>
    api.app.request("/v1/subjects/erase", json({ ip_hash: ipHash }, { ...bearer(key), ...headers }));
  const count = (organizationId: string, sql: string, hash: string) =>
    api.db.owner(async (q) => {
      const { rows } = await q.query<{ n: number }>(sql, [organizationId, hash]);
      return rows[0]?.n ?? 0;
    });
  const events = (organizationId: string, hash: string) =>
    count(
      organizationId,
      "SELECT count(*)::int AS n FROM events WHERE organization_id = $1 AND payload->'actor'->>'ip_hash' = $2",
      hash,
    );
  const containments = (organizationId: string, hash: string) =>
    count(
      organizationId,
      "SELECT count(*)::int AS n FROM containments WHERE organization_id = $1 AND ip_hash = $2",
      hash,
    );
  const lastEntry = async (key: string) => {
    const listed = await api.app.request("/v1/audit?limit=1", { headers: bearer(key) });
    return ListAuditResponseSchema.parse(await listed.json()).entries[0];
  };

  it("takes an actor hash only", async () => {
    await expectProblem(await exportOf(a.admin, SUBJECT_ADDRESS), 400);
    await expectProblem(
      await api.app.request(
        "/v1/subjects/export",
        json({ ip_hash: a.subjectHash, ip: SUBJECT_ADDRESS }, bearer(a.admin)),
      ),
      400,
    );
    await expectProblem(await exportOf(a.shield, a.subjectHash), 403);
  });

  it("exports the subject's Events and blocks, signed, and audits the counts", async () => {
    const res = await exportOf(a.admin, a.subjectHash);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe(DATA_EXPORT_CONTENT_TYPE);
    const text = await res.text();
    const lines = text.slice(0, -1).split("\n");
    const parsed = lines.map((line) => ExportLineSchema.parse(JSON.parse(line)));
    const manifest = parsed[0] as ExportManifestLine;
    const end = parsed.at(-1) as ExportEndLine;
    const rows = parsed.slice(1, -1) as ExportRowLine[];
    expect(manifest).toEqual({
      kind: "manifest",
      format: SUBJECT_EXPORT_FORMAT,
      organization_id: a.organizationId,
      generated_at: now().toISOString(),
      consistency: "per-page",
      tables: ["events", "containments"],
      subject: { ip_hash: a.subjectHash },
    });
    expect(end.counts).toEqual({ events: a.subjectEvents, containments: 2 });
    expect(rows.filter((line) => line.table === "events")).toHaveLength(a.subjectEvents);
    for (const line of rows) {
      const hash =
        line.table === "events" ? (line.row.payload as { actor: { ip_hash: string } }).actor.ip_hash : line.row.ip_hash;
      expect(hash).toBe(a.subjectHash);
    }
    expect(text).not.toContain(a.otherHash);
    const preceding = lines
      .slice(0, -1)
      .map((line) => `${line}\n`)
      .join("");
    expect(end.sha256).toBe(createHash("sha256").update(preceding, "utf8").digest("hex"));
    const key = AuditPublicKeyResponseSchema.parse(await (await api.app.request("/v1/audit/public-key")).json());
    expect(verifySignature(key.public_key, dataExportSignedText(end), end.signature)).toBe(true);
    const entry = await lastEntry(a.admin);
    expect(entry).toMatchObject({
      action: "subject.export",
      target: { kind: "subject", id: auditSubjectRef(a.organizationId, a.subjectHash) },
    });
    expect(entry?.summary).toContain(`${a.subjectEvents} Events`);
    expect(entry?.reason).toBeUndefined();
  });

  it("does not export another Organization's subject", async () => {
    const res = await exportOf(b.admin, a.subjectHash);
    expect(res.status).toBe(200);
    const end = ExportLineSchema.parse(JSON.parse((await res.text()).trim().split("\n").at(-1) as string));
    expect(end).toMatchObject({ kind: "end", counts: { events: 0, containments: 0 } });
  });

  it("refuses an erasure without a reason and erases nothing", async () => {
    const refused = await expectProblem(await erase(a.admin, a.subjectHash, {}), 400);
    expect(refused.type).toBe("https://antireverse.dev/problems/reason-required");
    expect(await events(a.organizationId, a.subjectHash)).toBe(a.subjectEvents);
    expect(await containments(a.organizationId, a.subjectHash)).toBe(2);
  });

  it("another Organization's erasure leaves the subject's rows alone", async () => {
    const res = await erase(b.admin, a.subjectHash);
    expect(res.status).toBe(200);
    expect(SubjectEraseResponseSchema.parse(await res.json()).report).toMatchObject({
      events_erased: 0,
      containments_erased: 0,
      active_containments: [],
    });
    expect(await events(a.organizationId, a.subjectHash)).toBe(a.subjectEvents);
  });

  it("erases the Events and ended blocks, keeps and lists the active block, audits with reason and counts", async () => {
    const res = await erase(a.admin, a.subjectHash);
    expect(res.status).toBe(200);
    const { report } = SubjectEraseResponseSchema.parse(await res.json());
    expect(report).toEqual({
      ip_hash: a.subjectHash,
      events_erased: a.subjectEvents,
      containments_erased: 1,
      active_containments: [{ id: a.activeContainmentId, expires_at: new Date(T0 + DAY).toISOString() }],
    });
    expect(await events(a.organizationId, a.subjectHash)).toBe(0);
    expect(await events(a.organizationId, a.otherHash)).toBe(a.otherEvents);
    expect(await containments(a.organizationId, a.subjectHash)).toBe(1);
    const entry = await lastEntry(a.admin);
    expect(entry).toMatchObject({
      action: "subject.erase",
      target: { kind: "subject", id: auditSubjectRef(a.organizationId, a.subjectHash) },
      reason: "Test change",
    });
    expect(entry?.summary).toContain(`${a.subjectEvents} Events`);
    expect(entry?.request_id).toBe(res.headers.get("x-request-id"));
  });

  it("erases the kept block once it has expired", async () => {
    clock.ms = T0 + DAY;
    const res = await erase(a.admin, a.subjectHash);
    const { report } = SubjectEraseResponseSchema.parse(await res.json());
    expect(report).toEqual({
      ip_hash: a.subjectHash,
      events_erased: 0,
      containments_erased: 1,
      active_containments: [],
    });
    expect(await containments(a.organizationId, a.subjectHash)).toBe(0);
  });

  it("never names the actor hash in the audit log: blocks, exports and erasures use the subject reference", async () => {
    const ref = auditSubjectRef(b.organizationId, b.subjectHash);
    const block = await api.app.request(
      `/v1/incidents/${b.incidentId}/containments`,
      json({ target: { kind: "actor", ip_hash: b.subjectHash }, ttl_s: 3600 }, withReason(bearer(b.admin))),
    );
    expect(block.status, await block.clone().text()).toBe(201);
    expect((await lastEntry(b.admin))?.summary).toContain(ref);
    expect((await exportOf(b.admin, b.subjectHash)).status).toBe(200);
    expect(await lastEntry(b.admin)).toMatchObject({ action: "subject.export", target: { kind: "subject", id: ref } });
    const erased = await erase(b.admin, b.subjectHash);
    expect(erased.status).toBe(200);
    // The caller is answered with the hash it sent; the log keeps only the reference.
    expect(SubjectEraseResponseSchema.parse(await erased.json()).report.ip_hash).toBe(b.subjectHash);
    expect(await lastEntry(b.admin)).toMatchObject({ action: "subject.erase", target: { kind: "subject", id: ref } });
    const naming = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ action: string }>(
        "SELECT action FROM audit_entries e WHERE organization_id = $1 AND e::text LIKE '%' || $2 || '%'",
        [b.organizationId, b.subjectHash.slice(4)],
      );
      return rows.map((row) => row.action);
    });
    expect(naming).toEqual([]);
  });

  it("finds the subject's Events by an index on the Organization and the actor hash", async () => {
    const indexes = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ indexdef: string }>(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename = 'events'",
      );
      return rows.map((row) => row.indexdef);
    });
    expect(
      indexes.some((definition) =>
        /\(organization_id, \(\(\(payload -> 'actor'::text\) ->> 'ip_hash'::text\)\)\)/.test(definition),
      ),
    ).toBe(true);
  });
});
