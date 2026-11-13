import { createHash, randomBytes, createHash as sha256Of } from "node:crypto";
import {
  AUDIT_GENESIS_HASH,
  type AuditEntry,
  AuditPublicKeyResponseSchema,
  type BuildManifest,
  canonicalJson,
  DATA_EXPORT_CONTENT_TYPE,
  DATA_EXPORT_FORMAT,
  dataExportSignedText,
  EXAMPLE_BUILD_MANIFEST,
  type ExportEndLine,
  ExportLineSchema,
  type ExportManifestLine,
  type ExportRowLine,
  ListAuditResponseSchema,
} from "@antireverse/protocol";
import { auditHash, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EXPORT_PAGE } from "../src/data/export.ts";
import { type OwnedDb, openDb, type Queryable } from "../src/db/db.ts";
import { newArtifactId } from "../src/stores/assessments.ts";
import { DELETION_TABLE } from "../src/stores/deletions.ts";
import { makeDataApi, rowsOf, type Seeded, seedOrganization, tenantTables } from "./data-seed.ts";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  verifySignature,
} from "./helpers.ts";

// Slice 18b: `GET /v1/organization/export` — every tenant table, paged, hashed and signed with the audit key.

const T0 = Date.parse("2026-11-13T09:00:00.000Z");

interface Parsed {
  text: string;
  lines: string[];
  manifest: ExportManifestLine;
  rows: ExportRowLine[];
  end: ExportEndLine;
}

function parse(text: string): Parsed {
  expect(text.endsWith("\n")).toBe(true);
  const lines = text.slice(0, -1).split("\n");
  const parsed = lines.map((line) => ExportLineSchema.parse(JSON.parse(line)));
  const [manifest, ...rest] = parsed;
  const end = rest.pop();
  if (manifest?.kind !== "manifest" || end?.kind !== "end") throw new Error("Not an export.");
  expect(rest.every((line) => line.kind === "row")).toBe(true);
  return { text, lines, manifest, rows: rest as ExportRowLine[], end };
}

/** The database, recording each query's text and how many rows it answered. */
function spying(db: OwnedDb, log: { sql: string; rows: number }[]): OwnedDb {
  const wrap = (q: Queryable): Queryable => ({
    async query(sql, params) {
      const result = await q.query(sql, params);
      log.push({ sql, rows: result.rows.length });
      return result as never;
    },
  });
  return {
    tx: (scope, fn) => db.tx(scope, (q) => fn(wrap(q))),
    owner: (fn) => db.owner((q) => fn(wrap(q))),
    close: () => db.close(),
  };
}

describe("organization export", () => {
  let api: Awaited<ReturnType<typeof makeDataApi>>;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const log: { sql: string; rows: number }[] = [];
  let a: Seeded;
  let b: Seeded;
  let exported: Parsed;
  let res: Response;

  beforeAll(async () => {
    const db = spying(await openDb(), log);
    api = await makeDataApi(now, { db });
    // More events than two pages hold: the export must page them.
    a = await seedOrganization(api, "Acme", { now, subjectEvents: 2 * EXPORT_PAGE + 1 });
    b = await seedOrganization(api, "Bravo", { now });
    log.length = 0;
    res = await api.app.request("/v1/organization/export", { headers: bearer(a.admin) });
    exported = parse(await res.text());
  });
  afterAll(async () => {
    expectNoKeyLogged(api);
    await api.close();
  });

  it("streams NDJSON as an attachment named after the Organization and the UTC date", () => {
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe(DATA_EXPORT_CONTENT_TYPE);
    expect(res.headers.get("content-disposition")).toBe(
      `attachment; filename="airverse-${a.organizationId}-2026-11-13.ndjson"`,
    );
    expect(exported.manifest).toEqual({
      kind: "manifest",
      format: DATA_EXPORT_FORMAT,
      organization_id: a.organizationId,
      generated_at: new Date(T0).toISOString(),
      consistency: "per-page",
      tables: exported.manifest.tables,
      audit_head: exported.manifest.audit_head,
    });
  });

  it("lists every tenant table of the catalog and the Organization itself", async () => {
    const tables = (await tenantTables(api)).filter((table) => table !== DELETION_TABLE);
    expect([...exported.manifest.tables].sort()).toEqual([...tables, "organizations"].sort());
    // The audit chain first (cut at the head the manifest names), then the Organization.
    expect(exported.manifest.tables.slice(0, 3)).toEqual(["audit_heads", "audit_entries", "organizations"]);
  });

  it("holds every row of the Organization and nothing of another, counts matching", async () => {
    const counts = await rowsOf(api, a.organizationId, exported.manifest.tables);
    expect(exported.end.counts).toEqual(counts);
    const seen: Record<string, number> = {};
    for (const line of exported.rows) {
      seen[line.table] = (seen[line.table] ?? 0) + 1;
      const owner = line.table === "organizations" ? line.row.id : line.row.organization_id;
      expect(owner, line.table).toBe(a.organizationId);
    }
    expect(seen).toEqual(Object.fromEntries(Object.entries(counts).filter(([, n]) => n > 0)));
    expect(exported.text).not.toContain(b.organizationId);
    // Rows come table by table in the manifest's order.
    const order = exported.rows.map((line) => exported.manifest.tables.indexOf(line.table));
    expect(order).toEqual([...order].sort((x, y) => x - y));
  });

  it("hashes every preceding line and signs counts and hash with the audit key", async () => {
    const preceding = exported.lines
      .slice(0, -1)
      .map((line) => `${line}\n`)
      .join("");
    expect(exported.end.sha256).toBe(createHash("sha256").update(preceding, "utf8").digest("hex"));
    const key = AuditPublicKeyResponseSchema.parse(await (await api.app.request("/v1/audit/public-key")).json());
    expect(exported.end.key_id).toBe(key.key_id);
    expect(verifySignature(key.public_key, dataExportSignedText(exported.end), exported.end.signature)).toBe(true);
    const forged = { ...exported.end, counts: { ...exported.end.counts, events: 0 } };
    expect(verifySignature(key.public_key, dataExportSignedText(forged), exported.end.signature)).toBe(false);
  });

  it("exports credentials as hashes, prefixes and last four only, never a key or secret", () => {
    for (const secret of a.secrets) {
      expect(secret.length).toBeGreaterThan(10);
      expect(exported.text).not.toContain(secret);
    }
    const keys = exported.rows.filter((line) => line.table === "api_keys").map((line) => line.row);
    expect(keys).toHaveLength(2);
    for (const key of keys) {
      expect(key.key_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(typeof key.prefix).toBe("string");
      expect(key.last4).toMatch(/^.{4}$/);
    }
    const webhook = exported.rows.find((line) => line.table === "alert_channels" && line.row.kind === "webhook");
    expect(webhook?.row).not.toHaveProperty("signing_secret");
    expect(webhook?.row.signing_secret_sha256).toMatch(/^[0-9a-f]{64}$/);
    const target = exported.rows.find((line) => line.table === "targets");
    expect(target?.row).not.toHaveProperty("token");
    expect(target?.row.token_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("gives artifact bytes as base64 and times as ISO 8601", () => {
    const files = exported.rows.filter((line) => line.table === "artifact_files");
    expect(files).toHaveLength(2);
    const texts = files.map((line) => Buffer.from(String(line.row.content), "base64").toString("utf8"));
    expect(texts.some((text) => text.includes("console.log"))).toBe(true);
    const organization = exported.rows.find((line) => line.table === "organizations");
    expect(organization?.row.created_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  });

  it("reads each table in pages of 500 by primary key", () => {
    const pages = log.filter((entry) => entry.sql.startsWith('SELECT * FROM "events"'));
    expect(pages.length).toBeGreaterThanOrEqual(3);
    expect(Math.max(...pages.map((page) => page.rows))).toBeLessThanOrEqual(EXPORT_PAGE);
    expect(pages.reduce((sum, page) => sum + page.rows, 0)).toBe(a.subjectEvents + a.otherEvents);
  });

  it("is audited as organization.export", async () => {
    const listed = await api.app.request("/v1/audit?limit=1", { headers: bearer(a.admin) });
    const [entry] = ListAuditResponseSchema.parse(await listed.json()).entries;
    expect(entry).toMatchObject({
      action: "organization.export",
      target: { kind: "organization", id: a.organizationId },
    });
    expect(entry?.request_id).toBe(res.headers.get("x-request-id"));
  });

  it("is for admin keys only", async () => {
    await expectProblem(await api.app.request("/v1/organization/export", { headers: bearer(a.shield) }), 403);
    await expectProblem(await api.app.request("/v1/organization/export"), 401);
  });
});

describe("organization export rate limit", () => {
  it("shares the per-Organization budget of audit verifications and exports", async () => {
    const api = await makeTestApi({ auditReadsPerMinute: 2 });
    try {
      const { admin_key } = await createOrganization(api);
      expect((await api.app.request("/v1/audit/verify", { headers: bearer(admin_key.key) })).status).toBe(200);
      const first = await api.app.request("/v1/organization/export", { headers: bearer(admin_key.key) });
      expect(first.status).toBe(200);
      await first.text();
      const refused = await api.app.request("/v1/organization/export", { headers: bearer(admin_key.key) });
      expect((await expectProblem(refused, 429)).type).toBe("https://antireverse.dev/problems/too-many-requests");
      expect(refused.headers.get("retry-after")).toMatch(/^\d+$/);
      await expectProblem(await api.app.request("/v1/audit/export", { headers: bearer(admin_key.key) }), 429);
    } finally {
      await api.close();
    }
  });
});

describe("export memory", () => {
  const FILES = 24;
  const FILE_BYTES = 1_048_576;

  it("holds one artifact file at a time: no chunk near the size of a page of them", async () => {
    const api = await makeTestApi();
    try {
      const org = await createOrganization(api, "Acme");
      const admin = org.admin_key.key;
      const organizationId = org.organization.id;
      const appId = (await createAppFor(api, admin)).app.id;
      const manifest: BuildManifest = { ...EXAMPLE_BUILD_MANIFEST, build_id: newId("bld"), app_id: appId };
      expect((await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)))).status).toBe(201);
      await api.db.owner(async (q) => {
        for (let i = 0; i < FILES; i++) {
          const id = newArtifactId();
          const content = randomBytes(FILE_BYTES);
          await q.query(
            `INSERT INTO artifacts (organization_id, id, app_id, build_id, files, bytes, created_at, kept_until)
             VALUES ($1, $2, $3, $4, 1, $5, now(), now() + interval '30 days')`,
            [organizationId, id, appId, manifest.build_id, FILE_BYTES],
          );
          await q.query(
            "INSERT INTO artifact_files (organization_id, artifact_id, path, sha256, content) VALUES ($1, $2, 'a.js', $3, $4)",
            [organizationId, id, sha256Of("sha256").update(content).digest("hex"), content],
          );
        }
      });
      const res = await api.app.request("/v1/organization/export", { headers: bearer(admin) });
      expect(res.status).toBe(200);
      const reader = (res.body as ReadableStream<Uint8Array>).getReader();
      let largest = 0;
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        largest = Math.max(largest, value.byteLength);
        total += value.byteLength;
      }
      expect(total).toBeGreaterThan(FILES * FILE_BYTES);
      expect(largest).toBeLessThan(8 * FILE_BYTES);
    } finally {
      await api.close();
    }
  });
});

describe("export consistency", () => {
  /** An exported audit row as the protocol's entry (as the store reads it). */
  function entryOf(row: Record<string, unknown>): AuditEntry {
    return {
      id: String(row.id),
      organization_id: String(row.organization_id),
      seq: Number(row.seq),
      at: String(row.at),
      actor: { kind: "admin_key", key_id: String(row.actor_key_id) },
      action: row.action as AuditEntry["action"],
      ...(row.app_id === null ? {} : { app_id: String(row.app_id) }),
      target: { kind: row.target_kind as AuditEntry["target"]["kind"], id: String(row.target_id) },
      ...(row.reason === null ? {} : { reason: String(row.reason) }),
      summary: String(row.summary),
      request_id: String(row.request_id),
      prev_hash: String(row.prev_hash),
      hash: String(row.hash),
    };
  }

  it("cuts the audit chain at the signed head read first, whatever is written while it streams", async () => {
    let hook: (() => Promise<void>) | undefined;
    const inner = await openDb();
    const wrap = (q: Queryable): Queryable => ({
      async query(sql, params) {
        const result = await q.query(sql, params);
        // After the first page of any table: a concurrent request runs between this page and the next.
        if (sql.startsWith("SELECT * FROM") && hook !== undefined) {
          const run = hook;
          hook = undefined;
          setImmediate(() => void run());
        }
        return result as never;
      },
    });
    const db: OwnedDb = {
      tx: (scope, fn) => inner.tx(scope, (q) => fn(wrap(q))),
      owner: (fn) => inner.owner((q) => fn(wrap(q))),
      close: () => inner.close(),
    };
    const api = await makeTestApi({ db });
    try {
      const org = await createOrganization(api, "Acme");
      const admin = org.admin_key.key;
      await createAppFor(api, admin);
      let written: Promise<number> | undefined;
      hook = async () => {
        written = Promise.resolve(
          api.app.request("/v1/allowlist", json({ cidr: "10.0.0.0/8", note: "Office" }, bearer(admin))),
        ).then((r) => r.status);
        await written;
      };
      const res = await api.app.request("/v1/organization/export", { headers: bearer(admin) });
      expect(res.status).toBe(200);
      const exported = parse(await res.text());
      expect(await written).toBe(201);
      expect(exported.manifest.consistency).toBe("per-page");
      const signed = exported.manifest.audit_head;
      if (signed === undefined) throw new Error("No audit head in the manifest.");
      const key = AuditPublicKeyResponseSchema.parse(await (await api.app.request("/v1/audit/public-key")).json());
      expect(verifySignature(key.public_key, canonicalJson(signed.head), signed.signature)).toBe(true);
      const heads = exported.rows.filter((line) => line.table === "audit_heads").map((line) => line.row);
      expect(heads).toEqual([{ organization_id: org.organization.id, seq: signed.head.seq, hash: signed.head.hash }]);
      const entries = exported.rows.filter((line) => line.table === "audit_entries").map((line) => entryOf(line.row));
      expect(entries.map((entry) => entry.seq)).toEqual(Array.from({ length: signed.head.seq }, (_, i) => i + 1));
      let prev = AUDIT_GENESIS_HASH;
      for (const entry of entries) {
        expect(entry.prev_hash).toBe(prev);
        const { hash, ...rest } = entry;
        expect(auditHash(rest)).toBe(hash);
        prev = hash;
      }
      expect(prev).toBe(signed.head.hash);
      // The concurrent change's entry came after the head: it is not in this export's chain.
      expect(entries.map((entry) => entry.action)).not.toContain("allowlist_entry.create");
    } finally {
      await api.close();
    }
  });
});
