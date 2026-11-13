// Slice 18b over HTTP, QASUITE TC-CON-007: an Organization with data in every area exports everything (hashed,
// signed, cut at a signed audit head), requests its deletion with a reason and its typed name, is refused on every
// key but for its deletion status, cancel and export, is purged after the 7-day grace by the daily job, and leaves no
// row in any table of the catalog; its signed deletion report verifies against the audit key, and a second
// Organization is untouched. The real API on a free port; the seed is the API tests' (apps/api/test/data-seed.ts),
// sent over HTTP, with the few rows no route writes on its own written as the owner.
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { type OwnedDb, type RunningApi, startApi, unavailableAssessor } from "@antireverse/api";
import {
  type AdvisoryInput,
  AuditPublicKeyResponseSchema,
  AuditVerifyResponseSchema,
  canonicalJson,
  DATA_EXPORT_FORMAT,
  DeletionStatusResponseSchema,
  dataExportSignedText,
  deletionReportSignedText,
  type ExportEndLine,
  ExportLineSchema,
  type ExportManifestLine,
  type ExportRowLine,
  ProblemSchema,
  SignedDeletionReportSchema,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FIXTURE_ADVISORIES_FILE, fixtureSource } from "../../apps/api/src/vulns/source.ts";
import { syncAdvisories } from "../../apps/api/src/vulns/sync.ts";
import {
  requestDeletion,
  rowsOf,
  type Seeded,
  seedOrganization,
  tablesWithoutRows,
  tenantTables,
} from "../../apps/api/test/data-seed.ts";
import type { TestApi } from "../../apps/api/test/helpers.ts";

const T0 = Date.parse("2026-11-13T09:00:00.000Z");
const DAY = 86_400_000;
const PENDING = "https://antireverse.dev/problems/organization-deletion-pending";
/** The owner's tombstones: they outlive the Organization by design (ticket 18b). */
const TOMBSTONES = "organization_deletions";

const clock = { ms: T0 };
const now = () => new Date(clock.ms);
let api: RunningApi;
let http: TestApi;
let a: Seeded;
let b: Seeded;
let tables: string[];
let bBefore: Record<string, number>;
let deletionId: string;
let auditKey: { key_id: string; public_key: string };

const owner = () => api.db as OwnedDb;
const get = (path: string, key?: string) =>
  fetch(`${api.url}${path}`, { headers: key === undefined ? {} : { authorization: `Bearer ${key}` } });

function verifies(text: string, signature: string): boolean {
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: auditKey.public_key }, format: "jwk" });
  return verify(null, Buffer.from(text, "utf8"), key, Buffer.from(signature, "base64url"));
}

async function expectPending(res: Response): Promise<void> {
  expect(res.status).toBe(403);
  expect(ProblemSchema.parse(await res.json()).type).toBe(PENDING);
}

beforeAll(async () => {
  api = await startApi({
    now,
    smtp: null,
    email: {
      mailer: { send: async (messages) => messages.map(() => ({ ok: true, code: 250 })) },
      sender: { address: "alerts@airverse.test", name: "Airverse" },
    },
    allowPrivateAlertUrls: true,
    assessor: unavailableAssessor(),
    prove: {
      resolver: {
        txt: async () => {
          throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
        },
        addresses: async () => [],
      },
      fetcher: async () => ({ ok: false, reason: "status" }),
    },
    // The test runs the purge itself.
    purge: { firstRunMs: 3_600_000 },
    logger: { info() {}, warn() {} },
  });
  const fixtures = JSON.parse(readFileSync(FIXTURE_ADVISORIES_FILE, "utf8")) as AdvisoryInput[];
  await syncAdvisories(owner(), fixtureSource(fixtures));
  // The seed's view of the API: every request over HTTP to the running server; the database as its owner.
  http = {
    app: { request: (path: string, init?: RequestInit) => fetch(`${api.url}${path}`, init) },
    db: owner(),
    issuedKeys: [],
    flushIncidents: async () => {},
  } as unknown as TestApi;
  const webhookUrl = "http://127.0.0.1:9/hook";
  a = await seedOrganization(http, "Acme Shop", { now, webhookUrl });
  b = await seedOrganization(http, "Bravo", { now, webhookUrl });
  tables = [...(await tenantTables(http)).filter((table) => table !== TOMBSTONES), "organizations"];
  bBefore = await rowsOf(http, b.organizationId, tables);
  auditKey = AuditPublicKeyResponseSchema.parse(await (await get("/v1/audit/public-key")).json());
}, 60_000);

afterAll(async () => {
  await api?.close();
});

describe("TC-CON-007: export, deletion and purge over HTTP", () => {
  it("has data of both Organizations in every tenant table", async () => {
    expect((await tablesWithoutRows(http, a.organizationId)).filter((t) => t !== TOMBSTONES)).toEqual([]);
    expect((await tablesWithoutRows(http, b.organizationId)).filter((t) => t !== TOMBSTONES)).toEqual([]);
  });

  it("exports every table, hashed and signed, cut at a signed audit head, counts matching", async () => {
    const res = await get("/v1/organization/export", a.admin);
    expect(res.status).toBe(200);
    const text = await res.text();
    const lines = text.slice(0, -1).split("\n");
    const parsed = lines.map((line) => ExportLineSchema.parse(JSON.parse(line)));
    const manifest = parsed[0] as ExportManifestLine;
    const end = parsed.at(-1) as ExportEndLine;
    const rows = parsed.slice(1, -1) as ExportRowLine[];
    expect(manifest).toMatchObject({ kind: "manifest", format: DATA_EXPORT_FORMAT, consistency: "per-page" });
    expect([...manifest.tables].sort()).toEqual([...tables].sort());

    const preceding = lines
      .slice(0, -1)
      .map((line) => `${line}\n`)
      .join("");
    expect(end.sha256).toBe(createHash("sha256").update(preceding, "utf8").digest("hex"));
    expect(end.key_id).toBe(auditKey.key_id);
    expect(verifies(dataExportSignedText(end), end.signature)).toBe(true);

    const head = manifest.audit_head;
    if (head === undefined) throw new Error("No audit head.");
    expect(verifies(canonicalJson(head.head), head.signature)).toBe(true);
    const entries = rows.filter((line) => line.table === "audit_entries").map((line) => line.row);
    expect(entries.map((entry) => entry.seq)).toEqual(Array.from({ length: head.head.seq }, (_, i) => i + 1));
    expect(entries.at(-1)?.hash).toBe(head.head.hash);

    // Counts: what the end line says, what the lines hold, and what the database holds (nothing written since).
    const seen: Record<string, number> = Object.fromEntries(manifest.tables.map((table) => [table, 0]));
    for (const line of rows) seen[line.table] = (seen[line.table] ?? 0) + 1;
    expect(end.counts).toEqual(seen);
    expect(end.counts).toEqual(await rowsOf(http, a.organizationId, manifest.tables));
    for (const secret of a.secrets) expect(text).not.toContain(secret);
  });

  it("requests the deletion with a reason and the typed name; every key is refused but status, cancel and export", async () => {
    deletionId = await requestDeletion(http, a);
    await expectPending(await get("/v1/organization", a.admin));
    await expectPending(await get("/v1/incidents", a.admin));
    await expectPending(await get("/v1/policy-bundle", a.shield));
    const status = await get("/v1/organization/deletion", a.admin);
    expect(status.status).toBe(200);
    const { deletion } = DeletionStatusResponseSchema.parse(await status.json());
    expect(deletion).toMatchObject({
      id: deletionId,
      status: "pending",
      purge_after: new Date(T0 + 7 * DAY).toISOString(),
    });
    const exported = await get("/v1/organization/export", a.admin);
    expect(exported.status).toBe(200);
    await exported.text();
    // The other Organization works as before.
    expect((await get("/v1/organization", b.admin)).status).toBe(200);
  });

  it("purges after the grace: the keys are unknown, no row is left in any table, the other Organization is untouched", async () => {
    clock.ms = T0 + 7 * DAY - 1;
    expect(await api.purge.runOnce()).toEqual({ due: 0, purged: 0, failed: 0 });
    clock.ms = T0 + 7 * DAY + 1;
    expect(await api.purge.runOnce()).toEqual({ due: 1, purged: 1, failed: 0 });

    expect((await get("/v1/organization", a.admin)).status).toBe(401);
    expect((await get("/v1/organization/deletion", a.admin)).status).toBe(401);
    expect((await get("/v1/policy-bundle", a.shield)).status).toBe(401);

    // The catalog as the owner: every table with an organization_id column, read now.
    const now = [...(await tenantTables(http)).filter((table) => table !== TOMBSTONES), "organizations"];
    const left = await rowsOf(http, a.organizationId, now);
    expect(Object.entries(left).filter(([, n]) => n !== 0)).toEqual([]);

    expect(await rowsOf(http, b.organizationId, tables)).toEqual(bBefore);
    const verified = await get("/v1/audit/verify", b.admin);
    expect(AuditVerifyResponseSchema.parse(await verified.json()).verify.valid).toBe(true);
  });

  it("serves the signed deletion report by its id", async () => {
    const res = await get(`/v1/deletions/${deletionId}/report`);
    expect(res.status).toBe(200);
    const signed = SignedDeletionReportSchema.parse(await res.json());
    expect(signed.report).toMatchObject({ deletion_id: deletionId, organization_id: a.organizationId });
    expect(signed.report.total_rows).toBe(Object.values(signed.report.rows).reduce((sum, n) => sum + n, 0));
    expect(signed.report.rows.organizations).toBe(1);
    expect(signed.key_id).toBe(auditKey.key_id);
    expect(verifies(deletionReportSignedText(signed.report), signed.signature)).toBe(true);
  });
});
