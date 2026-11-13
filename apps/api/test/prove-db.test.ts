import { generateVerificationToken, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { type Db, openDb } from "../src/db/db.ts";

vi.setConfig({ testTimeout: 30_000, hookTimeout: 30_000 });

// The Prove tables at the SQL level, as the request role (slice 14): targets and Rules of Engagement versions under
// row-level security with FORCE; a signed version can be inserted and read, never changed or removed.

const T = "2026-11-12T08:00:00.000Z";
const KEY = "key_0123456789abcdef01234567";
const SHA = "a".repeat(64);

describe("Prove tables", () => {
  let db: Db;
  let orgA: string;
  let orgB: string;

  async function organization(name: string): Promise<string> {
    const id = newId("org");
    await db.tx({ organizationId: id }, (q) =>
      q.query("INSERT INTO organizations (id, name) VALUES ($1, $2)", [id, name]),
    );
    return id;
  }

  const inOrg = <R>(organizationId: string, sql: string, params: unknown[] = []) =>
    db.tx({ organizationId }, (q) => q.query<R>(sql, params));

  async function target(organizationId: string, host: string, status = "pending"): Promise<string> {
    const id = newId("tgt");
    const verified = status !== "pending";
    await inOrg(
      organizationId,
      `INSERT INTO targets (organization_id, id, host, token, status, method, verified_at, last_checked_at,
         lapsed_reason, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9)`,
      [
        organizationId,
        id,
        host,
        generateVerificationToken(),
        status,
        verified ? "dns" : null,
        verified ? T : null,
        status === "lapsed" ? "dns: no_record; file: timeout" : null,
        T,
      ],
    );
    return id;
  }

  async function version(organizationId: string, number: number, scope: string[]): Promise<string> {
    const id = newId("roe");
    await inOrg(
      organizationId,
      `INSERT INTO rules_of_engagement (organization_id, id, version, scope, exclusions, intensity, window_days,
         window_from, window_to, contacts, signed_by, signed_at, content_sha256)
       VALUES ($1, $2, $3, $4, '{}', 'passive', '{mon}', '09:00', '17:00', '{sec@acme-shop.io}', $5, $6, $7)`,
      [organizationId, id, number, scope, KEY, T, SHA],
    );
    return id;
  }

  beforeAll(async () => {
    db = await openDb();
    orgA = await organization("A");
    orgB = await organization("B");
  });

  afterAll(async () => {
    await db.close();
  });

  it("forces row-level security on every Prove table", async () => {
    const { rows } = await db.tx("none", (q) =>
      q.query<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean }>(
        `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
         WHERE relname IN ('targets', 'rules_of_engagement', 'verify_limits') ORDER BY relname`,
      ),
    );
    expect(rows).toEqual([
      { relname: "rules_of_engagement", relrowsecurity: true, relforcerowsecurity: true },
      { relname: "targets", relrowsecurity: true, relforcerowsecurity: true },
      { relname: "verify_limits", relrowsecurity: true, relforcerowsecurity: true },
    ]);
  });

  it("hides one Organization's targets and versions from another and from no tenant", async () => {
    const id = await target(orgA, "hidden.acme-shop.io");
    await version(orgA, 1, [id]);
    const seen = async (scope: Parameters<Db["tx"]>[0]) =>
      db.tx(scope, async (q) => ({
        targets: (await q.query("SELECT id FROM targets WHERE id = $1", [id])).rows.length,
        versions: (await q.query("SELECT id FROM rules_of_engagement WHERE $1 = ANY(scope)", [id])).rows.length,
      }));
    expect(await seen({ organizationId: orgA })).toEqual({ targets: 1, versions: 1 });
    expect(await seen({ organizationId: orgB })).toEqual({ targets: 0, versions: 0 });
    expect(await seen("none")).toEqual({ targets: 0, versions: 0 });
    expect(
      (await inOrg(orgB, "UPDATE targets SET last_checked_at = now() WHERE id = $1 RETURNING id", [id])).rows,
    ).toEqual([]);
    expect((await inOrg(orgB, "DELETE FROM targets WHERE id = $1 RETURNING id", [id])).rows).toEqual([]);
    await expect(target(orgB, "x.acme-shop.io").then(() => {})).resolves.toBeUndefined();
    // Writing a row of another Organization fails the policy.
    await expect(
      inOrg(
        orgB,
        `INSERT INTO targets (organization_id, id, host, token, status, created_at)
         VALUES ($1, $2, 'y.acme-shop.io', $3, 'pending', $4)`,
        [orgA, newId("tgt"), generateVerificationToken(), T],
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it("keeps a host unique per Organization, and independent across Organizations", async () => {
    await target(orgA, "shop.acme-shop.io");
    await expect(target(orgA, "shop.acme-shop.io")).rejects.toThrow(/duplicate key|unique/);
    await expect(target(orgB, "shop.acme-shop.io")).resolves.toMatch(/^tgt_/);
  });

  it("holds a target to the status shape", async () => {
    await expect(
      inOrg(
        orgA,
        `INSERT INTO targets (organization_id, id, host, token, status, created_at)
         VALUES ($1, $2, 'shape.acme-shop.io', $3, 'verified', $4)`,
        [orgA, newId("tgt"), generateVerificationToken(), T],
      ),
    ).rejects.toThrow(/check constraint/);
    const id = await target(orgA, "lapsed.acme-shop.io", "verified");
    await expect(inOrg(orgA, "UPDATE targets SET status = 'lapsed' WHERE id = $1", [id])).rejects.toThrow(
      /check constraint/,
    );
  });

  it("never lets the request role change or remove a signed version", async () => {
    const id = await version(orgA, 2, [newId("tgt")]);
    await expect(inOrg(orgA, "UPDATE rules_of_engagement SET intensity = 'full' WHERE id = $1", [id])).rejects.toThrow(
      /permission denied/,
    );
    await expect(inOrg(orgA, "DELETE FROM rules_of_engagement WHERE id = $1", [id])).rejects.toThrow(
      /permission denied/,
    );
    await expect(inOrg(orgA, "TRUNCATE rules_of_engagement")).rejects.toThrow(/permission denied/);
    await expect(version(orgA, 2, [newId("tgt")])).rejects.toThrow(/duplicate key|unique/);
  });

  it("never lets the request role rewrite a target's host, token or creation", async () => {
    const id = await target(orgA, "fixed.acme-shop.io");
    for (const column of ["host = 'other.acme-shop.io'", `token = '${"b".repeat(43)}'`, "created_at = now()"]) {
      await expect(inOrg(orgA, `UPDATE targets SET ${column} WHERE id = $1`, [id])).rejects.toThrow(
        /permission denied/,
      );
    }
  });

  it("lists due targets across Organizations by id only, through prove_due_targets", async () => {
    const due = await target(orgB, "due.acme-shop.io", "verified");
    const { rows } = await db.tx("none", (q) =>
      q.query<Record<string, unknown>>("SELECT * FROM prove_due_targets($1::timestamptz, 1000)", [
        "2026-11-13T09:00:00.000Z",
      ]),
    );
    expect(rows).toContainEqual({ organization_id: orgB, target_id: due });
    for (const row of rows) expect(Object.keys(row).sort()).toEqual(["organization_id", "target_id"]);
    const early = await db.tx("none", (q) =>
      q.query("SELECT * FROM prove_due_targets($1::timestamptz, 1000)", ["2026-11-12T07:00:00.000Z"]),
    );
    expect(early.rows).toEqual([]);
  });
});
