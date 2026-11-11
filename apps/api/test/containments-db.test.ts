import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Db, openDb } from "../src/db/db.ts";

// The containment tables at the SQL level, as the request role: a block is never deleted, and once lifted it
// never changes again. Routes and stores have their own tests.

const T = "2026-11-10T12:00:00.000Z";
const LATER = "2026-11-10T12:05:00.000Z";
const KEY = "key_0123456789abcdef01234567";
const OTHER_KEY = "key_89abcdef0123456789abcdef";

describe("containment tables", () => {
  let db: Db;
  let orgA: string;
  let appA: string;

  const inA = <T>(sql: string, params: unknown[] = []) =>
    db.tx({ organizationId: orgA }, (q) => q.query<T>(sql, params));

  async function block(): Promise<string> {
    const id = newId("cnt");
    await inA(
      `INSERT INTO containments (organization_id, id, app_id, environment, incident_id, target_kind, ip_hash,
         created_at, expires_at, created_by)
       VALUES ($1, $2, $3, 'production', NULL, 'actor', $4, $5, $5::timestamptz + interval '1 hour', $6)`,
      [orgA, id, appA, `iph_${"a".repeat(32)}`, T, KEY],
    );
    return id;
  }

  const lifted = async (id: string) =>
    (
      await inA<{ lifted_at: Date | null; lifted_by: string | null }>(
        "SELECT lifted_at, lifted_by FROM containments WHERE id = $1",
        [id],
      )
    ).rows[0];

  beforeAll(async () => {
    db = await openDb();
    orgA = newId("org");
    appA = newId("app");
    await inA("INSERT INTO organizations (id, name) VALUES ($1, 'A')", [orgA]);
    await inA("INSERT INTO apps (id, organization_id, name) VALUES ($1, $2, 'App')", [appA, orgA]);
  });
  afterAll(async () => {
    await db.close();
  });

  it("lets the request role lift a block once", async () => {
    const id = await block();
    await inA("UPDATE containments SET lifted_at = $2, lifted_by = $3 WHERE id = $1", [id, LATER, KEY]);
    expect(await lifted(id)).toEqual({ lifted_at: new Date(LATER), lifted_by: KEY });
  });

  it("refuses to un-lift a block, or to lift it again with another key or time", async () => {
    const id = await block();
    await inA("UPDATE containments SET lifted_at = $2, lifted_by = $3 WHERE id = $1", [id, LATER, KEY]);
    await expect(inA("UPDATE containments SET lifted_at = NULL, lifted_by = NULL WHERE id = $1", [id])).rejects.toThrow(
      /lifted/,
    );
    await expect(inA("UPDATE containments SET lifted_by = $2 WHERE id = $1", [id, OTHER_KEY])).rejects.toThrow(
      /lifted/,
    );
    await expect(
      inA("UPDATE containments SET lifted_at = $2::timestamptz + interval '1 minute' WHERE id = $1", [id, LATER]),
    ).rejects.toThrow(/lifted/);
    // Even an UPDATE that writes the same values: a lifted block is final.
    await expect(
      inA("UPDATE containments SET lifted_at = $2, lifted_by = $3 WHERE id = $1", [id, LATER, KEY]),
    ).rejects.toThrow(/lifted/);
    expect(await lifted(id)).toEqual({ lifted_at: new Date(LATER), lifted_by: KEY });
  });

  it("refuses to change any other column, and to delete a block", async () => {
    const id = await block();
    for (const assignment of [
      "expires_at = expires_at + interval '1 day'",
      "ip_hash = 'iph_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
      "created_by = created_by",
    ]) {
      await expect(inA(`UPDATE containments SET ${assignment} WHERE id = $1`, [id])).rejects.toThrow(
        /permission denied|lifted/,
      );
    }
    await expect(inA("DELETE FROM containments WHERE id = $1", [id])).rejects.toThrow(/permission denied/);
    expect(await lifted(id)).toEqual({ lifted_at: null, lifted_by: null });
  });
});
