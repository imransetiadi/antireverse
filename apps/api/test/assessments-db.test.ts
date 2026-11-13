import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { type Db, openDb } from "../src/db/db.ts";

vi.setConfig({ testTimeout: 30_000, hookTimeout: 30_000 });

// The slice 12a tables at the SQL level, as the request role: row-level security with FORCE on each; the request role
// can neither delete an artifact nor change what identifies an Assessment.

const TABLES = ["artifact_files", "artifacts", "assessments", "build_routes"];

describe("Assessment tables", () => {
  let db: Db;

  beforeAll(async () => {
    db = await openDb();
  });
  afterAll(async () => {
    await db.close();
  });

  it("forces row-level security on every new table", async () => {
    const { rows } = await db.tx("none", (q) =>
      q.query<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean }>(
        `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
         WHERE relname = ANY($1) AND relkind = 'r' ORDER BY relname`,
        [TABLES],
      ),
    );
    expect(rows).toEqual(TABLES.map((relname) => ({ relname, relrowsecurity: true, relforcerowsecurity: true })));
  });

  it("gives the request role no DELETE on any of them and no UPDATE of identifying columns", async () => {
    const { rows } = await db.tx("none", (q) =>
      q.query<{ table_name: string; privilege_type: string }>(
        `SELECT table_name, privilege_type FROM information_schema.role_table_grants
         WHERE grantee = 'ar_app' AND table_name = ANY($1) ORDER BY table_name, privilege_type`,
        [TABLES],
      ),
    );
    expect(rows.filter((row) => row.privilege_type === "DELETE")).toEqual([]);
    expect(rows.filter((row) => row.privilege_type === "UPDATE")).toEqual([]);
    const columns = await db.tx("none", (q) =>
      q.query<{ table_name: string; column_name: string }>(
        `SELECT table_name, column_name FROM information_schema.column_privileges
         WHERE grantee = 'ar_app' AND privilege_type = 'UPDATE' AND table_name = ANY($1)
         ORDER BY table_name, column_name`,
        [TABLES],
      ),
    );
    const updatable = columns.rows.map((row) => `${row.table_name}.${row.column_name}`);
    expect(updatable).toContain("artifacts.kept_until");
    for (const fixed of [
      "assessments.organization_id",
      "assessments.id",
      "assessments.build_id",
      "assessments.tier",
      "assessments.artifact_id",
      "artifacts.organization_id",
      "artifacts.build_id",
    ]) {
      expect(updatable).not.toContain(fixed);
    }
  });

  it("shows no queue to a role without the definer functions' rights, only identifiers through them", async () => {
    const { rows } = await db.tx("none", (q) =>
      q.query<{ name: string; args: string }>(
        `SELECT p.proname AS name, pg_get_function_result(p.oid) AS args FROM pg_proc p
         WHERE p.proname IN ('assessment_queue', 'assessments_interrupt', 'assessment_artifacts_expire')
         ORDER BY p.proname`,
      ),
    );
    expect(rows.map((row) => row.name)).toEqual([
      "assessment_artifacts_expire",
      "assessment_queue",
      "assessments_interrupt",
    ]);
    expect(rows.find((row) => row.name === "assessment_queue")?.args).toBe(
      "TABLE(organization_id text, assessment_id text, status text)",
    );
  });
});
