import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { PGlite } from "@electric-sql/pglite";

/**
 * Applies every `.sql` file of `directory` that is not recorded yet, in name order, one transaction per
 * file. Returns the names applied by this call. A file that changed after it was applied is an error.
 * Must run as the database owner, before the session switches to the request role.
 */
export async function migrate(pg: PGlite, directory: string): Promise<string[]> {
  await pg.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);
  const recorded = await pg.query<{ version: string; checksum: string }>(
    "SELECT version, checksum FROM schema_migrations",
  );
  const done = new Map(recorded.rows.map((row) => [row.version, row.checksum]));

  const applied: string[] = [];
  const files = readdirSync(directory)
    .filter((name) => name.endsWith(".sql"))
    .sort();
  for (const file of files) {
    const sql = readFileSync(join(directory, file), "utf8");
    const checksum = createHash("sha256").update(sql).digest("hex");
    const known = done.get(file);
    if (known !== undefined) {
      if (known !== checksum) throw new Error(`Migration ${file} changed after it was applied.`);
      continue;
    }
    await pg.transaction(async (tx) => {
      await tx.exec(sql);
      await tx.query("INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)", [file, checksum]);
    });
    applied.push(file);
  }
  return applied;
}
