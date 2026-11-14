import { createHash } from "node:crypto";
import {
  dataExportSignedText,
  EXPORT_CONSISTENCY,
  type ExportEndLine,
  type ExportManifestLine,
  type ExportRowLine,
} from "@antireverse/protocol";
import type { Db, Queryable } from "../db/db.ts";
import type { Signer } from "../signer.ts";

// The NDJSON exports of slice 18b: the Organization export (every tenant table) and the subject export (one actor
// hash's Events and blocks). Line 1 is the manifest; then one line per row, table by table in the manifest's order,
// each table read by its primary key in pages (EXPORT_PAGE rows, fewer for tables with large rows: `PAGE_ROWS`), one
// transaction per page, yielding between pages, and each row enqueued as its own chunk, so that neither memory nor the
// database (one lock for every tenant) is held for long; the last line has the counts, the SHA-256 over the bytes of
// every preceding line and the audit key's signature (`dataExportSignedText`). Consistency is per page
// (`EXPORT_CONSISTENCY`): the audit chain alone is cut at a head read first. Credentials leave as their hashes: a
// secret column `x` is exported as `x_sha256`. Binary content is base64.

/** Rows read per transaction. */
export const EXPORT_PAGE = 500;

/**
 * Rows read per transaction of the tables whose rows can be large, so that a page stays near 4 MB at most: an
 * artifact file is up to 25 MB (one at a time), an inventory's components up to 2 MB, a logic file about 1 MB, a
 * route inventory about 0.5 MB, a Manifest 256 KB, an Assessment's results and calls a few hundred KB.
 */
export const PAGE_ROWS: Readonly<Record<string, number>> = Object.freeze({
  artifact_files: 1,
  inventories: 2,
  build_logic: 4,
  build_routes: 8,
  builds: 16,
  assessments: 16,
});

/**
 * Every table of the Organization export, in export order: the audit chain first (cut at the head the manifest
 * names), then the Organization, then each tenant table. A test compares it with the catalog (every table with an
 * `organization_id` column), so a table added later fails it until it is listed here — and its secret columns, if
 * any, are named in `SECRET_COLUMNS`, and its page size in `PAGE_ROWS` if its rows can be large.
 */
export const EXPORT_TABLES: readonly string[] = Object.freeze([
  "audit_heads",
  "audit_entries",
  "organizations",
  "api_keys",
  "apps",
  "builds",
  "build_beacons",
  "build_routes",
  "build_logic",
  "canaries",
  "artifacts",
  "artifact_files",
  "assessments",
  "inventories",
  "findings",
  "policy_versions",
  "patch_modes",
  "events",
  "incidents",
  "detections",
  "containments",
  "allowlist_entries",
  "alert_channels",
  "alert_recipients",
  "alert_deliveries",
  "targets",
  "verify_limits",
  "rules_of_engagement",
  "retention_runs",
  "setup_milestones",
]);

/** Columns that hold a secret in clear: exported as the SHA-256 (hex) of the value, under `<column>_sha256`. */
export const SECRET_COLUMNS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  // The webhook signing secret.
  alert_channels: ["signing_secret"],
  // The ownership verification token.
  targets: ["token"],
});

const yieldToOthers = () => new Promise<void>((resolve) => setImmediate(resolve));

const sha256 = (value: string | Uint8Array): string => createHash("sha256").update(value).digest("hex");

/** One stored value as JSON: times as ISO 8601, bytes as base64, 64-bit integers as numbers when exact. */
function exportValue(value: unknown): unknown {
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Uint8Array) return Buffer.from(value).toString("base64");
  if (typeof value === "bigint") return Number.isSafeInteger(Number(value)) ? Number(value) : value.toString();
  if (Array.isArray(value)) return value.map(exportValue);
  return value;
}

function exportRow(table: string, row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const secrets = SECRET_COLUMNS[table] ?? [];
  for (const [column, value] of Object.entries(row)) {
    if (secrets.includes(column)) {
      out[`${column}_sha256`] = value === null ? null : sha256(String(value));
    } else {
      out[column] = exportValue(value);
    }
  }
  return out;
}

/** One table's rows to export: which, and how to tell them by primary key. */
export interface ExportSource {
  table: string;
  /** SQL condition beyond the tenant's own rows (with `$1` the Organization id), using parameters from `$2`. */
  where?: string;
  params?: unknown[];
  /** Columns that order and page the rows, unique within the Organization. Default: the primary key. */
  key?: string[];
  /** Rows already read (the audit head as the export was cut at): exported as given, not read again. */
  rows?: Record<string, unknown>[];
}

/** The primary key columns of each table, in key order (from the catalog; readable by the request role). */
async function primaryKeys(q: Queryable, tables: readonly string[]): Promise<Map<string, string[]>> {
  const { rows } = await q.query<{ table_name: string; columns: string[] }>(
    `SELECT c.relname AS table_name,
       array_agg(a.attname::text ORDER BY array_position(i.indkey::int2[], a.attnum)) AS columns
     FROM pg_catalog.pg_index i
     JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
     JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey::int2[])
     WHERE i.indisprimary AND c.relnamespace = 'public'::regnamespace AND c.relname = ANY ($1::text[])
     GROUP BY c.relname`,
    [[...tables]],
  );
  return new Map(rows.map((row) => [row.table_name, row.columns]));
}

const quote = (name: string): string => `"${name.replace(/"/g, '""')}"`;

/** Up to `limit` rows of `source` after the key `after` (null: from the first). */
async function readPage(
  q: Queryable,
  organizationId: string,
  source: ExportSource,
  key: string[],
  after: unknown[] | null,
  limit: number,
): Promise<Record<string, unknown>[]> {
  const params: unknown[] = [organizationId, ...(source.params ?? [])];
  const conditions = [`${source.table === "organizations" ? "id" : "organization_id"} = $1`];
  if (source.where !== undefined) conditions.push(`(${source.where})`);
  if (after !== null) {
    const placeholders = after.map((value) => {
      params.push(value);
      return `$${params.length}`;
    });
    conditions.push(`(${key.map(quote).join(", ")}) > (${placeholders.join(", ")})`);
  }
  const { rows } = await q.query<Record<string, unknown>>(
    `SELECT * FROM ${quote(source.table)} WHERE ${conditions.join(" AND ")}
     ORDER BY ${key.map(quote).join(", ")} LIMIT ${limit}`,
    params,
  );
  return rows;
}

/**
 * The body of an export: the manifest, every row of every source (paged), and the signed end line. Reads in the
 * Organization's own transactions (row-level security applies), one per page.
 */
export function exportStream(options: {
  db: Db;
  organizationId: string;
  manifest: Omit<ExportManifestLine, "kind" | "tables" | "consistency">;
  sources: readonly ExportSource[];
  signer: Signer;
}): ReadableStream<Uint8Array> {
  const { db, organizationId, sources, signer } = options;
  const encoder = new TextEncoder();
  const hash = createHash("sha256");
  const counts: Record<string, number> = Object.fromEntries(sources.map((source) => [source.table, 0]));
  let keys: Map<string, string[]> | undefined;
  let index = -1; // -1: the manifest is next
  let after: unknown[] | null = null;
  let done = false;

  const emit = (controller: ReadableStreamDefaultController<Uint8Array>, text: string) => {
    const bytes = encoder.encode(text);
    hash.update(bytes);
    controller.enqueue(bytes);
  };

  /** One step: the manifest, one page of rows (possibly empty), or the end line. True when it enqueued something. */
  async function step(controller: ReadableStreamDefaultController<Uint8Array>): Promise<boolean> {
    if (index === -1) {
      const manifest: ExportManifestLine = {
        kind: "manifest",
        ...options.manifest,
        consistency: EXPORT_CONSISTENCY,
        tables: sources.map((source) => source.table),
      };
      emit(controller, `${JSON.stringify(manifest)}\n`);
      index = 0;
      return true;
    }
    const source = sources[index];
    if (source === undefined) {
      const sha = hash.digest("hex");
      const end: ExportEndLine = {
        kind: "end",
        counts,
        sha256: sha,
        key_id: signer.keyId,
        signature: signer.sign(encoder.encode(dataExportSignedText({ counts, sha256: sha }))),
      };
      controller.enqueue(encoder.encode(`${JSON.stringify(end)}\n`));
      done = true;
      controller.close();
      return true;
    }
    let page: Record<string, unknown>[];
    let limit = PAGE_ROWS[source.table] ?? EXPORT_PAGE;
    let key: string[] = [];
    if (source.rows !== undefined) {
      page = source.rows;
      limit = Number.POSITIVE_INFINITY;
    } else {
      await yieldToOthers();
      keys ??= await db.tx({ organizationId }, (q) =>
        primaryKeys(
          q,
          sources.map((s) => s.table),
        ),
      );
      key = source.key ?? keys.get(source.table) ?? [];
      if (key.length === 0) throw new Error(`The table ${source.table} has no primary key.`);
      const ordered = key;
      page = await db.tx({ organizationId }, (q) => readPage(q, organizationId, source, ordered, after, limit));
    }
    // One chunk per row: a page of large rows is never one large buffer.
    for (const row of page) {
      const line: ExportRowLine = { kind: "row", table: source.table, row: exportRow(source.table, row) };
      emit(controller, `${JSON.stringify(line)}\n`);
    }
    counts[source.table] = (counts[source.table] ?? 0) + page.length;
    const last = page.at(-1);
    if (last !== undefined) after = key.map((column) => last[column]);
    if (page.length < limit) {
      index++;
      after = null;
    }
    return page.length > 0;
  }

  return new ReadableStream<Uint8Array>({
    // A pull that enqueues nothing is not called again: step until a line is out (an empty table yields none).
    async pull(controller) {
      while (!done && !(await step(controller))) {
        // next table
      }
    },
  });
}
