import {
  type Component,
  DETECTION_RULES,
  type Environment,
  type FindingSeverity,
  type FindingSource,
  fixedVersions,
  isAffected,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import type { Db, OwnedDb, Queryable } from "../db/db.ts";
import { recordAndAlert } from "../detect/record.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import type { Notifier } from "../notify/notifier.ts";
import { advisoriesForPackages, type StoredAdvisory } from "../stores/advisories.ts";
import { reviveExpired } from "../stores/findings.ts";
import { recordDetection } from "../stores/incidents.ts";

// Matching (slice 19, SDD §12A, plan A5–A7): an inventory's components against the advisories that name their
// packages, and the Finding lifecycle. A Finding is keyed by (App, Environment, source, package, version, advisory)
// and, for a build Finding, its Build. The components matched are a Build's own, or for the runtime the union of
// the App Environment's live Shield instances (one inventory per instance, live while it posted within 24 hours).
//   - a match without a Finding of this scope moves the identity's open or ignored Finding of an older Build of the
//     App Environment here (a build match; id, first_seen and ignore kept — second review M-A), else inserts one,
//     open; a fixed Finding of the same key opens again, a withdrawn one too — or comes back ignored while the ignore
//     it kept is unexpired (L-A);
//   - an ignored Finding stays ignored until its expiry, then is open again;
//   - a Finding the components no longer match is fixed when its version left them (its ignore ends), and withdrawn
//     (D-060) when the version is still there but the advisory no longer covers it — keeping its ignore (L-A);
//   - for a Build, the open Findings of the App Environment's older Builds are fixed (or withdrawn, as above) when
//     this, newer, Build does not ship the same package version with the same advisory.
// "Opened" (a Detection, maybe an Incident) means: a new Finding (a moved one is not new), or one back to open from
// fixed or withdrawn — so the next Build of an unchanged lockfile opens nothing.
// Bounds (M4): closed runtime Findings are deleted 30 days after they closed; an App Environment keeps at most
// `FINDINGS_PER_SCOPE_MAX` Findings, the oldest closed ones deleted first.
// Logs never carry a package name, a version or an advisory: counts only.

/** A runtime instance that has not posted for this long is no longer part of the runtime set. */
export const INSTANCE_TTL_MS = 24 * 3_600_000;
/** Fixed and withdrawn runtime Findings are deleted this long after they closed. */
export const CLOSED_RUNTIME_RETENTION_MS = 30 * 86_400_000;
/** Findings kept per App Environment, all sources together. */
export const FINDINGS_PER_SCOPE_MAX = 20_000;

export interface InventoryInput {
  organizationId: string;
  appId: string;
  environment: Environment;
  source: FindingSource;
  /** The registered Build of a build inventory; null for a runtime inventory. */
  buildId: string | null;
  /** The runtime Shield instance that sent it (32 hex); '' or absent: the shared legacy instance. */
  instance?: string | undefined;
  /** This inventory's components (for the runtime: this instance's; the union is read from the database). */
  components: readonly Component[];
  /** When the inventory arrived (or, on a re-match, when it was matched): `first_seen`/`last_seen`. */
  at: Date;
}

/** A Finding that became open by this match (see "Opened" above). */
export interface OpenedFinding {
  id: string;
  appId: string;
  environment: Environment;
  buildId: string | null;
  advisoryId: string;
  severity: FindingSeverity;
  at: Date;
}

export interface MatchResult {
  /** Inventory row matched (for the runtime: the instance's row, or 0 on a re-match). */
  inventoryId: number;
  /** Component-advisory matches. */
  matched: number;
  opened: OpenedFinding[];
  fixed: number;
}

type Status = "open" | "fixed" | "ignored" | "withdrawn";

interface ExistingRow {
  id: string;
  package: string;
  version: string;
  advisory_id: string;
  status: Status;
  ignore_until: Date | null;
  severity: FindingSeverity;
  fixed_versions: string[];
  dev: boolean;
}

const RULE = DETECTION_RULES.find((rule) => rule.key === "vulnerable-component");
if (RULE === undefined) throw new Error("The vulnerable-component rule is missing from the protocol.");
const VULNERABLE_COMPONENT = RULE;

const keyOf = (pkg: string, version: string, advisory: string) => JSON.stringify([pkg, version, advisory]);
const componentKey = (pkg: string, version: string) => JSON.stringify([pkg, version]);

/** Stores the inventory: a Build's once; a runtime instance's replacing that instance's previous one. */
async function storeInventory(q: Queryable, input: InventoryInput): Promise<number> {
  const { rows } = await q.query<{ id: number }>(
    `INSERT INTO inventories (organization_id, app_id, environment, source, build_id, instance, components, received_at)
     VALUES ($1, $2, $3, $4, $5::text, $6, $7::jsonb, $8::timestamptz)
     ON CONFLICT (organization_id, app_id, environment, source, (COALESCE(build_id, '')), instance)
     DO UPDATE SET components = EXCLUDED.components, received_at = EXCLUDED.received_at
     RETURNING id`,
    [
      input.organizationId,
      input.appId,
      input.environment,
      input.source,
      input.buildId,
      input.source === "runtime" ? (input.instance ?? "") : "",
      JSON.stringify(input.components.map(({ name, version, dev }) => ({ name, version, dev }))),
      input.at.toISOString(),
    ],
  );
  const id = rows[0]?.id;
  if (id === undefined) throw new Error("The inventory was not stored.");
  return Number(id);
}

/**
 * The runtime set of an App Environment at `at`: expired instances deleted, the live ones' components united (a
 * name@version is a development dependency only if every instance says so).
 */
async function runtimeComponents(
  q: Queryable,
  appId: string,
  environment: Environment,
  at: Date,
): Promise<Component[]> {
  await q.query(
    `DELETE FROM inventories WHERE app_id = $1 AND environment = $2 AND source = 'runtime'
       AND received_at <= $3::timestamptz`,
    [appId, environment, new Date(at.getTime() - INSTANCE_TTL_MS).toISOString()],
  );
  const { rows } = await q.query<{ name: string; version: string; dev: boolean }>(
    `SELECT c->>'name' AS name, c->>'version' AS version, bool_and((c->>'dev')::boolean) AS dev
     FROM inventories, jsonb_array_elements(components) AS c
     WHERE app_id = $1 AND environment = $2 AND source = 'runtime'
     GROUP BY 1, 2`,
    [appId, environment],
  );
  return rows.map((row) => ({ name: row.name, version: row.version, dev: row.dev }));
}

/**
 * Stores (unless `inventoryId` is given: a re-match) and matches one inventory in the caller's tenant transaction,
 * and maintains the Findings of its scope. Returns the Findings it opened; the caller opens Incidents for the
 * Critical and High ones after its commit (`openIncidents`).
 */
export async function matchInventory(
  q: Queryable,
  input: InventoryInput,
  options: { inventoryId?: number; findingsMax?: number } = {},
): Promise<MatchResult> {
  const at = input.at.toISOString();
  const inventoryId = options.inventoryId ?? (await storeInventory(q, input));
  await reviveExpired(q, input.at);
  const components =
    input.source === "runtime"
      ? await runtimeComponents(q, input.appId, input.environment, input.at)
      : [...input.components];

  const names = [...new Set(components.map((component) => component.name))];
  const byName = new Map<string, StoredAdvisory[]>();
  for (const stored of await advisoriesForPackages(q, names)) {
    for (const entry of stored.advisory.affected) {
      if (entry.package.ecosystem !== "npm") continue;
      const list = byName.get(entry.package.name) ?? [];
      if (!list.includes(stored)) list.push(stored);
      byName.set(entry.package.name, list);
    }
  }

  const matches = new Map<string, { component: Component; stored: StoredAdvisory; fixed: string[] }>();
  for (const component of components) {
    for (const stored of byName.get(component.name) ?? []) {
      if (!isAffected(stored.advisory, component.name, component.version)) continue;
      matches.set(keyOf(component.name, component.version, stored.advisory.id), {
        component,
        stored,
        fixed: fixedVersions(stored.advisory, component.name),
      });
    }
  }

  const existing = await q.query<ExistingRow>(
    `SELECT id, package, version, advisory_id, status, ignore_until, severity, fixed_versions, dev FROM findings
     WHERE app_id = $1 AND environment = $2 AND source = $3 AND build_id IS NOT DISTINCT FROM $4::text
     FOR UPDATE`,
    [input.appId, input.environment, input.source, input.buildId],
  );
  const known = new Map(existing.rows.map((row) => [keyOf(row.package, row.version, row.advisory_id), row]));

  // M-A: an identity this Build carries that is open or ignored in an older Build of the App Environment moves
  // here (id, first_seen and ignore kept), so each identity has at most one open or ignored build Finding. (No row
  // lock: PostgreSQL refuses FOR UPDATE with DISTINCT ON, and every transaction holds the database's one lock.)
  const movable = new Map<string, string>();
  const fresh = [...matches.keys()].filter((key) => !known.has(key));
  if (input.source === "build" && fresh.length > 0) {
    const older = await q.query<{ id: string; package: string; version: string; advisory_id: string }>(
      `SELECT DISTINCT ON (f.package, f.version, f.advisory_id) f.id, f.package, f.version, f.advisory_id
       FROM findings f JOIN inventories i
         ON i.organization_id = f.organization_id AND i.app_id = f.app_id AND i.environment = f.environment
          AND i.source = 'build' AND i.build_id = f.build_id
       WHERE f.app_id = $1 AND f.environment = $2 AND f.source = 'build' AND f.status IN ('open', 'ignored')
         AND i.id < $3
       ORDER BY f.package, f.version, f.advisory_id, i.id DESC`,
      [input.appId, input.environment, inventoryId],
    );
    for (const row of older.rows) movable.set(keyOf(row.package, row.version, row.advisory_id), row.id);
  }

  const opened: OpenedFinding[] = [];
  const inserts: { id: string; component: Component; stored: StoredAdvisory; fixed: string[] }[] = [];
  const moves: { id: string; severity: FindingSeverity; dev: boolean; fixed: string[] }[] = [];
  const updates: { id: string; severity: FindingSeverity; dev: boolean; fixed: string[] }[] = [];
  const seen: string[] = [];
  for (const [key, { component, stored, fixed }] of matches) {
    const row = known.get(key);
    const severity = stored.severity;
    if (row === undefined) {
      const moving = movable.get(key);
      if (moving !== undefined) {
        moves.push({ id: moving, severity, dev: component.dev, fixed });
        continue;
      }
      const id = newId("fnd");
      inserts.push({ id, component, stored, fixed });
      opened.push({ id, ...scopeOf(input), advisoryId: stored.advisory.id, severity, at: input.at });
      continue;
    }
    // L-A: a withdrawn Finding whose ignore has not expired comes back ignored, without opening anything.
    const restoresIgnore =
      row.status === "withdrawn" && row.ignore_until !== null && row.ignore_until.getTime() > input.at.getTime();
    const back = row.status === "fixed" || row.status === "withdrawn";
    if (back && !restoresIgnore) {
      opened.push({ id: row.id, ...scopeOf(input), advisoryId: stored.advisory.id, severity, at: input.at });
    }
    const changed =
      back ||
      row.severity !== severity ||
      row.dev !== component.dev ||
      JSON.stringify(row.fixed_versions) !== JSON.stringify(fixed);
    if (changed) updates.push({ id: row.id, severity, dev: component.dev, fixed });
    else seen.push(row.id);
  }

  // Batched: one statement per kind of write, whatever the number of components (M4).
  if (inserts.length > 0) {
    await q.query(
      `INSERT INTO findings (id, organization_id, app_id, environment, source, build_id, package, version, dev,
         advisory_id, severity, fixed_versions, status, first_seen, last_seen, updated_at)
       SELECT n.id, $1, $2, $3, $4, $5::text, n.package, n.version, n.dev, n.advisory_id, n.severity,
         ARRAY(SELECT jsonb_array_elements_text(n.fixed)), 'open', $6::timestamptz, $6::timestamptz, $6::timestamptz
       FROM unnest($7::text[], $8::text[], $9::text[], $10::boolean[], $11::text[], $12::text[], $13::jsonb[])
         AS n(id, package, version, dev, advisory_id, severity, fixed)`,
      [
        input.organizationId,
        input.appId,
        input.environment,
        input.source,
        input.buildId,
        at,
        inserts.map((i) => i.id),
        inserts.map((i) => i.component.name),
        inserts.map((i) => i.component.version),
        inserts.map((i) => i.component.dev),
        inserts.map((i) => i.stored.advisory.id),
        inserts.map((i) => i.stored.severity),
        inserts.map((i) => JSON.stringify(i.fixed)),
      ],
    );
  }
  if (moves.length > 0) {
    await q.query(
      `UPDATE findings f SET build_id = $2, severity = u.severity, dev = u.dev,
         fixed_versions = ARRAY(SELECT jsonb_array_elements_text(u.fixed)),
         last_seen = GREATEST(f.last_seen, $1::timestamptz), updated_at = $1::timestamptz
       FROM unnest($3::text[], $4::text[], $5::boolean[], $6::jsonb[]) AS u(id, severity, dev, fixed)
       WHERE f.id = u.id`,
      [
        at,
        input.buildId,
        moves.map((u) => u.id),
        moves.map((u) => u.severity),
        moves.map((u) => u.dev),
        moves.map((u) => JSON.stringify(u.fixed)),
      ],
    );
  }
  if (updates.length > 0) {
    // fixed → open; withdrawn → ignored while its ignore lasts (L-A), else open with the ignore dropped.
    await q.query(
      `UPDATE findings f SET
         status = CASE WHEN f.status = 'fixed' THEN 'open'
                       WHEN f.status = 'withdrawn' AND f.ignore_until > $1::timestamptz THEN 'ignored'
                       WHEN f.status = 'withdrawn' THEN 'open'
                       ELSE f.status END,
         ignore_reason = CASE WHEN f.status = 'withdrawn' AND NOT (f.ignore_until > $1::timestamptz) THEN NULL
                              ELSE f.ignore_reason END,
         ignore_by = CASE WHEN f.status = 'withdrawn' AND NOT (f.ignore_until > $1::timestamptz) THEN NULL
                          ELSE f.ignore_by END,
         ignore_until = CASE WHEN f.status = 'withdrawn' AND NOT (f.ignore_until > $1::timestamptz) THEN NULL
                             ELSE f.ignore_until END,
         severity = u.severity, dev = u.dev, fixed_versions = ARRAY(SELECT jsonb_array_elements_text(u.fixed)),
         last_seen = GREATEST(f.last_seen, $1::timestamptz), updated_at = $1::timestamptz
       FROM unnest($2::text[], $3::text[], $4::boolean[], $5::jsonb[]) AS u(id, severity, dev, fixed)
       WHERE f.id = u.id`,
      [
        at,
        updates.map((u) => u.id),
        updates.map((u) => u.severity),
        updates.map((u) => u.dev),
        updates.map((u) => JSON.stringify(u.fixed)),
      ],
    );
  }
  if (seen.length > 0) {
    await q.query(`UPDATE findings SET last_seen = GREATEST(last_seen, $2::timestamptz) WHERE id = ANY($1::text[])`, [
      seen,
      at,
    ]);
  }

  // The scope's Findings the components no longer match: fixed when the version left them (the ignore ends), and
  // withdrawn when it is still installed but the advisory no longer covers it (the ignore is kept, L-A).
  const present = new Set(components.map((component) => componentKey(component.name, component.version)));
  const unmatched = existing.rows.filter(
    (row) => row.status !== "fixed" && !matches.has(keyOf(row.package, row.version, row.advisory_id)),
  );
  const isPresent = (row: ExistingRow) => present.has(componentKey(row.package, row.version));
  const gone = unmatched.filter((row) => !isPresent(row)).map((row) => row.id);
  const uncovered = unmatched.filter((row) => row.status !== "withdrawn" && isPresent(row)).map((row) => row.id);
  let fixedCount = 0;
  if (gone.length > 0) {
    const result = await q.query(
      `UPDATE findings SET status = 'fixed', ignore_reason = NULL, ignore_until = NULL, ignore_by = NULL,
         updated_at = $2::timestamptz
       WHERE id = ANY($1::text[]) RETURNING id`,
      [gone, at],
    );
    fixedCount += result.rows.length;
  }
  if (uncovered.length > 0) {
    await q.query(`UPDATE findings SET status = 'withdrawn', updated_at = $2::timestamptz WHERE id = ANY($1::text[])`, [
      uncovered,
      at,
    ]);
  }

  // Whether the Finding's package version is among this inventory's components: then the advisory no longer covers
  // it (withdrawn, ignore kept), else the version left (fixed, ignore ends). Constant text; $8/$9 hold the components.
  const INSTALLED = `EXISTS (SELECT 1 FROM unnest($8::text[], $9::text[]) AS c(package, version)
    WHERE c.package = f.package AND c.version = f.version)`;
  // A newer Build decides for the App Environment's older Builds (older: their inventory was stored earlier).
  if (input.source === "build") {
    const kept = [...matches.values()];
    const result = await q.query(
      `UPDATE findings f SET
         status = CASE WHEN ${INSTALLED} THEN 'withdrawn' ELSE 'fixed' END,
         ignore_reason = CASE WHEN ${INSTALLED} THEN f.ignore_reason END,
         ignore_until = CASE WHEN ${INSTALLED} THEN f.ignore_until END,
         ignore_by = CASE WHEN ${INSTALLED} THEN f.ignore_by END,
         updated_at = $4::timestamptz
       FROM inventories i
       WHERE f.app_id = $1 AND f.environment = $2 AND f.source = 'build' AND f.status IN ('open', 'ignored')
         AND i.organization_id = f.organization_id AND i.app_id = f.app_id AND i.environment = f.environment
         AND i.source = 'build' AND i.build_id = f.build_id AND i.id < $3
         AND NOT EXISTS (
           SELECT 1 FROM unnest($5::text[], $6::text[], $7::text[]) AS m(package, version, advisory_id)
           WHERE m.package = f.package AND m.version = f.version AND m.advisory_id = f.advisory_id)
       RETURNING f.id`,
      [
        input.appId,
        input.environment,
        inventoryId,
        at,
        kept.map((m) => m.component.name),
        kept.map((m) => m.component.version),
        kept.map((m) => m.stored.advisory.id),
        components.map((component) => component.name),
        components.map((component) => component.version),
      ],
    );
    fixedCount += result.rows.length;
  }

  await bound(q, input, options.findingsMax ?? FINDINGS_PER_SCOPE_MAX);
  return { inventoryId, matched: matches.size, opened, fixed: fixedCount };
}

/** Retention and the per-App-Environment cap (M4): closed Findings only, the oldest closed first. */
async function bound(q: Queryable, input: InventoryInput, findingsMax: number): Promise<void> {
  if (input.source === "runtime") {
    await q.query(
      `DELETE FROM findings WHERE app_id = $1 AND environment = $2 AND source = 'runtime'
         AND status IN ('fixed', 'withdrawn') AND updated_at < $3::timestamptz`,
      [input.appId, input.environment, new Date(input.at.getTime() - CLOSED_RUNTIME_RETENTION_MS).toISOString()],
    );
  }
  const { rows } = await q.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM findings WHERE app_id = $1 AND environment = $2",
    [input.appId, input.environment],
  );
  const over = (rows[0]?.n ?? 0) - findingsMax;
  if (over <= 0) return;
  await q.query(
    `DELETE FROM findings WHERE id IN (
       SELECT id FROM findings WHERE app_id = $1 AND environment = $2 AND status IN ('fixed', 'withdrawn')
       ORDER BY updated_at, id LIMIT $3)`,
    [input.appId, input.environment, over],
  );
}

function scopeOf(input: InventoryInput): Pick<OpenedFinding, "appId" | "environment" | "buildId"> {
  return { appId: input.appId, environment: input.environment, buildId: input.buildId };
}

export interface IncidentDeps {
  db: Db;
  notifier: Pick<Notifier, "incidentOpened">;
  logger?: Logger | undefined;
}

/**
 * Opens (or joins) a `vulnerable-component` Incident for each advisory among the newly opened Critical and High
 * Findings: one Detection per (App, Environment, advisory) of this match, grouped while the Incident is open or
 * acknowledged. Run after the matching transaction committed. Errors are logged by kind and swallowed: an inventory
 * is accepted whether or not its Incident could be written.
 */
export async function openIncidents(
  deps: IncidentDeps,
  organizationId: string,
  opened: OpenedFinding[],
): Promise<void> {
  const logger = redacting(deps.logger ?? consoleLogger);
  const groups = new Map<string, OpenedFinding>();
  for (const finding of opened) {
    if (finding.severity !== "critical" && finding.severity !== "high") continue;
    const key = JSON.stringify([finding.appId, finding.environment, finding.advisoryId]);
    if (!groups.has(key)) groups.set(key, finding);
  }
  for (const finding of groups.values()) {
    const severity = finding.severity as "critical" | "high";
    const at = finding.at.toISOString();
    try {
      await recordAndAlert(deps.db, deps.notifier, organizationId, (q) =>
        recordDetection(q, {
          organizationId,
          appId: finding.appId,
          environment: finding.environment,
          rule: VULNERABLE_COMPONENT,
          ipPrefix: null,
          count: 1,
          windowStart: at,
          windowEnd: at,
          detectedAt: finding.at,
          vulnerability: { advisoryId: finding.advisoryId, severity, buildId: finding.buildId },
        }),
      );
    } catch (error) {
      logger.warn(`exposure incident failed ${error instanceof Error ? error.name : "error"}`);
    }
  }
}

/**
 * Opens the Incidents of matched inventories after the response (second review L-C), as the Detector does: the
 * request only enqueues; the jobs run one after another, errors logged by kind only. `flush()` resolves when every
 * job enqueued so far has finished — for shutdown and for tests, which never need to sleep.
 */
export interface IncidentQueue {
  enqueue(organizationId: string, opened: OpenedFinding[]): void;
  flush(): Promise<void>;
}

export function createIncidentQueue(
  deps: IncidentDeps & {
    /** Runs a job. Default: at once, in the background. A test may hold jobs to run them itself. */
    schedule?: ((job: () => Promise<void>) => void) | undefined;
  },
): IncidentQueue {
  const pending = new Set<Promise<void>>();
  let tail: Promise<void> = Promise.resolve();
  const schedule =
    deps.schedule ??
    ((job: () => Promise<void>) => {
      // One after another: Incidents of one App group in order, and the database lock is never contended by many.
      const run = tail.then(job, job);
      tail = run;
      pending.add(run);
      void run.finally(() => pending.delete(run));
    });
  return {
    enqueue(organizationId, opened) {
      if (!opened.some((finding) => finding.severity === "critical" || finding.severity === "high")) return;
      // openIncidents never rejects: it logs each failure by its kind.
      schedule(() => openIncidents(deps, organizationId, opened));
    },
    async flush() {
      while (pending.size > 0) await Promise.allSettled([...pending]);
    },
  };
}

export interface RematchDeps extends IncidentDeps {
  /** The sync path's database: listing every Organization's inventories needs the owner. */
  db: OwnedDb;
  now?: (() => Date) | undefined;
}

/**
 * After a sync: matches every Organization's current inventories again — per App Environment, the latest Build's
 * and the runtime set (the union of its live instances) — each Organization in its own transaction, and opens the
 * Incidents. Returns counts only.
 */
export async function rematchAll(
  deps: RematchDeps,
): Promise<{ organizations: number; inventories: number; opened: number }> {
  const now = deps.now ?? (() => new Date());
  const logger = redacting(deps.logger ?? consoleLogger);
  const organizations = await deps.db.owner((q) =>
    q.query<{ organization_id: string }>("SELECT organization_id FROM exposure_inventory_organizations()"),
  );
  let inventories = 0;
  let openedCount = 0;
  for (const { organization_id: organizationId } of organizations.rows) {
    const opened = await deps.db.tx({ organizationId }, async (q) => {
      const latest = await q.query<{
        id: number;
        app_id: string;
        environment: Environment;
        source: FindingSource;
        build_id: string | null;
        components: Component[];
      }>(
        `SELECT DISTINCT ON (app_id, environment, source) id, app_id, environment, source, build_id,
           CASE WHEN source = 'build' THEN components ELSE '[]'::jsonb END AS components
         FROM inventories ORDER BY app_id, environment, source, id DESC`,
      );
      const all: OpenedFinding[] = [];
      for (const row of latest.rows) {
        const result = await matchInventory(
          q,
          {
            organizationId,
            appId: row.app_id,
            environment: row.environment,
            source: row.source,
            buildId: row.build_id,
            // A runtime re-match reads the union of the live instances itself.
            components: row.components,
            at: now(),
          },
          { inventoryId: Number(row.id) },
        );
        all.push(...result.opened);
      }
      inventories += latest.rows.length;
      return all;
    });
    openedCount += opened.length;
    await openIncidents(deps, organizationId, opened);
  }
  logger.info(
    `exposure rematch organizations=${organizations.rows.length} inventories=${inventories} opened=${openedCount}`,
  );
  return { organizations: organizations.rows.length, inventories, opened: openedCount };
}
