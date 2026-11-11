import {
  type BundlePatch,
  type DecisionMode,
  type Environment,
  FINDING_SEVERITIES,
  type FindingSeverity,
  PATCH_LIMITS,
  type VirtualPatch,
} from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";
import type { PatchCatalog } from "./catalog.ts";

// Activation (slice 20, D-061): a catalog patch is active in an App Environment while a Finding there is open or
// ignored for one of its advisories (the Finding's advisory id or one of the advisory's aliases) and its package is
// the patch's. The mode is the admin's (`patch_modes`), monitor without a row, and survives deactivation. The bundle
// carries the active patches ordered by their most severe Finding, then id, each
// one that still fits `PATCH_LIMITS.perBundle` and `PATCH_LIMITS.bundleBytesMax`; one that does not is skipped and
// reported as not shipped, and later ones are still tried. Everything here
// is read in the caller's tenant transaction: RLS keeps it to the Organization.

export interface PatchScope {
  appId: string;
  environment: Environment;
}

/** One catalog patch in one App Environment. */
export interface PatchState {
  patch: VirtualPatch;
  mode: DecisionMode;
  active: boolean;
  /** Carried by the bundle (active and within the bounds). */
  shipped: boolean;
  /** The open or ignored Findings that activate it, most severe first, then by id. */
  findings: string[];
  /** The advisory of the first of `findings` (the Finding's own id); null when inactive. */
  advisory: string | null;
  /** The severity of the first of `findings`; null when inactive. */
  severity: FindingSeverity | null;
}

const RANK = new Map<string, number>(FINDING_SEVERITIES.map((severity, index) => [severity, index]));
const rankOf = (severity: FindingSeverity | null) =>
  severity === null ? FINDING_SEVERITIES.length : (RANK.get(severity) ?? FINDING_SEVERITIES.length);
const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** A patch as the bundle carries it: members in the documented order, nothing else. */
function bundlePatch(state: PatchState): BundlePatch {
  const { patch } = state;
  return {
    id: patch.id,
    mode: state.mode,
    ...(patch.methods === undefined ? {} : { methods: [...patch.methods] }),
    ...(patch.path === undefined ? {} : { path: patch.path }),
    conditions: patch.conditions.map((condition) => ({ ...condition })),
    advisory: state.advisory as string,
  };
}

/**
 * The active patches of `states`, in order, as the bundle carries them: each one is taken while it fits
 * `PATCH_LIMITS.perBundle` entries and `PATCH_LIMITS.bundleBytesMax` UTF-8 bytes of JSON together with those taken
 * before it; one that does not fit is skipped (its id goes to `notShipped`) and later ones are still tried.
 */
export function selectShipped(states: readonly PatchState[]): { shipped: BundlePatch[]; notShipped: string[] } {
  const shipped: BundlePatch[] = [];
  const notShipped: string[] = [];
  // `[` and `]`, then one comma between entries.
  let bytes = 2;
  for (const state of states) {
    if (!state.active || state.advisory === null) continue;
    const entry = bundlePatch(state);
    const size = Buffer.byteLength(JSON.stringify(entry), "utf8") + (shipped.length > 0 ? 1 : 0);
    // One that does not fit is skipped; a later, smaller one may still fit (order kept among those shipped).
    if (shipped.length >= PATCH_LIMITS.perBundle || bytes + size > PATCH_LIMITS.bundleBytesMax) {
      notShipped.push(state.patch.id);
      continue;
    }
    bytes += size;
    shipped.push(entry);
  }
  return { shipped, notShipped };
}

interface FindingRow {
  id: string;
  package: string;
  advisory_id: string;
  aliases: string[];
  severity: FindingSeverity;
}

/**
 * Every catalog patch in the App Environment: active ones first, by their most severe Finding then id; inactive ones
 * after, by id. `shipped` is set as `selectShipped` decides.
 */
export async function patchStates(q: Queryable, catalog: PatchCatalog, scope: PatchScope): Promise<PatchState[]> {
  const packages = [...new Set(catalog.patches.map((patch) => patch.package))];
  // One after the other: a transaction runs one statement at a time.
  const found =
    packages.length === 0
      ? { rows: [] as FindingRow[] }
      : await q.query<FindingRow>(
          `SELECT f.id, f.package, f.advisory_id, a.aliases, f.severity
           FROM findings f JOIN advisories a ON a.id = f.advisory_id
           WHERE f.app_id = $1 AND f.environment = $2 AND f.status IN ('open', 'ignored')
             AND f.package = ANY($3::text[])`,
          [scope.appId, scope.environment, packages],
        );
  const modes = await q.query<{ patch_id: string; mode: DecisionMode }>(
    "SELECT patch_id, mode FROM patch_modes WHERE app_id = $1 AND environment = $2",
    [scope.appId, scope.environment],
  );
  const modeOf = new Map(modes.rows.map((row) => [row.patch_id, row.mode]));
  const states = catalog.patches.map((patch): PatchState => {
    const advisories = new Set(patch.advisories);
    const matching = found.rows
      .filter(
        (row) =>
          row.package === patch.package &&
          (advisories.has(row.advisory_id) || row.aliases.some((alias) => advisories.has(alias))),
      )
      .sort((a, b) => rankOf(a.severity) - rankOf(b.severity) || byText(a.id, b.id));
    const first = matching[0];
    return {
      patch,
      mode: modeOf.get(patch.id) ?? "monitor",
      active: first !== undefined,
      shipped: false,
      findings: matching.map((row) => row.id),
      advisory: first?.advisory_id ?? null,
      severity: first?.severity ?? null,
    };
  });
  states.sort(
    (a, b) =>
      Number(b.active) - Number(a.active) || rankOf(a.severity) - rankOf(b.severity) || byText(a.patch.id, b.patch.id),
  );
  const shipped = new Set(selectShipped(states).shipped.map((patch) => patch.id));
  for (const state of states) state.shipped = shipped.has(state.patch.id);
  return states;
}

/** The `patches` member of the App Environment's bundle (empty: no member). */
export async function bundlePatches(q: Queryable, catalog: PatchCatalog, scope: PatchScope): Promise<BundlePatch[]> {
  return selectShipped(await patchStates(q, catalog, scope)).shipped;
}

/** Stores the admin's mode for one patch in one App Environment. */
export async function setPatchMode(
  q: Queryable,
  input: {
    organizationId: string;
    appId: string;
    environment: Environment;
    patchId: string;
    mode: DecisionMode;
    by: string;
    at: Date;
  },
): Promise<void> {
  await q.query(
    `INSERT INTO patch_modes (organization_id, app_id, environment, patch_id, mode, updated_at, updated_by)
     VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7)
     ON CONFLICT (organization_id, app_id, environment, patch_id)
     DO UPDATE SET mode = EXCLUDED.mode, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
    [input.organizationId, input.appId, input.environment, input.patchId, input.mode, input.at.toISOString(), input.by],
  );
}

/**
 * Hits of each patch id in the App Environment: Events naming it received in the 24 hours before `at`, and the last.
 * An Event whose body was never checked (`patch_body: "unchecked"`, plan A6 F2) is not a hit.
 */
export async function patchHits(
  q: Queryable,
  scope: PatchScope,
  patchIds: readonly string[],
  at: Date,
): Promise<Map<string, { hits24h: number; lastHit: string | null }>> {
  const result = new Map<string, { hits24h: number; lastHit: string | null }>();
  if (patchIds.length === 0) return result;
  const { rows } = await q.query<{ patch_id: string; hits: number; last: Date | null }>(
    `SELECT payload->'decision'->>'patch_id' AS patch_id,
       (count(*) FILTER (WHERE received_at > $4::timestamptz AND received_at <= $5::timestamptz))::int AS hits,
       max(received_at) AS last
     FROM events
     WHERE app_id = $1 AND environment = $2 AND payload->'decision'->>'patch_id' = ANY($3::text[])
       AND COALESCE(payload->'decision'->>'patch_body', 'checked') NOT IN ('unchecked', 'undecodable')
     GROUP BY 1`,
    [
      scope.appId,
      scope.environment,
      [...patchIds],
      new Date(at.getTime() - 24 * 3_600_000).toISOString(),
      at.toISOString(),
    ],
  );
  for (const row of rows) {
    result.set(row.patch_id, { hits24h: row.hits, lastHit: row.last === null ? null : row.last.toISOString() });
  }
  return result;
}

/**
 * The advisory an `exploit-attempt` Incident of this patch is grouped by: the activating Finding's advisory while the
 * patch is active in the App Environment, else the catalog's first advisory of the patch (a Shield may still hold
 * an older bundle). Null for an id the catalog does not know: no Incident.
 */
export async function exploitAdvisory(
  q: Queryable,
  catalog: PatchCatalog,
  scope: PatchScope,
  patchId: string,
): Promise<string | null> {
  const patch = catalog.get(patchId);
  if (patch === undefined) return null;
  const state = (await patchStates(q, catalog, scope)).find((candidate) => candidate.patch.id === patchId);
  return state?.advisory ?? patch.advisories[0] ?? null;
}
