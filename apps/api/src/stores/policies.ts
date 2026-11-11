import type { Environment, Policy, PolicyRule, PolicyVersionSummary } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

/** Which Policy: the one of an App and Environment of the transaction's Organization. */
export interface PolicyTarget {
  organizationId: string;
  appId: string;
  environment: Environment;
}

const OF_TARGET = "organization_id = $1::text AND app_id = $2::text AND environment = $3::text";

function targetParams(target: PolicyTarget): string[] {
  return [target.organizationId, target.appId, target.environment];
}

/**
 * Stored Rules with their members in the documented order: `jsonb` keeps the order of a list, not of members.
 * `requires` (slice 04) only when the stored Rule has one.
 */
function toRules(stored: PolicyRule[]): PolicyRule[] {
  return stored.map((rule) => ({
    id: rule.id,
    name: rule.name,
    path: rule.path,
    methods: rule.methods,
    action: rule.action,
    mode: rule.mode,
    ...(rule.requires === undefined ? {} : { requires: rule.requires }),
  }));
}

/** The newest published version of the Policy; before the first publish, version 0 without Rules. */
export async function currentPolicy(q: Queryable, target: PolicyTarget): Promise<Policy> {
  const { rows } = await q.query<{ version: number; rules: PolicyRule[]; published_at: Date }>(
    `SELECT version, rules, published_at FROM policy_versions WHERE ${OF_TARGET} ORDER BY version DESC LIMIT 1`,
    targetParams(target),
  );
  const row = rows[0];
  const identity = { app_id: target.appId, environment: target.environment };
  if (row === undefined) return { ...identity, version: 0, rules: [], published_at: null };
  return { ...identity, version: row.version, rules: toRules(row.rules), published_at: row.published_at.toISOString() };
}

/** The number of the newest published version of the Policy; 0 before the first publish. */
export async function currentVersion(q: Queryable, target: PolicyTarget): Promise<number> {
  const { rows } = await q.query<{ version: number }>(
    `SELECT COALESCE(max(version), 0)::int AS version FROM policy_versions WHERE ${OF_TARGET}`,
    targetParams(target),
  );
  return rows[0]?.version ?? 0;
}

/** One published version of the Policy with its Rules, or null when that version does not exist. */
export async function findPolicyVersion(q: Queryable, target: PolicyTarget, version: number): Promise<Policy | null> {
  // Compared as bigint, as in findPolicyRules.
  const { rows } = await q.query<{ version: number; rules: PolicyRule[]; published_at: Date }>(
    `SELECT version, rules, published_at FROM policy_versions WHERE ${OF_TARGET} AND version = $4::bigint`,
    [...targetParams(target), version],
  );
  const row = rows[0];
  if (row === undefined) return null;
  return {
    app_id: target.appId,
    environment: target.environment,
    version: row.version,
    rules: toRules(row.rules),
    published_at: row.published_at.toISOString(),
  };
}

/** The Rules of one published version, or null when that version does not exist. */
export async function findPolicyRules(
  q: Queryable,
  target: PolicyTarget,
  version: number,
): Promise<PolicyRule[] | null> {
  // Compared as bigint: a number beyond the column's range is a version that does not exist, not an error.
  const { rows } = await q.query<{ rules: PolicyRule[] }>(
    `SELECT rules FROM policy_versions WHERE ${OF_TARGET} AND version = $4::bigint`,
    [...targetParams(target), version],
  );
  return rows[0] === undefined ? null : toRules(rows[0].rules);
}

/**
 * Stores `rules` as the version after the newest one, and returns the Policy. Of the admin key that
 * publishes, the prefix is stored: the statement reads it from the key's row.
 *
 * The version is computed in this statement. Two transactions can compute the same one only when they
 * run at the same time; the primary key then refuses the second (SQL state 23505). The caller holds the
 * App's row lock (`lockApp`), which makes publishers of one App wait for each other instead.
 */
export async function insertPolicyVersion(
  q: Queryable,
  target: PolicyTarget,
  input: { rules: PolicyRule[]; publishedAt: Date; publishedByKeyId: string },
): Promise<Policy> {
  const { rows } = await q.query<{ version: number; published_at: Date }>(
    `INSERT INTO policy_versions (organization_id, app_id, environment, version, rules, published_at, published_by)
     SELECT $1::text, $2::text, $3::text,
            COALESCE((SELECT max(version) FROM policy_versions WHERE ${OF_TARGET}), 0) + 1,
            $4::jsonb, $5::timestamptz, k.prefix
     FROM api_keys k
     WHERE k.id = $6::text
     RETURNING version, published_at`,
    [...targetParams(target), JSON.stringify(input.rules), input.publishedAt.toISOString(), input.publishedByKeyId],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The Policy version was not stored.");
  return {
    app_id: target.appId,
    environment: target.environment,
    version: row.version,
    rules: input.rules,
    published_at: row.published_at.toISOString(),
  };
}

/** The newest `limit` versions of the Policy, newest first, each with its number of Rules. */
export async function listPolicyVersions(
  q: Queryable,
  target: PolicyTarget,
  limit: number,
): Promise<PolicyVersionSummary[]> {
  const { rows } = await q.query<{ version: number; published_at: Date; rule_count: number; enforced_count: number }>(
    `SELECT version, published_at,
            jsonb_array_length(rules) AS rule_count,
            (SELECT count(*) FROM jsonb_array_elements(rules) AS rule WHERE rule->>'mode' = 'enforce')::int
              AS enforced_count
     FROM policy_versions
     WHERE ${OF_TARGET}
     ORDER BY version DESC
     LIMIT $4`,
    [...targetParams(target), limit],
  );
  return rows.map((row) => ({
    version: row.version,
    published_at: row.published_at.toISOString(),
    rule_count: row.rule_count,
    enforced_count: row.enforced_count,
  }));
}
