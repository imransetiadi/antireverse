import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type AuditEntry,
  EXAMPLE_ASSESSMENT,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_POLICY_RULE,
  EXAMPLE_SHIELD_EVENT,
} from "@antireverse/protocol";
import { auditHash, generateKey, hashKey, newId } from "@antireverse/protocol/server";
import type { PGlite } from "@electric-sql/pglite";
import { migrate } from "../src/db/migrate.ts";

// Slice 18h: the era seeds of the local upgrade check. No version of Airverse has been released, so "a previous
// version" is a migration prefix: the schema after 0001…K. Application code only speaks the head schema, so a database
// at an earlier schema cannot be seeded through the API. Instead each migration that creates tables has a seed step
// here, written in SQL against the schema *of that migration*: the columns, checks and triggers that existed then.
// The upgrade test applies migration K and then seed K, for every K in order; after step K the database is "version K
// with data", and every table that exists has a row (the test fails on a table without one, so a migration that adds
// a table must add its seed here).
//
// What the seeds are not: the rows a real old version would have written. The columns are each era's; the JSON inside
// them (Event payloads, Build manifests, Policy rules) has today's shape, because no older writer exists to copy.

export const MIGRATIONS_DIRECTORY = fileURLToPath(new URL("../migrations", import.meta.url));

/** The migration files in the order `migrate()` applies them. */
export function migrationFiles(): string[] {
  return readdirSync(MIGRATIONS_DIRECTORY)
    .filter((name) => name.endsWith(".sql"))
    .sort();
}

export function migrationSql(file: string): string {
  return readFileSync(`${MIGRATIONS_DIRECTORY}/${file}`, "utf8");
}

/** What a seed step needs of the database: SQL as its owner. PGlite and a PGlite transaction both fit. */
export interface SeedDb {
  query<R = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: R[] }>;
}

export interface EraTenant {
  organizationId: string;
  name: string;
  appId: string;
  appName: string;
  /** Keys made for this run only; the database holds their SHA-256, as it does for every key. */
  adminKey: string;
  adminKeyId: string;
  shieldKey: string;
  shieldKeyId: string;
  buildId: string;
  incidentId: string;
  webhookChannelId: string;
  targetId: string;
  roeId: string;
  campaignId: string;
  /** The ids of the Events seeded at 0001. */
  eventIds: string[];
  /** The audit entries seeded at 0031 (and, for the first tenant, one more at 0039). */
  auditEntries: number;
  auditHead: { seq: number; hash: string };
}

export interface EraContext {
  /** The seeded moment: every seeded timestamp derives from it. */
  at: Date;
  /** Two Organizations, so that tenant isolation can be checked after every upgrade. */
  a: EraTenant;
  b: EraTenant;
  /** The Organization the API owns from 0043 on (the synthetic probe's). */
  system: { organizationId: string; appId: string };
}

function tenant(name: string): EraTenant {
  return {
    organizationId: newId("org"),
    name,
    appId: newId("app"),
    appName: `${name} shop`,
    adminKey: generateKey("admin").key,
    adminKeyId: newId("key"),
    shieldKey: generateKey("shield", "production").key,
    shieldKeyId: newId("key"),
    buildId: newId("bld"),
    incidentId: newId("inc"),
    webhookChannelId: newId("chn"),
    targetId: newId("tgt"),
    roeId: newId("roe"),
    campaignId: newId("cmp"),
    eventIds: [],
    auditEntries: 0,
    auditHead: { seq: 0, hash: "0".repeat(64) },
  };
}

export function eraContext(at: Date = new Date("2026-11-20T10:00:00.000Z")): EraContext {
  return {
    at,
    a: tenant("Acme"),
    b: tenant("Globex"),
    system: { organizationId: newId("org"), appId: newId("app") },
  };
}

const ENVIRONMENT = "production";
const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");
const hex = (bytes: number): string => randomBytes(bytes).toString("hex");

/** A version-7 UUID for the given millisecond (the shape of an Event id). */
function uuidv7(ms: number): string {
  const bytes = randomBytes(16);
  bytes.writeUIntBE(ms, 0, 6);
  bytes[6] = 0x70 | ((bytes[6] ?? 0) & 0x0f);
  bytes[8] = 0x80 | ((bytes[8] ?? 0) & 0x3f);
  const h = bytes.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * One audit entry at the head of the tenant's chain, hashed with the protocol's `auditHash`. Before 0032 the writer
 * moved the chain head itself (`moveHead`); from 0032 a trigger does. `system`: an entry without a key (from 0039).
 */
async function appendAudit(
  db: SeedDb,
  ctx: EraContext,
  t: EraTenant,
  change: { action: AuditEntry["action"]; summary: string; reason?: string },
  options: { moveHead: boolean; system?: boolean },
): Promise<void> {
  const seq = t.auditHead.seq + 1;
  const unhashed = {
    id: newId("aud"),
    organization_id: t.organizationId,
    seq,
    at: new Date(ctx.at.getTime() + seq * 1_000).toISOString(),
    actor: options.system ? { kind: "system" } : { kind: "admin_key", key_id: t.adminKeyId },
    action: change.action,
    app_id: t.appId,
    target: { kind: "app", id: t.appId },
    ...(change.reason === undefined ? {} : { reason: change.reason }),
    summary: change.summary,
    request_id: randomUUID(),
    prev_hash: t.auditHead.hash,
  } as Omit<AuditEntry, "hash">;
  const hash = auditHash(unhashed);
  await db.query(
    `INSERT INTO audit_entries (id, organization_id, seq, at, actor_kind, actor_key_id, action, app_id, target_kind,
       target_id, reason, summary, request_id, prev_hash, hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'app', $8, $9, $10, $11, $12, $13)`,
    [
      unhashed.id,
      t.organizationId,
      seq,
      unhashed.at,
      options.system ? "system" : "admin_key",
      options.system ? null : t.adminKeyId,
      change.action,
      t.appId,
      change.reason ?? null,
      change.summary,
      unhashed.request_id,
      unhashed.prev_hash,
      hash,
    ],
  );
  if (options.moveHead) {
    await db.query("UPDATE audit_heads SET seq = $2, hash = $3 WHERE organization_id = $1", [
      t.organizationId,
      seq,
      hash,
    ]);
  }
  t.auditHead = { seq, hash };
  t.auditEntries += 1;
}

type Seed = (db: SeedDb, ctx: EraContext) => Promise<void>;

/**
 * The seed step of each migration that needs one, by file name. A step runs right after its migration, as the owner
 * of the database, and uses only what that migration's schema has.
 */
export const ERA_SEEDS: Readonly<Record<string, Seed>> = {
  // Organizations, Apps, keys (as hashes) and Events.
  "0001_init.sql": async (db, ctx) => {
    for (const t of [ctx.a, ctx.b]) {
      await db.query("INSERT INTO organizations (id, name, created_at) VALUES ($1, $2, $3)", [
        t.organizationId,
        t.name,
        ctx.at,
      ]);
      await db.query("INSERT INTO apps (id, organization_id, name, created_at) VALUES ($1, $2, $3, $4)", [
        t.appId,
        t.organizationId,
        t.appName,
        ctx.at,
      ]);
      await db.query(
        `INSERT INTO api_keys (id, organization_id, kind, key_hash, prefix, last4, created_at)
         VALUES ($1, $2, 'admin', $3, $4, $5, $6)`,
        [t.adminKeyId, t.organizationId, hashKey(t.adminKey), t.adminKey.slice(0, 12), t.adminKey.slice(-4), ctx.at],
      );
      await db.query(
        `INSERT INTO api_keys (id, organization_id, kind, app_id, environment, key_hash, prefix, last4, created_at)
         VALUES ($1, $2, 'shield', $3, $4, $5, $6, $7, $8)`,
        [
          t.shieldKeyId,
          t.organizationId,
          t.appId,
          ENVIRONMENT,
          hashKey(t.shieldKey),
          t.shieldKey.slice(0, 12),
          t.shieldKey.slice(-4),
          ctx.at,
        ],
      );
      const events = t === ctx.a ? 3 : 1;
      for (let i = 0; i < events; i++) {
        const ms = ctx.at.getTime() + i;
        const id = uuidv7(ms);
        const payload = { ...EXAMPLE_SHIELD_EVENT, event_id: id, ts: new Date(ms).toISOString() };
        await db.query(
          `INSERT INTO events (organization_id, event_id, app_id, environment, ts, received_at, type, payload)
           VALUES ($1, $2, $3, $4, $5, $5, $6, $7)`,
          [t.organizationId, id, t.appId, ENVIRONMENT, new Date(ms), payload.type, JSON.stringify(payload)],
        );
        t.eventIds.push(id);
      }
    }
  },

  // Two Policy versions of the first tenant (so that a roll back has somewhere to go), one of the second.
  "0002_policies.sql": async (db, ctx) => {
    const rule = (mode: string) => [{ ...EXAMPLE_POLICY_RULE, name: "Login", path: "/login", methods: ["POST"], mode }];
    const insert = (t: EraTenant, version: number, mode: string) =>
      db.query(
        `INSERT INTO policy_versions (organization_id, app_id, environment, version, rules, published_at, published_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [t.organizationId, t.appId, ENVIRONMENT, version, JSON.stringify(rule(mode)), ctx.at, t.adminKeyId],
      );
    await insert(ctx.a, 1, "monitor");
    await insert(ctx.a, 2, "enforce");
    await insert(ctx.b, 1, "monitor");
  },

  "0004_builds.sql": async (db, ctx) => {
    for (const t of [ctx.a, ctx.b]) {
      const manifest = { ...EXAMPLE_BUILD_MANIFEST, build_id: t.buildId, app_id: t.appId };
      await db.query(
        `INSERT INTO builds (organization_id, app_id, build_id, environment, version, profile, manifest, registered_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          t.organizationId,
          t.appId,
          t.buildId,
          ENVIRONMENT,
          manifest.version,
          manifest.profile,
          JSON.stringify(manifest),
          ctx.at,
        ],
      );
    }
  },

  // An Incident with one detection, a webhook channel and one delivery.
  "0006_incidents.sql": async (db, ctx) => {
    for (const t of [ctx.a, ctx.b]) {
      await db.query(
        `INSERT INTO incidents (id, organization_id, app_id, environment, rule, severity, title, status, ip_prefix,
           first_seen, last_seen, detection_count, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'blocked-burst', 'high', 'Burst of blocked requests', 'open', '203.0.113.0/24',
           $5, $5, 1, $5, $5)`,
        [t.incidentId, t.organizationId, t.appId, ENVIRONMENT, ctx.at],
      );
      await db.query(
        `INSERT INTO detections (id, organization_id, incident_id, app_id, environment, rule, ip_prefix, count,
           window_start, window_end, detected_at)
         VALUES ($1, $2, $3, $4, $5, 'blocked-burst', '203.0.113.0/24', 20, $6, $6, $6)`,
        [newId("dtc"), t.organizationId, t.incidentId, t.appId, ENVIRONMENT, ctx.at],
      );
      await db.query(
        `INSERT INTO alert_channels (id, organization_id, kind, name, url, signing_secret, created_at)
         VALUES ($1, $2, 'webhook', 'Pager', 'https://hooks.example.com/x', $3, $4)`,
        [t.webhookChannelId, t.organizationId, `whsec_${hex(24)}`, ctx.at],
      );
      await db.query(
        `INSERT INTO alert_deliveries (id, organization_id, channel_id, incident_id, attempt, outcome, status_code, at)
         VALUES ($1, $2, $3, $4, 1, 'delivered', 200, $5)`,
        [newId("dlv"), t.organizationId, t.webhookChannelId, t.incidentId, ctx.at],
      );
    }
  },

  "0007_canaries.sql": async (db, ctx) => {
    const t = ctx.a;
    await db.query(
      `INSERT INTO canaries (organization_id, id, app_id, environment, build_id, position, kind, value, created_at)
       VALUES ($1, $2, $3, $4, $5, 0, 'route', $6, $7)`,
      [t.organizationId, newId("cny"), t.appId, ENVIRONMENT, t.buildId, `/api/internal/${hex(4)}/debug`, ctx.at],
    );
  },

  // An active block of one actor, a lifted block of a prefix, and an allowlist entry.
  "0008_containment.sql": async (db, ctx) => {
    const t = ctx.a;
    const later = new Date(ctx.at.getTime() + 86_400_000);
    await db.query(
      `INSERT INTO containments (organization_id, id, app_id, environment, incident_id, target_kind, ip_hash,
         created_at, expires_at, created_by)
       VALUES ($1, $2, $3, $4, $5, 'actor', $6, $7, $8, $9)`,
      [
        t.organizationId,
        newId("cnt"),
        t.appId,
        ENVIRONMENT,
        t.incidentId,
        `iph_${hex(16)}`,
        ctx.at,
        later,
        t.adminKeyId,
      ],
    );
    await db.query(
      `INSERT INTO containments (organization_id, id, app_id, environment, target_kind, ip_prefix, created_at,
         expires_at, created_by, lifted_at, lifted_by)
       VALUES ($1, $2, $3, $4, 'prefix', '198.51.100.0/24', $5, $6, $7, $5, $7)`,
      [t.organizationId, newId("cnt"), t.appId, ENVIRONMENT, ctx.at, later, t.adminKeyId],
    );
    await db.query(
      `INSERT INTO allowlist_entries (organization_id, id, cidr, note, created_at, created_by)
       VALUES ($1, $2, '10.0.0.0/8', 'Office', $3, $4)`,
      [t.organizationId, newId("alw"), ctx.at, t.adminKeyId],
    );
  },

  "0010_beacon.sql": async (db, ctx) => {
    const t = ctx.a;
    await db.query(
      `INSERT INTO build_beacons (organization_id, app_id, build_id, environment, token, origins, created_at)
       VALUES ($1, $2, $3, $4, $5, ARRAY['https://shop.example.com'], $6)`,
      [t.organizationId, t.appId, t.buildId, ENVIRONMENT, `bcn_${hex(12)}`, ctx.at],
    );
  },

  // A public advisory, a runtime inventory and the open Finding they give.
  "0014_exposure.sql": async (db, ctx) => {
    const t = ctx.a;
    const advisory = "GHSA-era0-seed-0001";
    const affected = [{ package: "vuln-last", ranges: [{ introduced: "0", fixed: "1.3.0" }] }];
    await db.query(
      `INSERT INTO advisories (id, summary, severity, affected, published, modified)
       VALUES ($1, 'Seeded advisory', 'high', $2, $3, $3)`,
      [advisory, JSON.stringify(affected), ctx.at],
    );
    await db.query("INSERT INTO advisory_packages (package, advisory_id) VALUES ('vuln-last', $1)", [advisory]);
    await db.query(
      `INSERT INTO inventories (organization_id, app_id, environment, source, components, received_at)
       VALUES ($1, $2, $3, 'runtime', $4, $5)`,
      [
        t.organizationId,
        t.appId,
        ENVIRONMENT,
        JSON.stringify([{ name: "vuln-last", version: "1.2.0", dev: false }]),
        ctx.at,
      ],
    );
    await db.query(
      `INSERT INTO findings (id, organization_id, app_id, environment, source, package, version, dev, advisory_id,
         severity, fixed_versions, status, first_seen, last_seen, updated_at)
       VALUES ($1, $2, $3, $4, 'runtime', 'vuln-last', '1.2.0', false, $5, 'high', ARRAY['1.3.0'], 'open', $6, $6, $6)`,
      [newId("fnd"), t.organizationId, t.appId, ENVIRONMENT, advisory, ctx.at],
    );
  },

  "0018_patches.sql": async (db, ctx) => {
    const t = ctx.a;
    await db.query(
      `INSERT INTO patch_modes (organization_id, app_id, environment, patch_id, mode, updated_at, updated_by)
       VALUES ($1, $2, $3, 'vp_era_seed', 'monitor', $4, $5)`,
      [t.organizationId, t.appId, ENVIRONMENT, ctx.at, t.adminKeyId],
    );
  },

  // A pending Verified Target and signed Rules of Engagement.
  "0021_prove.sql": async (db, ctx) => {
    for (const t of [ctx.a, ctx.b]) {
      await db.query(
        `INSERT INTO targets (organization_id, id, host, token, status, created_at)
         VALUES ($1, $2, $3, $4, 'pending', $5)`,
        [
          t.organizationId,
          t.targetId,
          `shop-${t.organizationId.slice(4, 12)}.example.com`,
          randomBytes(32).toString("base64url"),
          ctx.at,
        ],
      );
    }
    const t = ctx.a;
    await db.query(
      `INSERT INTO rules_of_engagement (organization_id, id, version, scope, exclusions, intensity, window_days,
         window_from, window_to, contacts, signed_by, signed_at, content_sha256)
       VALUES ($1, $2, 1, ARRAY[$3], ARRAY[]::text[], 'passive', ARRAY['mon'], '09:00', '17:00',
         ARRAY['security@example.com'], $4, $5, $6)`,
      [t.organizationId, t.roeId, t.targetId, t.adminKeyId, ctx.at, sha256(t.roeId)],
    );
  },

  "0023_prove_review.sql": async (db, ctx) => {
    await db.query(
      "INSERT INTO verify_limits (organization_id, subject, window_start, attempts) VALUES ($1, '*', $2, 1)",
      [ctx.a.organizationId, ctx.at],
    );
  },

  // An email channel with one confirmed recipient, and one day's count of confirmation mails.
  "0024_email_alerts.sql": async (db, ctx) => {
    const t = ctx.a;
    const channel = newId("chn");
    await db.query(
      "INSERT INTO alert_channels (id, organization_id, kind, name, created_at) VALUES ($1, $2, 'email', 'On-call', $3)",
      [channel, t.organizationId, ctx.at],
    );
    await db.query(
      `INSERT INTO alert_recipients (id, organization_id, channel_id, address, status, confirmed_at)
       VALUES ($1, $2, $3, 'oncall@example.com', 'confirmed', $4)`,
      [newId("rcp"), t.organizationId, channel, ctx.at],
    );
    await db.query("INSERT INTO confirmation_mail_counts (address_hash, day, mails) VALUES ($1, $2::date, 1)", [
      sha256("oncall@example.com"),
      ctx.at,
    ]);
  },

  // A Build's routes, a kept artifact with one file, and an Assessment of it that failed.
  "0026_assessments.sql": async (db, ctx) => {
    const t = ctx.a;
    const artifact = `art_${hex(12)}`;
    const content = 'console.log("shop");';
    const later = new Date(ctx.at.getTime() + 7 * 86_400_000);
    await db.query("INSERT INTO build_routes (organization_id, app_id, build_id, routes) VALUES ($1, $2, $3, $4)", [
      t.organizationId,
      t.appId,
      t.buildId,
      JSON.stringify([{ method: "GET", path: "/api/products" }]),
    ]);
    await db.query(
      `INSERT INTO artifacts (organization_id, id, app_id, build_id, files, bytes, created_at, kept_until)
       VALUES ($1, $2, $3, $4, 1, $5, $6, $7)`,
      [t.organizationId, artifact, t.appId, t.buildId, Buffer.byteLength(content), ctx.at, later],
    );
    await db.query(
      `INSERT INTO artifact_files (organization_id, artifact_id, path, sha256, content)
       VALUES ($1, $2, 'dist/index.js', $3, $4)`,
      [t.organizationId, artifact, sha256(content), Buffer.from(content)],
    );
    await db.query(
      `INSERT INTO assessments (organization_id, id, app_id, build_id, environment, tier, status, scope,
         failure_reason, artifact_id, created_at, started_at, finished_at)
       VALUES ($1, $2, $3, $4, $5, 'T1', 'failed', $6, 'interrupted', $7, $8, $8, $8)`,
      [
        t.organizationId,
        newId("asm"),
        t.appId,
        t.buildId,
        ENVIRONMENT,
        JSON.stringify(EXAMPLE_ASSESSMENT.scope),
        artifact,
        ctx.at,
      ],
    );
  },

  "0029_build_logic.sql": async (db, ctx) => {
    const t = ctx.a;
    await db.query("INSERT INTO build_logic (organization_id, app_id, build_id, logic) VALUES ($1, $2, $3, $4)", [
      t.organizationId,
      t.appId,
      t.buildId,
      JSON.stringify({ functions: [{ name: "price" }] }),
    ]);
  },

  // The audit chain as its first writer left it: entries hashed by the protocol, the head moved by the writer (the
  // trigger that moves it arrives with 0032).
  "0031_audit.sql": async (db, ctx) => {
    await appendAudit(
      db,
      ctx,
      ctx.a,
      { action: "app.create", summary: `Created the App "${ctx.a.appName}"` },
      { moveHead: true },
    );
    await appendAudit(
      db,
      ctx,
      ctx.a,
      { action: "policy.publish", summary: "Published Policy version 2", reason: "Enforce the login Rule" },
      { moveHead: true },
    );
    await appendAudit(
      db,
      ctx,
      ctx.b,
      { action: "app.create", summary: `Created the App "${ctx.b.appName}"` },
      { moveHead: true },
    );
  },

  // A deletion request that was cancelled: the Organization lives on, the request stays as its record.
  "0033_data_controls.sql": async (db, ctx) => {
    const t = ctx.a;
    await db.query(
      `INSERT INTO organization_deletions (id, organization_id, organization_name, requested_at, requested_by, reason,
         purge_after, cancelled_at)
       VALUES ($1, $2, $3, $4, $5, 'Seeded request', $6, $4)`,
      [newId("del"), t.organizationId, t.name, ctx.at, t.adminKeyId, new Date(ctx.at.getTime() + 30 * 86_400_000)],
    );
  },

  // One retention run. The migration itself writes the set-up record of every App and the sweep's state.
  "0035_retention.sql": async (db, ctx) => {
    await db.query("INSERT INTO retention_runs (organization_id, ran_at, complete, counts) VALUES ($1, $2, true, $3)", [
      ctx.a.organizationId,
      ctx.at,
      JSON.stringify({ events: 1 }),
    ]);
  },

  "0036_usage.sql": async (db, ctx) => {
    const t = ctx.a;
    const tenantApp = [t.organizationId, t.appId];
    await db.query(
      `INSERT INTO usage_daily (organization_id, app_id, environment, day, requests, sandbox_seconds)
       VALUES ($1, $2, $3, $4::date, 5, 12)`,
      [...tenantApp, ENVIRONMENT, ctx.at],
    );
    await db.query(
      `INSERT INTO usage_devices (organization_id, app_id, month, device_ref)
       VALUES ($1, $2, date_trunc('month', $3::timestamptz AT TIME ZONE 'UTC')::date, $4)`,
      [...tenantApp, ctx.at, randomBytes(32)],
    );
    await db.query(
      "INSERT INTO usage_device_days (organization_id, app_id, day, new_refs) VALUES ($1, $2, $3::date, 1)",
      [...tenantApp, ctx.at],
    );
    await db.query(
      `INSERT INTO usage_monthly_devices (organization_id, app_id, month, devices)
       VALUES ($1, $2, date_trunc('month', $3::timestamptz AT TIME ZONE 'UTC')::date - interval '1 month', 4)`,
      [...tenantApp, ctx.at],
    );
  },

  "0037_slo.sql": async (db, ctx) => {
    const histogram = `{${Array.from({ length: 23 }, (_, i) => (i === 3 ? 9 : 0)).join(",")}}`;
    await db.query(
      `INSERT INTO slo_minutes (minute, slo, variant, good, total, histogram)
       VALUES (date_trunc('minute', $1::timestamptz), 'SLO-02', 'read', 9, 9, $2::bigint[])`,
      [ctx.at, histogram],
    );
    await db.query("INSERT INTO slo_alerts (slo, rule, since) VALUES ('SLO-02', 'ticket', $1)", [ctx.at]);
    await db.query("INSERT INTO slo_flushes (id, at) VALUES ($1, $2)", [hex(16), ctx.at]);
  },

  // A Campaign that ran and completed, with one logged request and one Finding, written in the order a real one is;
  // an entry of the audit chain without a key (the kind this migration allows); a suspended Organization.
  "0039_campaigns.sql": async (db, ctx) => {
    const t = ctx.a;
    await db.query(
      `INSERT INTO campaigns (organization_id, id, target_id, host, roe_id, roe_sha256, intensity, engine, status,
         staging_declared, created_by, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'passive', '{"name":"stand-in","version":"1","model":"stand-in"}', 'queued',
         true, $7, $8)`,
      [
        t.organizationId,
        t.campaignId,
        t.targetId,
        `shop-${t.organizationId.slice(4, 12)}.example.com`,
        t.roeId,
        sha256(t.roeId),
        t.adminKeyId,
        ctx.at,
      ],
    );
    await db.query(
      "UPDATE campaigns SET status = 'running', started_at = $2, pinned_address = '203.0.113.10' WHERE id = $1",
      [t.campaignId, ctx.at],
    );
    await db.query(
      `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome, status, bytes, ms)
       VALUES ($1, $2, 1, $3, 'GET', '/', 'sent', 200, 120, 15)`,
      [t.organizationId, t.campaignId, ctx.at],
    );
    await db.query(
      `INSERT INTO campaign_findings (organization_id, campaign_id, check_id, path, title, severity, state, evidence,
         first_seen_at, last_seen_at)
       VALUES ($1, $2, 'RW-01', '/', 'Missing security headers', 'low', 'unverified', $3, $4, $4)`,
      [t.organizationId, t.campaignId, JSON.stringify({ method: "GET", target: "/", status: 200 }), ctx.at],
    );
    await db.query(
      `UPDATE campaigns SET status = 'completed', end_reason = 'checks_complete', checks_ran = 1, checks_reported = 1,
         checks_inconclusive = 0, checks_skipped = 5, finished_at = $2
       WHERE id = $1`,
      [t.campaignId, ctx.at],
    );
    await appendAudit(
      db,
      ctx,
      t,
      { action: "campaign.end", summary: "The Campaign completed" },
      { moveHead: false, system: true },
    );
    await db.query(
      "INSERT INTO prove_suspensions (org_id, suspended_at, reason) VALUES ($1, $2, 'Seeded suspension')",
      [ctx.b.organizationId, ctx.at],
    );
  },

  // The Organization the API owns for its synthetic probes. 0043 is the head today: nothing upgrades this row yet.
  "0043_probes.sql": async (db, ctx) => {
    const { organizationId, appId } = ctx.system;
    await db.query("INSERT INTO organizations (id, name, created_at) VALUES ($1, 'Airverse synthetic probes', $2)", [
      organizationId,
      ctx.at,
    ]);
    await db.query("INSERT INTO apps (id, organization_id, name, created_at) VALUES ($1, $2, 'Probe', $3)", [
      appId,
      organizationId,
      ctx.at,
    ]);
    await db.query("INSERT INTO system_organizations (kind, org_id, app_id, created_at) VALUES ('probe', $1, $2, $3)", [
      organizationId,
      appId,
      ctx.at,
    ]);
  },
};

/**
 * One step of the walk: applies the migration `file` alone, through the migrator, and then its seed. `stepDirectory`
 * is an empty temporary directory the caller keeps for the whole walk: it collects the files applied so far, which is
 * how the migrator is given one new file at a time.
 */
export async function applyEra(pg: PGlite, ctx: EraContext, stepDirectory: string, file: string): Promise<string[]> {
  writeFileSync(join(stepDirectory, file), migrationSql(file));
  const applied = await migrate(pg, stepDirectory);
  await ERA_SEEDS[file]?.(pg, ctx);
  return applied;
}

export type TableRow = Record<string, unknown>;
/** Every base table of `public` with its rows as JSON. */
export type TableSnapshot = Map<string, TableRow[]>;

export async function snapshotTables(pg: PGlite): Promise<TableSnapshot> {
  const tables = await pg.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1`,
  );
  const out: TableSnapshot = new Map();
  for (const { table_name } of tables.rows) {
    const { rows } = await pg.query<{ row: TableRow }>(
      `SELECT to_jsonb(t) AS row FROM "${table_name}" t ORDER BY to_jsonb(t)::text`,
    );
    out.set(
      table_name,
      rows.map((r) => r.row),
    );
  }
  return out;
}
