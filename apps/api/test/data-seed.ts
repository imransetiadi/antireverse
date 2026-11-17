import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  type AdvisoryInput,
  type Component,
  ContainmentResponseSchema,
  CreateAlertChannelResponseSchema,
  DETECTION_RULES,
  DeletionResponseSchema,
  type Environment,
  EXAMPLE_CANARIES,
  EXAMPLE_SHIELD_EVENT,
  TargetResponseSchema,
} from "@antireverse/protocol";
import { actorHash, newId } from "@antireverse/protocol/server";
import { expect } from "vitest";
import type { AppDeps } from "../src/app.ts";
import { PATCH_CATALOG } from "../src/patches/catalog.ts";
import { createSigner, type Signer } from "../src/signer.ts";
import { insertContainment } from "../src/stores/containments.ts";
import { recordDetection } from "../src/stores/incidents.ts";
import { FIXTURE_ADVISORIES_FILE, fixtureSource } from "../src/vulns/source.ts";
import { syncAdvisories } from "../src/vulns/sync.ts";
import { artifactFor, fakeAssessor } from "./fake-assessor.ts";
import {
  batchOf,
  bearer,
  createAppFor,
  createOrganization,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
  withReason,
} from "./helpers.ts";

// Slice 18b: one Organization with rows in every area, through the API wherever a route writes them, so that the
// export, the purge and the subject requests run on realistic data. `tablesWithoutRows` says which tenant tables the
// seed left empty: the catalog-wide tests fail on any, so a table added later must get a seed here.

/** The client addresses of the seeded end users; the API only ever sees their actor hashes. */
export const SUBJECT_ADDRESS = "203.0.113.7";
export const OTHER_ADDRESS = "198.51.100.9";

export interface Seeded {
  organizationId: string;
  name: string;
  admin: string;
  shield: string;
  appId: string;
  environment: Environment;
  /** The seeded Incident (prefix 203.0.113.0/24, among the subject's Events). */
  incidentId: string;
  /** The actor hash of `SUBJECT_ADDRESS` under `shield`. */
  subjectHash: string;
  otherHash: string;
  /** Events of the subject and of the other actor. */
  subjectEvents: number;
  otherEvents: number;
  /** The subject's containments: one lifted, one active. */
  liftedContainmentId: string;
  activeContainmentId: string;
  /** Every secret the seed was handed (keys, the webhook signing secret, the target's verification token). */
  secrets: string[];
}

/**
 * The tables of `public` that hold no Organization's data, each with the reason. Every other table must have an
 * `organization_id` column (the purge and the export find tenant data by it): a table keyed only by an App, a Build
 * or anything else fails the catalog test until it gets the column or a reason here.
 */
export const GLOBAL_TABLES: Readonly<Record<string, string>> = {
  schema_migrations: "the applied migrations",
  database_epoch: "the database's identity (one row)",
  advisories: "the public vulnerability advisories, the same for everyone",
  advisory_packages: "the package index of the public advisories",
  confirmation_mail_counts:
    "confirmation mails per keyed address hash and day, across Organizations (the abuse cap of slice 06b); no Organization id, expires with its day",
  organization_deletions: "the owner's deletion requests and tombstones: they outlive the Organization",
  retention_sweep_state: "where the retention sweep's rotation over Organizations stands: one number, no identifier",
  prove_switch: "the operator's kill switch of Pentest Campaigns (slice 15a): one row, no tenant identifier",
  prove_suspensions:
    "the operator's list of Organizations whose Campaigns are suspended (slice 15a): an Organization id, a time and the operator's reason; removed with the Organization's row (cascade)",
  slo_alerts: "the burn rules firing now (slice 18d): SLO, rule and the episode's start, no tenant identifier",
  slo_flushes: "the ids of SLI batches written in the last day (slice 18d), so a retried batch is not counted twice",
  slo_minutes:
    "the operator's per-minute SLI buckets (slice 18d): SLO, counts and a latency histogram, no tenant identifier; swept after 35 days",
};

/** Base tables of `public` that are neither global nor carry an `organization_id` column (`organizations` is the root: its `id` is it). */
export async function tablesWithoutOrganization(api: TestApi): Promise<string[]> {
  return api.db.owner(async (q) => {
    const { rows } = await q.query<{ table_name: string }>(
      `SELECT t.table_name FROM information_schema.tables t
       WHERE t.table_schema = 'public' AND t.table_type = 'BASE TABLE'
         AND NOT EXISTS (SELECT 1 FROM information_schema.columns c WHERE c.table_schema = t.table_schema
           AND c.table_name = t.table_name AND c.column_name = 'organization_id')
       ORDER BY 1`,
    );
    return rows.map((row) => row.table_name).filter((table) => table !== "organizations" && !(table in GLOBAL_TABLES));
  });
}

/** Every base table in `public` with an `organization_id` column, from the catalog. */
export async function tenantTables(api: TestApi): Promise<string[]> {
  return api.db.owner(async (q) => {
    const { rows } = await q.query<{ table_name: string }>(
      `SELECT c.table_name FROM information_schema.columns c
       JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
       WHERE c.table_schema = 'public' AND c.column_name = 'organization_id' AND t.table_type = 'BASE TABLE'
       ORDER BY 1`,
    );
    return rows.map((row) => row.table_name);
  });
}

/** Rows per table of one Organization (as the owner, past row-level security); `organizations` by its id. */
export async function rowsOf(api: TestApi, organizationId: string, tables: string[]): Promise<Record<string, number>> {
  return api.db.owner(async (q) => {
    const counts: Record<string, number> = {};
    for (const table of tables) {
      const column = table === "organizations" ? "id" : "organization_id";
      const { rows } = await q.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${table}" WHERE ${column} = $1`, [
        organizationId,
      ]);
      counts[table] = rows[0]?.n ?? 0;
    }
    return counts;
  });
}

export interface SeedOptions {
  now: () => Date;
  /** Events of the subject; default 3. */
  subjectEvents?: number;
  /** The webhook channel's URL; default a public name (resolved by the test's stand-in DNS). */
  webhookUrl?: string;
}

export async function seedOrganization(api: TestApi, name: string, options: SeedOptions): Promise<Seeded> {
  const { now } = options;
  const created = await createOrganization(api, name);
  const organizationId = created.organization.id;
  const admin = created.admin_key.key;
  const app = await createAppFor(api, admin, { name: `${name} shop` });
  const appId = app.app.id;
  const shield = app.shield_key.key;
  const environment = app.shield_key.environment;
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    api.app.request(path, json(body, { ...bearer(admin), ...headers }));
  const ok = async (res: Response | Promise<Response>, status: number) => {
    const done = await res;
    expect(done.status, await done.clone().text()).toBe(status);
    return done;
  };

  // Builds, Canaries, beacons, routes and logic; an Assessment with its kept artifact.
  const { manifest, files } = artifactFor(appId, { canaries: [...EXAMPLE_CANARIES] });
  await ok(post(`/v1/apps/${appId}/builds`, { manifest }), 201);
  await ok(post(`/v1/apps/${appId}/builds/${manifest.build_id}/assessments`, { tier: "T1", files }), 202);

  // Inventory → Findings.
  const components: Component[] = [{ name: "vuln-last", version: "1.2.0", dev: false }];
  await ok(api.app.request("/v1/inventory", json({ components }, bearer(shield))), 202);
  await api.flushIncidents();

  // Policy versions and a virtual patch mode.
  await ok(
    api.app.request(`/v1/apps/${appId}/policies/${environment}`, {
      ...json({ rules: [{ name: "Login", path: "/login", methods: ["POST"], mode: "monitor" }] }, bearer(admin)),
      method: "PUT",
    }),
    201,
  );

  // Events of two actors.
  const subjectHash = actorHash(shield, SUBJECT_ADDRESS) as string;
  const otherHash = actorHash(shield, OTHER_ADDRESS) as string;
  const subjectEvents = options.subjectEvents ?? 3;
  const otherEvents = 2;
  const ms = now().getTime();
  const events = [
    ...Array.from({ length: subjectEvents }, (_, i) =>
      // Blocked: the evidence of the seeded blocked-burst Incident, so that the subject can be blocked as its Actor.
      shieldEvent(ms + i, {
        actor: { ip_prefix: "203.0.113.0/24", ip_hash: subjectHash },
        decision: { ...EXAMPLE_SHIELD_EVENT.decision, action: "block", mode: "enforce" },
      }),
    ),
    ...Array.from({ length: otherEvents }, (_, i) =>
      shieldEvent(ms + 100 + i, { actor: { ip_prefix: "198.51.100.0/24", ip_hash: otherHash } }),
    ),
  ];
  for (let i = 0; i < events.length; i += 500) {
    await ok(api.app.request("/v1/events", json(batchOf(events.slice(i, i + 500)), bearer(shield))), 202);
  }

  // An Incident with a detection, and the subject's blocks: one lifted (an ended block), one active.
  const ts = now().toISOString();
  const opened = await api.db.tx({ organizationId }, (q) =>
    recordDetection(q, {
      organizationId,
      appId,
      environment,
      rule: DETECTION_RULES[0],
      ipPrefix: "203.0.113.0/24",
      count: 20,
      windowStart: ts,
      windowEnd: new Date(ms + subjectEvents).toISOString(),
      detectedAt: now(),
    }),
  );
  const incidentId = opened.incident.id;
  const keyId = await api.db.owner(async (q) => {
    const { rows } = await q.query<{ id: string }>(
      "SELECT id FROM api_keys WHERE organization_id = $1 AND kind = 'admin'",
      [organizationId],
    );
    return rows[0]?.id ?? "";
  });
  const block = (expiresIn: number) =>
    api.db.tx({ organizationId }, (q) =>
      insertContainment(q, {
        organizationId,
        appId,
        environment,
        id: newId("cnt"),
        incidentId,
        target: { kind: "actor", ip_hash: subjectHash },
        createdAt: now(),
        expiresAt: new Date(now().getTime() + expiresIn),
        createdBy: keyId,
      }),
    );
  const lifted = await block(3_600_000);
  await ok(api.app.request(`/v1/containments/${lifted.id}/lift`, { method: "POST", headers: bearer(admin) }), 200);
  const prefixBlock = await ok(
    post(
      `/v1/incidents/${incidentId}/containments`,
      { target: { kind: "prefix" }, ttl_s: 3600, confirm_prefix: "203.0.113.0/24" },
      withReason(),
    ),
    201,
  );
  ContainmentResponseSchema.parse(await prefixBlock.json());
  const active = await block(86_400_000);

  // Allowlist, alert channels (webhook and email), a delivery.
  await ok(post("/v1/allowlist", { cidr: "10.0.0.0/8", note: "Office" }), 201);
  const webhook = CreateAlertChannelResponseSchema.parse(
    await (
      await ok(
        post("/v1/alert-channels", {
          kind: "webhook",
          name: "Pager",
          url: options.webhookUrl ?? "https://hooks.example.com/x",
        }),
        201,
      )
    ).json(),
  );
  await ok(post("/v1/alert-channels", { kind: "email", name: "On-call", recipients: ["oncall@acme.test"] }), 201);
  await api.db.owner((q) =>
    q.query(
      `INSERT INTO alert_deliveries (id, organization_id, channel_id, incident_id, attempt, outcome, status_code, at)
       VALUES ($1, $2, $3, $4, 1, 'delivered', 200, $5)`,
      [newId("dlv"), organizationId, webhook.channel.id, incidentId, now()] satisfies unknown[],
    ),
  );

  // A Verified Target attempt (verify_limits) and Rules of Engagement need a target.
  const target = TargetResponseSchema.parse(
    await (await ok(post("/v1/targets", { host: `shop-${organizationId.slice(4, 12)}.acme-shop.io` }), 201)).json(),
  );
  await api.app.request(`/v1/targets/${target.target.id}/verify`, { method: "POST", headers: bearer(admin) });

  // A virtual patch mode.
  await ok(
    post(`/v1/apps/${appId}/patches/${PATCH_CATALOG.patches[0]?.id}/mode`, { environment, mode: "monitor" }),
    200,
  );

  // What a route seeds only with a full route inventory, logic file, beacon or verified target: written directly.
  await api.db.owner(async (q) => {
    const build = [organizationId, appId, manifest.build_id];
    await q.query(
      `INSERT INTO build_beacons (organization_id, app_id, build_id, environment, token, origins, created_at)
       VALUES ($1, $2, $3, $4, $5, ARRAY['https://shop.acme-shop.io'], $6)`,
      [...build, environment, `bcn_${randomBytes(12).toString("hex")}`, now()],
    );
    await q.query("INSERT INTO build_routes (organization_id, app_id, build_id, routes) VALUES ($1, $2, $3, $4)", [
      ...build,
      JSON.stringify([{ method: "GET", path: "/api/products" }]),
    ]);
    await q.query("INSERT INTO build_logic (organization_id, app_id, build_id, logic) VALUES ($1, $2, $3, $4)", [
      ...build,
      JSON.stringify({ functions: [{ name: "price" }] }),
    ]);
    await q.query(
      `INSERT INTO rules_of_engagement (organization_id, id, version, scope, exclusions, intensity, window_days,
         window_from, window_to, contacts, signed_by, signed_at, content_sha256)
       VALUES ($1, $2, 1, ARRAY[$3], ARRAY[]::text[], 'passive', ARRAY['mon'], '09:00', '17:00',
         ARRAY['security@acme.test'], $4, $5, $6)`,
      [organizationId, newId("roe"), target.target.id, keyId, now(), "0".repeat(64)],
    );
    // A Pentest Campaign that completed (slice 15a), with one logged request and one Finding. Its log and Findings
    // are written while it runs (the database refuses them afterwards); then it ends.
    const campaignId = newId("cmp");
    await q.query(
      `INSERT INTO campaigns (organization_id, id, target_id, host, roe_id, roe_sha256, intensity, engine, status,
         staging_declared, created_by, created_at, started_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'passive', '{"name":"stand-in","version":"1","model":"stand-in"}', 'running',
         true, $7, $8, $8)`,
      [organizationId, campaignId, target.target.id, target.target.host, newId("roe"), "0".repeat(64), keyId, now()],
    );
    await q.query(
      `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome, status, bytes, ms)
       VALUES ($1, $2, 1, $3, 'GET', '/', 'sent', 200, 120, 15)`,
      [organizationId, campaignId, now()],
    );
    await q.query(
      `INSERT INTO campaign_findings (organization_id, campaign_id, check_id, path, title, severity, state, evidence,
         first_seen_at, last_seen_at)
       VALUES ($1, $2, 'RW-01', '/', 'Missing security headers', 'low', 'unverified', $3, $4, $4)`,
      [organizationId, campaignId, JSON.stringify({ method: "GET", target: "/", status: 200 }), now()],
    );
    await q.query(
      `UPDATE campaigns SET status = 'completed', end_reason = 'checks_complete', checks_ran = 1, checks_reported = 1,
         checks_inconclusive = 0, checks_skipped = 5, finished_at = $2
       WHERE id = $1`,
      [campaignId, now()],
    );
    // A retention run (slice 18c): written by the owner-only job.
    await q.query("INSERT INTO retention_runs (organization_id, ran_at, complete, counts) VALUES ($1, $2, true, $3)", [
      organizationId,
      now(),
      JSON.stringify({ events: 1 }),
    ]);
    // Usage (slice 17a): a Guard device reference of the current month (written through the attest route's definer) and
    // a rolled-up month (written by the owner-only rollup). The requests were metered by the ingest above.
    // (The reference is an HMAC the API computes under a month salt it keeps outside the database: any 32 bytes here.)
    await q.query("SELECT usage_record_device($1, $2, $3, 50000)", [appId, randomBytes(32), now()]);
    await q.query(
      `INSERT INTO usage_monthly_devices (organization_id, app_id, month, devices)
       VALUES ($1, $2, date_trunc('month', $3::timestamptz AT TIME ZONE 'UTC')::date - interval '1 month', 4)`,
      [organizationId, appId, now()],
    );
    // The set-up record (slice 18c): written by the owner-only sweep.
    await q.query(
      `INSERT INTO setup_milestones (organization_id, app_id, environment, shield_first_at, guard_first_at)
       VALUES ($1, $2, $3, $4, NULL)`,
      [organizationId, appId, environment, now()],
    );
  });

  return {
    organizationId,
    name,
    admin,
    shield,
    appId,
    environment,
    incidentId,
    subjectHash,
    otherHash,
    subjectEvents,
    otherEvents,
    liftedContainmentId: lifted.id,
    activeContainmentId: active.id,
    secrets: [
      admin,
      shield,
      admin.slice(-43),
      shield.slice(-43),
      webhook.signing_secret ?? "",
      target.verification.file_content,
    ],
  };
}

/** The tenant tables in which the Organization has no row. */
export async function tablesWithoutRows(api: TestApi, organizationId: string): Promise<string[]> {
  const tables = await tenantTables(api);
  const counts = await rowsOf(api, organizationId, tables);
  return tables.filter((table) => counts[table] === 0);
}

/** A test API with what the seed needs: a held Assessor, stand-in DNS and mail, the advisory fixtures, an audit key. */
export async function makeDataApi(
  now: () => Date,
  overrides: Partial<AppDeps> = {},
): Promise<TestApi & { auditSigner: Signer }> {
  const auditSigner = createSigner();
  const api = await makeTestApi({
    now,
    assessor: fakeAssessor(),
    resolve: async () => [{ address: "93.184.216.34", family: 4 }],
    email: {
      mailer: { send: async (messages) => messages.map(() => ({ ok: true, code: 250 })) },
      sender: { address: "alerts@airverse.test", name: "Airverse" },
    },
    prove: {
      resolver: {
        txt: async () => {
          throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
        },
        addresses: async () => [],
      },
      fetcher: async () => ({ ok: false, reason: "status" }),
    },
    auditSigner,
    auditReadsPerMinute: 10_000,
    ...overrides,
  });
  const fixtures = JSON.parse(readFileSync(FIXTURE_ADVISORIES_FILE, "utf8")) as AdvisoryInput[];
  await syncAdvisories(api.db, fixtureSource(fixtures));
  return { ...api, auditSigner };
}

/** Requests the deletion of the seeded Organization through the API and returns its id. */
export async function requestDeletion(api: TestApi, seeded: Seeded): Promise<string> {
  const res = await api.app.request(
    "/v1/organization/deletion",
    json({ confirm_name: seeded.name }, withReason(bearer(seeded.admin))),
  );
  expect(res.status, await res.clone().text()).toBe(201);
  return DeletionResponseSchema.parse(await res.json()).deletion.id;
}
