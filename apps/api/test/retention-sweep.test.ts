import { randomBytes } from "node:crypto";
import { EXAMPLE_SHIELD_EVENT } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRetentionJob } from "../src/data/retention.ts";
import type { Queryable } from "../src/db/db.ts";
import { lockedRetention, sweepRetention } from "../src/stores/retention.ts";
import { artifactFor, fakeAssessor } from "./fake-assessor.ts";
import {
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
  uuidv7,
  withReason,
} from "./helpers.ts";

// Slice 18c: the retention job end to end on the database. Three Organizations — Acme keeps Events 30 days, Bravo 395,
// Charlie 7 but its deletion is pending — each seeded with rows on both sides of every rule. The job must remove
// exactly the old ones of Acme and Bravo, leave Charlie untouched, continue across calls and runs when bounded, and
// never trip over the foreign keys between Incidents, their children and containments.

const NOW = Date.parse("2026-11-14T03:00:00.000Z");
const DAY = 86_400_000;
const ago = (days: number, extraMs = 0) => new Date(NOW - days * DAY - extraMs);

interface Org {
  name: string;
  organizationId: string;
  admin: string;
  appId: string;
  buildId: string;
  keyId: string;
  /** Row ids per table that the job must remove, and that it must keep. */
  gone: Record<string, string[]>;
  kept: Record<string, string[]>;
}

const TABLES = ["events", "containments", "incidents", "detections", "alert_deliveries", "assessments", "artifacts"];

/** Row ids of the given table still present for the Organization. */
async function present(api: TestApi, organizationId: string, table: string): Promise<string[]> {
  const id = table === "events" ? "event_id::text" : "id";
  return api.db.owner(async (q) => {
    const { rows } = await q.query<{ id: string }>(
      `SELECT ${id} AS id FROM "${table}" WHERE organization_id = $1 ORDER BY 1`,
      [organizationId],
    );
    return rows.map((row) => row.id);
  });
}

describe("retention job", () => {
  let api: TestApi;
  const clock = { ms: NOW };
  const now = () => new Date(clock.ms);
  const orgs: Org[] = [];

  async function organization(name: string, days: number): Promise<Org> {
    const created = await createOrganization(api, name);
    const organizationId = created.organization.id;
    const admin = created.admin_key.key;
    const appId = (await createAppFor(api, admin)).app.id;
    const { manifest, files } = artifactFor(appId);
    const post = (path: string, body: unknown) => api.app.request(path, json(body, bearer(admin)));
    expect((await post(`/v1/apps/${appId}/builds`, { manifest })).status).toBe(201);
    expect(
      (await post(`/v1/apps/${appId}/builds/${manifest.build_id}/assessments`, { tier: "T1", files })).status,
    ).toBe(202);
    const keyId = await api.db.owner(async (q) => {
      await q.query("UPDATE organizations SET event_retention_days = $2 WHERE id = $1", [organizationId, days]);
      const { rows } = await q.query<{ id: string }>(
        "SELECT id FROM api_keys WHERE organization_id = $1 AND kind = 'admin'",
        [organizationId],
      );
      return rows[0]?.id ?? "";
    });
    const org: Org = {
      name,
      organizationId,
      admin,
      appId,
      buildId: manifest.build_id,
      keyId,
      gone: Object.fromEntries(TABLES.map((t) => [t, []])),
      kept: Object.fromEntries(TABLES.map((t) => [t, []])),
    };
    // The Assessment the API queued stays (not finished).
    org.kept.assessments = await present(api, organizationId, "assessments");
    org.kept.artifacts = await present(api, organizationId, "artifacts");
    orgs.push(org);
    return org;
  }

  async function event(q: Queryable, org: Org, receivedAt: Date, guard: boolean): Promise<string> {
    const id = uuidv7(receivedAt.getTime());
    const payload = shieldEvent(receivedAt.getTime(), {
      event_id: id,
      attestation: guard ? { status: "valid", verdict: "trusted", risk: 0 } : EXAMPLE_SHIELD_EVENT.attestation,
    });
    await q.query(
      `INSERT INTO events (organization_id, event_id, app_id, environment, ts, received_at, type, payload)
       VALUES ($1, $2, $3, 'development', $4, $4, 'request.decision', $5)`,
      [org.organizationId, id, org.appId, receivedAt, JSON.stringify(payload)],
    );
    return id;
  }

  async function incident(
    q: Queryable,
    org: Org,
    lastSeen: Date,
    detections: number,
  ): Promise<{ id: string; detections: string[] }> {
    const id = newId("inc");
    await q.query(
      `INSERT INTO incidents (id, organization_id, app_id, environment, rule, severity, title, status, ip_prefix,
         first_seen, last_seen, detection_count, created_at, updated_at)
       VALUES ($1, $2, $3, 'development', 'blocked-burst', 'high', 'Burst', 'resolved', '203.0.113.0/24', $4, $4, 1, $4, $4)`,
      [id, org.organizationId, org.appId, lastSeen],
    );
    const ids: string[] = [];
    for (let i = 0; i < detections; i++) {
      const detection = newId("dtc");
      ids.push(detection);
      await q.query(
        `INSERT INTO detections (id, organization_id, incident_id, app_id, environment, rule, ip_prefix, count,
           window_start, window_end, detected_at)
         VALUES ($1, $2, $3, $4, 'development', 'blocked-burst', '203.0.113.0/24', 20, $5, $5, $5)`,
        [detection, org.organizationId, id, org.appId, lastSeen],
      );
    }
    return { id, detections: ids };
  }

  async function delivery(q: Queryable, org: Org, at: Date, incidentId: string | null): Promise<string> {
    const id = newId("dlv");
    await q.query(
      `INSERT INTO alert_deliveries (id, organization_id, channel_id, incident_id, attempt, outcome, status_code, at)
       VALUES ($1, $2, 'chn_000000000000000000000000', $3, 1, 'delivered', 200, $4)`,
      [id, org.organizationId, incidentId, at],
    );
    return id;
  }

  /** A containment created `createdDaysAgo` and ended at `endedAt` (lifted when `lifted`, else expiring then). */
  async function containment(
    q: Queryable,
    org: Org,
    incidentId: string | null,
    createdAt: Date,
    expiresAt: Date,
    liftedAt: Date | null,
  ): Promise<string> {
    const id = newId("cnt");
    await q.query(
      `INSERT INTO containments (organization_id, id, app_id, environment, incident_id, target_kind, ip_prefix,
         created_at, expires_at, created_by, lifted_at, lifted_by)
       VALUES ($1, $2, $3, 'development', $4, 'prefix', '203.0.113.0/24', $5, $6, $7, $8, $9)`,
      [org.organizationId, id, org.appId, incidentId, createdAt, expiresAt, org.keyId, liftedAt, liftedAt && org.keyId],
    );
    return id;
  }

  async function assessment(q: Queryable, org: Org, status: "failed" | "queued", finishedAt: Date | null) {
    const id = newId("asm");
    await q.query(
      `INSERT INTO assessments (organization_id, id, app_id, build_id, environment, tier, status, scope, failure_reason,
         created_at, started_at, finished_at)
       SELECT organization_id, $2, app_id, build_id, environment, tier, $3, scope, $4, $5, $6, $6
       FROM assessments WHERE organization_id = $1 LIMIT 1`,
      [
        org.organizationId,
        id,
        status,
        status === "failed" ? "engine stopped" : null,
        finishedAt === null ? now() : new Date(finishedAt.getTime() - 60_000),
        finishedAt,
      ],
    );
    return id;
  }

  async function artifact(q: Queryable, org: Org, keptUntil: Date): Promise<string> {
    const id = `art_${randomBytes(12).toString("hex")}`;
    await q.query(
      `INSERT INTO artifacts (organization_id, id, app_id, build_id, files, bytes, created_at, kept_until)
       VALUES ($1, $2, $3, $4, 1, 10, $5, $6)`,
      [org.organizationId, id, org.appId, org.buildId, new Date(keptUntil.getTime() - 30 * DAY), keptUntil],
    );
    return id;
  }

  /** Rows on both sides of every rule, by the Organization's Event retention (`days`). */
  async function seed(org: Org, days: number): Promise<void> {
    const { gone, kept } = org;
    const push = (bucket: Record<string, string[]>, table: string, ...ids: string[]) => bucket[table]?.push(...ids);
    await api.db.owner(async (q) => {
      // Events: just past and just within the retention; Guard Events past and within 30 days.
      push(gone, "events", await event(q, org, ago(days, 1000), false), await event(q, org, ago(days + 200), false));
      push(kept, "events", await event(q, org, ago(days, -1000), false), await event(q, org, ago(1), false));
      push(gone, "events", await event(q, org, ago(Math.min(days, 30), 1000), true));
      push(kept, "events", await event(q, org, ago(Math.min(days, 30), -1000), true));
      if (days > 30) push(kept, "events", await event(q, org, ago(31), false)); // a plain Event of the same age stays

      // Containments: lifted and expired past the retention go; one ended within it, and an active one, stay.
      push(gone, "containments", await containment(q, org, null, ago(days + 5), ago(days - 1), ago(days, 1000)));
      push(gone, "containments", await containment(q, org, null, ago(days + 5), ago(days, 1000), null));
      push(kept, "containments", await containment(q, org, null, ago(days + 5), ago(days, -1000), null));
      push(kept, "containments", await containment(q, org, null, ago(days + 5), new Date(NOW + DAY), null));

      // Incidents. Old and free: goes with its Detections and deliveries.
      const free = await incident(q, org, ago(395, 1000), 3);
      push(gone, "incidents", free.id);
      push(gone, "detections", ...free.detections);
      push(gone, "alert_deliveries", await delivery(q, org, ago(1), free.id));
      // Old, named by an active containment: stays, with its Detection.
      const blocked = await incident(q, org, ago(400), 1);
      push(kept, "incidents", blocked.id);
      push(kept, "detections", ...blocked.detections);
      push(kept, "containments", await containment(q, org, blocked.id, ago(days + 5), new Date(NOW + DAY), null));
      // Old, without Detections, named only by an ended containment within the retention: stays, and its delete is
      // never attempted (the containment's foreign key has no action).
      const bare = await incident(q, org, ago(400), 0);
      push(kept, "incidents", bare.id);
      push(kept, "containments", await containment(q, org, bare.id, ago(days + 5), ago(days, -1000), null));
      // Old, named by a containment that ended but is still within the Event retention: stays (the FK case).
      const recent = await incident(q, org, ago(400), 1);
      push(kept, "incidents", recent.id);
      push(kept, "detections", ...recent.detections);
      push(kept, "containments", await containment(q, org, recent.id, ago(days + 5), ago(days, -1000), null));
      // Old, named only by a containment past the retention: both go in the same run.
      const stale = await incident(q, org, ago(400), 1);
      push(gone, "incidents", stale.id);
      push(gone, "detections", ...stale.detections);
      push(gone, "containments", await containment(q, org, stale.id, ago(days + 5), ago(days, 1000), null));
      // Just within the evidence period: stays.
      const young = await incident(q, org, ago(395, -1000), 1);
      push(kept, "incidents", young.id);
      push(kept, "detections", ...young.detections);

      // Alert deliveries without an Incident, by age.
      push(gone, "alert_deliveries", await delivery(q, org, ago(395, 1000), null));
      push(kept, "alert_deliveries", await delivery(q, org, ago(395, -1000), null));

      // Assessments: finished past and within the evidence period; one queued long ago stays.
      push(gone, "assessments", await assessment(q, org, "failed", ago(395, 1000)));
      push(kept, "assessments", await assessment(q, org, "failed", ago(395, -1000)));

      // Artifacts: one whose keep date passed goes (assessment_artifacts_expire); one still kept stays.
      push(gone, "artifacts", await artifact(q, org, ago(0, 1000)));
      push(kept, "artifacts", await artifact(q, org, ago(-1)));
    });
  }

  beforeAll(async () => {
    api = await makeTestApi({ now, assessor: fakeAssessor() });
    const acme = await organization("Acme", 30);
    await seed(acme, 30);
    const bravo = await organization("Bravo", 395);
    await seed(bravo, 395);
    const charlie = await organization("Charlie", 7);
    await seed(charlie, 7);
    const res = await api.app.request(
      "/v1/organization/deletion",
      json({ confirm_name: "Charlie" }, withReason(bearer(charlie.admin))),
    );
    expect(res.status, await res.clone().text()).toBe(201);
  });
  afterAll(async () => {
    await api.close();
  });

  it("one bounded call removes at most `batch` rows per table and says that more is left", async () => {
    const before = await present(api, orgs[0]?.organizationId ?? "", "events");
    const swept = await api.db.owner((q) => sweepRetention(q, now(), 1));
    expect(swept.more).toBe(true);
    const perTable: Record<string, number> = {};
    for (const counts of Object.values(swept.rows)) {
      for (const [table, n] of Object.entries(counts)) perTable[table] = (perTable[table] ?? 0) + n;
    }
    // Each step has its own budget: Events (all, and those carrying a Guard report) and alert deliveries (of old
    // Incidents, and by age) have two steps each.
    for (const [table, n] of Object.entries(perTable)) {
      expect(n, table).toBeLessThanOrEqual(table === "events" || table === "alert_deliveries" ? 2 : 1);
    }
    expect(perTable.events).toBeGreaterThanOrEqual(1);
    // Charlie's deletion is pending: never swept.
    expect(Object.keys(swept.rows)).not.toContain(orgs[2]?.organizationId);
    expect((await present(api, orgs[0]?.organizationId ?? "", "events")).length).toBeLessThanOrEqual(before.length);
  });

  it("a run cut short by its call cap is recorded as incomplete and continues at the next run", async () => {
    const logger = captureLogger();
    const job = createRetentionJob({ db: api.db, now, logger, batch: 1, maxCallsPerRun: 2 });
    const first = await job.runOnce();
    expect(first).toMatchObject({ calls: 2, complete: false, failed: 0 });
    const runs = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ organization_id: string; complete: boolean }>(
        "SELECT organization_id, complete FROM retention_runs ORDER BY seq",
      );
      return rows;
    });
    // One row per swept Organization (Charlie's deletion is pending: none).
    expect(runs.map((run) => run.organization_id).sort()).toEqual(
      [orgs[0]?.organizationId, orgs[1]?.organizationId].sort(),
    );
    expect(runs.every((run) => run.complete === false)).toBe(true);
    // The artifact expiry is counted per Organization: Acme's one expired artifact is in its run.
    const acme = await api.db.tx({ organizationId: orgs[0]?.organizationId ?? "" }, async (q) => {
      const { rows } = await q.query<{ counts: Record<string, number> }>("SELECT counts FROM retention_runs");
      return rows[0]?.counts;
    });
    expect(acme?.artifacts).toBe(1);
    // A run cut short says so in the log, with counts only.
    expect(logger.lines.some((line) => line.startsWith("retention run incomplete"))).toBe(true);
  });

  it("removes exactly the old rows of every swept table, Organization by Organization", async () => {
    const logger = captureLogger();
    const job = createRetentionJob({ db: api.db, now, logger, batch: 2, maxCallsPerRun: 1000 });
    const result = await job.runOnce();
    expect(result).toMatchObject({ complete: true, failed: 0 });
    expect(result.calls).toBeGreaterThan(1);
    for (const org of orgs.slice(0, 2)) {
      for (const table of TABLES) {
        const left = await present(api, org.organizationId, table);
        expect(
          left.filter((id) => org.gone[table]?.includes(id)),
          `${org.name} ${table} gone`,
        ).toEqual([]);
        expect([...(org.kept[table] ?? [])].sort(), `${org.name} ${table} kept`).toEqual(
          left.filter((id) => org.kept[table]?.includes(id)),
        );
        expect(left.length, `${org.name} ${table} nothing else`).toBe(org.kept[table]?.length);
      }
    }
    // Logs carry counts, never an identifier.
    const text = logger.lines.join("\n");
    expect(text).toMatch(/retention run/);
    for (const org of orgs) expect(text).not.toContain(org.organizationId);
  });

  it("leaves the Organization whose deletion is pending untouched", async () => {
    const charlie = orgs[2] as Org;
    for (const table of TABLES) {
      const left = await present(api, charlie.organizationId, table);
      const seeded = [...(charlie.gone[table] ?? []), ...(charlie.kept[table] ?? [])];
      if (table === "artifacts") continue; // the existing artifact expiry is not per Organization
      expect(left.length, table).toBe(seeded.length);
    }
  });

  it("records the run per Organization with its counts, and a second run removes nothing", async () => {
    const acme = orgs[0] as Org;
    const last = await api.db.tx({ organizationId: acme.organizationId }, async (q) => {
      const { rows } = await q.query<{ complete: boolean; counts: Record<string, number> }>(
        "SELECT complete, counts FROM retention_runs ORDER BY ran_at DESC, seq DESC LIMIT 1",
      );
      return rows[0];
    });
    expect(last?.complete).toBe(true);
    expect(Object.keys(last?.counts ?? {}).length).toBeGreaterThan(0);
    const again = await createRetentionJob({ db: api.db, now, logger: captureLogger(), batch: 1000 }).runOnce();
    expect(again).toMatchObject({ calls: 1, complete: true, failed: 0, rows: {} });
  });

  it("keeps the 30 most recent runs per Organization", async () => {
    const job = createRetentionJob({ db: api.db, now, logger: captureLogger() });
    for (let i = 0; i < 31; i++) {
      clock.ms += 1000;
      await job.runOnce();
    }
    const counts = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ organization_id: string; n: number; newest: Date }>(
        "SELECT organization_id, count(*)::int AS n, max(ran_at) AS newest FROM retention_runs GROUP BY 1",
      );
      return rows;
    });
    expect(counts).toHaveLength(2);
    for (const row of counts) {
      expect(row.n).toBe(30);
      expect(row.newest.getTime()).toBe(clock.ms);
    }
  });
});

describe("retention fairness and the set-up record", () => {
  let api: TestApi;
  const clock = { ms: NOW };
  const now = () => new Date(clock.ms);
  const orgs = {} as { big: { organizationId: string; appId: string } };
  beforeAll(async () => {
    api = await makeTestApi({ now });
  });
  afterAll(async () => {
    await api.close();
  });

  async function organization(name: string, days: number) {
    const created = await createOrganization(api, name);
    const organizationId = created.organization.id;
    const admin = created.admin_key.key;
    const appId = (await createAppFor(api, admin, { name: "Shop", environment: "development" })).app.id;
    await api.db.owner((q) =>
      q.query("UPDATE organizations SET event_retention_days = $2 WHERE id = $1", [organizationId, days]),
    );
    return { organizationId, admin, appId };
  }

  async function events(org: { organizationId: string; appId: string }, receivedAt: Date, n: number, guard = false) {
    const ids: string[] = [];
    await api.db.owner(async (q) => {
      for (let i = 0; i < n; i++) {
        const ms = receivedAt.getTime() + i;
        const id = uuidv7(ms);
        ids.push(id);
        const payload = shieldEvent(ms, {
          event_id: id,
          attestation: guard ? { status: "valid", verdict: "suspect", risk: 70 } : EXAMPLE_SHIELD_EVENT.attestation,
        });
        await q.query(
          `INSERT INTO events (organization_id, event_id, app_id, environment, ts, received_at, type, payload)
           VALUES ($1, $2, $3, 'development', $4, $4, 'request.decision', $5)`,
          [org.organizationId, id, org.appId, new Date(ms), JSON.stringify(payload)],
        );
      }
    });
    return ids;
  }

  it("serves every Organization even when one has more backlog than a run can take", async () => {
    const big = await organization("Big", 7);
    orgs.big = big;
    const small = await organization("Small", 7);
    await events(big, new Date(clock.ms - 10 * DAY), 6);
    const [old] = await events(small, new Date(clock.ms - 400 * DAY), 1);
    const logger = captureLogger();
    const job = createRetentionJob({ db: api.db, now, logger, batch: 2, maxCallsPerRun: 2 });
    for (let run = 0; run < 3; run++) {
      await events(big, new Date(clock.ms - 10 * DAY + 1000), 4);
      clock.ms += 1000;
      await job.runOnce();
    }
    const left = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ n: number }>("SELECT count(*)::int AS n FROM events WHERE event_id = $1", [old]);
      return rows[0]?.n;
    });
    expect(left).toBe(0);
  });

  it("gives the Guard Events their own budget", async () => {
    const org = await organization("Guarded", 395);
    await events(org, new Date(clock.ms - 400 * DAY), 1);
    await events(org, new Date(clock.ms - 31 * DAY), 1, true);
    // Big still has a backlog: with a batch of 3, each of the three Organizations gets a share of 1 per step.
    await events(orgs.big, new Date(clock.ms - 10 * DAY), 6);
    const swept = await api.db.owner((q) => sweepRetention(q, now(), 3));
    expect(swept.rows[org.organizationId]?.events).toBe(2);
  });

  it("keeps the set-up steps done after the sweep removes the Events that did them", async () => {
    const org = await organization("Setup", 30);
    await events(org, new Date(clock.ms - 40 * DAY), 1, true);
    const setup = async () => {
      const res = await api.app.request(`/v1/apps/${org.appId}/setup?environment=development`, {
        headers: bearer(org.admin),
      });
      expect(res.status).toBe(200);
      return ((await res.json()) as { setup: unknown }).setup;
    };
    const before = await setup();
    expect(before).toMatchObject({ shield: { done_at: expect.any(String) }, guard: { done_at: expect.any(String) } });
    await createRetentionJob({ db: api.db, now, logger: captureLogger() }).runOnce();
    const left = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM events WHERE organization_id = $1",
        [org.organizationId],
      );
      return rows[0]?.n;
    });
    expect(left).toBe(0);
    expect(await setup()).toEqual(before);
  });

  it("keeps the set-up steps done after a subject erasure removes the Events that did them", async () => {
    const org = await organization("Erased", 30);
    const ipHash = "iph_0123456789abcdef0123456789abcdef";
    const ms = clock.ms - DAY;
    const id = uuidv7(ms);
    await api.db.owner((q) =>
      q.query(
        `INSERT INTO events (organization_id, event_id, app_id, environment, ts, received_at, type, payload)
         VALUES ($1, $2, $3, 'development', $4, $4, 'request.decision', $5)`,
        [
          org.organizationId,
          id,
          org.appId,
          new Date(ms),
          JSON.stringify(
            shieldEvent(ms, {
              event_id: id,
              actor: { ip_prefix: "203.0.113.0/24", ip_hash: ipHash },
              attestation: { status: "valid", verdict: "suspect", risk: 70 },
            }),
          ),
        ],
      ),
    );
    const setup = async () => {
      const res = await api.app.request(`/v1/apps/${org.appId}/setup?environment=development`, {
        headers: bearer(org.admin),
      });
      expect(res.status).toBe(200);
      return ((await res.json()) as { setup: unknown }).setup;
    };
    const before = await setup();
    expect(before).toMatchObject({ shield: { done_at: expect.any(String) }, guard: { done_at: expect.any(String) } });
    const erased = await api.app.request(
      "/v1/subjects/erase",
      json({ ip_hash: ipHash }, withReason(bearer(org.admin))),
    );
    expect(erased.status, await erased.clone().text()).toBe(200);
    expect(((await erased.json()) as { report: { events_erased: number } }).report.events_erased).toBe(1);
    expect(await setup()).toEqual(before);
  });

  it("reads the retention for a change under a row lock", async () => {
    const seen: string[] = [];
    await lockedRetention(
      {
        async query<R>(sql: string) {
          seen.push(sql);
          return { rows: [{ event_retention_days: 30 }] as R[] };
        },
      },
      "org_000000000000000000000001",
    );
    expect(seen.join("\n")).toMatch(/FOR UPDATE/);
  });
});
