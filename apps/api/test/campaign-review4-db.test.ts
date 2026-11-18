import { cpSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { STAND_IN_ENGINE } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { GateRecord } from "../src/campaign/gate.ts";
import type { Queryable } from "../src/db/db.ts";
import { migrate } from "../src/db/migrate.ts";
import {
  claimCampaign,
  endCampaign,
  findCampaign,
  insertCampaign,
  insertCampaignRequest,
  listCampaignRequests,
  settleCampaignRequest,
} from "../src/stores/campaigns.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, fourth independent safety review, migration 0040 as the request role (`ar_app`): a refused probe's row
// holds no text of the engine (R1, D-110), the states a Campaign may pass through (R5, D-108), and what the migration
// does to evidence stored before it (R6).

const AT = new Date("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const MIGRATIONS = fileURLToPath(new URL("../migrations", import.meta.url));

describe("migration 0040: the fourth review's rules in the database", () => {
  let api: TestApi;
  let org: string;

  const scope = <T>(fn: (q: Queryable) => Promise<T>) => api.db.tx({ organizationId: org }, fn);
  const sqlState = async (work: Promise<unknown>): Promise<string | undefined> => {
    try {
      await work;
      return undefined;
    } catch (error) {
      return String((error as { code?: unknown }).code);
    }
  };
  const create = () =>
    scope((q) =>
      insertCampaign(q, {
        organizationId: org,
        id: newId("cmp"),
        targetId: "tgt_0123456789abcdef01234567",
        host: "shop.acme-shop.io",
        roeId: "roe_0123456789abcdef01234567",
        roeSha256: "b".repeat(64),
        intensity: "passive",
        engine: STAND_IN_ENGINE,
        createdBy: KEY,
        createdAt: AT,
      }),
    );
  const stop = (id: string) =>
    scope((q) => endCampaign(q, id, { reason: "owner_stop", started: false, checks: null, at: AT }));
  const row = (seq: number, over: Partial<GateRecord> = {}): GateRecord => ({
    seq,
    method: "GET",
    target: "/",
    asked: null,
    outcome: "sending",
    reason: null,
    status: null,
    failure: null,
    bytes: 0,
    ms: 0,
    ...over,
  });
  const update = (id: string, set: string) =>
    sqlState(scope((q) => q.query(`UPDATE campaigns SET ${set} WHERE id = $1`, [id])));

  beforeAll(async () => {
    api = await makeTestApi();
    org = (await createOrganization(api, "Acme")).organization.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("R1: a refused probe's row holds its reason and how much it asked for — the database takes no other method label", async () => {
    const campaign = await create();
    const insert = (entry: GateRecord) => sqlState(scope((q) => insertCampaignRequest(q, org, campaign.id, entry, AT)));
    const refused = { outcome: "refused" as const, reason: "not_in_catalog" as const, target: null };
    expect(await insert(row(1, { ...refused, method: "OTHER", asked: 2048 }))).toBeUndefined();
    expect(await insert(row(2, { ...refused, method: null, asked: 0 }))).toBeUndefined();
    expect(
      await insert(row(3, { ...refused, method: "GET", target: "/search", reason: "path_excluded", asked: 7 })),
    ).toBeUndefined();
    // A method of the engine's own choosing, a refusal without its count, a count on a row that is not a refusal.
    expect(await insert(row(4, { ...refused, method: "TRACE", asked: 5 }))).toBe("23514");
    expect(await insert(row(4, { ...refused, method: "SECRETTEXT", asked: 5 }))).toBe("23514");
    expect(
      await sqlState(
        scope((q) =>
          q.query(
            `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome, reason)
             VALUES ($1, $2, 4, now(), 'OTHER', NULL, 'refused', 'not_in_catalog')`,
            [org, campaign.id],
          ),
        ),
      ),
    ).toBe("23514");
    expect(
      await sqlState(
        scope((q) =>
          q.query(
            `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome, asked_chars)
             VALUES ($1, $2, 4, now(), 'GET', '/', 'sending', 5)`,
            [org, campaign.id],
          ),
        ),
      ),
    ).toBe("23514");
    expect(
      await sqlState(
        scope((q) =>
          q.query(
            `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, outcome, reason, asked_chars)
             VALUES ($1, $2, 4, now(), 'OTHER', 'refused', 'not_in_catalog', 1000001)`,
            [org, campaign.id],
          ),
        ),
      ),
    ).toBe("23514");
    expect(await insert(row(4))).toBeUndefined();
    expect(
      (await scope((q) => listCampaignRequests(q, campaign.id))).map((r) => [
        r.outcome,
        r.method,
        r.target,
        r.asked_chars,
      ]),
    ).toEqual([
      // Fifth review (D-113): as buckets, not counts.
      ["refused", "OTHER", null, 1_000_000],
      ["refused", null, null, 0],
      ["refused", "GET", "/search", 256],
      ["sending", "GET", "/", null],
    ]);
    await stop(campaign.id);
  });

  it("R5: the review's forgery — INSERT queued, then one UPDATE to completed with six clean checks — is refused", async () => {
    const campaign = await create();
    expect(
      await update(
        campaign.id,
        `status = 'completed', end_reason = 'checks_complete', started_at = created_at, finished_at = created_at,
         pinned_address = '203.0.113.10', checks_ran = 6, checks_reported = 0, checks_skipped = 0, checks_inconclusive = 0`,
      ),
    ).toBe("23514");
    // The same as the owner of the database.
    expect(
      await sqlState(
        api.db.owner((q) =>
          q.query(
            `UPDATE campaigns SET status = 'completed', end_reason = 'checks_complete', finished_at = created_at
             WHERE id = $1`,
            [campaign.id],
          ),
        ),
      ),
    ).toBe("23514");
    expect((await scope((q) => findCampaign(q, campaign.id)))?.status).toBe("queued");
    await stop(campaign.id);
  });

  it("R5: from queued, a Campaign starts only with a pinned address, and ends only as stopped, refused or failed without check counts", async () => {
    const campaign = await create();
    const ended = "end_reason = 'x', finished_at = created_at";
    const refusedUpdates = [
      "status = 'running', started_at = created_at",
      `status = 'interrupted', ${ended}`,
      `status = 'completed', ${ended}`,
      `status = 'failed', ${ended}, checks_ran = 0, checks_reported = 0, checks_skipped = 6, checks_inconclusive = 0`,
      `status = 'stopped', ${ended}, checks_ran = 6, checks_reported = 6, checks_skipped = 0, checks_inconclusive = 0`,
      `status = 'stopped', ${ended}, findings_dropped = 3`,
      `status = 'refused', ${ended}, started_at = created_at`,
      "checks_ran = 1, checks_reported = 1, checks_skipped = 0, checks_inconclusive = 0",
      "pinned_address = '203.0.113.10'",
    ];
    const outcomes: (string | undefined)[] = [];
    for (const set of refusedUpdates) outcomes.push(await update(campaign.id, set));
    expect(outcomes).toEqual(refusedUpdates.map(() => "23514"));
    // What the runner does: a stop request, then the claim with the address.
    expect(await scope((q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"))).toBe(true);
    expect(await scope((q) => findCampaign(q, campaign.id))).toMatchObject({ status: "running" });
    await scope((q) => endCampaign(q, campaign.id, { reason: "owner_stop", started: true, checks: null, at: AT }));
    for (const status of ["stopped", "refused", "failed"] as const) {
      const queued = await create();
      expect(await update(queued.id, `status = '${status}', ${ended}`)).toBeUndefined();
    }
  });

  it("R5: a running Campaign completes only when a request of it was sent; its address is not rewritten", async () => {
    const campaign = await create();
    await scope((q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"));
    const complete = () =>
      sqlState(
        scope((q) =>
          endCampaign(q, campaign.id, {
            reason: "checks_complete",
            started: true,
            checks: { ran: 6, reported: 0, inconclusive: 0, skipped: 0 },
            at: AT,
          }),
        ),
      );
    // The two-statement walk queued → running → completed, without a request: refused.
    expect(await complete()).toBe("23514");
    expect(await update(campaign.id, "pinned_address = '198.51.100.7'")).toBe("23514");
    expect(await update(campaign.id, "started_at = started_at + interval '1 hour'")).toBe("23514");
    // A row that is only being sent, or was refused, is not a sent request.
    await scope((q) => insertCampaignRequest(q, org, campaign.id, row(1), AT));
    await scope((q) =>
      insertCampaignRequest(q, org, campaign.id, row(2, { outcome: "refused", reason: "path_excluded", asked: 1 }), AT),
    );
    expect(await complete()).toBe("23514");
    await scope((q) => settleCampaignRequest(q, campaign.id, { ...row(1), outcome: "sent", status: 200 }));
    expect(await complete()).toBeUndefined();
    expect(await scope((q) => findCampaign(q, campaign.id))).toMatchObject({
      status: "completed",
      checks: { ran: 6, reported: 0, inconclusive: 0, skipped: 0 },
    });
  });

  it("R5: a running Campaign may still end stopped, failed or interrupted without a sent request", async () => {
    for (const reason of ["owner_stop", "engine_error", "api_shutdown"] as const) {
      const campaign = await create();
      await scope((q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"));
      expect(
        await scope((q) =>
          endCampaign(q, campaign.id, {
            reason,
            started: true,
            checks: { ran: 0, reported: 0, inconclusive: 0, skipped: 6 },
            at: AT,
          }),
        ),
      ).toBe(true);
    }
  });
});

describe("migration 0040 on a database that held Campaigns before it (R6, R1)", () => {
  it("empties excerpts, drops body hashes, keeps of a Content-Security-Policy only that it was sent, and removes the text of refused rows", async () => {
    const before = mkdtempSync(join(tmpdir(), "ar-migrations-"));
    const pg = await PGlite.create();
    try {
      for (const file of readdirSync(MIGRATIONS)) {
        if (file < "0040") cpSync(join(MIGRATIONS, file), join(before, file));
      }
      await migrate(pg, before);
      const campaign = "cmp_0123456789abcdef01234567";
      await pg.query("INSERT INTO organizations (id, name) VALUES ('org_0123456789abcdef01234567', 'Acme')");
      await pg.query(
        `INSERT INTO campaigns (organization_id, id, target_id, host, roe_id, roe_sha256, intensity, engine, status,
           staging_declared, created_by, created_at, started_at)
         VALUES ('org_0123456789abcdef01234567', $1, 'tgt_0123456789abcdef01234567', 'shop.acme-shop.io',
           'roe_0123456789abcdef01234567', $2, 'passive', '{}', 'running', true, $3, now(), now())`,
        [campaign, "b".repeat(64), KEY],
      );
      await pg.query(
        `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome, reason, status, bytes)
         VALUES ('org_0123456789abcdef01234567', $1, 1, now(), 'GET', '/', 'sent', NULL, 200, 1048576),
                ('org_0123456789abcdef01234567', $1, 2, now(), 'TRACE', '/text-read-from-a-response', 'refused', 'method_not_allowed', NULL, 0),
                ('org_0123456789abcdef01234567', $1, 3, now(), NULL, NULL, 'refused', 'malformed_probe', NULL, 0),
                ('org_0123456789abcdef01234567', $1, 4, now(), 'GET', '/admin', 'refused', 'path_excluded', NULL, 0)`,
        [campaign],
      );
      const evidence = (headers: Record<string, string>) =>
        JSON.stringify({
          method: "GET",
          target: "/",
          status: 200,
          headers,
          excerpt: "x".repeat(2000),
          body_sha256: "a".repeat(64),
          truncated: false,
          location: null,
        });
      await pg.query(
        `INSERT INTO campaign_findings (organization_id, campaign_id, check_id, path, title, severity, state, evidence,
           first_seen_at, last_seen_at)
         VALUES ('org_0123456789abcdef01234567', $1, 'RW-02', '/a', 't', 'low', 'confirmed', $2, now(), now()),
                ('org_0123456789abcdef01234567', $1, 'RW-03', '/b', 't', 'low', 'confirmed', $3, now(), now())`,
        [
          campaign,
          evidence({ "content-security-policy": "script-src 'nonce-r4nd0mN0nce'", "content-type": "text/html" }),
          evidence({ server: "nginx" }),
        ],
      );
      await pg.query(
        "UPDATE campaigns SET status = 'completed', end_reason = 'checks_complete', finished_at = now() WHERE id = $1",
        [campaign],
      );

      expect(await migrate(pg, MIGRATIONS)).toEqual(readdirSync(MIGRATIONS).filter((file) => file >= "0040"));

      const findings = await pg.query<{ path: string; evidence: Record<string, unknown> }>(
        "SELECT path, evidence FROM campaign_findings ORDER BY path",
      );
      expect(findings.rows.map((finding) => finding.evidence)).toEqual([
        {
          method: "GET",
          target: "/",
          status: 200,
          headers: { "content-security-policy": "[present]", "content-type": "text/html" },
          excerpt: "",
          truncated: false,
          location: null,
        },
        {
          method: "GET",
          target: "/",
          status: 200,
          headers: { server: "nginx" },
          excerpt: "",
          truncated: false,
          location: null,
        },
      ]);
      expect(JSON.stringify(findings.rows)).not.toMatch(/r4nd0m|nonce/);
      const requests = await pg.query<{
        seq: number;
        method: string | null;
        target: string | null;
        asked_chars: number | null;
      }>("SELECT seq, method, target, asked_chars FROM campaign_requests ORDER BY seq");
      expect(requests.rows).toEqual([
        { seq: 1, method: "GET", target: "/", asked_chars: null },
        // What it asked for is gone; how much it was is what the old row still shows.
        // (Migration 0041 then turns the lengths into buckets: at most 256 characters.)
        { seq: 2, method: "OTHER", target: null, asked_chars: 256 },
        { seq: 3, method: null, target: null, asked_chars: 0 },
        { seq: 4, method: "GET", target: null, asked_chars: 256 },
      ]);
    } finally {
      await pg.close();
      rmSync(before, { recursive: true, force: true });
    }
  }, 60_000);
});
