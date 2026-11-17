import { STAND_IN_ENGINE } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Queryable } from "../src/db/db.ts";
import {
  campaignControl,
  campaignQueue,
  claimCampaign,
  createdInLastDay,
  endCampaign,
  findCampaign,
  insertCampaign,
  insertCampaignRequest,
  interruptRunningCampaigns,
  listCampaignFindings,
  listCampaignRequests,
  listCampaigns,
  operatorState,
  reportFinding,
  requestStop,
  setKillSwitch,
  setSuspension,
  settleCampaignRequest,
  sweepCampaigns,
} from "../src/stores/campaigns.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, migration 0039: what the database itself holds to — tenancy, one active Campaign per Organization, an
// end that is final, the restart rule, the operator's switch, and retention.

const AT = new Date("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const EVIDENCE = {
  method: "GET" as const,
  target: "/",
  status: 200,
  headers: {},
  excerpt: "x",
  truncated: false,
  location: null,
};

describe("migration 0039: Campaigns in the database", () => {
  let api: TestApi;
  let orgA: string;
  let orgB: string;

  const scope = <T>(organizationId: string, fn: (q: Queryable) => Promise<T>) => api.db.tx({ organizationId }, fn);
  const sqlState = async (work: Promise<unknown>): Promise<string | undefined> => {
    try {
      await work;
      return undefined;
    } catch (error) {
      return String((error as { code?: unknown }).code);
    }
  };
  const create = (organizationId: string, at = AT, host = "shop.acme-shop.io") =>
    scope(organizationId, (q) =>
      insertCampaign(q, {
        organizationId,
        id: newId("cmp"),
        targetId: "tgt_0123456789abcdef01234567",
        host,
        roeId: "roe_0123456789abcdef01234567",
        roeSha256: "b".repeat(64),
        intensity: "passive",
        engine: STAND_IN_ENGINE,
        createdBy: KEY,
        createdAt: at,
      }),
    );
  // Fourth review (D-108): a Campaign completes only from running, after a request of it was sent. These tests end
  // theirs the way a queued or running one can end at any time: stopped.
  const end = (organizationId: string, id: string, at = AT) =>
    scope(organizationId, (q) => endCampaign(q, id, { reason: "owner_stop", started: true, checks: null, at }));

  beforeAll(async () => {
    api = await makeTestApi();
    orgA = (await createOrganization(api, "Acme")).organization.id;
    orgB = (await createOrganization(api, "Globex")).organization.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("stores a queued Campaign that only its Organization sees", async () => {
    const campaign = await create(orgA);
    expect(campaign).toMatchObject({
      status: "queued",
      end_reason: null,
      staging_declared: true,
      engine: STAND_IN_ENGINE,
      requests_sent: 0,
      requests_refused: 0,
      response_bytes: 0,
      checks: null,
      stop: null,
    });
    expect(await scope(orgB, (q) => findCampaign(q, campaign.id))).toBeNull();
    expect(await scope(orgB, (q) => listCampaigns(q, 50))).toEqual([]);
    expect(await api.db.tx("none", (q) => findCampaign(q, campaign.id))).toBeNull();
    // Another Organization cannot write into it either.
    expect(await scope(orgB, (q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"))).toBe(false);
    expect(await scope(orgB, (q) => requestStop(q, campaign.id, { keyId: KEY, reason: "x", at: AT }))).toBe(false);
    expect(
      await sqlState(
        scope(orgB, (q) =>
          insertCampaignRequest(
            q,
            orgA,
            campaign.id,
            {
              seq: 1,
              method: "GET",
              target: "/",
              asked: null,
              outcome: "sent",
              reason: null,
              status: 200,
              failure: null,
              bytes: 1,
              ms: 1,
            },
            AT,
          ),
        ),
      ),
    ).toMatch(/^(?:42501|23514)$/);
    await end(orgA, campaign.id);
  });

  it("admits one queued or running Campaign per Organization, and another once it ended", async () => {
    const first = await create(orgA);
    expect(await sqlState(create(orgA))).toBe("23505");
    // Another Organization is not affected.
    const other = await create(orgB);
    expect(await scope(orgA, (q) => claimCampaign(q, first.id, AT, "203.0.113.10"))).toBe(true);
    expect(await sqlState(create(orgA))).toBe("23505");
    expect(await end(orgA, first.id)).toBe(true);
    const second = await create(orgA);
    expect(second.status).toBe("queued");
    await end(orgA, second.id);
    await end(orgB, other.id);
  });

  it("an end is final: an ended Campaign cannot be changed, restarted or stopped", async () => {
    const campaign = await create(orgA);
    await scope(orgA, (q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"));
    // It completes as a real one does (fourth review, D-108): running, with a request that was sent.
    const sent = {
      seq: 1,
      method: "GET",
      target: "/",
      asked: null,
      outcome: "sent" as const,
      reason: null,
      status: 200,
      failure: null,
      bytes: 1,
      ms: 1,
    };
    await scope(orgA, (q) => insertCampaignRequest(q, orgA, campaign.id, sent, AT));
    const complete = () =>
      scope(orgA, (q) =>
        endCampaign(q, campaign.id, { reason: "checks_complete", started: true, checks: null, at: AT }),
      );
    expect(await complete()).toBe(true);
    expect(await complete()).toBe(false);
    expect(await end(orgA, campaign.id)).toBe(false);
    expect(await scope(orgA, (q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"))).toBe(false);
    expect(await scope(orgA, (q) => requestStop(q, campaign.id, { keyId: KEY, reason: "x", at: AT }))).toBe(false);
    for (const sql of [
      "UPDATE campaigns SET status = 'queued', end_reason = NULL, finished_at = NULL WHERE id = $1",
      "UPDATE campaigns SET status = 'running', end_reason = NULL, finished_at = NULL WHERE id = $1",
      "UPDATE campaigns SET end_reason = 'owner_stop', status = 'stopped' WHERE id = $1",
    ]) {
      expect(await sqlState(scope(orgA, (q) => q.query(sql, [campaign.id])))).toBe("23514");
      // The owner of the database is held to it too.
      expect(await sqlState(api.db.owner((q) => q.query(sql, [campaign.id])))).toBe("23514");
    }
    // The request role cannot rewrite what a Campaign was authorised for, nor delete it.
    expect(
      await sqlState(scope(orgA, (q) => q.query("UPDATE campaigns SET host = 'x.io' WHERE id = $1", [campaign.id]))),
    ).toBe("42501");
    expect(await sqlState(scope(orgA, (q) => q.query("DELETE FROM campaigns WHERE id = $1", [campaign.id])))).toBe(
      "42501",
    );
    expect(await scope(orgA, (q) => findCampaign(q, campaign.id))).toMatchObject({
      status: "completed",
      end_reason: "checks_complete",
    });
  });

  it("review: a stop request is set once and never cleared or rewritten, on a queued or running Campaign too", async () => {
    const campaign = await create(orgA);
    expect(await scope(orgA, (q) => requestStop(q, campaign.id, { keyId: KEY, reason: "Wrong target", at: AT }))).toBe(
      true,
    );
    for (const sql of [
      "UPDATE campaigns SET stop_requested_at = NULL, stop_requested_by = NULL, stop_reason = NULL WHERE id = $1",
      "UPDATE campaigns SET stop_reason = 'never mind' WHERE id = $1",
      "UPDATE campaigns SET stop_requested_at = stop_requested_at + interval '1 hour' WHERE id = $1",
    ]) {
      expect(await sqlState(scope(orgA, (q) => q.query(sql, [campaign.id])))).toBe("23514");
      expect(await sqlState(api.db.owner((q) => q.query(sql, [campaign.id])))).toBe("23514");
    }
    expect(await scope(orgA, (q) => findCampaign(q, campaign.id))).toMatchObject({ stop: { reason: "Wrong target" } });
    await end(orgA, campaign.id);
  });

  it("review: a request row is written as sending and settled once; a settled row cannot be rewritten", async () => {
    const campaign = await create(orgA);
    const row = {
      seq: 1,
      method: "GET",
      target: "/",
      asked: null,
      outcome: "sending" as const,
      reason: null,
      status: null,
      failure: null,
      bytes: 0,
      ms: 0,
    };
    await scope(orgA, (q) => insertCampaignRequest(q, orgA, campaign.id, row, AT));
    // While it is not settled, it already counts as sent.
    expect(await scope(orgA, (q) => findCampaign(q, campaign.id))).toMatchObject({ requests_sent: 1 });
    const settle = (status: number) =>
      scope(orgA, (q) =>
        settleCampaignRequest(q, campaign.id, { ...row, outcome: "sent", status, bytes: 70_000, ms: 12 }),
      );
    expect(await settle(200)).toBe(true);
    expect(await settle(500)).toBe(false);
    expect(await scope(orgA, (q) => listCampaignRequests(q, campaign.id))).toMatchObject([
      { seq: 1, outcome: "sent", status: 200, bytes: 70_000, ms: 12 },
    ]);
    expect(
      await scope(orgB, (q) => settleCampaignRequest(q, campaign.id, { ...row, outcome: "sent", status: 200 })),
    ).toBe(false);
    await end(orgA, campaign.id);
  });

  it("review2 L4: an ended Campaign's history cannot be added to or rewritten, and the log has no gaps", async () => {
    const campaign = await create(orgA);
    const row = (seq: number, outcome: "sending" | "refused" = "sending") => ({
      seq,
      method: "GET",
      target: "/",
      asked: null,
      outcome,
      reason: outcome === "refused" ? ("owner_stop" as const) : null,
      status: null,
      failure: null,
      bytes: 0,
      ms: 0,
    });
    const insert = (seq: number, outcome: "sending" | "refused" = "sending") =>
      sqlState(scope(orgA, (q) => insertCampaignRequest(q, orgA, campaign.id, row(seq, outcome), AT)));
    const finding = (path: string) =>
      sqlState(
        scope(orgA, (q) =>
          reportFinding(q, orgA, campaign.id, {
            checkId: "RW-03",
            path,
            title: "t",
            severity: "high",
            evidence: EVIDENCE,
            at: AT,
          }),
        ),
      );
    // The log is contiguous: the next row is the last plus one, and never beyond 200.
    expect(await insert(2)).toBe("23514");
    expect(await insert(1)).toBeUndefined();
    expect(await insert(1)).toBe("23514");
    expect(await insert(3)).toBe("23514");
    expect(await insert(2)).toBeUndefined();
    expect(await insert(201)).toBe("23514");
    expect(await finding("/a")).toBeUndefined();
    // A row that never left is settled as such, and does not count as sent.
    expect(await scope(orgA, (q) => settleCampaignRequest(q, campaign.id, { ...row(2), outcome: "not_sent" }))).toBe(
      true,
    );
    expect(await scope(orgA, (q) => findCampaign(q, campaign.id))).toMatchObject({ requests_sent: 1 });

    await end(orgA, campaign.id);
    // Ended: nothing is added, and nothing is rewritten — by the request role or by the owner.
    expect(await insert(3)).toBe("23514");
    expect(await insert(3, "refused")).toBe("23514");
    expect(await finding("/later")).toBe("23514");
    expect(await finding("/a")).toBe("23514");
    for (const sql of [
      "UPDATE campaign_findings SET evidence = '{}'::jsonb, state = 'confirmed' WHERE campaign_id = $1",
      "UPDATE campaign_requests SET outcome = 'sending' WHERE campaign_id = $1 AND seq = 2",
      "UPDATE campaign_requests SET outcome = 'sent', status = 500 WHERE campaign_id = $1 AND seq = 2",
    ]) {
      expect(await sqlState(scope(orgA, (q) => q.query(sql, [campaign.id])))).toBe("23514");
      expect(await sqlState(api.db.owner((q) => q.query(sql, [campaign.id])))).toBe("23514");
    }
    for (const sql of [
      "UPDATE campaign_requests SET target = '/x' WHERE campaign_id = $1",
      "DELETE FROM campaign_requests WHERE campaign_id = $1",
      "DELETE FROM campaign_findings WHERE campaign_id = $1",
    ]) {
      expect(await sqlState(scope(orgA, (q) => q.query(sql, [campaign.id])))).toBe("42501");
    }
    // The one thing still allowed after the end: settling the row of a request that was in flight.
    expect(
      await scope(orgA, (q) => settleCampaignRequest(q, campaign.id, { ...row(1), outcome: "sent", status: 200 })),
    ).toBe(true);
    expect(await scope(orgA, (q) => findCampaign(q, campaign.id))).toMatchObject({
      requests_sent: 1,
      requests_refused: 0,
    });
    expect(await scope(orgA, (q) => listCampaignFindings(q, campaign.id))).toMatchObject([
      { path: "/a", state: "unverified" },
    ]);
  });

  it("review2: the queue is read in pages, oldest first", async () => {
    const first = await create(orgA, new Date(AT.getTime() - 2000));
    const second = await create(orgB, new Date(AT.getTime() - 1000));
    const ids = async (limit: number, offset: number) =>
      (await api.db.tx("none", (q) => campaignQueue(q, limit, offset))).map((entry) => entry.campaignId);
    expect(await ids(10, 0)).toEqual([first.id, second.id]);
    expect(await ids(1, 0)).toEqual([first.id]);
    expect(await ids(1, 1)).toEqual([second.id]);
    expect(await ids(1, 2)).toEqual([]);
    await end(orgA, first.id);
    await end(orgB, second.id);
  });

  it("a running Campaign never goes back to queued", async () => {
    const campaign = await create(orgA);
    await scope(orgA, (q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"));
    expect(
      await sqlState(
        scope(orgA, (q) =>
          q.query("UPDATE campaigns SET status = 'queued', started_at = NULL WHERE id = $1", [campaign.id]),
        ),
      ),
    ).toBe("23514");
    await end(orgA, campaign.id);
  });

  it("restart: running becomes interrupted and stays so; queued stays queued", async () => {
    const running = await create(orgA);
    await scope(orgA, (q) => claimCampaign(q, running.id, AT, "203.0.113.10"));
    const queued = await create(orgB);
    const interrupted = await api.db.tx("none", (q) => interruptRunningCampaigns(q, new Date(AT.getTime() + 1000)));
    expect(interrupted).toEqual([{ organizationId: orgA, campaignId: running.id }]);
    expect(await scope(orgA, (q) => findCampaign(q, running.id))).toMatchObject({
      status: "interrupted",
      end_reason: "api_restart",
    });
    expect(await scope(orgB, (q) => findCampaign(q, queued.id))).toMatchObject({ status: "queued" });
    expect(await api.db.tx("none", (q) => interruptRunningCampaigns(q, AT))).toEqual([]);
    expect(await scope(orgA, (q) => claimCampaign(q, running.id, AT, "203.0.113.10"))).toBe(false);
    const queue = await api.db.tx("none", (q) => campaignQueue(q, 100));
    expect(queue).toEqual([
      {
        organizationId: orgB,
        campaignId: queued.id,
        host: "shop.acme-shop.io",
        status: "queued",
        deletionPending: false,
      },
    ]);
    await end(orgB, queued.id);
  });

  it("the gate's control read: the switch, the suspension, a stop request", async () => {
    const campaign = await create(orgA);
    await scope(orgA, (q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"));
    const control = () => scope(orgA, (q) => campaignControl(q, campaign.id));
    const clear = { killed: false, suspended: false, stopRequested: false, deletionPending: false };
    expect(await control()).toEqual(clear);

    await api.db.tx("none", (q) => setKillSwitch(q, true, AT, "Incident 42"));
    expect(await control()).toEqual({ ...clear, killed: true });
    expect(await api.db.tx("none", (q) => operatorState(q))).toEqual({
      killed: true,
      killed_at: AT.toISOString(),
      suspended: [],
    });
    await api.db.tx("none", (q) => setKillSwitch(q, false, AT, "Over"));

    expect(await api.db.tx("none", (q) => setSuspension(q, orgA, true, AT, "Abuse report"))).toBe(true);
    expect(await api.db.tx("none", (q) => setSuspension(q, orgA, true, AT, "Again"))).toBe(false);
    expect(await api.db.tx("none", (q) => setSuspension(q, "org_ffffffffffffffffffffffff", true, AT, "x"))).toBe(false);
    expect(await control()).toEqual({ ...clear, suspended: true });
    // Another Organization is not suspended by it.
    const other = await create(orgB);
    await scope(orgB, (q) => claimCampaign(q, other.id, AT, "203.0.113.10"));
    expect(await scope(orgB, (q) => campaignControl(q, other.id))).toEqual(clear);
    expect((await api.db.tx("none", (q) => operatorState(q))).suspended).toEqual([
      { organization_id: orgA, suspended_at: AT.toISOString() },
    ]);
    expect(await api.db.tx("none", (q) => setSuspension(q, orgA, false, AT, "Cleared"))).toBe(true);

    expect(await scope(orgA, (q) => requestStop(q, campaign.id, { keyId: KEY, reason: "Wrong target", at: AT }))).toBe(
      true,
    );
    expect(await control()).toEqual({ ...clear, stopRequested: true });
    expect(await scope(orgA, (q) => findCampaign(q, campaign.id))).toMatchObject({
      stop: { requested_at: AT.toISOString(), requested_by: KEY, reason: "Wrong target" },
    });
    // A Campaign that is not this Organization's, or not running, counts as stopped; no tenant, as everything.
    expect(await scope(orgB, (q) => campaignControl(q, campaign.id))).toMatchObject({ stopRequested: true });
    expect(await api.db.tx("none", (q) => campaignControl(q, campaign.id))).toEqual({
      killed: true,
      suspended: true,
      stopRequested: true,
      deletionPending: true,
    });
    await end(orgA, campaign.id);
    expect(await control()).toMatchObject({ stopRequested: true });
    await end(orgB, other.id);
  });

  it("the request role cannot read or write the operator's tables directly", async () => {
    for (const sql of [
      "SELECT * FROM prove_switch",
      "UPDATE prove_switch SET killed = false",
      "SELECT * FROM prove_suspensions",
      "DELETE FROM prove_suspensions",
      "SELECT * FROM campaigns_retention_sweep(now(), 10)",
    ]) {
      expect({ sql, state: await sqlState(scope(orgA, (q) => q.query(sql))) }).toEqual({ sql, state: "42501" });
    }
  });

  it("a Finding is unverified until the same check and path is reported again; then confirmed, once", async () => {
    const campaign = await create(orgA);
    const report = (path: string, at: Date) =>
      scope(orgA, (q) =>
        reportFinding(q, orgA, campaign.id, {
          checkId: "RW-03",
          path,
          title: "Admin data without authentication",
          severity: "high",
          evidence: { ...EVIDENCE, target: path },
          at,
        }),
      );
    const later = new Date(AT.getTime() + 2000);
    expect(await report("/api/admin/reports", AT)).toBe("unverified");
    expect(await report("/api/other", AT)).toBe("unverified");
    expect(await report("/api/admin/reports", later)).toBe("confirmed");
    expect(await report("/api/admin/reports", later)).toBe("confirmed");
    const findings = await scope(orgA, (q) => listCampaignFindings(q, campaign.id));
    expect(findings.map((f) => [f.path, f.state, f.first_seen_at, f.last_seen_at])).toEqual([
      ["/api/admin/reports", "confirmed", AT.toISOString(), later.toISOString()],
      ["/api/other", "unverified", AT.toISOString(), AT.toISOString()],
    ]);
    expect(await scope(orgB, (q) => listCampaignFindings(q, campaign.id))).toEqual([]);
    await end(orgA, campaign.id);
  });

  it("counts the Campaigns created in the last 24 hours, per Organization and per Target", async () => {
    const counted = await scope(orgA, (q) => createdInLastDay(q, "tgt_0123456789abcdef01234567", AT));
    expect(counted.organization).toBeGreaterThanOrEqual(5);
    expect(counted.target).toBe(counted.organization);
    expect(await scope(orgA, (q) => createdInLastDay(q, "tgt_ffffffffffffffffffffffff", AT))).toMatchObject({
      target: 0,
    });
    const next = new Date(AT.getTime() + 86_400_000);
    expect(await scope(orgA, (q) => createdInLastDay(q, "tgt_0123456789abcdef01234567", next))).toMatchObject({
      organization: 0,
      target: 0,
    });
  });

  it("an audit entry's actor is an admin key with its id, or the system or the operator without one", async () => {
    const insert = (kind: string, keyId: string | null) =>
      api.db.owner((q) =>
        q.query(
          `INSERT INTO audit_entries (id, organization_id, seq, at, actor_kind, actor_key_id, action, target_kind,
             target_id, summary, request_id, prev_hash, hash)
           VALUES ($1, $2, 999, now(), $3, $4, 'campaign.start', 'campaign', 'x', 's', gen_random_uuid(), $5, $5)`,
          [newId("aud"), orgA, kind, keyId, "0".repeat(64)],
        ),
      );
    // 23514: the actor's own constraints refuse these (the chain trigger would refuse later, with another state).
    expect(await sqlState(insert("admin_key", null))).toBe("23514");
    expect(await sqlState(insert("system", KEY))).toBe("23514");
    expect(await sqlState(insert("operator", KEY))).toBe("23514");
    expect(await sqlState(insert("robot", null))).toBe("23514");
  });

  it("retention removes Campaigns 395 days after they ended, with their log and Findings", async () => {
    const old = await create(orgB, new Date(AT.getTime() - 400 * 86_400_000));
    await scope(orgB, (q) => claimCampaign(q, old.id, new Date(AT.getTime() - 400 * 86_400_000), "203.0.113.10"));
    await scope(orgB, (q) =>
      insertCampaignRequest(
        q,
        orgB,
        old.id,
        {
          seq: 1,
          method: "GET",
          target: "/",
          asked: null,
          outcome: "sent",
          reason: null,
          status: 200,
          failure: null,
          bytes: 10,
          ms: 5,
        },
        AT,
      ),
    );
    await scope(orgB, (q) =>
      reportFinding(q, orgB, old.id, {
        checkId: "RW-01",
        path: "/",
        title: "t",
        severity: "low",
        evidence: EVIDENCE,
        at: AT,
      }),
    );
    await end(orgB, old.id, new Date(AT.getTime() - 396 * 86_400_000));
    const recent = await create(orgB, new Date(AT.getTime() - 394 * 86_400_000));
    await end(orgB, recent.id, new Date(AT.getTime() - 394 * 86_400_000));

    expect(await api.db.owner((q) => sweepCampaigns(q, AT, 100))).toEqual({ [orgB]: 1 });
    expect(await scope(orgB, (q) => findCampaign(q, old.id))).toBeNull();
    expect(await scope(orgB, (q) => findCampaign(q, recent.id))).not.toBeNull();
    const left = await api.db.owner((q) =>
      q.query<{ n: number }>(
        `SELECT (SELECT count(*) FROM campaign_requests WHERE campaign_id = $1)::int
              + (SELECT count(*) FROM campaign_findings WHERE campaign_id = $1)::int AS n`,
        [old.id],
      ),
    );
    expect(left.rows[0]?.n).toBe(0);
    expect(await api.db.owner((q) => sweepCampaigns(q, AT, 100))).toEqual({});
  });
});
