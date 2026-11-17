import { CAMPAIGN_LIMITS, STAND_IN_ENGINE } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { GateRecord } from "../src/campaign/gate.ts";
import type { Queryable } from "../src/db/db.ts";
import {
  claimCampaign,
  endCampaign,
  findCampaign,
  insertCampaign,
  insertCampaignRequest,
  listCampaignRequests,
  reportFinding,
  requestStop,
  setKillSwitch,
  setSuspension,
  settleCampaignRequest,
  startControl,
} from "../src/stores/campaigns.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, third independent safety review, migration 0040: what the database itself holds to, as the request role
// (`ar_app`) — the true byte count of a request (F1), a Campaign that is always born queued and an ended Campaign's
// request log (F6, D-108), the evidence window (F5, D-107) and the claim that the operator's switch refuses (F4).

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

describe("migration 0040: the third review's rules in the database", () => {
  let api: TestApi;
  let orgA: string;

  const scope = <T>(organizationId: string, fn: (q: Queryable) => Promise<T>) => api.db.tx({ organizationId }, fn);
  const sqlState = async (work: Promise<unknown>): Promise<string | undefined> => {
    try {
      await work;
      return undefined;
    } catch (error) {
      return String((error as { code?: unknown }).code);
    }
  };
  const create = (organizationId: string) =>
    scope(organizationId, (q) =>
      insertCampaign(q, {
        organizationId,
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
  const end = (organizationId: string, id: string) =>
    scope(organizationId, (q) =>
      // Fourth review (D-108): `completed` needs a running Campaign with a sent request; these end as stopped.
      endCampaign(q, id, { reason: "owner_stop", started: true, checks: null, at: AT }),
    );
  const sending = (seq: number): GateRecord => ({
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
  });

  beforeAll(async () => {
    api = await makeTestApi();
    orgA = (await createOrganization(api, "Acme")).organization.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("F1: a request's row holds what its connection really read, however much, and the new failure", async () => {
    const campaign = await create(orgA);
    // The review's number (about 1 GB), and one beyond 32 bits.
    for (const [seq, bytes] of [
      [1, 1_050_624_947],
      [2, 5_000_000_000],
    ] as const) {
      await scope(orgA, (q) => insertCampaignRequest(q, orgA, campaign.id, sending(seq), AT));
      expect(
        await scope(orgA, (q) =>
          settleCampaignRequest(q, campaign.id, { ...sending(seq), outcome: "sent", failure: "read_limit", bytes }),
        ),
      ).toBe(true);
    }
    const log = await scope(orgA, (q) => listCampaignRequests(q, campaign.id));
    expect(log.map((row) => [row.failure, row.bytes])).toEqual([
      ["read_limit", 1_050_624_947],
      ["read_limit", 5_000_000_000],
    ]);
    expect(log.every((row) => typeof row.bytes === "number")).toBe(true);
    expect((await scope(orgA, (q) => findCampaign(q, campaign.id)))?.response_bytes).toBe(6_050_624_947);
    await end(orgA, campaign.id);
  });

  it("F6: a Campaign is born queued — a forged INSERT of any other state is refused", async () => {
    const insert = (columns: string, values: string) =>
      sqlState(
        scope(orgA, (q) =>
          q.query(
            `INSERT INTO campaigns (organization_id, id, target_id, host, roe_id, roe_sha256, intensity, engine,
               staging_declared, created_by, created_at, ${columns})
             VALUES ($1, $2, 'tgt_0123456789abcdef01234567', 'shop.acme-shop.io', 'roe_0123456789abcdef01234567',
               $3, 'passive', '{"name":"stand-in","version":"1","model":"stand-in"}', true, $4, $5, ${values})`,
            [orgA, newId("cmp"), "b".repeat(64), KEY, AT],
          ),
        ),
      );
    const forged: [string, string][] = [
      // The review's forgery: a Campaign that "completed" with six clean checks and never ran.
      [
        "status, end_reason, started_at, finished_at, checks_ran, checks_reported, checks_skipped, checks_inconclusive",
        "'completed', 'checks_complete', now(), now(), 6, 0, 0, 0",
      ],
      ["status, started_at", "'running', now()"],
      ["status, end_reason, finished_at", "'refused', 'target_not_verified', now()"],
      ["status, end_reason, finished_at", "'stopped', 'owner_stop', now()"],
      ["status, started_at, pinned_address", "'running', now(), '203.0.113.10'"],
      ["status, pinned_address", "'queued', '203.0.113.10'"],
      ["status, findings_dropped", "'queued', 1"],
      ["status, stop_requested_at, stop_requested_by, stop_reason", `'queued', now(), '${KEY}', 'x'`],
    ];
    const outcomes: (string | undefined)[] = [];
    for (const [columns, values] of forged) outcomes.push(await insert(columns, values));
    expect(outcomes).toEqual(forged.map(() => "23514"));
    // The owner of the database is held to it too.
    expect(
      await sqlState(
        api.db.owner((q) =>
          q.query(
            `INSERT INTO campaigns (organization_id, id, target_id, host, roe_id, roe_sha256, intensity, engine,
               staging_declared, created_by, created_at, status, started_at)
             VALUES ($1, $2, 'tgt_0123456789abcdef01234567', 'shop.acme-shop.io', 'roe_0123456789abcdef01234567',
               $3, 'passive', '{}', true, $4, $5, 'running', now())`,
            [orgA, newId("cmp"), "b".repeat(64), KEY, AT],
          ),
        ),
      ),
    ).toBe("23514");
    // The honest one passes.
    expect(await insert("status", "'queued'")).toBeUndefined();
    const stored = await scope(orgA, (q) =>
      q.query<{ id: string }>("SELECT id FROM campaigns WHERE status = 'queued'"),
    );
    for (const row of stored.rows) await end(orgA, row.id);
  });

  it("F6: after the end, a row in flight is settled as sent only — never as not_sent", async () => {
    const campaign = await create(orgA);
    for (const seq of [1, 2, 3, 4]) {
      await scope(orgA, (q) => insertCampaignRequest(q, orgA, campaign.id, sending(seq), AT));
    }
    // While the Campaign is queued or running, a row whose request never left is settled as such.
    expect(
      await scope(orgA, (q) => settleCampaignRequest(q, campaign.id, { ...sending(1), outcome: "not_sent" })),
    ).toBe(true);
    expect((await scope(orgA, (q) => findCampaign(q, campaign.id)))?.requests_sent).toBe(3);

    await end(orgA, campaign.id);
    const before = await scope(orgA, (q) => findCampaign(q, campaign.id));
    // The review's rewrite: a request that went out is made to look as if it never left.
    for (const run of [scope.bind(null, orgA), api.db.owner.bind(api.db)] as const) {
      expect(
        await sqlState(
          (run as (fn: (q: Queryable) => Promise<unknown>) => Promise<unknown>)((q) =>
            q.query("UPDATE campaign_requests SET outcome = 'not_sent' WHERE campaign_id = $1 AND seq = 2", [
              campaign.id,
            ]),
          ),
        ),
      ).toBe("23514");
    }
    expect(
      await sqlState(scope(orgA, (q) => settleCampaignRequest(q, campaign.id, { ...sending(3), outcome: "not_sent" }))),
    ).toBe("23514");
    expect(await scope(orgA, (q) => findCampaign(q, campaign.id))).toEqual(before);
    // The late, legitimate settle of the request that was in flight when the end came still works: as sent, with
    // what came of it (here: it was cut off).
    expect(
      await scope(orgA, (q) =>
        settleCampaignRequest(q, campaign.id, { ...sending(2), outcome: "sent", failure: "aborted", bytes: 3100 }),
      ),
    ).toBe(true);
    expect(
      await scope(orgA, (q) => settleCampaignRequest(q, campaign.id, { ...sending(3), outcome: "sent", status: 200 })),
    ).toBe(true);
    const log = await scope(orgA, (q) => listCampaignRequests(q, campaign.id));
    expect(log.map((row) => `${row.seq} ${row.outcome} ${row.status ?? row.failure ?? "-"}`)).toEqual([
      "1 not_sent -",
      "2 sent aborted",
      "3 sent 200",
      "4 sending -",
    ]);
    expect((await scope(orgA, (q) => findCampaign(q, campaign.id)))?.requests_sent).toBe(3);
  });

  it("F5: a Finding's evidence holds a window of at most 200 characters and no hash of the body", async () => {
    const campaign = await create(orgA);
    const report = (evidence: Record<string, unknown>, path: string) =>
      sqlState(
        scope(orgA, (q) =>
          reportFinding(q, orgA, campaign.id, {
            checkId: "RW-03",
            path,
            title: "t",
            severity: "high",
            evidence: evidence as never,
            at: AT,
          }),
        ),
      );
    expect(CAMPAIGN_LIMITS.evidenceWindowMax).toBe(200);
    expect(await report({ ...EVIDENCE, excerpt: "x".repeat(200) }, "/a")).toBeUndefined();
    expect(await report({ ...EVIDENCE, excerpt: "x".repeat(201) }, "/b")).toBe("23514");
    expect(await report({ ...EVIDENCE, body_sha256: "a".repeat(64) }, "/c")).toBe("23514");
    // The automatic repeat cannot widen it either.
    expect(await report({ ...EVIDENCE, excerpt: "x".repeat(2048) }, "/a")).toBe("23514");
    await end(orgA, campaign.id);
  });

  it("F4: the claim itself refuses a Campaign under the kill switch, a suspension or a stop request", async () => {
    const claim = (id: string) => scope(orgA, (q) => claimCampaign(q, id, AT, "203.0.113.10"));
    const campaign = await create(orgA);
    expect(await scope(orgA, (q) => startControl(q, campaign.id))).toEqual({
      killed: false,
      suspended: false,
      stopRequested: false,
      deletionPending: false,
    });

    await api.db.tx("none", (q) => setKillSwitch(q, true, AT, "drill"));
    expect((await scope(orgA, (q) => startControl(q, campaign.id))).killed).toBe(true);
    expect(await claim(campaign.id)).toBe(false);
    await api.db.tx("none", (q) => setKillSwitch(q, false, AT, "drill over"));

    await api.db.tx("none", (q) => setSuspension(q, orgA, true, AT, "drill"));
    expect((await scope(orgA, (q) => startControl(q, campaign.id))).suspended).toBe(true);
    expect(await claim(campaign.id)).toBe(false);
    await api.db.tx("none", (q) => setSuspension(q, orgA, false, AT, "drill over"));

    expect(await scope(orgA, (q) => requestStop(q, campaign.id, { keyId: KEY, reason: "stop", at: AT }))).toBe(true);
    expect((await scope(orgA, (q) => startControl(q, campaign.id))).stopRequested).toBe(true);
    expect(await claim(campaign.id)).toBe(false);
    expect((await scope(orgA, (q) => findCampaign(q, campaign.id)))?.status).toBe("queued");
    await end(orgA, campaign.id);

    // Nothing in the way: it is claimed.
    const free = await create(orgA);
    expect(await claim(free.id)).toBe(true);
    // An unknown or ended Campaign counts as stopped.
    expect((await scope(orgA, (q) => startControl(q, campaign.id))).stopRequested).toBe(true);
    expect((await scope(orgA, (q) => startControl(q, newId("cmp")))).stopRequested).toBe(true);
    await end(orgA, free.id);
  });
});
