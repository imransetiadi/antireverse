import { STAND_IN_ENGINE } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Queryable } from "../src/db/db.ts";
import {
  campaignsWithoutOperatorEntry,
  claimCampaign,
  endCampaign,
  insertCampaign,
  setKillSwitch,
  setSuspension,
} from "../src/stores/campaigns.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, sixth independent safety review, migration 0042 as the request role (`ar_app`). F6: a stop completes the
// operator's entry only for Campaigns that ended under THAT stop — since the switch was last turned on, or since the
// Organization was suspended. I2: a Campaign's status and its end reason say the same thing.

const T = Date.parse("2026-11-16T10:00:00.000Z");
const HOUR = 3_600_000;
const KEY = "key_0123456789abcdef01234567";

describe("migration 0042: the sixth review's rules in the database", () => {
  let api: TestApi;
  let orgs: string[];

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
        createdAt: new Date(T - 48 * HOUR),
      }),
    );
  /** A Campaign of `organizationId` that ended at `at` with `reason`, without any operator entry. */
  const ended = async (organizationId: string, reason: "operator_kill" | "organization_suspended", at: number) => {
    const campaign = await create(organizationId);
    await scope(organizationId, (q) =>
      endCampaign(q, campaign.id, { reason, started: false, checks: null, at: new Date(at) }),
    );
    return campaign.id;
  };
  const missing = (reason: "operator_kill" | "organization_suspended", organizationId?: string) =>
    api.db.tx("none", (q) => campaignsWithoutOperatorEntry(q, { reason, organizationId }));

  beforeAll(async () => {
    api = await makeTestApi();
    orgs = [];
    for (const name of ["A", "B", "C"]) orgs.push((await createOrganization(api, name)).organization.id);
  });
  afterAll(async () => {
    await api.close();
  });

  it("F6: a kill completes entries only for Campaigns that ended since the switch was turned on", async () => {
    const [a, b] = orgs as [string, string, string];
    // Yesterday's kill, long lifted: its Campaign ended 23 hours ago and never got its entry.
    const earlier = await ended(a, "operator_kill", T - 23 * HOUR);
    // No kill is on: nothing is anyone's to complete.
    expect(await missing("operator_kill")).toEqual([]);
    await api.db.tx("none", (q) => setKillSwitch(q, true, new Date(T), "today's incident"));
    const today = await ended(b, "operator_kill", T + 1000);
    const atOnce = await ended(a, "operator_kill", T);
    expect((await missing("operator_kill")).map((row) => row.campaignId).sort()).toEqual([today, atOnce].sort());
    expect((await missing("operator_kill")).map((row) => row.campaignId)).not.toContain(earlier);
    expect(await missing("operator_kill", b)).toEqual([{ organizationId: b, campaignId: today }]);
    // Lifted: nothing more is written in that kill's name.
    await api.db.tx("none", (q) => setKillSwitch(q, false, new Date(T + 2000), "over"));
    expect(await missing("operator_kill")).toEqual([]);
    // Turned on again later: the Campaigns of the kill before are not this one's.
    await api.db.tx("none", (q) => setKillSwitch(q, true, new Date(T + HOUR), "another incident"));
    expect(await missing("operator_kill")).toEqual([]);
    await api.db.tx("none", (q) => setKillSwitch(q, false, new Date(T + HOUR + 1), "over"));
  });

  it("F6: a suspension completes entries only for that Organization's Campaigns that ended since it was suspended", async () => {
    const [, , c] = orgs as [string, string, string];
    const before = await ended(c, "organization_suspended", T - 23 * HOUR);
    expect(await missing("organization_suspended", c)).toEqual([]);
    await api.db.tx("none", (q) => setSuspension(q, c, true, new Date(T), "review6"));
    const under = await ended(c, "organization_suspended", T + 5);
    expect(await missing("organization_suspended", c)).toEqual([{ organizationId: c, campaignId: under }]);
    expect(await missing("organization_suspended")).toEqual([{ organizationId: c, campaignId: under }]);
    expect(await missing("organization_suspended", orgs[0])).toEqual([]);
    void before;
    await api.db.tx("none", (q) => setSuspension(q, c, false, new Date(T + 10), "over"));
    expect(await missing("organization_suspended", c)).toEqual([]);
  });

  it("I2: a status and an end reason that contradict each other are refused", async () => {
    const [a] = orgs as [string, string, string];
    const update = async (set: string, running: boolean) => {
      const campaign = await create(a);
      if (running) await scope(a, (q) => claimCampaign(q, campaign.id, new Date(T), "203.0.113.10"));
      const state = await sqlState(
        scope(a, (q) => q.query(`UPDATE campaigns SET ${set}, finished_at = now() WHERE id = $1`, [campaign.id])),
      );
      if (state !== undefined) {
        await scope(a, (q) =>
          endCampaign(q, campaign.id, { reason: "owner_stop", started: running, checks: null, at: new Date(T) }),
        );
      }
      return state;
    };
    const contradictions: [string, boolean][] = [
      // The review's: a "stopped" Campaign whose reason says it ran all its checks.
      ["status = 'stopped', end_reason = 'checks_complete'", true],
      ["status = 'stopped', end_reason = 'engine_error'", true],
      ["status = 'stopped', end_reason = 'x'", false],
      ["status = 'failed', end_reason = 'owner_stop'", true],
      ["status = 'failed', end_reason = 'checks_complete'", true],
      ["status = 'failed', end_reason = 'api_shutdown'", true],
      ["status = 'refused', end_reason = 'operator_kill'", false],
      ["status = 'refused', end_reason = 'engine_error'", false],
      ["status = 'interrupted', end_reason = 'engine_error'", true],
      ["status = 'interrupted', end_reason = 'owner_stop'", true],
    ];
    const refused: (string | undefined)[] = [];
    for (const [set, running] of contradictions) refused.push(await update(set, running));
    expect(refused).toEqual(contradictions.map(() => "23514"));
    const agreeing: [string, boolean][] = [
      ["status = 'stopped', end_reason = 'owner_stop'", true],
      ["status = 'stopped', end_reason = 'deletion_pending'", false],
      ["status = 'stopped', end_reason = 'operator_kill'", false],
      ["status = 'stopped', end_reason = 'organization_suspended'", true],
      ["status = 'failed', end_reason = 'engine_error'", false],
      ["status = 'failed', end_reason = 'byte_budget'", true],
      ["status = 'refused', end_reason = 'target_not_verified'", false],
      ["status = 'interrupted', end_reason = 'api_shutdown'", true],
    ];
    const accepted: (string | undefined)[] = [];
    for (const [set, running] of agreeing) accepted.push(await update(set, running));
    expect(accepted).toEqual(agreeing.map(() => undefined));
  });
});
