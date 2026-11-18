import { cpSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { STAND_IN_ENGINE } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit, operatorActor } from "../src/audit.ts";
import type { GateRecord } from "../src/campaign/gate.ts";
import type { Queryable } from "../src/db/db.ts";
import { migrate } from "../src/db/migrate.ts";
import {
  campaignsWithoutOperatorEntry,
  claimCampaign,
  endCampaign,
  insertCampaign,
  insertCampaignRequest,
  listCampaignRequests,
} from "../src/stores/campaigns.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, fifth independent safety review, migration 0041 as the request role (`ar_app`): how much a refused probe
// asked for is a bucket (D-113), a running Campaign never becomes "refused", and the read that finds Campaigns an
// operator's stop ended without the operator's entry.

const AT = new Date("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const MIGRATIONS = fileURLToPath(new URL("../migrations", import.meta.url));

describe("migration 0041: the fifth review's rules in the database", () => {
  let api: TestApi;
  let org: string;
  let other: string;

  const scope = <T>(fn: (q: Queryable) => Promise<T>, organizationId = org) => api.db.tx({ organizationId }, fn);
  const sqlState = async (work: Promise<unknown>): Promise<string | undefined> => {
    try {
      await work;
      return undefined;
    } catch (error) {
      return String((error as { code?: unknown }).code);
    }
  };
  const create = (organizationId = org) =>
    scope(
      (q) =>
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
      organizationId,
    );
  const refused = (seq: number, asked: number): GateRecord => ({
    seq,
    method: "OTHER",
    target: null,
    asked,
    outcome: "refused",
    reason: "not_in_catalog",
    status: null,
    failure: null,
    bytes: 0,
    ms: 0,
  });

  beforeAll(async () => {
    api = await makeTestApi();
    org = (await createOrganization(api, "Acme")).organization.id;
    other = (await createOrganization(api, "Globex")).organization.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("5: a refused row holds a bucket of what was asked — the store writes one, the database takes no other number", async () => {
    const campaign = await create();
    const asked = [0, 1, 97, 256, 257, 1024, 1025, 600_000];
    for (const [index, chars] of asked.entries()) {
      await scope((q) => insertCampaignRequest(q, org, campaign.id, refused(index + 1, chars), AT));
    }
    expect((await scope((q) => listCampaignRequests(q, campaign.id))).map((row) => row.asked_chars)).toEqual([
      0, 256, 256, 256, 1024, 1024, 1_000_000, 1_000_000,
    ]);
    // The review's channel: a count of the engine's choosing, written past the store.
    for (const chars of [1, 97, 255, 1023, 65_536, 999_999]) {
      expect(
        await sqlState(
          scope((q) =>
            q.query(
              `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, outcome, reason, asked_chars)
               VALUES ($1, $2, 9, now(), 'OTHER', 'refused', 'not_in_catalog', $3)`,
              [org, campaign.id, chars],
            ),
          ),
        ),
        String(chars),
      ).toBe("23514");
    }
    await scope((q) => endCampaign(q, campaign.id, { reason: "owner_stop", started: false, checks: null, at: AT }));
  });

  it("a running Campaign never becomes `refused`: that is said of one that did not start", async () => {
    const campaign = await create();
    await scope((q) => claimCampaign(q, campaign.id, AT, "203.0.113.10"));
    expect(
      await sqlState(
        scope((q) =>
          q.query(
            "UPDATE campaigns SET status = 'refused', end_reason = 'target_not_verified', finished_at = now() WHERE id = $1",
            [campaign.id],
          ),
        ),
      ),
    ).toBe("23514");
    expect(
      await sqlState(
        api.db.owner((q) =>
          q.query("UPDATE campaigns SET status = 'refused', end_reason = 'x', finished_at = now() WHERE id = $1", [
            campaign.id,
          ]),
        ),
      ),
    ).toBe("23514");
    // It still ends as failed, stopped or interrupted.
    expect(
      await scope((q) =>
        endCampaign(q, campaign.id, { reason: "target_not_verified", started: true, checks: null, at: AT }),
      ),
    ).toBe(true);
  });

  it("1: finds the Campaigns a stop ended that have no operator entry — and only those", async () => {
    const earlier = await create();
    await scope((q) => endCampaign(q, earlier.id, { reason: "owner_stop", started: false, checks: null, at: AT }));
    const mine = await create();
    const theirs = await create(other);
    // `earlier` ended for a reason of its own; the other two by the operator's kill, one of them with its entry.
    await scope((q) => endCampaign(q, mine.id, { reason: "operator_kill", started: false, checks: null, at: AT }));
    await scope(
      (q) => endCampaign(q, theirs.id, { reason: "operator_kill", started: false, checks: null, at: AT }),
      other,
    );
    await scope((q) =>
      audit(q, operatorActor(org, "0b0e7a8e-6d2f-4c57-9f0c-2a1b3c4d5e6f", "drill"), {
        action: "campaign.operator_kill",
        target: { kind: "campaign", id: mine.id },
        summary: "The operator stopped all Campaigns: this Organization's Campaign was ended.",
        at: AT,
      }),
    );
    const since = new Date(AT.getTime() - 3_600_000);
    const missing = (reason: "operator_kill" | "organization_suspended", organizationId?: string) =>
      api.db.tx("none", (q) => campaignsWithoutOperatorEntry(q, { reason, organizationId, since }));
    expect(await missing("operator_kill")).toEqual([{ organizationId: other, campaignId: theirs.id }]);
    expect(await missing("operator_kill", org)).toEqual([]);
    expect(await missing("operator_kill", other)).toEqual([{ organizationId: other, campaignId: theirs.id }]);
    expect(await missing("organization_suspended")).toEqual([]);
    // Not one that ended before `since`.
    expect(
      await api.db.tx("none", (q) =>
        campaignsWithoutOperatorEntry(q, { reason: "operator_kill", since: new Date(AT.getTime() + 1000) }),
      ),
    ).toEqual([]);
  });
});

describe("migration 0041 on a database that held refused rows before it", () => {
  it("turns the counts of 0040 into buckets", async () => {
    const before = mkdtempSync(join(tmpdir(), "ar-migrations-"));
    const pg = await PGlite.create();
    try {
      for (const file of readdirSync(MIGRATIONS)) if (file < "0041") cpSync(join(MIGRATIONS, file), join(before, file));
      await migrate(pg, before);
      const campaign = "cmp_0123456789abcdef01234567";
      await pg.query("INSERT INTO organizations (id, name) VALUES ('org_0123456789abcdef01234567', 'Acme')");
      await pg.query(
        `INSERT INTO campaigns (organization_id, id, target_id, host, roe_id, roe_sha256, intensity, engine, status,
           staging_declared, created_by, created_at)
         VALUES ('org_0123456789abcdef01234567', $1, 'tgt_0123456789abcdef01234567', 'shop.acme-shop.io',
           'roe_0123456789abcdef01234567', $2, 'passive', '{}', 'queued', true, $3, now())`,
        [campaign, "b".repeat(64), KEY],
      );
      const counts = [0, 1, 99, 256, 257, 1024, 1025, 1_000_000];
      for (const [index, chars] of counts.entries()) {
        await pg.query(
          `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, outcome, reason, asked_chars)
           VALUES ('org_0123456789abcdef01234567', $1, $2, now(), 'OTHER', 'refused', 'not_in_catalog', $3)`,
          [campaign, index + 1, chars],
        );
      }
      await pg.query(
        `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome)
         VALUES ('org_0123456789abcdef01234567', $1, 9, now(), 'GET', '/', 'sending')`,
        [campaign],
      );
      await pg.query(
        "UPDATE campaigns SET status = 'stopped', end_reason = 'owner_stop', finished_at = now() WHERE id = $1",
        [campaign],
      );
      expect(await migrate(pg, MIGRATIONS)).toEqual(readdirSync(MIGRATIONS).filter((file) => file >= "0041"));
      const rows = await pg.query<{ asked_chars: number | null }>(
        "SELECT asked_chars FROM campaign_requests ORDER BY seq",
      );
      expect(rows.rows.map((row) => row.asked_chars)).toEqual([
        0,
        256,
        256,
        256,
        1024,
        1024,
        1_000_000,
        1_000_000,
        null,
      ]);
    } finally {
      await pg.close();
      rmSync(before, { recursive: true, force: true });
    }
  }, 60_000);
});
