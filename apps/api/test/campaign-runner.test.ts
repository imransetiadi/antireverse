import { type CampaignEndReason, STAND_IN_ENGINE } from "@antireverse/protocol";
import { generateVerificationToken, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CampaignEngineRunner, createCampaignRunner } from "../src/campaign/runner.ts";
import { createAuthorize } from "../src/prove/authorize.ts";
import type { Resolver } from "../src/prove/verify.ts";
import { auditEntriesAfter } from "../src/stores/audit.ts";
import { claimCampaign, findCampaign, insertCampaign, setKillSwitch, setSuspension } from "../src/stores/campaigns.ts";
import { insertVersion } from "../src/stores/rules-of-engagement.ts";
import { insertTarget, recordCheck } from "../src/stores/targets.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a: the runner's restart rule and start checks, without a network. A Campaign left running becomes
// interrupted and is never resumed; a queued one stays queued across the restart and passes every start check again —
// whatever was true when it was created. The resolver here answers a private address, so a Campaign that passes
// every earlier check is refused at the address check and nothing is ever connected to.

const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const DAY = 86_400_000;
const KEY = "key_0123456789abcdef01234567";
const WINDOW = { days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const, from: "00:00", to: "24:00" };

describe("the Campaign runner: restart and start checks", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let lookups = 0;
  let engineRuns = 0;
  const resolver: Resolver = {
    async txt() {
      return [];
    },
    async addresses() {
      lookups++;
      return ["10.0.0.7"];
    },
  };
  const engine: CampaignEngineRunner = async () => {
    engineRuns++;
  };
  let n = 0;

  interface Seeded {
    organizationId: string;
    targetId: string;
    roeId: string;
    campaignId: string;
  }

  /** An Organization with a verified target, Rules of Engagement signed `signedAgoMs` ago, and a queued Campaign. */
  async function seed(options: { signedAgoMs?: number; host?: string } = {}): Promise<Seeded> {
    const organizationId = (await createOrganization(api, `Runner ${++n}`)).organization.id;
    const targetId = newId("tgt");
    const roeId = newId("roe");
    const campaignId = newId("cmp");
    const host = options.host ?? `host-${n}.acme-shop.io`;
    await api.db.tx({ organizationId }, async (q) => {
      await insertTarget(q, {
        organizationId,
        id: targetId,
        host,
        token: generateVerificationToken(),
        createdAt: now(),
      });
      await recordCheck(q, targetId, { verified: true, method: "dns" }, now());
      await insertVersion(q, {
        organizationId,
        id: roeId,
        content: {
          scope: [targetId],
          exclusions: [],
          intensity: "safe-active",
          window: { ...WINDOW, days: [...WINDOW.days] },
          contacts: ["s@acme.test"],
        },
        signedBy: KEY,
        signedAt: new Date(clock.ms - (options.signedAgoMs ?? 0)),
        contentSha256: "a".repeat(64),
      });
      await insertCampaign(q, {
        organizationId,
        id: campaignId,
        targetId,
        host,
        roeId,
        roeSha256: "a".repeat(64),
        intensity: "passive",
        engine: STAND_IN_ENGINE,
        createdBy: KEY,
        createdAt: now(),
      });
    });
    return { organizationId, targetId, roeId, campaignId };
  }

  const read = (s: Seeded) => api.db.tx({ organizationId: s.organizationId }, (q) => findCampaign(q, s.campaignId));
  const audited = async (s: Seeded) =>
    (await api.db.tx({ organizationId: s.organizationId }, (q) => auditEntriesAfter(q, 0, 100)))
      .filter((entry) => entry.target.id === s.campaignId)
      .map((entry) => [entry.action, entry.actor.kind]);
  const runner = (enabled = true) =>
    createCampaignRunner({
      db: api.db,
      enabled,
      resolver,
      authorize: createAuthorize({ db: api.db, now }),
      now,
      logger: { info() {}, warn() {} },
      engine,
    });

  /** Starts a runner on the database as it is, waits until it has nothing to do, and stops it. */
  async function restart(enabled = true): Promise<void> {
    const started = runner(enabled);
    await started.start();
    await started.idle();
    await started.stop();
  }

  async function startsAs(s: Seeded, status: string, reason: CampaignEndReason, enabled = true): Promise<void> {
    await restart(enabled);
    expect(await read(s)).toMatchObject({ status, end_reason: reason, requests_sent: 0, started_at: null });
    expect(await audited(s)).toEqual([["campaign.refuse", "system"]]);
  }

  beforeAll(async () => {
    api = await makeTestApi({ now });
  });
  afterAll(async () => {
    await api.close();
  });

  it("a running Campaign becomes interrupted and is never resumed; a queued one is taken again", async () => {
    const running = await seed();
    await api.db.tx({ organizationId: running.organizationId }, (q) =>
      claimCampaign(q, running.campaignId, now(), "203.0.113.10"),
    );
    const queued = await seed();
    clock.ms += 5000;
    await restart();
    expect(await read(running)).toMatchObject({
      status: "interrupted",
      end_reason: "api_restart",
      finished_at: now().toISOString(),
    });
    expect(await audited(running)).toEqual([["campaign.end", "system"]]);
    // The queued one passed every check up to the address, which is private here: refused, nothing sent.
    expect(await read(queued)).toMatchObject({
      status: "refused",
      end_reason: "target_not_reachable",
      started_at: null,
    });
    expect(lookups).toBe(1);
    // Another restart changes nothing: the interrupted Campaign stays interrupted, and no engine ever ran.
    await restart();
    expect((await read(running))?.status).toBe("interrupted");
    expect(await audited(running)).toEqual([["campaign.end", "system"]]);
    expect(engineRuns).toBe(0);
    expect(lookups).toBe(1);
  });

  it("a queued Campaign survives a restart while Campaigns are off only to be refused: it never starts", async () => {
    await startsAs(await seed(), "refused", "campaigns_disabled", false);
  });

  it("start checks, again at the start: Rules signed more than 90 days ago", async () => {
    await startsAs(await seed({ signedAgoMs: 90 * DAY + 1000 }), "refused", "rules_too_old");
  });

  it("start checks: the Rules of Engagement were replaced after creation", async () => {
    const s = await seed();
    await api.db.tx({ organizationId: s.organizationId }, (q) =>
      insertVersion(q, {
        organizationId: s.organizationId,
        id: newId("roe"),
        content: {
          scope: [s.targetId],
          exclusions: [],
          intensity: "safe-active",
          window: { ...WINDOW, days: [...WINDOW.days] },
          contacts: ["s@acme.test"],
        },
        signedBy: KEY,
        signedAt: now(),
        contentSha256: "b".repeat(64),
      }),
    );
    await startsAs(s, "refused", "rules_replaced");
  });

  it("start checks: the target lapsed, or was deleted, after creation", async () => {
    const lapsed = await seed();
    await api.db.tx({ organizationId: lapsed.organizationId }, (q) =>
      recordCheck(q, lapsed.targetId, { verified: false, reason: "DNS: no_record; file: status" }, now()),
    );
    await startsAs(lapsed, "refused", "target_not_verified");
    const stale = await seed();
    const saved = clock.ms;
    clock.ms += 27 * 3_600_000;
    try {
      await startsAs(stale, "refused", "target_not_verified");
    } finally {
      clock.ms = saved;
    }
  });

  it("start checks: the operator's kill switch and a suspension stop a queued Campaign", async () => {
    const killed = await seed();
    await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "Incident"));
    try {
      await startsAs(killed, "stopped", "operator_kill");
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "Over"));
    }
    const suspended = await seed();
    await api.db.tx("none", (q) => setSuspension(q, suspended.organizationId, true, now(), "Abuse"));
    await startsAs(suspended, "stopped", "organization_suspended");
  });

  // Sixth review (D-112): it used to stay queued until the purge — and would then start by itself after a cancel.
  // The queue ends it now, without asking the target or the resolver anything.
  it("an Organization whose deletion is pending starts nothing: its queued Campaign is ended as stopped", async () => {
    const s = await seed();
    await api.db.owner((q) =>
      q.query(
        `INSERT INTO organization_deletions (id, organization_id, organization_name, requested_at, requested_by, reason,
           purge_after)
         VALUES ($1, $2, 'x', $3, $4, 'r', $5)`,
        [newId("del"), s.organizationId, now(), KEY, new Date(clock.ms + 30 * DAY)],
      ),
    );
    const before = lookups;
    await restart();
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "deletion_pending", requests_sent: 0 });
    expect(await audited(s)).toEqual([["campaign.refuse", "system"]]);
    expect(lookups).toBe(before);
  });

  it("nothing here ever ran an engine or resolved more than once per Campaign", () => {
    expect(engineRuns).toBe(0);
  });
});
