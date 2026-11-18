import {
  CampaignResponseSchema,
  campaignAuthorisationPhrase,
  confirmationPhrase,
  ProveOperatorStateSchema,
  TargetResponseSchema,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CampaignRunner, type CampaignService, createCampaignRunner } from "../src/campaign/runner.ts";
import { openDb } from "../src/db/db.ts";
import { createAuthorize } from "../src/prove/authorize.ts";
import type { Fetcher, Resolver } from "../src/prove/verify.ts";
import { auditEntriesAfter } from "../src/stores/audit.ts";
import { bearer, createOrganization, json, makeTestApi, type TestApi, withReason } from "./helpers.ts";

// Slice 15a, fifth independent safety review, over the routes: a suspension whose stop failed and is asked for again
// (1), two kills at once (3), and a deletion request, its cancel, and the next Campaign (6, D-112).

const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const HOST = "shop.acme-shop.io";
const OPS = "ops-token-for-campaign-review5-tests-01";
const now = () => new Date(T0);
const silent = { info() {}, warn() {} };

describe("review5 15a: the routes", () => {
  let api: TestApi;
  let runner: CampaignRunner;
  const txt = new Map<string, string[][]>();
  /** TXT for verification; addresses never resolve, so a launched Campaign stays in its start checks. */
  const resolver: Resolver = {
    async txt(name) {
      const records = txt.get(name);
      if (records === undefined) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      return records;
    },
    addresses: () => new Promise<string[]>(() => {}),
  };
  const fetcher: Fetcher = async () => ({ ok: false, reason: "status" });
  /** What the routes are given: the real runner, with its operator stop replaceable by a test. */
  const stops = { fail: 0, calls: 0, answer: null as number | null };
  let service: CampaignService;

  beforeAll(async () => {
    const db = await openDb();
    runner = createCampaignRunner({
      db,
      enabled: true,
      resolver,
      authorize: createAuthorize({ db, now }),
      now,
      logger: silent,
      engine: async () => {},
    });
    service = {
      enabled: true,
      wake: () => runner.wake(),
      abort: (id, reason) => runner.abort(id, reason),
      isActive: (id) => runner.isActive(id),
      cut: (organizationId, reason) => runner.cut(organizationId, reason),
      activeCount: () => runner.activeCount(),
      async operatorStop(input) {
        stops.calls++;
        if (stops.fail > 0) {
          stops.fail--;
          throw new Error("the stop failed");
        }
        return stops.answer ?? runner.operatorStop(input);
      },
    };
    api = await makeTestApi({ db, now, prove: { resolver, fetcher }, campaigns: service, opsToken: OPS });
    await runner.start();
  });
  afterAll(async () => {
    await runner.stop();
    await api.close();
  });

  async function organization(name: string) {
    const created = await createOrganization(api, name);
    const admin = created.admin_key.key;
    const added = TargetResponseSchema.parse(
      await (await api.app.request("/v1/targets", json({ host: HOST }, bearer(admin)))).json(),
    );
    txt.set(added.verification.dns_name, [[added.verification.dns_value]]);
    await api.app.request(`/v1/targets/${added.target.id}/verify`, { method: "POST", headers: bearer(admin) });
    const signed = await api.app.request(
      "/v1/rules-of-engagement",
      json(
        {
          scope: [added.target.id],
          exclusions: [],
          intensity: "safe-active",
          window: { days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], from: "00:00", to: "24:00" },
          contacts: ["security@acme.test"],
          confirm: confirmationPhrase("safe-active"),
        },
        { ...bearer(admin), ...withReason() },
      ),
    );
    expect(signed.status).toBe(201);
    const launch = () =>
      api.app.request(
        "/v1/campaigns",
        json(
          {
            target_id: added.target.id,
            intensity: "passive",
            confirm: campaignAuthorisationPhrase(HOST),
            staging: true,
          },
          { ...bearer(admin), ...withReason() },
        ),
      );
    const read = async (id: string) =>
      CampaignResponseSchema.parse(
        await (await api.app.request(`/v1/campaigns/${id}`, { headers: bearer(admin) })).json(),
      ).campaign;
    const entries = async (id: string) =>
      (await api.db.tx({ organizationId: created.organization.id }, (q) => auditEntriesAfter(q, 0, 1000))).filter(
        (entry) => entry.target.id === id,
      );
    return { id: created.organization.id, name, admin, launch, read, entries };
  }
  const ops = (path: string) => api.app.request(path, json({ reason: "review5" }, bearer(OPS)));
  const launched = async (org: Awaited<ReturnType<typeof organization>>) => {
    const res = await org.launch();
    expect(res.status, await res.clone().text()).toBe(202);
    return CampaignResponseSchema.parse(await res.json()).campaign;
  };

  it("1: a suspension whose stop failed, asked for again — the stop is run again, though the suspension is already on", async () => {
    const org = await organization("Suspended");
    const campaign = await launched(org);
    stops.fail = 1;
    stops.calls = 0;
    const first = await ops(`/v1/ops/prove/organizations/${org.id}/suspend`);
    expect(first.status).toBe(500);
    // Asked again: nothing changes in the suspension, and the stop still has its work to do.
    const second = await ops(`/v1/ops/prove/organizations/${org.id}/suspend`);
    expect(second.status).toBe(200);
    expect(stops.calls).toBe(2);
    expect(ProveOperatorStateSchema.parse(await second.json())).toMatchObject({ stopped: 1 });
    expect(await org.read(campaign.id)).toMatchObject({ status: "stopped", end_reason: "organization_suspended" });
    expect((await org.entries(campaign.id)).filter((entry) => entry.action === "campaign.operator_kill")).toHaveLength(
      1,
    );
    // The suspension itself was entered once.
    const all = await api.db.tx({ organizationId: org.id }, (q) => auditEntriesAfter(q, 0, 1000));
    expect(all.filter((entry) => entry.action === "campaign.operator_suspend")).toHaveLength(1);
    // A third time: nothing left to do.
    const third = await ops(`/v1/ops/prove/organizations/${org.id}/suspend`);
    expect(ProveOperatorStateSchema.parse(await third.json())).toMatchObject({ stopped: 0 });
    // Resuming an Organization that is not suspended, or suspending an unknown one, is still not found.
    expect((await ops("/v1/ops/prove/organizations/org_ffffffffffffffffffffffff/suspend")).status).toBe(404);
  });

  it("3: two kills at once over the route — one entry for the Campaign, counted once", async () => {
    const org = await organization("Killed twice");
    const campaign = await launched(org);
    try {
      const answers = await Promise.all([ops("/v1/ops/prove/kill"), ops("/v1/ops/prove/kill")]);
      expect(answers.map((res) => res.status)).toEqual([200, 200]);
      const counts = [];
      for (const res of answers) counts.push(ProveOperatorStateSchema.parse(await res.json()).stopped);
      expect(counts.sort()).toEqual([0, 1]);
    } finally {
      await ops("/v1/ops/prove/enable");
    }
    expect(await org.read(campaign.id)).toMatchObject({ status: "stopped", end_reason: "operator_kill" });
    expect((await org.entries(campaign.id)).filter((entry) => entry.action === "campaign.operator_kill")).toHaveLength(
      1,
    );
  });

  it("6 (D-112): a deletion request ends the queued Campaign; after a cancel the Organization launches a new one", async () => {
    const org = await organization("Leaving and staying");
    const campaign = await launched(org);
    // Taken by the runner: in its start checks (its name never resolves), still queued in the database.
    for (let i = 0; i < 200 && !runner.isActive(campaign.id); i++)
      await new Promise((resolve) => setTimeout(resolve, 5));
    expect(runner.isActive(campaign.id)).toBe(true);
    const requested = await api.app.request(
      "/v1/organization/deletion",
      json({ confirm_name: org.name }, { ...bearer(org.admin), ...withReason() }),
    );
    expect(requested.status).toBe(201);
    const cancelled = await api.app.request("/v1/organization/deletion", {
      method: "DELETE",
      headers: { ...bearer(org.admin), ...withReason() },
    });
    expect(cancelled.status, await cancelled.clone().text()).toBe(200);
    // Not left queued: ended, with its entry — and not blocking the next one.
    expect(await org.read(campaign.id)).toMatchObject({
      status: "stopped",
      end_reason: "deletion_pending",
      requests_sent: 0,
    });
    expect((await org.entries(campaign.id)).at(-1)).toMatchObject({ action: "campaign.refuse" });
    const next = await launched(org);
    expect(next.id).not.toBe(campaign.id);
    expect((await org.read(next.id)).status).toBe("queued");
    await runner.abort(next.id, "api_shutdown");
  });
});
