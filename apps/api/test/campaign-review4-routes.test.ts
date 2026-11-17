import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CampaignService } from "../src/campaign/runner.ts";
import { openDb } from "../src/db/db.ts";
import { bearer, createOrganization, json, makeTestApi, type TestApi, withReason } from "./helpers.ts";

// Slice 15a, fourth independent safety review, from its observations: what a route does between the moment a stop is
// committed and the moment the Campaigns running in this process are aborted. Nothing may be awaited in between.

const OPS = "ops-token-for-campaign-review4-tests-01";

describe("review4 15a: the routes abort in-process Campaigns right after the commit", () => {
  let api: TestApi;
  /** What happened, in order: the runner's calls and the statements that write an audit entry. */
  const order: string[] = [];
  const service: CampaignService = {
    enabled: true,
    wake() {},
    abort: async () => {},
    isActive: () => false,
    cut: (organizationId, reason) => void order.push(`cut ${organizationId} ${reason}`),
    operatorStop: async (input) => {
      order.push(`operatorStop ${input.reason}`);
      return 0;
    },
    activeCount: async () => 0,
  };

  beforeAll(async () => {
    const db = await openDb();
    const watched = new Proxy(db, {
      get(target, property) {
        if (property === "tx") {
          return (scope: unknown, fn: (q: unknown) => unknown) =>
            (target.tx as (s: unknown, f: (q: unknown) => unknown) => unknown)(scope, (q) =>
              fn({
                query: (sql: string, params?: unknown[]) => {
                  if (/INSERT INTO audit_entries/.test(sql)) order.push(`audit ${String(params?.[6])}`);
                  if (/prove_suspension_set/.test(sql)) order.push("suspension committed next");
                  return (q as { query: (s: string, p?: unknown[]) => unknown }).query(sql, params);
                },
              }),
            );
        }
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as typeof db;
    api = await makeTestApi({ db: watched, campaigns: service, opsToken: OPS });
  });
  afterAll(async () => {
    await api.close();
  });

  it("suspending an Organization: the runner is told before the audit entry of the suspension is written", async () => {
    const created = await createOrganization(api, "Suspended");
    order.length = 0;
    const res = await api.app.request(
      `/v1/ops/prove/organizations/${created.organization.id}/suspend`,
      json({ reason: "review4" }, bearer(OPS)),
    );
    expect(res.status).toBe(200);
    expect(order).toEqual([
      "suspension committed next",
      "operatorStop organization_suspended",
      "audit campaign.operator_suspend",
    ]);
  });

  it("requesting the Organization's deletion: its Campaigns running here are cut as soon as it is committed", async () => {
    const created = await createOrganization(api, "Leaving");
    order.length = 0;
    const res = await api.app.request(
      "/v1/organization/deletion",
      json({ confirm_name: "Leaving" }, { ...bearer(created.admin_key.key), ...withReason() }),
    );
    expect(res.status).toBe(201);
    expect(order).toEqual(["audit organization.deletion.request", `cut ${created.organization.id} deletion_pending`]);
    // A request that is refused cuts nothing.
    const other = await createOrganization(api, "Staying");
    order.length = 0;
    const refused = await api.app.request(
      "/v1/organization/deletion",
      json({ confirm_name: "Not its name" }, { ...bearer(other.admin_key.key), ...withReason() }),
    );
    expect(refused.status).toBe(400);
    expect(order).toEqual([]);
  });
});
