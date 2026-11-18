import {
  CampaignResponseSchema,
  campaignAuthorisationPhrase,
  confirmationPhrase,
  ListCampaignsResponseSchema,
  ProblemSchema,
  TargetResponseSchema,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CampaignService } from "../src/campaign/runner.ts";
import type { Fetcher, Resolver } from "../src/prove/verify.ts";
import { bearer, createOrganization, json, makeTestApi, type TestApi, withReason } from "./helpers.ts";

// Slice 15a, third independent safety review, from its unconfirmed list: several `POST /v1/campaigns` of one
// Organization at the same moment. One is created; every other is told that a Campaign is active (409) — none is
// answered with a 500. (Not reproduced: the API's database runs one transaction at a time, so the check and the
// INSERT of one request cannot interleave with another's. Kept as a regression test.)

const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const HOST = "shop.acme-shop.io";

describe("review3 15a: concurrent creation", () => {
  let api: TestApi;
  const now = () => new Date(T0);
  const txt = new Map<string, string[][]>();
  const resolver: Resolver = {
    async txt(name) {
      const records = txt.get(name);
      if (records === undefined) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      return records;
    },
    async addresses() {
      throw new Error("not used");
    },
  };
  const fetcher: Fetcher = async () => ({ ok: false, reason: "status" });
  const service: CampaignService = {
    enabled: true,
    wake() {},
    abort: async () => {},
    isActive: () => false,
    cut: async () => {},
    operatorStop: async () => 0,
    activeCount: async () => 0,
  };

  beforeAll(async () => {
    api = await makeTestApi({ now, prove: { resolver, fetcher }, campaigns: service });
  });
  afterAll(async () => {
    await api.close();
  });

  it("ten at once for one Organization: one 202, nine 409 `campaign-active`, no 500", async () => {
    const created = await createOrganization(api, "Concurrent");
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

    const post = () =>
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
    const responses = await Promise.all(Array.from({ length: 10 }, post));
    const statuses = responses.map((response) => response.status).sort();
    expect(statuses).toEqual([202, ...Array.from({ length: 9 }, () => 409)]);
    for (const response of responses) {
      if (response.status === 202) CampaignResponseSchema.parse(await response.json());
      else
        expect(ProblemSchema.parse(await response.json()).detail).toMatch(/already has a queued or running Campaign/);
    }
    const list = ListCampaignsResponseSchema.parse(
      await (await api.app.request("/v1/campaigns", { headers: bearer(admin) })).json(),
    );
    expect(list.campaigns).toHaveLength(1);
  });
});
