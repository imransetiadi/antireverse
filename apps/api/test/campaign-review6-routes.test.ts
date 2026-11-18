import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CampaignService } from "../src/campaign/runner.ts";
import { bearer, createOrganization, json, makeTestApi, type TestApi, withReason } from "./helpers.ts";

// Slice 15a, sixth independent safety review, F2 over the route: a deletion that is committed is answered 201,
// whatever becomes of the cut that follows it.

describe("review6 15a: the deletion route and a cut that fails", () => {
  let api: TestApi;
  const cuts: string[] = [];
  const service: CampaignService = {
    enabled: true,
    wake() {},
    abort: async () => {},
    isActive: () => false,
    async cut(organizationId, reason) {
      cuts.push(`${organizationId} ${reason}`);
      throw new Error("the queue is not readable");
    },
    operatorStop: async () => 0,
    activeCount: async () => 0,
  };

  beforeAll(async () => {
    api = await makeTestApi({ campaigns: service });
  });
  afterAll(async () => {
    await api.close();
  });

  it("answers 201 for the committed deletion; a second request is refused as for any pending deletion", async () => {
    const created = await createOrganization(api, "Leaving");
    const request = () =>
      api.app.request(
        "/v1/organization/deletion",
        json({ confirm_name: "Leaving" }, { ...bearer(created.admin_key.key), ...withReason() }),
      );
    const first = await request();
    // It answered 500 after the deletion was committed: the caller could not know that it stood.
    expect(first.status).toBe(201);
    expect(cuts).toEqual([`${created.organization.id} deletion_pending`]);
    const status = await api.app.request("/v1/organization/deletion", { headers: bearer(created.admin_key.key) });
    expect(status.status).toBe(200);
    expect(((await status.json()) as { deletion: unknown }).deletion).not.toBeNull();
    expect((await request()).status).toBe(403);
  });
});
