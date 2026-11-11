// @vitest-environment node
import { EXAMPLE_FINDING, EXAMPLE_VIRTUAL_PATCH } from "@antireverse/protocol";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The live feed names patches by the titles of the Environments it actually shows (Jev, 0.86).
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  listPatches: vi.fn(),
}));

import { feedPatchTitles } from "@/features/patches/load.ts";
import * as api from "@/lib/api.ts";
import { eventAt } from "./helpers/events.ts";

const appId = EXAMPLE_FINDING.app_id;
const summary = (id: string, title: string) => ({
  id,
  title,
  advisories: [...EXAMPLE_VIRTUAL_PATCH.advisories],
  package: EXAMPLE_VIRTUAL_PATCH.package,
  mode: "monitor" as const,
  active: true,
  shipped: true,
  findings: [],
  hits_24h: 0,
  last_hit: null,
});

beforeEach(() => {
  vi.mocked(api.listPatches).mockReset();
});

describe("feedPatchTitles", () => {
  it("reads the titles of each Environment present in the feed, once each, and merges them", async () => {
    vi.mocked(api.listPatches).mockImplementation(async (_key, _app, environment) => ({
      patches: [summary(`vp_${environment}_only`, `Title in ${environment}`)],
    }));
    const events = [
      eventAt(1_000, { environment: "staging" }),
      eventAt(2_000, { environment: "development" }),
      eventAt(3_000, { environment: "staging" }),
    ];
    expect(await feedPatchTitles("aro_key", appId, events)).toEqual({
      vp_staging_only: "Title in staging",
      vp_development_only: "Title in development",
    });
    expect(
      vi
        .mocked(api.listPatches)
        .mock.calls.map((call) => call[2])
        .sort(),
    ).toEqual(["development", "staging"]);
  });

  it("reads nothing for an empty feed, and leaves out an Environment whose patches could not be read", async () => {
    expect(await feedPatchTitles("aro_key", appId, [])).toEqual({});
    expect(api.listPatches).not.toHaveBeenCalled();
    vi.mocked(api.listPatches).mockImplementation(async (_key, _app, environment) => {
      if (environment === "production") throw new api.ApiError("403", 403);
      return { patches: [summary("vp_staging_only", "Staging title")] };
    });
    const events = [eventAt(1_000, { environment: "production" }), eventAt(2_000, { environment: "staging" })];
    expect(await feedPatchTitles("aro_key", appId, events)).toEqual({ vp_staging_only: "Staging title" });
  });

  it("passes on a key the API no longer accepts", async () => {
    vi.mocked(api.listPatches).mockRejectedValue(new api.UnauthorizedError("401"));
    await expect(feedPatchTitles("aro_key", appId, [eventAt(1_000)])).rejects.toBeInstanceOf(api.UnauthorizedError);
  });
});
