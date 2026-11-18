import { campaignRequestTarget, inCampaignCatalog } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { STAND_IN_CATALOG, STAND_IN_MARKER, STAND_IN_REDIRECT, standInEngine } from "../src/index.ts";

// Slice 15a, fourth independent safety review, R1 (D-110): the stand-in declares, beside its checks, every probe it
// may send. The host reads that catalog from the engine's definition and gives it to the gate; nothing an engine
// posts while it runs can add to it.

describe("review4 R1: the stand-in's probe catalog", () => {
  it("declares exactly the probes of its checks: method, path, and the one value each query name may have", () => {
    // Fifth review: each probe also names the check it serves.
    expect(standInEngine.probes).toEqual([
      { method: "GET", path: "/", checks: ["RW-01"] },
      { method: "GET", path: "/api/orders/x", checks: ["RW-02"] },
      { method: "GET", path: "/api/admin/reports", checks: ["RW-03"] },
      { method: "GET", path: "/api/orders/1001", checks: ["RW-04"] },
      { method: "GET", path: "/search", checks: ["RW-05"], query: { q: { exact: STAND_IN_MARKER } } },
      { method: "GET", path: "/go", checks: ["RW-06"], query: { to: { exact: STAND_IN_REDIRECT } } },
    ]);
    expect(Object.isFrozen(standInEngine.probes)).toBe(true);
    expect(Object.isFrozen(standInEngine.probes[4]?.query?.q)).toBe(true);
  });

  it("holds every probe the checks send, and none of their neighbours", () => {
    for (const check of STAND_IN_CATALOG) {
      expect(inCampaignCatalog(standInEngine.probes, check.probe), check.id).toBe(true);
      expect(campaignRequestTarget(check.probe)).not.toBeNull();
    }
    for (const probe of [
      { method: "HEAD", path: "/" },
      { method: "GET", path: "/search", query: { q: "anything else" } },
      { method: "GET", path: "/go", query: { to: "https://other.example/" } },
      { method: "GET", path: "/api/orders/1002" },
    ]) {
      expect(inCampaignCatalog(standInEngine.probes, probe)).toBe(false);
    }
  });
});
