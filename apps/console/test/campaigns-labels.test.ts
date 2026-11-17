// @vitest-environment node
import {
  CAMPAIGN_END_REASONS,
  CAMPAIGN_FINDING_STATES,
  CAMPAIGN_REFUSAL_REASONS,
  CAMPAIGN_SEND_FAILURES,
  CAMPAIGN_STATUSES,
  EXAMPLE_RULES_OF_ENGAGEMENT,
  EXAMPLE_TARGET,
  type RulesOfEngagementVersion,
  type Target,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  campaignEffect,
  END_REASON_LABEL,
  eligibility,
  endReasonText,
  FINDING_STATE_LABEL,
  isActive,
  offeredIntensities,
  REFUSAL_LABEL,
  SEND_FAILURE_LABEL,
  STATUS_LABEL,
} from "@/features/campaigns/labels.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// Slice 15a: the words of Campaigns, the addresses, and which targets and intensities the form offers.

const NOW = Date.parse("2026-11-12T12:00:00.000Z");
const shop: Target = EXAMPLE_TARGET;
const api: Target = { ...EXAMPLE_TARGET, id: "tgt_aaaaaaaaaaaaaaaaaaaaaaaa", host: "api.acme-shop.io" };
const pending: Target = {
  ...EXAMPLE_TARGET,
  id: "tgt_cccccccccccccccccccccccc",
  host: "staging.acme-shop.io",
  status: "pending",
  verified_at: null,
};
const rules: RulesOfEngagementVersion = {
  ...EXAMPLE_RULES_OF_ENGAGEMENT,
  scope: [shop.id, pending.id],
  signed_at: "2026-11-10T08:00:00.000Z",
};

describe("Campaign words", () => {
  it("has plain words for every status, end reason, refusal reason, send failure and Finding state", () => {
    for (const status of CAMPAIGN_STATUSES) expect(t(STATUS_LABEL[status])).toMatch(/^[A-Z][a-z]+$/);
    for (const reason of CAMPAIGN_END_REASONS) {
      const text = endReasonText(reason);
      expect(text.length).toBeGreaterThan(10);
      expect(text).not.toContain("_");
      expect(text).not.toContain("{");
      expect(END_REASON_LABEL[reason]).toBe(`campaign.end.${reason}`);
    }
    for (const reason of CAMPAIGN_REFUSAL_REASONS) expect(t(REFUSAL_LABEL[reason])).not.toContain("_");
    for (const failure of CAMPAIGN_SEND_FAILURES) expect(t(SEND_FAILURE_LABEL[failure])).not.toContain("_");
    for (const state of CAMPAIGN_FINDING_STATES) expect(t(FINDING_STATE_LABEL[state])).toMatch(/^[A-Z]/);
    expect(t(FINDING_STATE_LABEL.unverified)).toBe("Unverified");
    expect(t(FINDING_STATE_LABEL.confirmed)).toBe("Confirmed");
    expect(endReasonText("request_budget")).toBe("The budget of 60 requests was used up.");
    expect(endReasonText("refusal_limit")).toBe("20 probes were refused, so the Campaign was ended.");
    expect(endReasonText("verification_path_excluded")).toBe(
      "The Rules of Engagement exclude the path of the ownership file, which every Campaign reads at its start. No request was sent.",
    );
    expect(t(SEND_FAILURE_LABEL.invalid_response)).toBe("Invalid response");
    expect(t(SEND_FAILURE_LABEL.read_limit)).toBe("Read limit passed");
  });

  it("states the effect in the numbers of the protocol's limits", () => {
    expect(campaignEffect()).toBe(
      "At most 60 GET or HEAD requests, 1 per second, for at most 5 minutes. No request bodies, cookies or credentials. Redirects are never followed.",
    );
  });

  it("knows which statuses are still active", () => {
    expect(CAMPAIGN_STATUSES.filter(isActive)).toEqual(["queued", "running"]);
  });
});

describe("what the new Campaign form offers", () => {
  it("offers only verified targets in the scope of the current Rules of Engagement", () => {
    expect(eligibility([shop, api, pending], rules, NOW)).toEqual({ kind: "ok", targets: [shop] });
  });

  it("says why nothing qualifies", () => {
    expect(eligibility([], null, NOW)).toEqual({ kind: "none", why: "no-targets" });
    expect(eligibility([pending], null, NOW)).toEqual({ kind: "none", why: "no-verified" });
    expect(eligibility([shop], null, NOW)).toEqual({ kind: "none", why: "no-rules" });
    expect(eligibility([api, pending], rules, NOW)).toEqual({ kind: "none", why: "none-in-scope" });
    const old = { ...rules, signed_at: "2026-08-01T08:00:00.000Z" };
    expect(eligibility([shop], old, NOW)).toEqual({ kind: "none", why: "rules-too-old" });
    // Exactly 90 days is still covered.
    const edge = { ...rules, signed_at: new Date(NOW - 90 * 86_400_000).toISOString() };
    expect(eligibility([shop], edge, NOW).kind).toBe("ok");
  });

  it("says when the Rules of Engagement exclude the ownership file every Campaign reads at its start", () => {
    for (const exclusions of [["/.well-known"], ["/.well-known/airverse-verification.txt"], ["/"]]) {
      expect(eligibility([shop], { ...rules, exclusions }, NOW)).toEqual({
        kind: "none",
        why: "verification-path-excluded",
      });
    }
    expect(eligibility([shop], { ...rules, exclusions: ["/admin", "/.well-known-other"] }, NOW).kind).toBe("ok");
  });

  it("offers passive and safe-active, never full, and never more than was signed", () => {
    expect(offeredIntensities("passive")).toEqual(["passive"]);
    expect(offeredIntensities("safe-active")).toEqual(["passive", "safe-active"]);
    expect(offeredIntensities("full")).toEqual(["passive", "safe-active"]);
  });
});

describe("Campaign addresses", () => {
  it("never carries a key, and opens the stop step and the notices through the address", () => {
    const id = "cmp_0123456789abcdef01234567";
    expect(ROUTES.campaigns).toBe("/prove/campaigns");
    expect(ROUTES.newCampaign).toBe("/prove/campaigns/new");
    expect(ROUTES.campaign(id)).toBe(`/prove/campaigns/${id}`);
    expect(ROUTES.campaign(id, { confirm: "stop" })).toBe(`/prove/campaigns/${id}?confirm=stop`);
    expect(ROUTES.campaign(id, { notice: "ended" })).toBe(`/prove/campaigns/${id}?notice=ended`);
    expect(ROUTES.campaign(id, { notice: "report-failed" })).toBe(`/prove/campaigns/${id}?notice=report-failed`);
    expect(ROUTES.campaignReport(id)).toBe(`/api/campaigns/${id}/report`);
    expect(ROUTES.opsProve({ done: "kill", stopped: 2 })).toBe("/ops?prove=kill&stopped=2");
    expect(ROUTES.opsProve({ done: "resume" })).toBe("/ops?prove=resume");
  });
});
