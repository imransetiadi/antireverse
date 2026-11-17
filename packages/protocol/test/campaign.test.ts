import { describe, expect, it } from "vitest";
import {
  AuditEntrySchema,
  CAMPAIGN_END_REASONS,
  CAMPAIGN_LIMITS,
  CAMPAIGN_REFUSAL_REASONS,
  CAMPAIGN_STAND_IN_NOTICE,
  CAMPAIGN_STATUSES,
  CampaignProbeSchema,
  CampaignRequestSchema,
  CampaignSchema,
  CreateCampaignRequestSchema,
  campaignAuthorisationPhrase,
  campaignChecksSentence,
  campaignRequestTarget,
  canonicalCampaignPath,
  EXAMPLE_AUDIT_ENTRY,
  EXAMPLE_CAMPAIGN,
  FATAL_CAMPAIGN_REFUSALS,
  ID_PATTERNS,
  STAND_IN_ENGINE,
  statusOfEndReason,
} from "../src/index.ts";

// Slice 15a: the Pentest Campaign contract. The budgets are fixed in code: this test pins every number of the
// ticket's table, so a change to one is a change to this file too.

describe("campaign limits", () => {
  it("are exactly the ticket's table", () => {
    expect(CAMPAIGN_LIMITS).toMatchObject({
      requestsMax: 60,
      wallTimeS: 300,
      minSpacingMs: 1000,
      responseBytesMax: 2 * 1024 * 1024,
      responseReadBytesMax: 64 * 1024,
      requestTimeoutMs: 5000,
      refusalsMax: 20,
      consecutiveFailuresMax: 5,
      runningPerOrganization: 1,
      runningPerHost: 1,
      runningInAll: 2,
      createdPerOrganizationPerDay: 5,
      createdPerTargetPerDay: 3,
      roeMaxAgeDays: 90,
      storedRequestsMax: 200,
      evidenceWindowMax: 200,
      retentionDays: 395,
    });
    expect(Object.isFrozen(CAMPAIGN_LIMITS)).toBe(true);
  });

  it("has a cmp id pattern", () => {
    expect(ID_PATTERNS.cmp.test("cmp_0123456789abcdef01234567")).toBe(true);
  });
});

describe("the stand-in's honesty", () => {
  it("carries the exact sentence and the engine tag", () => {
    expect(CAMPAIGN_STAND_IN_NOTICE).toBe(
      "Scripted checks. They measure the pipeline and its safety controls. This is not a penetration test.",
    );
    expect(STAND_IN_ENGINE).toEqual({ name: "stand-in", version: "1", model: "stand-in" });
  });

  it("states checks as ran, reported and skipped, never as an absence of vulnerabilities", () => {
    expect(campaignChecksSentence({ ran: 6, reported: 5, inconclusive: 0, skipped: 0 })).toBe(
      "6 checks ran, 5 reported a finding, 0 were skipped.",
    );
    expect(campaignChecksSentence({ ran: 1, reported: 0, inconclusive: 0, skipped: 5 })).toBe(
      "1 check ran, 0 reported a finding, 5 were skipped.",
    );
    expect(campaignChecksSentence({ ran: 0, reported: 0, inconclusive: 0, skipped: 1 })).not.toMatch(
      /no vulnerabilit/i,
    );
  });
});

describe("the typed phrase", () => {
  it("names the host", () => {
    expect(campaignAuthorisationPhrase("shop.acme-shop.io")).toBe("I authorise a test of shop.acme-shop.io");
    expect(() => campaignAuthorisationPhrase("Shop.Acme-Shop.io")).toThrow(TypeError);
    expect(() => campaignAuthorisationPhrase("127.0.0.1")).toThrow(TypeError);
  });

  it("is part of a creation request, with the staging declaration", () => {
    const body = {
      target_id: "tgt_0123456789abcdef01234567",
      intensity: "passive",
      confirm: "I authorise a test of shop.acme-shop.io",
      staging: true,
    };
    expect(CreateCampaignRequestSchema.safeParse(body).success).toBe(true);
    expect(CreateCampaignRequestSchema.safeParse({ ...body, staging: false }).success).toBe(false);
    expect(CreateCampaignRequestSchema.safeParse({ ...body, staging: "true" }).success).toBe(false);
    expect(CreateCampaignRequestSchema.safeParse({ ...body, intensity: "full" }).success).toBe(false);
    expect(CreateCampaignRequestSchema.safeParse({ ...body, confirm: undefined }).success).toBe(false);
  });
});

describe("canonicalCampaignPath", () => {
  it("accepts plain absolute paths unchanged", () => {
    for (const path of ["/", "/api/orders/1001", "/search", "/a-b_c.d~e/f", "/.well-known/x.txt", "/a/"]) {
      expect(canonicalCampaignPath(path)).toBe(path);
    }
  });

  it("refuses anything a server or a URL parser could read differently", () => {
    for (const path of [
      "",
      "api",
      "//evil.example.net/x",
      "https://evil.example.net/",
      "/\\evil.example.net",
      "/a/../b",
      "/a/./b",
      "/..",
      "/a//b",
      "/a%2fb",
      "/%2e%2e/x",
      "/a?b=1",
      "/a#b",
      "/a;x=1",
      "/a:b",
      "/a@b",
      "/a b",
      "/a\r\nHost: evil",
      "/\u0000",
      "/café",
      "/a.",
      "/admin./x",
      `/${"a".repeat(1024)}`,
      null,
      7,
      { path: "/" },
    ]) {
      expect({ path, canonical: canonicalCampaignPath(path) }).toEqual({ path, canonical: null });
    }
  });
});

describe("campaignRequestTarget", () => {
  it("joins the path and the encoded query, in the order given", () => {
    expect(campaignRequestTarget({ method: "GET", path: "/" })).toBe("/");
    expect(campaignRequestTarget({ method: "GET", path: "/search", query: { q: '"><x y>', page: "2" } })).toBe(
      "/search?q=%22%3E%3Cx%20y%3E&page=2",
    );
    expect(
      campaignRequestTarget({ method: "GET", path: "/go", query: { to: "https://other.example.net/a?b=c#d" } }),
    ).toBe("/go?to=https%3A%2F%2Fother.example.net%2Fa%3Fb%3Dc%23d");
    // Characters encodeURIComponent leaves alone but a lenient server may treat specially are encoded too.
    expect(campaignRequestTarget({ method: "HEAD", path: "/s", query: { q: "a'(b)*!" } })).toBe(
      "/s?q=a%27%28b%29%2A%21",
    );
  });

  it("answers null for a probe that is not canonical", () => {
    expect(campaignRequestTarget({ method: "GET", path: "/a/../b" })).toBeNull();
    expect(campaignRequestTarget({ method: "GET", path: "/a", query: { "b c": "1" } })).toBeNull();
    expect(campaignRequestTarget({ method: "GET", path: "/a", query: { b: "x\r\ny" } })).toBeNull();
    expect(campaignRequestTarget({ method: "GET", path: "/a", query: { b: "x".repeat(513) } })).toBeNull();
  });
});

describe("CampaignProbeSchema", () => {
  it("is strict: host, scheme, port, body, headers and cookies are not expressible", () => {
    expect(CampaignProbeSchema.safeParse({ method: "GET", path: "/" }).success).toBe(true);
    expect(CampaignProbeSchema.safeParse({ method: "HEAD", path: "/", query: { a: "b" } }).success).toBe(true);
    for (const extra of ["host", "url", "scheme", "port", "body", "headers", "cookies", "auth"]) {
      expect(CampaignProbeSchema.safeParse({ method: "GET", path: "/", [extra]: "x" }).success).toBe(false);
    }
  });
});

describe("statuses and end reasons", () => {
  it("are fixed lists, and every end reason has one status", () => {
    expect(CAMPAIGN_STATUSES).toEqual([
      "queued",
      "running",
      "completed",
      "stopped",
      "refused",
      "failed",
      "interrupted",
    ]);
    for (const reason of CAMPAIGN_END_REASONS) {
      expect(["completed", "stopped", "refused", "failed", "interrupted"]).toContain(statusOfEndReason(reason, true));
    }
    expect(statusOfEndReason("checks_complete", true)).toBe("completed");
    expect(statusOfEndReason("owner_stop", true)).toBe("stopped");
    expect(statusOfEndReason("operator_kill", false)).toBe("stopped");
    expect(statusOfEndReason("target_not_verified", false)).toBe("refused");
    expect(statusOfEndReason("target_not_verified", true)).toBe("failed");
    expect(statusOfEndReason("api_restart", true)).toBe("interrupted");
  });

  it("every fatal refusal is an end reason", () => {
    for (const reason of FATAL_CAMPAIGN_REFUSALS) {
      expect(CAMPAIGN_REFUSAL_REASONS).toContain(reason);
      expect(CAMPAIGN_END_REASONS as readonly string[]).toContain(reason);
    }
    expect(FATAL_CAMPAIGN_REFUSALS).not.toContain("path_excluded");
    // Fourth review (D-110): a probe that is not one of the engine's catalog — another method included — ends the
    // Campaign.
    expect(FATAL_CAMPAIGN_REFUSALS).toContain("method_not_allowed");
  });
});

describe("the example Campaign and the audit actors", () => {
  it("the example parses", () => {
    expect(CampaignSchema.parse(EXAMPLE_CAMPAIGN)).toEqual(EXAMPLE_CAMPAIGN);
  });

  it("an audit entry's actor is an admin key, the system or the operator", () => {
    const { actor: _actor, ...rest } = EXAMPLE_AUDIT_ENTRY;
    expect(AuditEntrySchema.safeParse(EXAMPLE_AUDIT_ENTRY).success).toBe(true);
    expect(AuditEntrySchema.safeParse({ ...rest, actor: { kind: "system" }, action: "campaign.start" }).success).toBe(
      true,
    );
    expect(
      AuditEntrySchema.safeParse({ ...rest, actor: { kind: "operator" }, action: "campaign.operator_kill" }).success,
    ).toBe(true);
    expect(AuditEntrySchema.safeParse({ ...rest, actor: { kind: "admin_key" } }).success).toBe(false);
    expect(
      AuditEntrySchema.safeParse({ ...rest, actor: { kind: "system", key_id: EXAMPLE_AUDIT_ENTRY.actor.key_id } })
        .success,
    ).toBe(false);
  });
});

describe("slice 15a review", () => {
  it("M2: a request target is at most 1,024 characters", () => {
    const value = "x".repeat(512);
    expect(campaignRequestTarget({ method: "GET", path: "/", query: { a: value } })).toHaveLength(516);
    expect(campaignRequestTarget({ method: "GET", path: "/", query: { a: value, b: value } })).toBeNull();
    expect(campaignRequestTarget({ method: "GET", path: "/", query: { a: "é".repeat(200) } })).toBeNull();
    expect(CAMPAIGN_LIMITS).toMatchObject({ requestTargetMax: 1024, responseHeaderBytesMax: 16_384 });
  });

  it("M2: a request log row is written before the send, and a send can fail with an invalid response", () => {
    const row = {
      seq: 1,
      at: "2026-11-16T10:00:00.000Z",
      method: "GET",
      target: "/",
      outcome: "sending",
      reason: null,
      status: null,
      failure: null,
      bytes: 0,
      ms: 0,
      asked_chars: null,
    };
    expect(CampaignRequestSchema.safeParse(row).success).toBe(true);
    expect(CampaignRequestSchema.safeParse({ ...row, outcome: "sent", failure: "invalid_response" }).success).toBe(
      true,
    );
    expect(CampaignRequestSchema.safeParse({ ...row, outcome: "queued" }).success).toBe(false);
  });

  it("L1, L3, M1: dropped Findings are counted; the verification path must not be excluded; an engine error is a failure", () => {
    expect(EXAMPLE_CAMPAIGN.findings_dropped).toBe(0);
    expect(CampaignSchema.safeParse({ ...EXAMPLE_CAMPAIGN, findings_dropped: undefined }).success).toBe(false);
    expect(CAMPAIGN_END_REASONS).toContain("verification_path_excluded");
    expect(statusOfEndReason("verification_path_excluded", false)).toBe("refused");
    expect(statusOfEndReason("engine_error", false)).toBe("failed");
    expect(statusOfEndReason("engine_error", true)).toBe("failed");
  });
});

describe("slice 15a second review", () => {
  it("M3: a check whose response could not be read is inconclusive, and the sentence says how many and why", () => {
    expect(campaignChecksSentence({ ran: 6, reported: 6, inconclusive: 0, skipped: 0 })).toBe(
      "6 checks ran, 6 reported a finding, 0 were skipped.",
    );
    expect(campaignChecksSentence({ ran: 2, reported: 2, inconclusive: 4, skipped: 0 })).toBe(
      "2 checks ran, 2 reported a finding, 4 were inconclusive (4 responses could not be read as text or in full), 0 were skipped.",
    );
    expect(campaignChecksSentence({ ran: 0, reported: 0, inconclusive: 1, skipped: 5 })).toBe(
      "0 checks ran, 0 reported a finding, 1 was inconclusive (1 response could not be read as text or in full), 5 were skipped.",
    );
    expect(EXAMPLE_CAMPAIGN.checks).toEqual({ ran: 6, reported: 6, inconclusive: 0, skipped: 0 });
    expect(CampaignSchema.safeParse({ ...EXAMPLE_CAMPAIGN, checks: { ran: 6, reported: 6, skipped: 0 } }).success).toBe(
      false,
    );
  });

  it("L7: a request that never left has an outcome of its own", () => {
    const row = {
      seq: 3,
      at: "2026-11-16T10:00:00.000Z",
      method: "GET",
      target: "/",
      outcome: "not_sent",
      reason: null,
      status: null,
      failure: null,
      bytes: 0,
      ms: 0,
      asked_chars: null,
    };
    expect(CampaignRequestSchema.safeParse(row).success).toBe(true);
  });
});
