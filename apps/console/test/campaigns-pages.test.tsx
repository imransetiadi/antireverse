import {
  CAMPAIGN_STAND_IN_NOTICE,
  EXAMPLE_RULES_OF_ENGAGEMENT,
  EXAMPLE_TARGET,
  type ListCampaignsResponse,
  type RulesOfEngagementVersion,
  type Target,
} from "@antireverse/protocol";
import { render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { completed, highFinding, refused, reportOf, running, sentRequest } from "./helpers/campaigns.ts";
import { EMPTY_USAGE } from "./helpers/usage.ts";

// Slice 15a: the three Campaign pages and the line on Settings → Usage, each state of each, rendered with the API
// client, the session guard, the Server Actions and the navigation replaced.
vi.mock("@/app/actions.ts", () => ({
  createCampaignAction: vi.fn(),
  stopCampaignAction: vi.fn(),
  signOutAction: vi.fn(),
}));
const guard = vi.hoisted(() => ({ session: null as unknown }));
vi.mock("@/lib/guard.ts", () => ({ requireSession: vi.fn(async () => guard.session) }));
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  listCampaigns: vi.fn(),
  listTargets: vi.fn(),
  getCurrentRulesOfEngagement: vi.fn(),
  getCampaignReport: vi.fn(),
  listCampaignRequests: vi.fn(),
  getUsage: vi.fn(),
}));
vi.mock("next/navigation", async (original) => ({
  ...(await original<typeof import("next/navigation")>()),
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
  notFound: vi.fn(() => {
    throw new Error("NOT_FOUND");
  }),
  useRouter: () => ({ refresh: vi.fn() }),
}));

import CampaignPage from "@/app/prove/campaigns/[campaignId]/page.tsx";
import NewCampaignPage from "@/app/prove/campaigns/new/page.tsx";
import CampaignsPage from "@/app/prove/campaigns/page.tsx";
import UsagePage from "@/app/settings/usage/page.tsx";
import * as api from "@/lib/api.ts";

const organization = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };
const NOW = Date.parse("2026-11-12T12:00:00.000Z");
const shop: Target = EXAMPLE_TARGET;
const api2: Target = { ...EXAMPLE_TARGET, id: "tgt_aaaaaaaaaaaaaaaaaaaaaaaa", host: "api.acme-shop.io" };
const pending: Target = {
  ...EXAMPLE_TARGET,
  id: "tgt_cccccccccccccccccccccccc",
  host: "staging.acme-shop.io",
  status: "pending",
  verified_at: null,
};
const rules: RulesOfEngagementVersion = {
  ...EXAMPLE_RULES_OF_ENGAGEMENT,
  scope: [shop.id],
  signed_at: "2026-11-10T08:00:00.000Z",
};
const list = (overrides: Partial<ListCampaignsResponse> = {}): ListCampaignsResponse => ({
  campaigns: [running, completed],
  enabled: true,
  blocked: null,
  notice: CAMPAIGN_STAND_IN_NOTICE,
  ...overrides,
});

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(NOW);
  for (const fn of [
    api.listCampaigns,
    api.listTargets,
    api.getCurrentRulesOfEngagement,
    api.getCampaignReport,
    api.listCampaignRequests,
    api.getUsage,
  ]) {
    vi.mocked(fn).mockReset();
  }
  guard.session = { key: "k", organization };
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("/prove/campaigns", () => {
  const open = async () => render(await CampaignsPage());

  it("shows the notice, the list and the New Campaign button, with Campaigns current in the navigation", async () => {
    vi.mocked(api.listCampaigns).mockResolvedValue(list());
    await open();
    expect(api.listCampaigns).toHaveBeenCalledWith("k");
    expect(screen.getByRole("heading", { level: 1, name: "Campaigns" })).toBeTruthy();
    expect(screen.getByTestId("campaign-notice-text").textContent).toBe(CAMPAIGN_STAND_IN_NOTICE);
    expect(screen.getAllByTestId("campaign-row")).toHaveLength(2);
    expect(screen.getByTestId("campaign-new").getAttribute("href")).toBe("/prove/campaigns/new");
    expect(screen.getByTestId("nav-campaigns").getAttribute("aria-current")).toBe("page");
    expect(screen.queryByTestId("campaigns-disabled")).toBeNull();
    expect(screen.queryByTestId("campaigns-blocked")).toBeNull();
  });

  it("has an empty state that still shows the notice", async () => {
    vi.mocked(api.listCampaigns).mockResolvedValue(list({ campaigns: [] }));
    await open();
    expect(screen.getByTestId("campaigns-empty")).toBeTruthy();
    expect(screen.getByTestId("campaign-notice-text").textContent).toBe(CAMPAIGN_STAND_IN_NOTICE);
    expect(screen.getByTestId("campaign-new")).toBeTruthy();
  });

  it("says Campaigns are switched off on this API and offers no create button", async () => {
    vi.mocked(api.listCampaigns).mockResolvedValue(list({ campaigns: [], enabled: false }));
    await open();
    expect(screen.getByTestId("campaigns-disabled").textContent).toContain("Campaigns are switched off on this API");
    expect(screen.queryByTestId("campaign-new")).toBeNull();
    expect(document.querySelector('a[href="/prove/campaigns/new"]')).toBeNull();
    expect(screen.getByTestId("campaigns-empty").textContent).toBe("No Campaigns yet.");
  });

  it("says when the operator stopped all Campaigns or suspended the Organization; ended Campaigns stay listed", async () => {
    vi.mocked(api.listCampaigns).mockResolvedValue(list({ campaigns: [completed], blocked: "operator_kill" }));
    const first = await open();
    expect(screen.getByTestId("campaigns-blocked").textContent).toContain("The operator has stopped all Campaigns.");
    expect(screen.queryByTestId("campaign-new")).toBeNull();
    expect(screen.getAllByTestId("campaign-row")).toHaveLength(1);
    first.unmount();
    vi.mocked(api.listCampaigns).mockResolvedValue(list({ blocked: "organization_suspended" }));
    await open();
    expect(screen.getByTestId("campaigns-blocked").textContent).toContain("suspended Campaigns for this Organization");
    expect(screen.queryByTestId("campaign-new")).toBeNull();
  });

  it("leaves for sign-in when the key stopped working, and for Data controls while a deletion is pending (D-084)", async () => {
    vi.mocked(api.listCampaigns).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(CampaignsPage()).rejects.toThrow("REDIRECT /sign-in?reason=expired");
    vi.mocked(api.listCampaigns).mockRejectedValueOnce(new api.DeletionPendingError("403"));
    await expect(CampaignsPage()).rejects.toThrow("REDIRECT /settings/data?blocked=1");
  });
});

describe("/prove/campaigns/new", () => {
  const open = async () => render(await NewCampaignPage());
  const given = (targets: Target[], version: RulesOfEngagementVersion | null, campaigns = list()) => {
    vi.mocked(api.listTargets).mockResolvedValue({ targets });
    vi.mocked(api.getCurrentRulesOfEngagement).mockResolvedValue({ version });
    vi.mocked(api.listCampaigns).mockResolvedValue(campaigns);
  };

  it("offers only verified targets in the scope of the current Rules of Engagement", async () => {
    given([shop, api2, pending], rules);
    await open();
    expect(screen.getByRole("heading", { level: 1, name: "New Campaign" })).toBeTruthy();
    const radios = screen.getAllByRole("radio", { name: /acme-shop\.io/ });
    expect(radios.map((radio) => (radio as HTMLInputElement).value)).toEqual([shop.id]);
    expect(screen.getByTestId("campaign-rules").getAttribute("data-roe-id")).toBe(rules.id);
    expect(screen.getByTestId("campaign-launch")).toBeTruthy();
  });

  it("says why no target qualifies, with the way to fix it, and shows no form", async () => {
    const cases: Array<[Target[], RulesOfEngagementVersion | null, string, string]> = [
      [[], null, "There are no targets yet. Add a host you own and verify it first.", "/prove/targets"],
      [[pending], rules, "No target is verified. Verify a host on its page first.", "/prove/targets"],
      [
        [shop],
        null,
        "No Rules of Engagement are signed. Sign a version that names the target you want to test first.",
        "/prove/rules-of-engagement",
      ],
      [
        [api2],
        rules,
        "No verified target is in the scope of the current Rules of Engagement. Sign a version that names the target first.",
        "/prove/rules-of-engagement",
      ],
      [
        [shop],
        { ...rules, exclusions: ["/.well-known"] },
        "The current Rules of Engagement exclude /.well-known/airverse-verification.txt, the ownership file every Campaign reads at its start. Sign a version that does not exclude it first.",
        "/prove/rules-of-engagement",
      ],
      [
        [shop],
        { ...rules, signed_at: "2026-08-01T08:00:00.000Z" },
        "The current Rules of Engagement were signed more than 90 days ago. Sign them again first.",
        "/prove/rules-of-engagement",
      ],
    ];
    for (const [targets, version, message, href] of cases) {
      given(targets, version);
      const page = await open();
      const none = screen.getByTestId("campaign-none");
      expect(none.textContent).toContain(message);
      expect(within(none).getByRole("link").getAttribute("href")).toBe(href);
      expect(screen.queryByTestId("campaign-launch")).toBeNull();
      page.unmount();
    }
  });

  it("shows no form while Campaigns are switched off, stopped or suspended, and says which", async () => {
    given([shop], rules, list({ enabled: false }));
    const first = await open();
    expect(screen.getByTestId("campaigns-disabled")).toBeTruthy();
    expect(screen.queryByTestId("campaign-launch")).toBeNull();
    first.unmount();
    given([shop], rules, list({ blocked: "operator_kill" }));
    await open();
    expect(screen.getByTestId("campaigns-blocked")).toBeTruthy();
    expect(screen.queryByTestId("campaign-launch")).toBeNull();
  });

  it("leaves for sign-in or Data controls when the API says so", async () => {
    given([shop], rules);
    vi.mocked(api.listTargets).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(NewCampaignPage()).rejects.toThrow("REDIRECT /sign-in?reason=expired");
    vi.mocked(api.getCurrentRulesOfEngagement).mockRejectedValueOnce(new api.DeletionPendingError("403"));
    await expect(NewCampaignPage()).rejects.toThrow("REDIRECT /settings/data?blocked=1");
  });
});

describe("/prove/campaigns/[campaignId]", () => {
  const open = async (id: string, query: Record<string, string | string[] | undefined> = {}) =>
    render(await CampaignPage({ params: Promise.resolve({ campaignId: id }), searchParams: Promise.resolve(query) }));

  it("shows one Campaign from its report and its request log", async () => {
    vi.mocked(api.getCampaignReport).mockResolvedValue({ report: reportOf(completed, [highFinding]) });
    vi.mocked(api.listCampaignRequests).mockResolvedValue({ requests: [sentRequest] });
    await open(completed.id);
    expect(api.getCampaignReport).toHaveBeenCalledWith("k", completed.id);
    expect(api.listCampaignRequests).toHaveBeenCalledWith("k", completed.id);
    expect(screen.getByRole("heading", { level: 1, name: "Campaign against shop.acme-shop.io" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "All Campaigns" }).getAttribute("href")).toBe("/prove/campaigns");
    expect(screen.getAllByTestId("campaign-finding")).toHaveLength(1);
    expect(screen.getAllByTestId("request-row")).toHaveLength(1);
    expect(screen.getAllByTestId("campaign-notice-text")[0]?.textContent).toBe(CAMPAIGN_STAND_IN_NOTICE);
    expect(screen.queryByTestId("campaign-stop")).toBeNull();
  });

  it("opens the stop step and the notices through the address, and only for known values", async () => {
    vi.mocked(api.getCampaignReport).mockResolvedValue({ report: reportOf(running) });
    vi.mocked(api.listCampaignRequests).mockResolvedValue({ requests: [] });
    const plain = await open(running.id);
    expect(screen.getByTestId("campaign-stop")).toBeTruthy();
    expect(screen.queryByTestId("campaign-confirm")).toBeNull();
    plain.unmount();
    const confirming = await open(running.id, { confirm: "stop" });
    expect(screen.getByTestId("campaign-confirm")).toBeTruthy();
    confirming.unmount();
    const ended = await open(running.id, { notice: "ended", confirm: "other" });
    expect(screen.getByTestId("campaign-notice-ended")).toBeTruthy();
    expect(screen.queryByTestId("campaign-confirm")).toBeNull();
    ended.unmount();
    await open(running.id, { notice: "<script>" });
    expect(screen.queryByTestId("campaign-notice-ended")).toBeNull();
    expect(screen.queryByTestId("campaign-notice-report")).toBeNull();
  });

  it("shows a Campaign that was refused at start: no request, no Finding, and why", async () => {
    vi.mocked(api.getCampaignReport).mockResolvedValue({ report: reportOf(refused) });
    vi.mocked(api.listCampaignRequests).mockResolvedValue({ requests: [] });
    await open(refused.id);
    expect(screen.getByTestId("campaign-status").textContent).toBe("Refused");
    expect(screen.getByTestId("campaign-why").textContent).toContain("No request was sent.");
    expect(screen.getByTestId("campaign-requests-empty")).toBeTruthy();
  });

  it("is not found for a malformed id (the API is not asked) and for a Campaign the API does not know", async () => {
    await expect(open("cmp_nope")).rejects.toThrow("NOT_FOUND");
    expect(api.getCampaignReport).not.toHaveBeenCalled();
    vi.mocked(api.getCampaignReport).mockRejectedValueOnce(new api.NotFoundError("404"));
    vi.mocked(api.listCampaignRequests).mockResolvedValue({ requests: [] });
    await expect(open(completed.id)).rejects.toThrow("NOT_FOUND");
  });

  it("leaves for sign-in or Data controls when the API says so", async () => {
    vi.mocked(api.listCampaignRequests).mockResolvedValue({ requests: [] });
    vi.mocked(api.getCampaignReport).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(open(completed.id)).rejects.toThrow("REDIRECT /sign-in?reason=expired");
    vi.mocked(api.getCampaignReport).mockRejectedValueOnce(new api.DeletionPendingError("403"));
    await expect(open(completed.id)).rejects.toThrow("REDIRECT /settings/data?blocked=1");
  });
});

describe("Settings → Usage", () => {
  it("says in one line that Campaigns are not metered in this version", async () => {
    vi.mocked(api.getUsage).mockResolvedValue(EMPTY_USAGE);
    render(await UsagePage({ searchParams: Promise.resolve({}) }));
    expect(screen.getByTestId("usage-campaigns").textContent).toBe("Campaigns are not metered in this version.");
  });
});
