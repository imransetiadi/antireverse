import {
  CAMPAIGN_REPORT_LIMITS,
  CAMPAIGN_STAND_IN_NOTICE,
  campaignChecksSentence,
  EXAMPLE_RULES_OF_ENGAGEMENT,
  EXAMPLE_TARGET,
  type RulesOfEngagementVersion,
  STAND_IN_ENGINE,
  type Target,
} from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  completed,
  failedRequest,
  highFinding,
  lowFinding,
  queued,
  refused,
  refusedRequest,
  reportOf,
  running,
  sentRequest,
  stopped,
} from "./helpers/campaigns.ts";

// Slice 15a: the Campaign screens — the list, the form that launches one, and one Campaign with its Stop step, its
// Findings, its request log and its report — rendered with the Server Actions and the router replaced by fakes.
vi.mock("@/app/actions.ts", () => ({
  createCampaignAction: vi.fn(),
  stopCampaignAction: vi.fn(),
  signOutAction: vi.fn(),
}));
const router = vi.hoisted(() => ({ refresh: vi.fn() }));
vi.mock("next/navigation", async (original) => ({
  ...(await original<typeof import("next/navigation")>()),
  useRouter: () => router,
}));

import * as actions from "@/app/actions.ts";
import { AppShell } from "@/components/app-shell.tsx";
import { AutoRefresh } from "@/features/campaigns/auto-refresh.tsx";
import { CampaignView, REFRESH_SECONDS } from "@/features/campaigns/campaign-detail.tsx";
import { CampaignList, CampaignsAvailability } from "@/features/campaigns/campaign-list.tsx";
import { CampaignNotice } from "@/features/campaigns/campaign-notice.tsx";
import { CampaignStatusChip } from "@/features/campaigns/campaign-status.tsx";
import { NewCampaignForm } from "@/features/campaigns/new-campaign-form.tsx";

const MONO = /\bcode-[1-3]\b/;
const organization = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };
const shop: Target = EXAMPLE_TARGET;
const api: Target = { ...EXAMPLE_TARGET, id: "tgt_aaaaaaaaaaaaaaaaaaaaaaaa", host: "api.acme-shop.io" };
const rules: RulesOfEngagementVersion = {
  ...EXAMPLE_RULES_OF_ENGAGEMENT,
  scope: [shop.id, api.id],
  exclusions: ["/admin", "/checkout"],
  intensity: "safe-active",
  window: { days: ["mon", "tue"], from: "09:00", to: "17:00" },
};

const fieldsOf = (data: FormData): Record<string, string[]> => {
  const values: Record<string, string[]> = {};
  for (const [name, value] of data.entries()) values[name] = [...(values[name] ?? []), String(value)];
  return values;
};
const sent = (action: unknown): Record<string, string[]> => {
  const data = vi.mocked(action as (previous: unknown, data: FormData) => unknown).mock.calls.at(-1)?.[1];
  if (!data) throw new Error("the action was not called");
  return fieldsOf(data);
};

beforeEach(() => {
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
  router.refresh.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("navigation", () => {
  it("has Campaigns in the Prove group, after Targets and Rules of Engagement", () => {
    render(
      <AppShell organization={organization} current="campaigns">
        <p>content</p>
      </AppShell>,
    );
    const prove = screen.getByRole("navigation", { name: "Prove" });
    expect(
      within(prove)
        .getAllByRole("link")
        .map((link) => link.textContent),
    ).toEqual(["Targets", "Rules of Engagement", "Campaigns"]);
    const link = within(prove).getByRole("link", { name: "Campaigns" });
    expect(link.getAttribute("href")).toBe("/prove/campaigns");
    expect(link.getAttribute("aria-current")).toBe("page");
    // The operator pages are never linked from the tenant navigation.
    expect(document.querySelector('a[href^="/ops"]')).toBeNull();
  });
});

describe("CampaignNotice", () => {
  it("shows the protocol's sentence word for word and the engine tag", () => {
    render(<CampaignNotice engine={STAND_IN_ENGINE} notice="whatever the API said" />);
    const notice = screen.getByTestId("campaign-notice");
    expect(notice.getAttribute("role")).toBe("note");
    expect(within(notice).getByTestId("campaign-notice-text").textContent).toBe(CAMPAIGN_STAND_IN_NOTICE);
    expect(CAMPAIGN_STAND_IN_NOTICE).toBe(
      "Scripted checks. They measure the pipeline and its safety controls. This is not a penetration test.",
    );
    const tag = within(notice).getByTestId("campaign-engine");
    expect(tag.textContent).toBe("stand-in");
    expect(tag.className).toMatch(MONO);
  });

  it("shows another engine's own notice as plain text", () => {
    render(<CampaignNotice engine={{ name: "other", version: "2", model: "m" }} notice="<b>Another</b> notice." />);
    expect(screen.getByTestId("campaign-notice-text").textContent).toBe("<b>Another</b> notice.");
    expect(screen.getByTestId("campaign-notice").querySelector("b")).toBeNull();
  });
});

describe("CampaignStatusChip", () => {
  it("carries each status by a word and its own glyph, never by colour alone", () => {
    const shapes = new Set<string>();
    for (const [status, word] of [
      ["queued", "Queued"],
      ["running", "Running"],
      ["completed", "Completed"],
      ["stopped", "Stopped"],
      ["refused", "Refused"],
      ["failed", "Failed"],
      ["interrupted", "Interrupted"],
    ] as const) {
      const { unmount } = render(<CampaignStatusChip status={status} />);
      const chip = screen.getByTestId("campaign-status");
      expect(chip.textContent).toBe(word);
      expect(chip.getAttribute("data-status")).toBe(status);
      expect(chip.getAttribute("title")).toBeTruthy();
      shapes.add(chip.querySelector("svg")?.getAttribute("data-shape") ?? "");
      unmount();
    }
    expect(shapes.size).toBe(7);
    expect(shapes.has("")).toBe(false);
  });
});

describe("CampaignList", () => {
  it("lists status, target host, intensity, the engine tag, counts and the created time, linked to each Campaign", () => {
    render(<CampaignList campaigns={[running, completed, refused]} />);
    const table = screen.getByRole("table", { name: "Campaigns of the Organization, newest first" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toEqual(["Target", "Status", "Intensity", "Engine", "Requests", "Checks", "Created UTC"]);
    const rows = screen.getAllByTestId("campaign-row");
    expect(rows.map((row) => row.getAttribute("data-campaign-id"))).toEqual([running.id, completed.id, refused.id]);
    const done = rows[1] as HTMLElement;
    const host = within(done).getByTestId("campaign-host");
    expect(host.textContent).toBe("shop.acme-shop.io");
    expect(host.getAttribute("href")).toBe(`/prove/campaigns/${completed.id}`);
    expect(within(done).getByTestId("campaign-status").textContent).toBe("Completed");
    expect(within(done).getByTestId("campaign-intensity").textContent).toBe("safe-active");
    expect(within(done).getByTestId("campaign-engine").textContent).toBe("stand-in");
    expect(within(done).getByTestId("campaign-requests").textContent).toBe(
      `${completed.requests_sent} sent, 0 refused`,
    );
    expect(within(done).getByTestId("campaign-checks").textContent).toBe(
      "6 checks ran, 6 reported a finding, 0 were skipped.",
    );
    expect(within(done).getByTestId("campaign-created").textContent).toBe("2026-11-16 10:00:00");
    expect(within(rows[0] as HTMLElement).getByTestId("campaign-checks").textContent).toBe("Not ended yet");
    expect(within(rows[2] as HTMLElement).getByTestId("campaign-checks").textContent).toBe("None ran");
  });

  it("has an empty state", () => {
    render(<CampaignList campaigns={[]} />);
    expect(screen.getByTestId("campaigns-empty").textContent).toContain("No Campaigns yet.");
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("CampaignsAvailability", () => {
  it("says nothing while Campaigns can be created", () => {
    const { container } = render(<CampaignsAvailability enabled blocked={null} />);
    expect(container.textContent).toBe("");
  });

  it("says that Campaigns are switched off on this API", () => {
    render(<CampaignsAvailability enabled={false} blocked={null} />);
    expect(screen.getByTestId("campaigns-disabled").textContent).toBe(
      "Campaigns are switched off on this API, so none can be created. The operator of the service turns them on.",
    );
  });

  it("says when the operator stopped all Campaigns or suspended this Organization", () => {
    const { rerender } = render(<CampaignsAvailability enabled blocked="operator_kill" />);
    expect(screen.getByTestId("campaigns-blocked").textContent).toBe(
      "The operator has stopped all Campaigns. None can be created until the operator enables them again.",
    );
    rerender(<CampaignsAvailability enabled blocked="organization_suspended" />);
    expect(screen.getByTestId("campaigns-blocked").textContent).toBe(
      "The operator has suspended Campaigns for this Organization. None can be created until the suspension is lifted.",
    );
    expect(screen.getByTestId("campaigns-blocked").getAttribute("data-blocked")).toBe("organization_suspended");
  });
});

describe("NewCampaignForm", () => {
  it("offers the given targets, each with its exact phrase, and the first is chosen", () => {
    render(<NewCampaignForm targets={[shop, api]} rules={rules} />);
    const radios = screen.getAllByRole("radio", { name: /acme-shop\.io/ });
    expect(radios.map((radio) => (radio as HTMLInputElement).value)).toEqual([shop.id, api.id]);
    expect((radios[0] as HTMLInputElement).checked).toBe(true);
    expect(screen.getAllByTestId("campaign-phrase").map((phrase) => phrase.textContent)).toEqual([
      "I authorise a test of shop.acme-shop.io",
      "I authorise a test of api.acme-shop.io",
    ]);
    expect(screen.getByTestId("campaign-phrase-current").textContent).toBe("I authorise a test of shop.acme-shop.io");
    fireEvent.click(radios[1] as HTMLElement);
    expect(screen.getByTestId("campaign-phrase-current").textContent).toBe("I authorise a test of api.acme-shop.io");
  });

  it("limits the intensity to passive and safe-active, and to what was signed", () => {
    const { unmount } = render(<NewCampaignForm targets={[shop]} rules={rules} />);
    const intensity = screen.getByRole("group", { name: "Intensity" });
    expect(
      within(intensity)
        .getAllByRole("radio")
        .map((radio) => (radio as HTMLInputElement).value),
    ).toEqual(["passive", "safe-active"]);
    expect(intensity.textContent).toContain("At most safe-active, the intensity that was signed.");
    unmount();
    render(<NewCampaignForm targets={[shop]} rules={{ ...rules, intensity: "passive" }} />);
    expect(
      within(screen.getByRole("group", { name: "Intensity" }))
        .getAllByRole("radio")
        .map((radio) => (radio as HTMLInputElement).value),
    ).toEqual(["passive"]);
    unmount();
    render(<NewCampaignForm targets={[shop]} rules={{ ...rules, intensity: "full" }} />);
    expect(screen.queryByRole("radio", { name: "full" })).toBeNull();
  });

  it("summarises the Rules of Engagement and states the effect in numbers", () => {
    render(<NewCampaignForm targets={[shop]} rules={rules} />);
    const summary = screen.getByTestId("campaign-rules");
    expect(within(summary).getByTestId("campaign-rules-window").textContent).toBe("Mon, Tue, 09:00 to 17:00 UTC");
    expect(
      within(summary)
        .getAllByTestId("campaign-rules-exclusion")
        .map((item) => item.textContent),
    ).toEqual(["/admin", "/checkout"]);
    expect(within(summary).getByTestId("campaign-rules-intensity").textContent).toBe("safe-active");
    expect(screen.getByTestId("campaign-effect").textContent).toBe(
      "At most 60 GET or HEAD requests, 1 per second, for at most 5 minutes. No request bodies, cookies or credentials. Redirects are never followed.",
    );
    expect(screen.getByTestId("campaign-notice-text").textContent).toBe(CAMPAIGN_STAND_IN_NOTICE);
  });

  it("says when no path is excluded", () => {
    render(<NewCampaignForm targets={[shop]} rules={{ ...rules, exclusions: [] }} />);
    expect(screen.getByTestId("campaign-rules").textContent).toContain("No path is excluded.");
  });

  it("requires the phrase, the staging declaration and a reason, also without JavaScript", () => {
    render(<NewCampaignForm targets={[shop]} rules={rules} />);
    const phrase = screen.getByLabelText("Type the phrase to authorise") as HTMLInputElement;
    expect(phrase.required).toBe(true);
    expect(phrase.name).toBe("confirm");
    expect(phrase.getAttribute("autocomplete")).toBe("off");
    const staging = screen.getByRole("checkbox", { name: "This target is a staging or test system" });
    expect((staging as HTMLInputElement).required).toBe(true);
    expect((staging as HTMLInputElement).checked).toBe(false);
    expect((staging as HTMLInputElement).name).toBe("staging");
    const reason = screen.getByLabelText("Reason") as HTMLInputElement;
    expect(reason.required).toBe(true);
    expect(reason.name).toBe("reason");
    // A real form with a submit button: it posts without client code.
    const form = phrase.closest("form") as HTMLFormElement;
    expect(within(form).getByRole("button", { name: "Launch Campaign" }).getAttribute("type")).toBe("submit");
  });

  it("sends the target, the intensity, the phrase, the declaration and the reason", async () => {
    vi.mocked(actions.createCampaignAction).mockResolvedValue(null);
    render(<NewCampaignForm targets={[shop, api]} rules={rules} />);
    fireEvent.click(screen.getByRole("radio", { name: /api\.acme-shop\.io/ }));
    fireEvent.click(screen.getByRole("radio", { name: "safe-active" }));
    fireEvent.change(screen.getByLabelText("Type the phrase to authorise"), {
      target: { value: "I authorise a test of api.acme-shop.io" },
    });
    fireEvent.click(screen.getByRole("checkbox", { name: "This target is a staging or test system" }));
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Quarterly test" } });
    await act(async () => {
      fireEvent.submit(screen.getByTestId("campaign-launch").closest("form") as HTMLFormElement);
    });
    expect(sent(actions.createCampaignAction)).toEqual({
      target: [api.id],
      intensity: ["safe-active"],
      confirm: ["I authorise a test of api.acme-shop.io"],
      staging: ["on"],
      reason: ["Quarterly test"],
    });
  });

  it("shows each refusal at its field and in the summary, keeps the choices and the reason, and empties the phrase", async () => {
    vi.mocked(actions.createCampaignAction).mockResolvedValue({
      ok: false,
      errors: [
        { path: "target", message: "Nothing was launched. This target is not in the scope." },
        { path: "confirm", message: "Nothing was launched. Type the phrase." },
        { path: "staging", message: "Nothing was launched. Declare it." },
        { path: "", message: "Nothing was launched. Campaigns are switched off on this API." },
      ],
      values: { target: api.id, intensity: "safe-active" },
      reason: "Quarterly test",
    });
    render(<NewCampaignForm targets={[shop, api]} rules={rules} />);
    fireEvent.change(screen.getByLabelText("Type the phrase to authorise"), { target: { value: "wrong" } });
    await act(async () => {
      fireEvent.submit(screen.getByTestId("campaign-launch").closest("form") as HTMLFormElement);
    });
    const summary = screen.getByTestId("error-summary");
    expect(within(summary).getAllByRole("listitem")).toHaveLength(4);
    expect(
      within(summary)
        .getByRole("link", { name: /^Target:/ })
        .getAttribute("href"),
    ).toBe("#campaign-target");
    expect(summary.textContent).toContain("Campaigns are switched off on this API.");
    expect(screen.getByTestId("campaign-target-error").textContent).toContain("not in the scope");
    expect(screen.getByTestId("campaign-confirm-error").textContent).toContain("Type the phrase");
    expect(screen.getByTestId("campaign-staging-error").textContent).toContain("Declare it");
    expect((screen.getByRole("radio", { name: /api\.acme-shop\.io/ }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole("radio", { name: "safe-active" }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText("Reason") as HTMLInputElement).value).toBe("Quarterly test");
    expect((screen.getByLabelText("Type the phrase to authorise") as HTMLInputElement).value).toBe("");
    expect(
      (screen.getByRole("checkbox", { name: "This target is a staging or test system" }) as HTMLInputElement).checked,
    ).toBe(false);
  });
});

describe("CampaignView", () => {
  const view = (
    campaign = completed,
    options: { confirmStop?: boolean; notice?: "ended" | "report-failed"; findings?: (typeof highFinding)[] } = {},
  ) => (
    <CampaignView
      report={reportOf(campaign, options.findings ?? [highFinding, lowFinding])}
      requests={[sentRequest, refusedRequest, failedRequest]}
      confirmStop={options.confirmStop ?? false}
      notice={options.notice}
    />
  );

  it("shows the notice, the engine, the status and the end reason in words", () => {
    render(view());
    expect(screen.getAllByTestId("campaign-notice-text")[0]?.textContent).toBe(CAMPAIGN_STAND_IN_NOTICE);
    expect(screen.getByTestId("campaign-status").textContent).toBe("Completed");
    expect(screen.getByTestId("campaign-why").textContent).toBe("The engine ran every check it had.");
    expect(screen.getByTestId("campaign-facts").textContent).toContain("safe-active");
    expect(screen.getByTestId("campaign-requests").textContent).toBe(`${completed.requests_sent} sent, 0 refused`);
    expect(screen.getByTestId("campaign-staging").textContent).toBe(
      "Declared a staging or test system by key_0123456789abcdef01234567. Not verified.",
    );
    expect(screen.getByTestId("campaign-roe").textContent).toBe(completed.roe_id);
  });

  it("explains a Campaign that was refused at start, and one that was stopped, with who stopped it and why", () => {
    const { unmount } = render(view(refused, { findings: [] }));
    expect(screen.getByTestId("campaign-status").textContent).toBe("Refused");
    expect(screen.getByTestId("campaign-why").textContent).toBe(
      "The host did not resolve, or an address it resolves to is not public. No request was sent.",
    );
    expect(screen.getByTestId("campaign-checks").textContent).toBe("No check ran.");
    unmount();
    render(view(stopped));
    expect(screen.getByTestId("campaign-why").textContent).toBe("Stopped with an admin key of this Organization.");
    expect(screen.getByTestId("campaign-stop-request").textContent).toBe(
      "By key_0123456789abcdef01234567 at 2026-11-16 10:00:05 UTC: Wrong window",
    );
  });

  it("always shows Stop while the Campaign is queued or running, and never once it ended", () => {
    for (const campaign of [queued, running]) {
      const { unmount } = render(view(campaign, { findings: [] }));
      const stop = screen.getByTestId("campaign-stop");
      expect(stop.textContent).toBe("Stop Campaign");
      expect(stop.getAttribute("href")).toBe(`/prove/campaigns/${campaign.id}?confirm=stop`);
      unmount();
    }
    for (const campaign of [completed, stopped, refused]) {
      const { unmount } = render(view(campaign));
      expect(screen.queryByTestId("campaign-stop")).toBeNull();
      expect(screen.queryByTestId("campaign-confirm")).toBeNull();
      unmount();
    }
    // The address cannot open the step for a Campaign that ended.
    render(view(completed, { confirmStop: true }));
    expect(screen.queryByTestId("campaign-confirm")).toBeNull();
  });

  it("stops in one confirmation step with a required reason", async () => {
    render(view(running, { confirmStop: true, findings: [] }));
    const step = screen.getByTestId("campaign-confirm");
    expect(within(step).getByTestId("confirm-question").textContent).toBe(
      "Stop the Campaign against shop.acme-shop.io? No further request is sent.",
    );
    const reason = within(step).getByTestId("confirm-reason") as HTMLInputElement;
    expect(reason.required).toBe(true);
    expect(within(step).getByTestId("confirm-cancel").getAttribute("href")).toBe(`/prove/campaigns/${running.id}`);
    fireEvent.change(reason, { target: { value: "Wrong window" } });
    await act(async () => {
      fireEvent.submit(reason.closest("form") as HTMLFormElement);
    });
    expect(sent(actions.stopCampaignAction)).toEqual({
      campaignId: [running.id],
      confirm: [running.id],
      reason: ["Wrong window"],
    });
  });

  it("shows why a stop was refused, at the reason field, and keeps the reason", async () => {
    vi.mocked(actions.stopCampaignAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "reason", message: "Nothing was saved. Give a reason." }],
      reason: "",
    });
    render(view(running, { confirmStop: true, findings: [] }));
    await act(async () => {
      fireEvent.submit(screen.getByTestId("confirm-reason").closest("form") as HTMLFormElement);
    });
    expect(screen.getByTestId("error-summary").textContent).toContain("Give a reason");
    expect(screen.getByTestId("confirm-reason").getAttribute("aria-invalid")).toBe("true");
  });

  it("refreshes by itself while active — also without JavaScript — and not once it ended", () => {
    const active = renderToString(view(running, { findings: [] }));
    expect(active).toContain(`<noscript><meta http-equiv="refresh" content="${REFRESH_SECONDS}"/></noscript>`);
    expect(active).toContain("campaign-auto-refresh");
    // While the stop step is open a reload without JavaScript would empty the reason: no meta refresh then.
    const confirming = renderToString(view(running, { confirmStop: true, findings: [] }));
    expect(confirming).not.toContain("http-equiv");
    expect(confirming).toContain("campaign-auto-refresh");
    const ended = renderToString(view(completed));
    expect(ended).not.toContain("http-equiv");
    expect(ended).not.toContain("campaign-auto-refresh");
    render(view(running, { findings: [] }));
    expect(screen.getByTestId("campaign-why").textContent).toBe(
      `Running. This page refreshes every ${REFRESH_SECONDS} seconds.`,
    );
    expect(screen.getByTestId("campaign-refresh").getAttribute("href")).toBe(`/prove/campaigns/${running.id}`);
  });

  it("says how many checks ran, reported and were skipped in the protocol's sentence, never that nothing was found", () => {
    const { unmount } = render(view(stopped, { findings: [] }));
    expect(screen.getByTestId("campaign-checks").textContent).toBe(
      campaignChecksSentence({ ran: 2, reported: 1, inconclusive: 0, skipped: 4 }),
    );
    expect(screen.getByTestId("campaign-findings-empty").textContent).toBe(
      "The checks that ran reported no Finding. That says nothing about what was not checked.",
    );
    expect(document.body.textContent).not.toMatch(/no vulnerabilit/i);
    unmount();
    render(view(running, { findings: [] }));
    expect(screen.getByTestId("campaign-checks").textContent).toBe("The checks are counted when the Campaign ends.");
    expect(screen.getByTestId("campaign-findings-empty").textContent).toBe("No Findings so far.");
  });

  it("says when reported Findings could not be stored: the list is then incomplete", () => {
    const { unmount } = render(view());
    expect(screen.queryByTestId("campaign-findings-dropped")).toBeNull();
    unmount();
    render(view({ ...completed, status: "failed", end_reason: "engine_error", findings_dropped: 2 }));
    const dropped = screen.getByTestId("campaign-findings-dropped");
    expect(dropped.getAttribute("role")).toBe("alert");
    expect(dropped.textContent).toBe(
      "2 reported Findings could not be stored, so this Campaign ended as failed. The list below is incomplete.",
    );
  });

  it("lists Findings with the severity as a word and an icon, and the state Unverified or Confirmed", () => {
    render(view());
    const findings = screen.getAllByTestId("campaign-finding");
    expect(findings.map((finding) => finding.getAttribute("data-check-id"))).toEqual(["RW-03", "RW-06"]);
    const high = findings[0] as HTMLElement;
    expect(within(high).getByRole("heading", { name: "Admin data without authentication" })).toBeTruthy();
    const badge = within(high).getByTestId("severity-badge");
    expect(badge.textContent).toBe("High");
    expect(badge.querySelector("svg")).not.toBeNull();
    const confirmedState = within(high).getByTestId("finding-state");
    expect(confirmedState.textContent).toBe("Confirmed");
    expect(confirmedState.getAttribute("data-state")).toBe("confirmed");
    expect(confirmedState.querySelector("svg")).not.toBeNull();
    const low = findings[1] as HTMLElement;
    expect(within(low).getByTestId("severity-badge").textContent).toBe("Low");
    const unverified = within(low).getByTestId("finding-state");
    expect(unverified.textContent).toBe("Unverified");
    expect(unverified.querySelector("svg")?.getAttribute("data-shape")).not.toBe(
      confirmedState.querySelector("svg")?.getAttribute("data-shape"),
    );
    expect(within(low).getByTestId("finding-location").textContent).toBe("To another host. It was not followed.");
    expect(within(low).getByTestId("finding-truncated")).toBeTruthy();
    expect(within(low).getByTestId("finding-excerpt-none").textContent).toBe("The response had no body.");
    expect(screen.getByTestId("campaign-findings-count").textContent).toBe("2 Findings");
  });

  it("shows evidence as plain text: never HTML, never a link, the excerpt in a scrollable monospace block", () => {
    const hostile = {
      ...highFinding,
      title: 'A <img src=x onerror="alert(1)"> title',
      evidence: {
        ...highFinding.evidence,
        target: "/search?q=<script>alert(1)</script>",
        headers: { "content-type": "text/html", "x-note": "<a href='https://evil.example'>click</a>" },
        excerpt:
          '<script>alert(1)</script><a href="https://evil.example/x">https://evil.example/x</a> javascript:alert(1)',
      },
    };
    render(view(completed, { findings: [hostile] }));
    const finding = screen.getByTestId("campaign-finding");
    expect(finding.querySelector("script")).toBeNull();
    expect(finding.querySelector("img")).toBeNull();
    expect(finding.querySelector("a")).toBeNull();
    const excerpt = within(finding).getByTestId("finding-excerpt");
    expect(excerpt.tagName).toBe("PRE");
    expect(excerpt.textContent).toBe(hostile.evidence.excerpt);
    expect(excerpt.children).toHaveLength(0);
    expect(excerpt.className).toMatch(MONO);
    // The block scrolls inside itself, is reachable by keyboard and is named for a screen reader.
    const region = within(finding).getByRole("region", { name: "Response excerpt of check RW-03, redacted" });
    expect(region.contains(excerpt)).toBe(true);
    expect(region.className).toMatch(/\boverflow-auto\b/);
    expect(region.className).toMatch(/\bmax-h-24\b/);
    expect(region.getAttribute("tabindex")).toBe("0");
    expect(within(finding).getByTestId("finding-request").textContent).toBe("GET /search?q=<script>alert(1)</script>");
    expect(within(finding).getByTestId("finding-status").textContent).toBe("200");
    expect(within(finding).getByTestId("finding-headers").textContent).toContain(
      "<a href='https://evil.example'>click</a>",
    );
    expect(within(finding).getByTestId("finding-hash").textContent).toBe("c".repeat(64));
  });

  it("lists the request log with refusals and their reasons, and requests without a response", () => {
    render(view());
    const table = screen.getByRole("table", { name: "Requests of this Campaign, oldest first" });
    const rows = within(table).getAllByTestId("request-row");
    expect(rows).toHaveLength(3);
    expect(within(rows[0] as HTMLElement).getByTestId("request-target").textContent).toBe("GET /");
    expect(within(rows[0] as HTMLElement).getByTestId("request-outcome").textContent).toBe("Sent");
    expect(within(rows[0] as HTMLElement).getByTestId("request-result").textContent).toBe("Status 200");
    const refusedRow = rows[1] as HTMLElement;
    expect(refusedRow.getAttribute("data-outcome")).toBe("refused");
    expect(within(refusedRow).getByTestId("request-outcome").textContent).toBe("Refused, not sent");
    expect(within(refusedRow).getByTestId("request-outcome").querySelector("svg")).not.toBeNull();
    expect(within(refusedRow).getByTestId("request-result").textContent).toBe("Reason: Path excluded");
    expect(within(rows[2] as HTMLElement).getByTestId("request-result").textContent).toBe("No response: Timed out");
    expect(table.querySelector("a")).toBeNull();
    expect(screen.getByTestId("campaign-requests-lead").textContent).toContain("At most 200 rows are kept");
  });

  it("says of a request that never left that it was not sent, not that it got no response", () => {
    render(
      <CampaignView
        report={reportOf(stopped, [])}
        requests={[{ ...sentRequest, seq: 1, outcome: "not_sent", status: null, bytes: 0, ms: 0 }]}
        confirmStop={false}
        notice={undefined}
      />,
    );
    const row = screen.getByTestId("request-row");
    expect(row.getAttribute("data-outcome")).toBe("not_sent");
    expect(within(row).getByTestId("request-outcome").textContent).toBe("Not sent");
    expect(within(row).getByTestId("request-result").textContent).toBe("A stop came before it left");
  });

  it("offers the report as a download through the Console, with the notice and the limits beside it", () => {
    render(view());
    const report = screen.getByTestId("campaign-report");
    const link = within(report).getByTestId("campaign-report-download");
    expect(link.getAttribute("href")).toBe(`/api/campaigns/${completed.id}/report`);
    // A plain link: the route handler answers with an attachment, and a refusal comes back as a page, not a file.
    expect(link.hasAttribute("download")).toBe(false);
    expect(within(report).getByTestId("campaign-notice-text").textContent).toBe(CAMPAIGN_STAND_IN_NOTICE);
    expect(
      within(report)
        .getAllByTestId("campaign-report-limit")
        .map((item) => item.textContent),
    ).toEqual([...CAMPAIGN_REPORT_LIMITS]);
  });

  it("says once that the Campaign had already ended, or that the report could not be made", () => {
    const { unmount } = render(view(completed, { notice: "ended" }));
    expect(screen.getByTestId("campaign-notice-ended").textContent).toBe(
      "This Campaign had already ended, so there was nothing to stop.",
    );
    expect(screen.getByTestId("campaign-notice-ended").getAttribute("role")).toBe("status");
    unmount();
    render(view(completed, { notice: "report-failed" }));
    expect(screen.getByTestId("campaign-notice-report").getAttribute("role")).toBe("alert");
  });
});

describe("AutoRefresh", () => {
  it("asks the router for fresh data every few seconds, and stops when it leaves the page", () => {
    vi.useFakeTimers();
    const { unmount } = render(<AutoRefresh seconds={5} />);
    expect(router.refresh).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(5_000);
    });
    expect(router.refresh).toHaveBeenCalledTimes(1);
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(router.refresh).toHaveBeenCalledTimes(3);
    unmount();
    act(() => {
      vi.advanceTimersByTime(20_000);
    });
    expect(router.refresh).toHaveBeenCalledTimes(3);
  });
});
