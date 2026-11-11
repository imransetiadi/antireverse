import {
  type Advisory,
  type Build,
  EXAMPLE_ADVISORY,
  EXAMPLE_BUILD,
  EXAMPLE_FINDING,
  EXAMPLE_FINDING_INCIDENT,
  FINDING_SEVERITIES,
  type Finding,
  type FindingSeverity,
} from "@antireverse/protocol";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Slice 19: the Finding screens, rendered with the Server Actions replaced by fakes — what a form sends is
// the contract.
vi.mock("@/app/actions.ts", () => ({
  ignoreFindingAction: vi.fn(),
  reopenFindingAction: vi.fn(),
  updateIncidentAction: vi.fn(),
  createContainmentAction: vi.fn(),
  liftContainmentAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import * as actions from "@/app/actions.ts";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { SeverityBadge } from "@/components/severity-badge.tsx";
import { BuildDetail } from "@/features/builds/build-detail.tsx";
import { FindingDetail } from "@/features/findings/finding-detail.tsx";
import { FindingFilters } from "@/features/findings/finding-filters.tsx";
import { FindingList } from "@/features/findings/finding-list.tsx";
import { FindingStatusTag } from "@/features/findings/status-tag.tsx";
import { IncidentDetail } from "@/features/incidents/incident-detail.tsx";
import { ROUTES } from "@/lib/routes.ts";

const MONO = /\bcode-[1-3]\b/;
const appId = EXAMPLE_FINDING.app_id;
const organization = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-10T08:00:00.000Z" };
const appNames = new Map([[appId, "shop-web"]]);
// 2026-11-11 15:30 UTC: the ignore window is 2026-11-12 to 2027-02-09, 2026-12-11 by default.
const NOW = Date.UTC(2026, 10, 11, 15, 30);

const finding = (overrides: Partial<Finding>): Finding => ({ ...EXAMPLE_FINDING, ...overrides });
const runtime = finding({
  id: "fnd_aaaaaaaaaaaaaaaaaaaaaaaa",
  source: "runtime",
  build_id: null,
  environment: "production",
  severity: "critical",
  package: "@example/ui",
  version: "4.0.0-rc.1",
  advisory_id: "GHSA-aaaa-bbbb-cccc",
  aliases: ["CVE-2026-20001", "GHSA-zzzz-yyyy-xxxx", "CVE-2026-20002", "CVE-2026-20003"],
  fixed_versions: [],
  last_seen: "2026-11-11T09:00:00.000Z",
});
const fixed = finding({ id: "fnd_bbbbbbbbbbbbbbbbbbbbbbbb", status: "fixed", severity: "unknown", aliases: [] });
const ignored = finding({
  id: "fnd_cccccccccccccccccccccccc",
  status: "ignored",
  severity: "low",
  ignore: { reason: "Only used in tests", until: "2026-12-11T00:00:00.000Z", by: "key_0123456789abcdef01234567" },
});

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
const submit = async (control: HTMLElement): Promise<void> => {
  await act(async () => {
    fireEvent.click(control);
  });
};

beforeEach(() => {
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
});

describe("SeverityBadge — Finding severities", () => {
  const expected: Record<FindingSeverity, { word: string; shape: string }> = {
    critical: { word: "Critical", shape: "warning-octagon" },
    high: { word: "High", shape: "warning" },
    medium: { word: "Medium", shape: "warning-circle" },
    low: { word: "Low", shape: "info" },
    unknown: { word: "Unknown", shape: "question" },
  };

  it.each(FINDING_SEVERITIES)("draws %s with its own shape and word", (severity) => {
    render(<SeverityBadge severity={severity} />);
    const badge = screen.getByTestId("severity-badge");
    expect(badge.getAttribute("data-severity")).toBe(severity);
    expect(badge.textContent).toBe(expected[severity].word);
    expect(badge.querySelector("svg")?.getAttribute("data-shape")).toBe(expected[severity].shape);
    expect(badge.outerHTML).not.toMatch(/#[0-9a-fA-F]{3,8}\b|rgb\(/);
  });

  it("gives Unknown a shape no other severity uses", () => {
    render(<SeverityBadge severity="unknown" />);
    expect(Object.values(expected).filter((one) => one.shape === "question")).toHaveLength(1);
    expect(screen.getByTestId("severity-badge").className).toContain("text-sev-info");
  });
});

describe("navigation", () => {
  it("has Findings in the main navigation, marked when current", () => {
    render(
      <AppShell organization={organization} current="findings">
        <p>content</p>
      </AppShell>,
    );
    const main = screen.getByRole("navigation", { name: "Main" });
    expect(
      within(main)
        .getAllByRole("link")
        .map((link) => [link.textContent, link.getAttribute("href")]),
    ).toEqual([
      ["Apps", "/apps"],
      ["Incidents", "/incidents"],
      ["Findings", "/findings"],
    ]);
    expect(screen.getByTestId("nav-findings").getAttribute("aria-current")).toBe("page");
  });

  it("has a Findings tab among the App's screens", () => {
    render(<AppNav appId={appId} current="findings" />);
    const link = screen.getByRole("link", { name: "Findings" });
    expect(link.getAttribute("href")).toBe(`/apps/${appId}/findings`);
    expect(link.getAttribute("data-testid")).toBe("app-nav-findings");
    expect(link.getAttribute("aria-current")).toBe("page");
  });
});

describe("FindingFilters", () => {
  it("offers severity, status and source as links that keep the other filters", () => {
    render(
      <FindingFilters
        query={{ severity: "high", advisory: "GHSA-2c3m-4p5q-6r7v" }}
        href={(query) => ROUTES.findings(query)}
      />,
    );
    const severity = screen.getByRole("navigation", { name: "Filter by severity" });
    expect(
      within(severity)
        .getAllByRole("link")
        .map((link) => [link.textContent, link.getAttribute("href")]),
    ).toEqual([
      ["All", "/findings?advisory=GHSA-2c3m-4p5q-6r7v"],
      ["Critical", "/findings?severity=critical&advisory=GHSA-2c3m-4p5q-6r7v"],
      ["High", "/findings?severity=high&advisory=GHSA-2c3m-4p5q-6r7v"],
      ["Medium", "/findings?severity=medium&advisory=GHSA-2c3m-4p5q-6r7v"],
      ["Low", "/findings?severity=low&advisory=GHSA-2c3m-4p5q-6r7v"],
      ["Unknown", "/findings?severity=unknown&advisory=GHSA-2c3m-4p5q-6r7v"],
    ]);
    expect(screen.getByTestId("finding-filter-severity-high").getAttribute("aria-current")).toBe("page");
    expect(screen.getByTestId("finding-filter-severity-all").getAttribute("aria-current")).toBeNull();

    const status = screen.getByRole("navigation", { name: "Filter by status" });
    expect(
      within(status)
        .getAllByRole("link")
        .map((link) => [link.textContent, link.getAttribute("href")]),
    ).toEqual([
      ["All", "/findings?severity=high&advisory=GHSA-2c3m-4p5q-6r7v"],
      ["Open", "/findings?severity=high&status=open&advisory=GHSA-2c3m-4p5q-6r7v"],
      ["Fixed", "/findings?severity=high&status=fixed&advisory=GHSA-2c3m-4p5q-6r7v"],
      ["Ignored", "/findings?severity=high&status=ignored&advisory=GHSA-2c3m-4p5q-6r7v"],
      ["Withdrawn", "/findings?severity=high&status=withdrawn&advisory=GHSA-2c3m-4p5q-6r7v"],
    ]);
    expect(screen.getByTestId("finding-filter-status-all").getAttribute("aria-current")).toBe("page");

    const source = screen.getByRole("navigation", { name: "Filter by source" });
    expect(
      within(source)
        .getAllByRole("link")
        .map((link) => link.textContent),
    ).toEqual(["All", "Build", "Running server"]);
    expect(screen.getByTestId("finding-filter-source-runtime").getAttribute("href")).toBe(
      "/findings?severity=high&source=runtime&advisory=GHSA-2c3m-4p5q-6r7v",
    );
  });
});

describe("FindingList", () => {
  it("shows severity, package, App, advisory, source, status, fix and last seen, in the API's order", () => {
    render(
      <FindingList
        findings={[EXAMPLE_FINDING, runtime, fixed, ignored]}
        appNames={appNames}
        query={{}}
        clearHref="/findings"
      />,
    );
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Severity",
      "Package",
      "App",
      "Advisory",
      "Source",
      "Status",
      "Fixed in",
      "Last seen UTC",
    ]);
    const rows = screen.getAllByTestId("finding-row");
    expect(rows.map((row) => row.getAttribute("data-finding-id"))).toEqual([
      EXAMPLE_FINDING.id,
      runtime.id,
      fixed.id,
      ignored.id,
    ]);

    const first = within(rows[0] as HTMLElement);
    expect(first.getByTestId("severity-badge").textContent).toBe("High");
    const link = first.getByTestId("finding-link");
    expect(link.textContent).toBe("example-parser@1.2.3");
    expect(link.getAttribute("href")).toBe(`/findings/${EXAMPLE_FINDING.id}`);
    expect(link.className).toMatch(MONO);
    expect(first.getByTestId("finding-app").textContent).toBe("shop-web");
    expect(first.getByTestId("finding-advisory").textContent).toBe("GHSA-2c3m-4p5q-6r7v");
    expect(first.getByTestId("finding-cve").textContent).toBe("CVE-2026-10001");
    expect(first.queryByTestId("finding-cve-more")).toBeNull();
    expect(first.getByTestId("finding-source").textContent).toBe("Build");
    expect(first.getByTestId("finding-status").textContent).toBe("Open");
    expect(first.getByTestId("finding-status").querySelector("svg")?.getAttribute("data-shape")).toBe("shield-warning");
    expect(first.getByTestId("finding-fixed-in").textContent).toBe("1.2.4");
    expect(first.getByTestId("finding-last-seen").textContent).toBe("2026-11-10 08:30:01");

    const second = within(rows[1] as HTMLElement);
    expect(second.getByTestId("severity-badge").textContent).toBe("Critical");
    expect(second.getByTestId("finding-link").textContent).toBe("@example/ui@4.0.0-rc.1");
    expect(second.getByTestId("finding-cve").textContent).toBe("CVE-2026-20001");
    expect(second.getByTestId("finding-cve-more").textContent).toBe("+2 more");
    expect(second.getByTestId("finding-source").textContent).toBe("Running server");
    expect(second.getByTestId("finding-fixed-in").textContent).toBe("No fix yet");

    const third = within(rows[2] as HTMLElement);
    expect(third.getByTestId("severity-badge").textContent).toBe("Unknown");
    expect(third.queryByTestId("finding-cve")).toBeNull();
    expect(third.getByTestId("finding-status").textContent).toBe("Fixed");
    expect(third.getByTestId("finding-status").querySelector("svg")?.getAttribute("data-shape")).toBe("check-circle");

    const fourth = within(rows[3] as HTMLElement);
    expect(fourth.getByTestId("finding-status").textContent).toBe("Ignored");
    expect(fourth.getByTestId("finding-status").querySelector("svg")?.getAttribute("data-shape")).toBe("eye-slash");
  });

  it("shows a withdrawn Finding with its own glyph, word and colour (D-060)", () => {
    render(<FindingStatusTag status="withdrawn" />);
    const tag = screen.getByTestId("finding-status");
    expect(tag.textContent).toBe("Withdrawn");
    expect(tag.getAttribute("data-status")).toBe("withdrawn");
    expect(tag.querySelector("svg")?.getAttribute("data-shape")).toBe("file-x");
    expect(tag.className).toContain("text-finding-withdrawn");
    expect(tag.className).toContain("border-finding-withdrawn");
  });

  it("offers no action on a withdrawn Finding", () => {
    render(
      <FindingDetail
        finding={finding({ status: "withdrawn" })}
        advisory={EXAMPLE_ADVISORY}
        appName="shop-web"
        build={null}
        confirmIgnore={false}
        now={NOW}
      />,
    );
    expect(screen.queryByRole("button", { name: /ignore|reopen/i })).toBeNull();
  });

  it("leaves the App column out on an App's own list", () => {
    render(<FindingList findings={[EXAMPLE_FINDING]} query={{}} clearHref={ROUTES.appFindings(appId)} />);
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).not.toContain("App");
  });

  it("says what Findings are and how components arrive when there is none at all", () => {
    render(<FindingList findings={[]} appNames={appNames} query={{}} clearHref="/findings" />);
    const empty = screen.getByTestId("findings-empty");
    expect(empty.textContent).toContain(
      "No findings. Anti Reverse checks the packages your builds ship and your servers run against known advisories.",
    );
    expect(empty.textContent).toContain("antireverse harden");
    expect(empty.textContent).toContain("--register");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("says no Finding matches when a filtered list is empty and offers to clear the filters", () => {
    render(<FindingList findings={[]} appNames={appNames} query={{ severity: "critical" }} clearHref="/findings" />);
    const empty = screen.getByTestId("findings-empty");
    expect(empty.textContent).toContain("No Findings match these filters.");
    expect(within(empty).getByRole("link", { name: "Show all Findings" }).getAttribute("href")).toBe("/findings");
  });

  it("names the advisory the list is narrowed to, with a way back to every Finding", () => {
    render(
      <FindingList
        findings={[EXAMPLE_FINDING]}
        appNames={appNames}
        query={{ advisory: "GHSA-2c3m-4p5q-6r7v" }}
        clearHref="/findings"
      />,
    );
    const scope = screen.getByTestId("findings-scope");
    expect(scope.textContent).toContain("GHSA-2c3m-4p5q-6r7v");
    expect(within(scope).getByRole("link", { name: "Show all Findings" }).getAttribute("href")).toBe("/findings");
  });
});

describe("FindingDetail", () => {
  const build: Build = { ...EXAMPLE_BUILD, component_count: 3 };

  function show(
    shown: Finding,
    options: { confirmIgnore?: boolean; advisory?: Advisory; build?: Build | null } = {},
  ): void {
    render(
      <FindingDetail
        finding={shown}
        advisory={options.advisory ?? EXAMPLE_ADVISORY}
        appName="shop-web"
        build={options.build === undefined ? build : options.build}
        confirmIgnore={options.confirmIgnore ?? false}
        now={NOW}
      />,
    );
  }

  it("heads the page with the severity, the advisory id, the status and the summary", () => {
    show(EXAMPLE_FINDING);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("GHSA-2c3m-4p5q-6r7v");
    expect(screen.getByTestId("finding-severity").textContent).toBe("High");
    expect(screen.getByTestId("finding-status").textContent).toBe("Open");
    expect(screen.getByTestId("finding-summary").textContent).toBe("Denial of service in example-parser");
    expect(screen.getByTestId("finding-back").getAttribute("href")).toBe("/findings");
  });

  it("lists the facts: package, dev dependency, App, Environment, the Build it was found in, times, aliases", () => {
    show(EXAMPLE_FINDING);
    const facts = within(screen.getByTestId("finding-facts"));
    expect(facts.getByTestId("fact-package").textContent).toBe("example-parser@1.2.3");
    expect(facts.getByTestId("fact-package").className).toMatch(MONO);
    expect(facts.getByTestId("fact-dev").textContent).toBe("No");
    expect(facts.getByTestId("fact-app").textContent).toBe("shop-web");
    expect(facts.getByTestId("environment-tag").textContent).toBe("Development");
    const where = facts.getByTestId("fact-build-link");
    expect(where.textContent).toBe("Build 1.4.0");
    expect(where.getAttribute("href")).toBe(`/apps/${appId}/builds/${EXAMPLE_FINDING.build_id}`);
    expect(facts.getByTestId("fact-first-seen").textContent).toBe("2026-11-10 08:30:01 UTC");
    expect(facts.getByTestId("fact-last-seen").textContent).toBe("2026-11-10 08:30:01 UTC");
    expect(facts.getAllByTestId("fact-alias").map((alias) => alias.textContent)).toEqual(["CVE-2026-10001"]);
  });

  it("names a Build it could not read by its id, and a runtime Finding by its server's Environment", () => {
    show(finding({ dev: true }), { build: null });
    expect(screen.getByTestId("fact-build-link").textContent).toBe(EXAMPLE_FINDING.build_id);
    expect(screen.getByTestId("fact-dev").textContent).toBe("Yes");
    cleanup();

    show(runtime, { build: null });
    expect(screen.queryByTestId("fact-build-link")).toBeNull();
    expect(screen.getByTestId("fact-where").textContent).toBe("Running server in production");
    expect(screen.getByTestId("fact-aliases").textContent).toContain("GHSA-zzzz-yyyy-xxxx");
  });

  it("renders the affected ranges readably and suggests the first fixed version above the installed one", () => {
    show(EXAMPLE_FINDING);
    expect(screen.getAllByTestId("finding-range").map((range) => range.textContent)).toEqual([
      "< 1.2.4",
      ">= 2.0.0, < 2.1.1",
    ]);
    expect(screen.getByTestId("finding-fix-suggestion").textContent).toBe("Upgrade to 1.2.4 or later");
    expect(screen.getAllByTestId("finding-fixed-version").map((version) => version.textContent)).toEqual([
      "1.2.4",
      "2.1.1",
    ]);
  });

  it("says there is no fix yet when the advisory names none", () => {
    show(runtime, {
      advisory: {
        ...EXAMPLE_ADVISORY,
        affected: [
          {
            package: { ecosystem: "npm", name: "@example/ui" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
          },
        ],
      },
    });
    expect(screen.getAllByTestId("finding-range").map((range) => range.textContent)).toEqual(["All versions"]);
    expect(screen.queryByTestId("finding-fix-suggestion")).toBeNull();
    expect(screen.getByTestId("finding-fix-none").textContent).toContain("No fix yet");
  });

  it("links the advisory on osv.dev as a plain external link", () => {
    show(EXAMPLE_FINDING);
    const link = screen.getByTestId("finding-osv-link");
    expect(link.getAttribute("href")).toBe("https://osv.dev/vulnerability/GHSA-2c3m-4p5q-6r7v");
    expect(link.getAttribute("rel")).toBe("noreferrer noopener");
  });

  it("offers Ignore as a link to the confirmation step; nothing is sent from the page itself", () => {
    show(EXAMPLE_FINDING);
    const ignore = screen.getByTestId("finding-ignore");
    expect(ignore.tagName).toBe("A");
    expect(ignore.getAttribute("href")).toBe(`/findings/${EXAMPLE_FINDING.id}?confirm=ignore`);
    expect(screen.queryByTestId("finding-confirm")).toBeNull();
    expect(screen.queryByTestId("finding-reopen")).toBeNull();
  });

  it("asks before ignoring, with a reason and a date from tomorrow up to 90 days ahead (30 by default)", async () => {
    show(EXAMPLE_FINDING, { confirmIgnore: true });
    const step = within(screen.getByTestId("finding-confirm"));
    expect(step.getByTestId("confirm-question").textContent).toBe(
      "Ignore GHSA-2c3m-4p5q-6r7v in example-parser@1.2.3 for shop-web (development)?",
    );
    const reason = step.getByLabelText("Reason") as HTMLInputElement;
    expect(reason.required).toBe(true);
    expect(reason.maxLength).toBe(200);
    const until = step.getByLabelText("Ignore until (UTC)") as HTMLInputElement;
    expect(until.type).toBe("date");
    expect(until.min).toBe("2026-11-12");
    expect(until.max).toBe("2027-02-09");
    expect(until.value).toBe("2026-12-11");
    expect(step.getByTestId("confirm-cancel").getAttribute("href")).toBe(`/findings/${EXAMPLE_FINDING.id}`);
    expect(screen.queryByTestId("finding-ignore")).toBeNull();

    fireEvent.change(reason, { target: { value: "Not reachable" } });
    await submit(step.getByTestId("confirm-submit"));
    expect(sent(actions.ignoreFindingAction)).toEqual({
      findingId: [EXAMPLE_FINDING.id],
      confirm: [EXAMPLE_FINDING.id],
      reason: ["Not reachable"],
      until: ["2026-12-11"],
    });
  });

  it("shows a refused reason or date next to its field and keeps what was typed", async () => {
    vi.mocked(actions.ignoreFindingAction).mockResolvedValue({
      ok: false,
      errors: [
        { path: "reason", message: "Enter a reason." },
        { path: "until", message: "Choose a date from tomorrow up to 90 days ahead." },
      ],
      values: { reason: "", until: "2027-03-01" },
    });
    show(EXAMPLE_FINDING, { confirmIgnore: true });
    // Filled in the browser; the action alone decides (here: it refuses both fields).
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: " " } });
    await submit(screen.getByTestId("confirm-submit"));
    expect(screen.getByTestId("error-summary").textContent).toContain("Enter a reason.");
    expect(screen.getByTestId("finding-reason-error").textContent).toBe("Enter a reason.");
    expect(screen.getByTestId("finding-until-error").textContent).toBe(
      "Choose a date from tomorrow up to 90 days ahead.",
    );
    expect((screen.getByLabelText("Ignore until (UTC)") as HTMLInputElement).value).toBe("2027-03-01");
  });

  it("shows why, until when and by whom an ignored Finding is ignored, and reopens it at once", async () => {
    show(ignored, { confirmIgnore: true });
    expect(screen.getByTestId("finding-status").textContent).toBe("Ignored");
    expect(screen.getByTestId("finding-ignore-reason").textContent).toBe("Only used in tests");
    expect(screen.getByTestId("finding-ignore-until").textContent).toBe("2026-12-11 00:00:00 UTC");
    expect(screen.getByTestId("finding-ignore-by").textContent).toBe("key_0123456789abcdef01234567");
    // Already ignored: no second ignore step, whatever the address says.
    expect(screen.queryByTestId("finding-confirm")).toBeNull();
    expect(screen.queryByTestId("finding-ignore")).toBeNull();
    await submit(screen.getByTestId("finding-reopen"));
    expect(sent(actions.reopenFindingAction)).toEqual({ findingId: [ignored.id] });
  });

  it("offers neither Ignore nor Reopen for a fixed Finding and says why", () => {
    show(fixed);
    expect(screen.queryByTestId("finding-ignore")).toBeNull();
    expect(screen.queryByTestId("finding-reopen")).toBeNull();
    expect(screen.getByTestId("finding-fixed-note")).toBeTruthy();
  });
});

describe("BuildDetail — Findings", () => {
  const build: Build = { ...EXAMPLE_BUILD, component_count: 412 };
  const other = finding({ id: "fnd_dddddddddddddddddddddddd", build_id: "bld_ffffffffffffffffffffffff" });

  it("counts the Build's open Findings by severity and links to its filtered list", () => {
    render(
      <BuildDetail
        build={build}
        appName="shop-web"
        findings={[
          EXAMPLE_FINDING,
          finding({ id: "fnd_eeeeeeeeeeeeeeeeeeeeeeee", severity: "critical" }),
          ignored,
          other,
        ]}
      />,
    );
    const section = within(screen.getByTestId("build-findings"));
    expect(section.getByRole("heading", { name: "Findings" })).toBeTruthy();
    expect(section.getByTestId("build-components").textContent).toBe("Components: 412");
    const counts = Object.fromEntries(
      section
        .getAllByTestId("build-findings-count")
        .map((count) => [count.getAttribute("data-severity"), count.textContent]),
    );
    expect(counts).toEqual({
      critical: "Critical1",
      high: "High1",
      medium: "Medium0",
      low: "Low0",
      unknown: "Unknown0",
    });
    expect(section.getByTestId("build-findings-link").getAttribute("href")).toBe(
      `/apps/${appId}/findings?build=${EXAMPLE_BUILD.build_id}`,
    );
  });

  it("says when no component list was sent, when nothing is open and when the Findings could not be read", () => {
    const { unmount } = render(<BuildDetail build={EXAMPLE_BUILD} appName="shop-web" findings={[ignored]} />);
    expect(screen.getByTestId("build-components").textContent).toBe("No component list was sent with this Build.");
    expect(screen.getByTestId("build-findings-none").textContent).toBe("No open Findings in this Build.");
    unmount();
    render(<BuildDetail build={build} appName="shop-web" findings={null} />);
    expect(screen.getByTestId("build-findings-unavailable")).toBeTruthy();
    expect(screen.getByTestId("build-components").textContent).toBe("Components: 412");
  });
});

describe("IncidentDetail — vulnerable component", () => {
  it("links the advisory of a vulnerable component Incident to the Finding list narrowed to it", () => {
    render(
      <IncidentDetail
        incident={EXAMPLE_FINDING_INCIDENT}
        detections={[]}
        evidence={[]}
        appName="shop-web"
        confirmResolve={false}
        actors={[]}
        containments={[]}
        now={NOW}
      />,
    );
    const link = screen.getByTestId("fact-advisory-link");
    expect(link.textContent).toBe("GHSA-2c3m-4p5q-6r7v");
    expect(link.getAttribute("href")).toBe("/findings?advisory=GHSA-2c3m-4p5q-6r7v");
    expect(link.className).toMatch(MONO);
  });
});
