import {
  type AlertChannel,
  type Detection,
  EXAMPLE_ALERT_CHANNEL,
  EXAMPLE_BUILD,
  EXAMPLE_CANARIES,
  EXAMPLE_CANARY_INCIDENT,
  EXAMPLE_DETECTION,
  EXAMPLE_INCIDENT,
  EXAMPLE_STORED_EVENT,
  type Incident,
  type IncidentStatus,
  SEVERITIES,
  type Severity,
} from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The screens are rendered with the Server Actions replaced by fakes: what a form sends is the contract.
vi.mock("@/app/actions.ts", () => ({
  updateIncidentAction: vi.fn(),
  createContainmentAction: vi.fn(),
  liftContainmentAction: vi.fn(),
  createAlertChannelAction: vi.fn(),
  deleteAlertChannelAction: vi.fn(),
  testAlertChannelAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import * as actions from "@/app/actions.ts";
import { AppShell } from "@/components/app-shell.tsx";
import { SeverityBadge } from "@/components/severity-badge.tsx";
import { AddChannelForm } from "@/features/alerts/add-channel-form.tsx";
import { ChannelList } from "@/features/alerts/channel-list.tsx";
import { IncidentDetail } from "@/features/incidents/incident-detail.tsx";
import { IncidentList } from "@/features/incidents/incident-list.tsx";
import { statusFrom } from "@/features/incidents/query.ts";
import { StatusFilter } from "@/features/incidents/status-filter.tsx";

const SECRET = `whsec_${"c".repeat(43)}`;
const FULL_URL = "https://hooks.example.com/services/T000/B000/secret-path-k/ar";
const organization = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-10T08:00:00.000Z" };
const appNames = new Map([[EXAMPLE_INCIDENT.app_id, "shop-web"]]);
/** The render time of an Incident page (slice 09: the containment confirmation states the expiry from it). */
const NOW = Date.UTC(2026, 10, 10, 9, 0, 0);

const incident = (overrides: Partial<Incident>): Incident => ({ ...EXAMPLE_INCIDENT, ...overrides });
const acknowledged = incident({
  id: "inc_aaaaaaaaaaaaaaaaaaaaaaaa",
  status: "acknowledged",
  severity: "medium",
  rule: "failed-signin-burst",
  title: "Failed sign-in burst",
  ip_prefix: "198.51.100.0/24",
});
const resolved = incident({
  id: "inc_bbbbbbbbbbbbbbbbbbbbbbbb",
  status: "resolved",
  app_id: "app_ffffffffffffffffffffffff",
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
  Object.defineProperty(navigator, "clipboard", { value: { writeText: vi.fn() }, configurable: true });
});

describe("SeverityBadge", () => {
  const expected: Record<Severity, { word: string; shape: string }> = {
    critical: { word: "Critical", shape: "warning-octagon" },
    high: { word: "High", shape: "warning" },
    medium: { word: "Medium", shape: "warning-circle" },
    low: { word: "Low", shape: "info" },
    info: { word: "Info", shape: "circle" },
  };

  it.each(SEVERITIES)("draws %s as a shape, a word and its token colour — never colour alone", (severity) => {
    render(<SeverityBadge severity={severity} />);
    const badge = screen.getByTestId("severity-badge");
    expect(badge.getAttribute("data-severity")).toBe(severity);
    expect(badge.textContent).toBe(expected[severity].word);
    const shape = badge.querySelector("svg");
    expect(shape?.getAttribute("aria-hidden")).toBe("true");
    expect(shape?.getAttribute("data-shape")).toBe(expected[severity].shape);
    expect(badge.className).toContain(`text-sev-${severity === "critical" ? "critical-text" : severity}`);
    // Tokens only: no raw colour value in the markup.
    expect(badge.outerHTML).not.toMatch(/#[0-9a-fA-F]{3,8}\b|rgb\(/);
  });
});

describe("StatusFilter", () => {
  it("links to every status and marks the current one with aria-current", () => {
    render(<StatusFilter current="acknowledged" />);
    const nav = screen.getByRole("navigation", { name: "Filter by status" });
    const links = within(nav).getAllByRole("link");
    expect(links.map((link) => [link.textContent, link.getAttribute("href")])).toEqual([
      ["All", "/incidents"],
      ["Open", "/incidents?status=open"],
      ["Acknowledged", "/incidents?status=acknowledged"],
      ["Resolved", "/incidents?status=resolved"],
    ]);
    expect(screen.getByTestId("incident-filter-acknowledged").getAttribute("aria-current")).toBe("page");
    expect(screen.getByTestId("incident-filter-all").getAttribute("aria-current")).toBeNull();
  });

  it("marks All when there is no filter", () => {
    render(<StatusFilter current={undefined} />);
    expect(screen.getByTestId("incident-filter-all").getAttribute("aria-current")).toBe("page");
  });

  it("reads only a known status from the address", () => {
    expect(statusFrom("open")).toBe("open");
    expect(statusFrom("resolved")).toBe("resolved");
    expect(statusFrom(undefined)).toBeUndefined();
    expect(statusFrom("closed")).toBeUndefined();
    expect(statusFrom(["open", "resolved"])).toBeUndefined();
  });
});

describe("IncidentList", () => {
  it("shows severity, title, App name, status and last seen for each Incident, in the API's order", () => {
    render(
      <IncidentList incidents={[EXAMPLE_INCIDENT, acknowledged, resolved]} appNames={appNames} status={undefined} />,
    );
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Severity",
      "Incident",
      "App",
      "Status",
      "Last seen UTC",
    ]);
    const rows = screen.getAllByTestId("incident-row");
    expect(rows.map((row) => row.getAttribute("data-incident-id"))).toEqual([
      EXAMPLE_INCIDENT.id,
      acknowledged.id,
      resolved.id,
    ]);
    const first = within(rows[0] as HTMLElement);
    expect(first.getByTestId("severity-badge").textContent).toBe("High");
    expect(first.getByTestId("severity-badge").querySelector("svg")?.getAttribute("data-shape")).toBe("warning");
    const link = first.getByRole("link", { name: "Blocked burst" });
    expect(link.getAttribute("href")).toBe(`/incidents/${EXAMPLE_INCIDENT.id}`);
    expect(link.getAttribute("data-testid")).toBe("incident-link");
    expect(first.getByTestId("incident-app").textContent).toBe("shop-web");
    expect(first.getByTestId("incident-status").textContent).toBe("Open");
    expect(first.getByTestId("incident-last-seen").textContent).toBe("2026-11-10 08:19:59");

    const second = within(rows[1] as HTMLElement);
    expect(second.getByTestId("severity-badge").textContent).toBe("Medium");
    expect(second.getByTestId("incident-status").textContent).toBe("Acknowledged");
    // An App that is not in the list (deleted, or not loaded) shows its identifier.
    expect(within(rows[2] as HTMLElement).getByTestId("incident-app").textContent).toBe(resolved.app_id);
    expect(within(rows[2] as HTMLElement).getByTestId("incident-status").textContent).toBe("Resolved");
  });

  it("lists a Canary Incident with the title Canary used, like any rule", () => {
    render(<IncidentList incidents={[EXAMPLE_CANARY_INCIDENT]} appNames={appNames} status={undefined} />);
    const row = within(screen.getByTestId("incident-row"));
    expect(row.getByRole("link", { name: "Canary used" }).getAttribute("href")).toBe(
      `/incidents/${EXAMPLE_CANARY_INCIDENT.id}`,
    );
    expect(row.getByTestId("severity-badge").textContent).toBe("High");
  });

  it("says what will appear when there is no Incident at all, and points at alert set-up", () => {
    render(<IncidentList incidents={[]} appNames={appNames} status={undefined} />);
    const empty = screen.getByTestId("incidents-empty");
    expect(empty.textContent).toContain(
      "No Incidents yet. An Incident opens when a managed detection rule sees a burst of blocked requests or failed sign in attempts from one network.",
    );
    expect(within(empty).getByRole("link", { name: "Set up alert channels" }).getAttribute("href")).toBe(
      "/settings/alerts",
    );
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("states the filter when a filtered list is empty and offers to clear it", () => {
    render(<IncidentList incidents={[]} appNames={appNames} status="acknowledged" />);
    const empty = screen.getByTestId("incidents-empty");
    expect(empty.textContent).toContain("No Incidents with the status Acknowledged.");
    expect(within(empty).getByRole("link", { name: "Show all Incidents" }).getAttribute("href")).toBe("/incidents");
  });
});

describe("IncidentDetail", () => {
  const detections: Detection[] = [
    EXAMPLE_DETECTION,
    {
      ...EXAMPLE_DETECTION,
      id: "dtc_aaaaaaaaaaaaaaaaaaaaaaaa",
      count: 20,
      window_start: "2026-11-10T08:40:00.000Z",
      window_end: "2026-11-10T08:41:30.000Z",
      detected_at: "2026-11-10T08:41:31.000Z",
    },
  ];
  const evidence = [
    EXAMPLE_STORED_EVENT,
    {
      ...EXAMPLE_STORED_EVENT,
      event_id: "0193f9a0-0000-7000-8000-000000000002",
      request: { ...EXAMPLE_STORED_EVENT.request, status: 403 },
    },
  ];

  function show(status: IncidentStatus, confirmResolve = false, more: Partial<Incident> = {}) {
    render(
      <IncidentDetail
        incident={incident({ status, detection_count: 2, last_seen: "2026-11-10T08:41:30.000Z", ...more })}
        detections={detections}
        evidence={evidence}
        appName="shop-web"
        confirmResolve={confirmResolve}
        actors={[]}
        containments={[]}
        now={NOW}
      />,
    );
  }

  it("heads the page with the severity badge, the title and the status", () => {
    show("open");
    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("Blocked burst");
    // The eyebrow is a way back to the list, not the identifier (it is set in capitals).
    expect(screen.getByTestId("incident-back").getAttribute("href")).toBe("/incidents");
    expect(document.body.textContent).not.toContain(EXAMPLE_INCIDENT.id);
    expect(screen.getByTestId("incident-severity").textContent).toBe("High");
    expect(screen.getByTestId("incident-severity").getAttribute("data-severity")).toBe("high");
    expect(screen.getByTestId("incident-status").textContent).toBe("Open");
  });

  it("lists the facts: App, Environment, network, first and last seen, Detection count", () => {
    show("open");
    const facts = screen.getByTestId("incident-facts");
    const terms = within(facts)
      .getAllByRole("term")
      .map((term) => term.textContent);
    expect(terms).toEqual(["App", "Environment", "Network", "Detection rule", "First seen", "Last seen", "Detections"]);
    expect(within(facts).getByTestId("fact-app").textContent).toBe("shop-web");
    expect(within(facts).getByTestId("environment-tag").textContent).toBe("Development");
    expect(within(facts).getByTestId("fact-network").textContent).toBe("203.0.113.0/24");
    expect(within(facts).getByTestId("fact-rule").textContent).toBe("Blocked burst");
    expect(within(facts).getByTestId("fact-first-seen").textContent).toBe("2026-11-10 08:18:00 UTC");
    expect(within(facts).getByTestId("fact-last-seen").textContent).toBe("2026-11-10 08:41:30 UTC");
    expect(within(facts).getByTestId("fact-detections").textContent).toBe("2");
  });

  describe("a Credential stuffing Incident (slice 08)", () => {
    const PREFIX = "198.51.100.0/24";
    const RULE_ID = "rul_fedcba9876543210fedcba98";
    const HASH = "iph_2932b22c0f1e4d5a9b8c7d6e5f4a3b2c";
    const stuffing = incident({
      rule: "credential-stuffing",
      title: "Credential stuffing",
      severity: "high",
      ip_prefix: PREFIX,
    });
    const stuffingDetection: Detection = {
      ...EXAMPLE_DETECTION,
      rule: "credential-stuffing",
      ip_prefix: PREFIX,
      count: 50,
      window_start: "2026-11-10T08:15:00.000Z",
      window_end: "2026-11-10T08:19:59.000Z",
    };
    const login = { method: "POST", route: "/login", latency_ms: 12.5 } as const;
    const stuffingEvidence = [
      {
        ...EXAMPLE_STORED_EVENT,
        event_id: "0193f9a0-0000-7000-8000-000000000011",
        request: { ...login, status: 429 },
        decision: { ...EXAMPLE_STORED_EVENT.decision, action: "throttle", mode: "enforce", rule_id: RULE_ID } as const,
        actor: { ...EXAMPLE_STORED_EVENT.actor, ip_prefix: PREFIX },
      },
      {
        ...EXAMPLE_STORED_EVENT,
        event_id: "0193f9a0-0000-7000-8000-000000000010",
        request: { ...login, status: 401 },
        actor: { ...EXAMPLE_STORED_EVENT.actor, ip_prefix: PREFIX },
      },
    ];

    function showStuffing(status: IncidentStatus = "open") {
      render(
        <IncidentDetail
          incident={{ ...stuffing, status }}
          detections={[stuffingDetection]}
          evidence={stuffingEvidence}
          appName="shop-web"
          confirmResolve={false}
          actors={[{ ip_hash: HASH, events: 2 }]}
          containments={[]}
          now={NOW}
        />,
      );
    }

    it("heads the page like a Blocked burst: High, the title, the network and the rule among the facts", () => {
      showStuffing();
      expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Credential stuffing");
      expect(screen.getByTestId("incident-severity").getAttribute("data-severity")).toBe("high");
      const facts = screen.getByTestId("incident-facts");
      const terms = within(facts)
        .getAllByRole("term")
        .map((term) => term.textContent);
      expect(terms).toEqual([
        "App",
        "Environment",
        "Network",
        "Detection rule",
        "First seen",
        "Last seen",
        "Detections",
      ]);
      expect(within(facts).getByTestId("fact-network").textContent).toBe(PREFIX);
      expect(within(facts).getByTestId("fact-rule").textContent).toBe("Credential stuffing");
    });

    it("offers Containment of the Actor and of the network, and lists the Actors and the blocks", () => {
      showStuffing();
      const bar = screen.getByTestId("containment-bar");
      expect(
        within(bar)
          .getAllByRole("button")
          .map((button) => button.textContent),
      ).toEqual(["Block actor", "Block network"]);
      expect((within(bar).getByLabelText("Actor") as HTMLSelectElement).value).toBe(HASH);
      expect(screen.queryByTestId("containment-clone-note")).toBeNull();
      expect(screen.getByRole("heading", { name: "Actors" })).toBeTruthy();
      expect(screen.getAllByTestId("actor-row")).toHaveLength(1);
      expect(screen.getByRole("heading", { name: "Blocks" })).toBeTruthy();
    });

    it("names the rule and the counted window in the timeline", () => {
      showStuffing();
      const [item] = screen.getAllByTestId("detection-item");
      expect(item?.textContent).toContain("Credential stuffing");
      expect(item?.textContent).toContain("50");
      expect(item?.textContent).toContain("08:15:00");
    });

    it("shows the evidence with the Throttled chip on the refused request and its 429", () => {
      showStuffing();
      const rows = within(screen.getByTestId("incident-evidence")).getAllByTestId("event-row");
      expect(rows).toHaveLength(2);
      const cells = (row: HTMLElement | undefined) =>
        within(row as HTMLElement)
          .getAllByRole("cell")
          .map((cell) => cell.textContent);
      expect(cells(rows[0])[1]).toBe("Throttled");
      expect(cells(rows[0]).slice(4, 7)).toEqual(["POST", "/login", "429"]);
      const chip = within(rows[0] as HTMLElement).getByTestId("decision-chip");
      expect(chip.getAttribute("data-decision")).toBe("throttle");
      expect(chip.querySelector("svg")?.getAttribute("data-shape")).toBe("hourglass-medium");
      expect(cells(rows[1]).slice(4, 7)).toEqual(["POST", "/login", "401"]);
      expect(cells(rows[1])[8]).toBe(PREFIX);
    });

    it("lists it among the Incidents by its title, with the High badge", () => {
      render(<IncidentList incidents={[stuffing]} appNames={appNames} status={undefined} />);
      const row = screen.getByTestId("incident-row");
      expect(within(row).getByRole("link", { name: "Credential stuffing" }).getAttribute("href")).toBe(
        `/incidents/${stuffing.id}`,
      );
      expect(row.getAttribute("data-severity")).toBe("high");
    });
  });

  describe("a Canary Incident", () => {
    const [key] = EXAMPLE_CANARIES;
    if (!key) throw new Error("EXAMPLE_CANARIES is empty");
    const canaryBuild = {
      ...EXAMPLE_BUILD,
      canaries: EXAMPLE_CANARIES.map(({ id, kind }) => ({ id, kind })),
    };
    const canaryDetection: Detection = { ...EXAMPLE_DETECTION, rule: "canary-touched", count: 1, canary_id: key.id };

    function showCanary(build: typeof canaryBuild | null) {
      render(
        <IncidentDetail
          incident={EXAMPLE_CANARY_INCIDENT}
          detections={[canaryDetection]}
          evidence={[]}
          appName="shop-web"
          confirmResolve={false}
          canaryBuild={build}
          actors={[]}
          containments={[]}
          now={NOW}
        />,
      );
    }

    it("adds the Canary (kind word and id) and its Build, linked, to the facts", () => {
      showCanary(canaryBuild);
      expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Canary used");
      const facts = screen.getByTestId("incident-facts");
      const terms = within(facts)
        .getAllByRole("term")
        .map((term) => term.textContent);
      expect(terms).toEqual([
        "App",
        "Environment",
        "Network",
        "Detection rule",
        "Canary",
        "Build",
        "First seen",
        "Last seen",
        "Detections",
      ]);
      expect(within(facts).getByTestId("fact-rule").textContent).toBe("Canary used");
      const canary = within(within(facts).getByTestId("fact-canary"));
      expect(canary.getByTestId("fact-canary-kind").textContent).toBe("Decoy key");
      expect(canary.getByTestId("fact-canary-id").textContent).toBe(key.id);
      const link = within(facts).getByTestId("fact-build-link");
      expect(link.getAttribute("href")).toBe(
        `/apps/${EXAMPLE_CANARY_INCIDENT.app_id}/builds/${EXAMPLE_CANARY_INCIDENT.build_id}`,
      );
      expect(link.textContent).toBe("Build 1.4.0");
      expect(within(facts).getByTestId("fact-build-id").textContent).toBe(EXAMPLE_CANARY_INCIDENT.build_id);
      // The decoy value never reaches the Console.
      expect(document.body.textContent).not.toContain(key.value);
    });

    it("still names the Canary by id and links the Build by id when the Build could not be read", () => {
      showCanary(null);
      const facts = screen.getByTestId("incident-facts");
      expect(within(facts).queryByTestId("fact-canary-kind")).toBeNull();
      expect(within(facts).getByTestId("fact-canary-id").textContent).toBe(key.id);
      const link = within(facts).getByTestId("fact-build-link");
      expect(link.getAttribute("href")).toBe(
        `/apps/${EXAMPLE_CANARY_INCIDENT.app_id}/builds/${EXAMPLE_CANARY_INCIDENT.build_id}`,
      );
      expect(link.textContent).toBe(EXAMPLE_CANARY_INCIDENT.build_id);
    });

    it("names the Canary rule in the timeline", () => {
      showCanary(canaryBuild);
      expect(screen.getByTestId("detection-item").textContent).toContain("Canary used");
    });
  });

  it("shows no Canary or Build fact for an Incident of another rule", () => {
    show("open");
    expect(screen.queryByTestId("fact-canary")).toBeNull();
    expect(screen.queryByTestId("fact-build-link")).toBeNull();
  });

  it("shows the Detections as a timeline, oldest first, with count, window and detection time", () => {
    show("open");
    const timeline = screen.getByTestId("incident-timeline");
    const items = within(timeline).getAllByTestId("detection-item");
    expect(items.map((item) => item.getAttribute("data-detection-id"))).toEqual([
      EXAMPLE_DETECTION.id,
      "dtc_aaaaaaaaaaaaaaaaaaaaaaaa",
    ]);
    expect(items[0]?.textContent).toContain("Detected 2026-11-10 08:20:00 UTC");
    expect(items[0]?.textContent).toContain("20 matching Events between 08:18:00 and 08:19:59 UTC");
  });

  it("shows the evidence with the live-feed row format: time, Decision chip, Client, Signature, method, route, status, network", () => {
    show("open");
    const section = screen.getByTestId("incident-evidence");
    const rows = within(section).getAllByTestId("event-row");
    expect(rows).toHaveLength(2);
    const row = within(rows[0] as HTMLElement);
    expect(row.getByTestId("decision-chip").getAttribute("data-decision")).toBe(EXAMPLE_STORED_EVENT.decision.action);
    expect(rows[0]?.textContent).toContain(EXAMPLE_STORED_EVENT.request.method);
    expect(rows[0]?.textContent).toContain(EXAMPLE_STORED_EVENT.request.route);
    expect(
      within(section)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual(["Time UTC", "Decision", "Client", "Signature", "Method", "Route", "Status", "Latency", "Network"]);
    expect(row.getByTestId("attestation-chip").getAttribute("data-attestation")).toBe("unreported");
    expect(row.getByTestId("signature-chip").getAttribute("data-signature")).toBe("unreported");
    expect(within(section).getByTestId("client-note").textContent).toBe(
      "Client shows the Guard attestation Shield verified for each request. It is evidence, not proof.",
    );
  });

  it("says when there is no stored evidence", () => {
    render(
      <IncidentDetail
        incident={EXAMPLE_INCIDENT}
        detections={[]}
        evidence={[]}
        appName="shop-web"
        confirmResolve={false}
        actors={[]}
        containments={[]}
        now={NOW}
      />,
    );
    expect(screen.getByTestId("evidence-empty").textContent).toBe(
      "No stored Events from this network in the Incident's time span.",
    );
    expect(screen.queryAllByTestId("event-row")).toHaveLength(0);
  });

  it("offers Acknowledge and Resolve while open; Acknowledge sends at once, Resolve only links to the confirmation", async () => {
    show("open");
    const acknowledge = screen.getByRole("button", { name: "Acknowledge" });
    expect(acknowledge.getAttribute("data-testid")).toBe("incident-acknowledge");
    const resolve = screen.getByRole("link", { name: "Resolve" });
    expect(resolve.getAttribute("data-testid")).toBe("incident-resolve");
    expect(resolve.getAttribute("href")).toBe(`/incidents/${EXAMPLE_INCIDENT.id}?confirm=resolve`);
    // Resolve is not a button on the page: nothing can send it without the confirmation step.
    expect(screen.queryByRole("button", { name: "Resolve" })).toBeNull();

    await submit(acknowledge);
    expect(sent(actions.updateIncidentAction)).toEqual({ incidentId: [EXAMPLE_INCIDENT.id], status: ["acknowledged"] });
  });

  it("offers only Resolve while acknowledged", () => {
    show("acknowledged");
    expect(screen.queryByTestId("incident-acknowledge")).toBeNull();
    expect(screen.getByTestId("incident-resolve")).toBeTruthy();
  });

  it("offers no action once resolved, and says why", () => {
    show("resolved", true);
    expect(screen.queryByTestId("incident-acknowledge")).toBeNull();
    expect(screen.queryByTestId("incident-resolve")).toBeNull();
    // A resolved Incident never shows the confirmation, whatever the address says.
    expect(screen.queryByTestId("incident-confirm")).toBeNull();
    expect(screen.getByTestId("incident-resolved-note").textContent).toBe(
      "This Incident is resolved. A later burst from the same network opens a new one.",
    );
  });

  it("asks once before resolving, naming the Incident, the App and the Environment", async () => {
    show("acknowledged", true);
    const dialog = screen.getByTestId("incident-confirm");
    expect(dialog.getAttribute("role")).toBe("alertdialog");
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Resolve Blocked burst on shop-web (development)? A later burst from 203.0.113.0/24 will open a new Incident.",
    );
    expect(dialog.textContent).toContain("A resolved Incident is never reopened.");
    expect(within(dialog).getByTestId("confirm-cancel").getAttribute("href")).toBe(`/incidents/${EXAMPLE_INCIDENT.id}`);
    // While the step is open the Resolve link gives way to it.
    expect(screen.queryByTestId("incident-resolve")).toBeNull();

    await submit(within(dialog).getByTestId("confirm-submit"));
    expect(sent(actions.updateIncidentAction)).toEqual({
      incidentId: [EXAMPLE_INCIDENT.id],
      status: ["resolved"],
      confirm: [EXAMPLE_INCIDENT.id],
    });
  });

  it("shows the action's refusal — e.g. the Incident changed (409) — in the error summary", async () => {
    vi.mocked(actions.updateIncidentAction).mockResolvedValue({
      ok: false,
      errors: [
        {
          path: "",
          message:
            "This Incident changed since the page was loaded, so nothing was saved. Reload the page and try again.",
        },
      ],
    });
    show("open");
    await submit(screen.getByTestId("incident-acknowledge"));
    expect(screen.getByTestId("error-summary").textContent).toContain(
      "This Incident changed since the page was loaded, so nothing was saved. Reload the page and try again.",
    );
  });
});

describe("ChannelList", () => {
  const slack: AlertChannel = {
    ...EXAMPLE_ALERT_CHANNEL,
    id: "chn_aaaaaaaaaaaaaaaaaaaaaaaa",
    kind: "slack",
    name: "Ops Slack",
    host: "hooks.slack.com",
    url_last4: "Zx9Q",
  };
  const row = (id: string): HTMLElement => {
    const found = screen
      .getAllByTestId("channel-row")
      .find((element) => element.getAttribute("data-channel-id") === id);
    if (!found) throw new Error(`no row for ${id}`);
    return found;
  };

  it("lists kind, name, host…last4 and created time; never the URL", () => {
    render(<ChannelList channels={[EXAMPLE_ALERT_CHANNEL, slack]} confirmRemoveId={undefined} />);
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Name",
      "Kind",
      "Destination",
      "Created UTC",
      "Actions",
    ]);
    const hook = within(row(EXAMPLE_ALERT_CHANNEL.id));
    expect(hook.getByRole("rowheader").textContent).toBe("Ops webhook");
    expect(hook.getByTestId("channel-kind").textContent).toBe("Webhook");
    expect(hook.getByTestId("channel-destination").textContent).toBe("hooks.example.com…k/ar");
    expect(hook.getByTestId("channel-created-at").textContent).toBe("2026-11-10 08:00:00");
    expect(within(row(slack.id)).getByTestId("channel-kind").textContent).toBe("Slack");
    expect(within(row(slack.id)).getByTestId("channel-destination").textContent).toBe("hooks.slack.com…Zx9Q");
    expect(document.body.innerHTML).not.toContain("https://");
  });

  it("says what will appear when there is no channel", () => {
    render(<ChannelList channels={[]} confirmRemoveId={undefined} />);
    expect(screen.getByTestId("channels-empty").textContent).toBe(
      "No alert channels yet. Add a webhook or a Slack channel to be told when an Incident opens.",
    );
  });

  it("sends a test to one channel and shows Delivered", async () => {
    vi.mocked(actions.testAlertChannelAction).mockResolvedValue({ ok: true, outcome: "delivered", statusCode: 204 });
    render(<ChannelList channels={[EXAMPLE_ALERT_CHANNEL, slack]} confirmRemoveId={undefined} />);
    const test = within(row(slack.id)).getByRole("button", { name: "Send test" });
    expect(test.getAttribute("data-testid")).toBe("channel-test");
    await submit(test);
    expect(sent(actions.testAlertChannelAction)).toEqual({ channelId: [slack.id] });
    const outcome = within(row(slack.id)).getByTestId("channel-test-outcome");
    expect(outcome.textContent).toBe("Delivered");
    expect(outcome.getAttribute("data-outcome")).toBe("delivered");
    expect(outcome.getAttribute("role")).toBe("status");
    // Only the channel that was tested shows an outcome.
    expect(within(row(EXAMPLE_ALERT_CHANNEL.id)).queryByTestId("channel-test-outcome")).toBeNull();
  });

  it("shows Failed with the status code, or with no response", async () => {
    vi.mocked(actions.testAlertChannelAction).mockResolvedValueOnce({ ok: true, outcome: "failed", statusCode: 500 });
    render(<ChannelList channels={[EXAMPLE_ALERT_CHANNEL]} confirmRemoveId={undefined} />);
    await submit(screen.getByTestId("channel-test"));
    expect(screen.getByTestId("channel-test-outcome").textContent).toBe("Failed — status 500");
    expect(screen.getByTestId("channel-test-outcome").getAttribute("data-outcome")).toBe("failed");

    vi.mocked(actions.testAlertChannelAction).mockResolvedValueOnce({ ok: true, outcome: "failed", statusCode: null });
    await submit(screen.getByTestId("channel-test"));
    expect(screen.getByTestId("channel-test-outcome").textContent).toBe("Failed — no response");
  });

  it("shows a refusal of the test as the outcome", async () => {
    vi.mocked(actions.testAlertChannelAction).mockResolvedValueOnce({
      ok: false,
      message: "This channel no longer exists. Reload the page to see the current list.",
    });
    render(<ChannelList channels={[EXAMPLE_ALERT_CHANNEL]} confirmRemoveId={undefined} />);
    await submit(screen.getByTestId("channel-test"));
    expect(screen.getByTestId("channel-test-outcome").textContent).toBe(
      "This channel no longer exists. Reload the page to see the current list.",
    );
  });

  it("makes Remove a link to the confirmation step, never a direct removal", () => {
    render(<ChannelList channels={[EXAMPLE_ALERT_CHANNEL]} confirmRemoveId={undefined} />);
    const remove = screen.getByRole("link", { name: "Remove" });
    expect(remove.getAttribute("data-testid")).toBe("channel-remove");
    expect(remove.getAttribute("href")).toBe(`/settings/alerts?remove=${EXAMPLE_ALERT_CHANNEL.id}`);
    expect(screen.queryByTestId("channel-confirm")).toBeNull();
  });

  it("asks before removing, naming the channel and its destination, and sends the confirmation", async () => {
    render(<ChannelList channels={[EXAMPLE_ALERT_CHANNEL, slack]} confirmRemoveId={EXAMPLE_ALERT_CHANNEL.id} />);
    const dialog = screen.getByTestId("channel-confirm");
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Remove the alert channel Ops webhook? New Incidents will no longer be sent to hooks.example.com…k/ar.",
    );
    expect(dialog.textContent).toContain("This cannot be undone.");
    expect(within(dialog).getByTestId("confirm-cancel").getAttribute("href")).toBe("/settings/alerts");
    await submit(within(dialog).getByTestId("confirm-submit"));
    expect(sent(actions.deleteAlertChannelAction)).toEqual({
      channelId: [EXAMPLE_ALERT_CHANNEL.id],
      confirm: [EXAMPLE_ALERT_CHANNEL.id],
    });
  });

  it("opens no confirmation for an id that is not listed", () => {
    render(<ChannelList channels={[EXAMPLE_ALERT_CHANNEL]} confirmRemoveId="chn_ffffffffffffffffffffffff" />);
    expect(screen.queryByTestId("channel-confirm")).toBeNull();
  });
});

describe("AddChannelForm", () => {
  const fill = (kind: string, name: string, url: string) => {
    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: kind } });
    fireEvent.change(screen.getByLabelText("Channel name"), { target: { value: name } });
    fireEvent.change(screen.getByLabelText("URL"), { target: { value: url } });
  };

  it("has labelled fields for kind (Webhook or Slack), name and URL", () => {
    render(<AddChannelForm />);
    const kind = screen.getByLabelText("Kind") as HTMLSelectElement;
    expect(Array.from(kind.options).map((option) => [option.value, option.textContent])).toEqual([
      ["webhook", "Webhook"],
      ["slack", "Slack"],
    ]);
    expect((screen.getByLabelText("URL") as HTMLInputElement).type).toBe("url");
    expect(screen.getByRole("button", { name: "Add channel" }).getAttribute("data-testid")).toBe("channel-add");
  });

  it("shows a new webhook's signing secret once, and never the URL", async () => {
    vi.mocked(actions.createAlertChannelAction).mockResolvedValue({
      ok: true,
      channel: EXAMPLE_ALERT_CHANNEL,
      signingSecret: SECRET,
    });
    render(<AddChannelForm />);
    fill("webhook", "Ops webhook", FULL_URL);
    await submit(screen.getByTestId("channel-add"));
    expect(sent(actions.createAlertChannelAction)).toEqual({
      kind: ["webhook"],
      name: ["Ops webhook"],
      url: [FULL_URL],
    });
    expect(screen.getByTestId("channel-created").textContent).toBe("Ops webhook was added");
    expect(screen.getByTestId("signing-secret").textContent).toBe(SECRET);
    expect(screen.getByRole("heading", { name: "Signing secret — shown once" })).toBeTruthy();
    expect(document.body.innerHTML).not.toContain(FULL_URL);

    // Done: the secret leaves the screen and cannot be brought back.
    await submit(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByTestId("signing-secret")).toBeNull();
    expect(document.body.innerHTML).not.toContain(SECRET);
    expect(screen.getByTestId("channel-add")).toBeTruthy();
  });

  it("shows no secret for a Slack channel", async () => {
    const slack = { ...EXAMPLE_ALERT_CHANNEL, kind: "slack" as const, name: "Ops Slack" };
    vi.mocked(actions.createAlertChannelAction).mockResolvedValue({ ok: true, channel: slack });
    render(<AddChannelForm />);
    fill("slack", "Ops Slack", FULL_URL);
    await submit(screen.getByTestId("channel-add"));
    expect(screen.getByTestId("channel-created").textContent).toBe("Ops Slack was added");
    expect(screen.queryByTestId("signing-secret")).toBeNull();
    expect(document.body.innerHTML).not.toMatch(/whsec_/);
  });

  it("shows a refused URL below the field without echoing it", async () => {
    vi.mocked(actions.createAlertChannelAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "url", message: "This address cannot receive alerts. Use an https:// URL on a public host." }],
      values: { kind: "slack", name: "Ops" },
    });
    render(<AddChannelForm />);
    fill("slack", "Ops", FULL_URL);
    await submit(screen.getByTestId("channel-add"));
    const url = screen.getByLabelText("URL") as HTMLInputElement;
    expect(url.getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByTestId("channel-url-error").textContent).toBe(
      "This address cannot receive alerts. Use an https:// URL on a public host.",
    );
    expect(url.getAttribute("aria-describedby")).toContain("channel-url-error");
    expect(screen.getByTestId("error-summary")).toBeTruthy();
    expect(document.body.innerHTML).not.toContain(FULL_URL);
    expect((screen.getByLabelText("Channel name") as HTMLInputElement).value).toBe("Ops");
    expect((screen.getByLabelText("Kind") as HTMLSelectElement).value).toBe("slack");
  });

  it("shows the 10-channel cap", async () => {
    vi.mocked(actions.createAlertChannelAction).mockResolvedValue({
      ok: false,
      errors: [
        { path: "", message: "An organization holds at most 10 alert channels. Remove one before adding another." },
      ],
      values: { kind: "webhook", name: "Ops" },
    });
    render(<AddChannelForm />);
    fill("webhook", "Ops", FULL_URL);
    await submit(screen.getByTestId("channel-add"));
    expect(screen.getByTestId("error-summary").textContent).toContain(
      "An organization holds at most 10 alert channels. Remove one before adding another.",
    );
  });
});

describe("AppShell navigation", () => {
  it("has Apps, Incidents and Findings in the main navigation and Alerts in settings, marking the current one", () => {
    render(
      <AppShell organization={organization} current="incidents">
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
    const settings = screen.getByRole("navigation", { name: "Settings" });
    expect(within(settings).getByRole("link", { name: "Alerts" }).getAttribute("href")).toBe("/settings/alerts");
    expect(screen.getByTestId("nav-incidents").getAttribute("aria-current")).toBe("page");
    expect(screen.getByTestId("nav-apps").getAttribute("aria-current")).toBeNull();
    expect(screen.getByTestId("nav-alerts").getAttribute("aria-current")).toBeNull();
  });

  it("marks Alerts on the alert settings", () => {
    render(
      <AppShell organization={organization} current="alerts">
        <p>content</p>
      </AppShell>,
    );
    expect(screen.getByTestId("nav-alerts").getAttribute("aria-current")).toBe("page");
  });
});
