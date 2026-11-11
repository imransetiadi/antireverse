import {
  type Build,
  type Detection,
  EXAMPLE_BUILD,
  EXAMPLE_CLONE_INCIDENT,
  EXAMPLE_DETECTION,
  EXAMPLE_INCIDENT,
  EXAMPLE_STORED_EVENT,
  type Incident,
} from "@antireverse/protocol";
import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Slice 10, contract P4: the Clone Beacon on the Build page, and a clone Incident on the Incident page and in
// the Incident list — rendered with the Server Actions replaced by fakes.

// The monospace named text styles (UIUX.md §4.3): identifiers, hashes, routes and data are set in Geist Mono.
const MONO = /\bcode-[1-3]\b/;

vi.mock("@/app/actions.ts", () => ({
  updateIncidentAction: vi.fn(),
  createContainmentAction: vi.fn(),
  liftContainmentAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import { BuildDetail } from "@/features/builds/build-detail.tsx";
import { ContainmentBar } from "@/features/containment/containment-bar.tsx";
import { IncidentDetail } from "@/features/incidents/incident-detail.tsx";
import { IncidentList } from "@/features/incidents/incident-list.tsx";

const NOW = Date.UTC(2026, 10, 10, 11, 0, 0);
const ORIGINS = ["https://shop.example", "https://www.shop.example:8443"];
const LONG_ORIGIN = `https://${"a".repeat(60)}.${"b".repeat(60)}.example`;
const withBeacon: Build = { ...EXAMPLE_BUILD, beacon: { origins: ORIGINS } };
const appNames = new Map([[EXAMPLE_INCIDENT.app_id, "shop-web"]]);

/** Two reports of the clone: one from a known network, one whose reporter address had no usable prefix. */
const cloneDetections: Detection[] = [
  {
    ...EXAMPLE_DETECTION,
    id: "dtc_bbbbbbbbbbbbbbbbbbbbbbbb",
    rule: "clone-origin",
    ip_prefix: null,
    count: 1,
    window_start: "2026-11-10T10:40:00.000Z",
    window_end: "2026-11-10T10:40:00.000Z",
    detected_at: "2026-11-10T10:40:01.000Z",
    origin: "https://clone.example",
  },
  {
    ...EXAMPLE_DETECTION,
    id: "dtc_aaaaaaaaaaaaaaaaaaaaaaaa",
    rule: "clone-origin",
    ip_prefix: "198.51.100.0/24",
    count: 1,
    window_start: "2026-11-10T10:00:00.000Z",
    window_end: "2026-11-10T10:00:00.000Z",
    detected_at: "2026-11-10T10:00:01.000Z",
    origin: "https://clone.example",
  },
];

beforeEach(() => {
  Object.defineProperty(navigator, "clipboard", { value: { writeText: vi.fn() }, configurable: true });
});

describe("BuildDetail — Clone Beacon", () => {
  it("reads On with the number of allowed origins, and lists each origin as plain text", () => {
    render(<BuildDetail build={withBeacon} appName="shop-web" />);
    const markers = within(screen.getByTestId("build-markers"));
    const fact = markers.getByTestId("build-beacon");
    expect(fact.getAttribute("data-status")).toBe("on");
    expect(fact.textContent).toContain("Clone Beacon");
    expect(markers.getByTestId("build-beacon-value").textContent).toBe("On · 2 origins");
    const list = markers.getByRole("list", { name: "Allowed origins" });
    expect(list.getAttribute("data-testid")).toBe("build-beacon-origins");
    const rows = within(list).getAllByTestId("beacon-origin");
    expect(rows.map((row) => row.textContent)).toEqual(ORIGINS);
    for (const row of rows) {
      expect(row.className).toMatch(MONO);
      expect(row.className).toContain("break-all");
      expect(row.querySelector("a")).toBeNull();
    }
    expect(markers.queryAllByRole("link")).toEqual([]);
  });

  it("says 1 origin for a single one, and wraps a long origin", () => {
    render(<BuildDetail build={{ ...EXAMPLE_BUILD, beacon: { origins: [LONG_ORIGIN] } }} appName="shop-web" />);
    expect(screen.getByTestId("build-beacon-value").textContent).toBe("On · 1 origin");
    const row = screen.getByTestId("beacon-origin");
    expect(row.textContent).toBe(LONG_ORIGIN);
    expect(row.className).toContain("break-all");
  });

  it("reads Off for a Build without a beacon, with what would turn it on, and lists no origin", () => {
    render(<BuildDetail build={EXAMPLE_BUILD} appName="shop-web" />);
    const fact = screen.getByTestId("build-beacon");
    expect(fact.getAttribute("data-status")).toBe("off");
    expect(screen.getByTestId("build-beacon-value").textContent).toBe("Off");
    expect(screen.queryByTestId("build-beacon-origins")).toBeNull();
    expect(screen.getByTestId("build-beacon-off").textContent).toBe(
      "No Clone Beacon in this Build. Harden plants one when the Build is registered with --origin.",
    );
  });
});

describe("IncidentDetail — a clone Incident", () => {
  function showClone(more: Partial<Incident> = {}, build: Build | null = withBeacon) {
    render(
      <IncidentDetail
        incident={{ ...EXAMPLE_CLONE_INCIDENT, detection_count: 2, ...more }}
        detections={cloneDetections}
        evidence={[EXAMPLE_STORED_EVENT]}
        appName="shop-web"
        confirmResolve={false}
        canaryBuild={build}
        actors={[{ ip_hash: "iph_2932b22cf89905dbc929c64247ddad3e", events: 3 }]}
        containments={[]}
        now={NOW}
        block={{ kind: "prefix", ttl: 3600 }}
      />,
    );
  }

  it("heads the page Clone detected, High", () => {
    showClone();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Clone detected");
    expect(screen.getByTestId("incident-severity").textContent).toBe("High");
  });

  it("lists the facts: App, Environment, Origin, rule, Build, first and last seen, Detections — no Network", () => {
    showClone();
    const facts = screen.getByTestId("incident-facts");
    const terms = within(facts)
      .getAllByRole("term")
      .map((term) => term.textContent);
    expect(terms).toEqual([
      "App",
      "Environment",
      "Origin",
      "Detection rule",
      "Build",
      "First seen",
      "Last seen",
      "Detections",
    ]);
    expect(within(facts).queryByTestId("fact-network")).toBeNull();
    expect(within(facts).getByTestId("fact-rule").textContent).toBe("Clone detected");
    expect(within(facts).getByTestId("fact-detections").textContent).toBe("2");
  });

  it("shows the origin as plain monospace text that wraps — never a link — with a Copy button", () => {
    showClone({ origin: LONG_ORIGIN });
    const fact = screen.getByTestId("fact-origin");
    const value = within(fact).getByTestId("fact-origin-value");
    expect(value.textContent).toBe(LONG_ORIGIN);
    expect(value.className).toMatch(MONO);
    expect(value.className).toContain("break-all");
    expect(fact.querySelector("a")).toBeNull();
    // No link anywhere on the page points at the suspected copy.
    for (const link of screen.getAllByRole("link")) expect(link.getAttribute("href")).not.toContain(LONG_ORIGIN);
    expect(within(fact).getByRole("button", { name: "Copy" })).toBeTruthy();
  });

  it("links the Build by version, with its id, as for a Canary; by id alone when it could not be read", () => {
    showClone();
    const link = screen.getByTestId("fact-build-link");
    expect(link.getAttribute("href")).toBe(
      `/apps/${EXAMPLE_CLONE_INCIDENT.app_id}/builds/${EXAMPLE_CLONE_INCIDENT.build_id}`,
    );
    expect(link.textContent).toBe("Build 1.4.0");
    expect(screen.getByTestId("fact-build-id").textContent).toBe(EXAMPLE_CLONE_INCIDENT.build_id);
    expect(screen.queryByTestId("fact-canary")).toBeNull();
  });

  it("links the Build by id when it could not be read", () => {
    showClone({}, null);
    expect(screen.getByTestId("fact-build-link").textContent).toBe(EXAMPLE_CLONE_INCIDENT.build_id);
  });

  it("shows the Detections as the timeline, oldest first, each with its time and reporter network", () => {
    showClone();
    const items = screen.getAllByTestId("detection-item");
    expect(items.map((item) => item.getAttribute("data-detection-id"))).toEqual([
      "dtc_aaaaaaaaaaaaaaaaaaaaaaaa",
      "dtc_bbbbbbbbbbbbbbbbbbbbbbbb",
    ]);
    const [first, second] = items as [HTMLElement, HTMLElement];
    expect(first.textContent).toContain("Detection: Clone detected");
    expect(within(first).getByTestId("detection-time").textContent).toBe("Detected 2026-11-10 10:00:01 UTC");
    expect(first.textContent).toContain("Reporter network");
    expect(within(first).getByTestId("detection-reporter").textContent).toBe("198.51.100.0/24");
    expect(within(second).getByTestId("detection-reporter").textContent).toBe("Unknown network");
    // A report is not a burst of Events: no Event count or window.
    expect(first.textContent).not.toContain("matching Events");
  });

  it("replaces the containment bar with a note, and shows no Actors, blocks or Events evidence", () => {
    showClone();
    expect(screen.queryByTestId("containment-bar")).toBeNull();
    expect(screen.queryByTestId("containment-block-network")).toBeNull();
    expect(screen.queryByTestId("containment-confirm")).toBeNull();
    expect(screen.getByTestId("containment-clone-note").textContent).toBe(
      "Containment does not apply to a clone. Take the copy down at its host.",
    );
    expect(screen.queryByRole("heading", { name: "Actors" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Blocks" })).toBeNull();
    expect(screen.queryByTestId("incident-evidence")).toBeNull();
    expect(screen.queryByTestId("evidence-empty")).toBeNull();
  });

  it("keeps the status actions; resolving names the origin, not a network", () => {
    render(
      <IncidentDetail
        incident={EXAMPLE_CLONE_INCIDENT}
        detections={cloneDetections}
        evidence={[]}
        appName="shop-web"
        confirmResolve={true}
        canaryBuild={withBeacon}
        actors={[]}
        containments={[]}
        now={NOW}
      />,
    );
    expect(screen.getByTestId("incident-acknowledge")).toBeTruthy();
    expect(screen.getByTestId("incident-confirm").textContent).toContain(
      "Resolve Clone detected on shop-web (development)? A later report from https://clone.example will open a new Incident.",
    );
  });

  it("says a later report of the same origin opens a new one once resolved", () => {
    showClone({ status: "resolved" });
    expect(screen.getByTestId("incident-resolved-note").textContent).toBe(
      "This Incident is resolved. A later report from the same origin opens a new one.",
    );
    expect(screen.getByTestId("containment-clone-note")).toBeTruthy();
  });
});

describe("IncidentDetail — an Incident of another rule is unchanged", () => {
  it("keeps the Network fact, the containment bar, the Actors and the evidence, and shows no Origin", () => {
    render(
      <IncidentDetail
        incident={EXAMPLE_INCIDENT}
        detections={[EXAMPLE_DETECTION]}
        evidence={[EXAMPLE_STORED_EVENT]}
        appName="shop-web"
        confirmResolve={false}
        actors={[]}
        containments={[]}
        now={NOW}
      />,
    );
    expect(screen.getByTestId("fact-network").textContent).toBe("203.0.113.0/24");
    expect(screen.queryByTestId("fact-origin")).toBeNull();
    expect(screen.getByTestId("containment-bar")).toBeTruthy();
    expect(screen.queryByTestId("containment-clone-note")).toBeNull();
    expect(screen.getByRole("heading", { name: "Actors" })).toBeTruthy();
    expect(screen.getByTestId("incident-evidence")).toBeTruthy();
    expect(screen.queryByTestId("detection-reporter")).toBeNull();
    expect(screen.getByTestId("detection-item").textContent).toContain("20 matching Events");
  });

  it("shows an em dash for a missing network rather than an empty fact", () => {
    render(
      <IncidentDetail
        incident={{ ...EXAMPLE_INCIDENT, ip_prefix: null }}
        detections={[]}
        evidence={[]}
        appName="shop-web"
        confirmResolve={false}
        actors={[]}
        containments={[]}
        now={NOW}
      />,
    );
    expect(screen.getByTestId("fact-network").textContent).toBe("—");
  });
});

describe("ContainmentBar — without a network prefix", () => {
  const noPrefix: Incident = { ...EXAMPLE_INCIDENT, ip_prefix: null };
  const actor = { ip_hash: "iph_2932b22cf89905dbc929c64247ddad3e", events: 3 };

  it("offers Block actor only: there is no network to block", () => {
    render(<ContainmentBar incident={noPrefix} appName="shop-web" actors={[actor]} block={null} expiry={null} />);
    expect(screen.getByTestId("containment-block-actor")).toBeTruthy();
    expect(screen.queryByTestId("containment-block-network")).toBeNull();
  });

  it("opens no network confirmation even when the address asks for one", () => {
    render(
      <ContainmentBar
        incident={noPrefix}
        appName="shop-web"
        actors={[actor]}
        block={{ kind: "prefix", ttl: 3600 }}
        expiry="12:00 UTC"
      />,
    );
    expect(screen.queryByTestId("containment-confirm")).toBeNull();
  });

  it("says nothing can be blocked when there is neither an Actor nor a network", () => {
    render(<ContainmentBar incident={noPrefix} appName="shop-web" actors={[]} block={null} expiry={null} />);
    expect(screen.queryByTestId("containment-block-network")).toBeNull();
    expect(screen.getByTestId("containment-no-actor").textContent).toBe(
      "Nothing to block: this Incident names no Actor and no network.",
    );
  });
});

describe("IncidentList — a clone Incident", () => {
  it("shows the origin as plain text under the title, and nothing extra for other Incidents", () => {
    render(
      <IncidentList incidents={[EXAMPLE_CLONE_INCIDENT, EXAMPLE_INCIDENT]} appNames={appNames} status={undefined} />,
    );
    const [clone, other] = screen.getAllByTestId("incident-row") as [HTMLElement, HTMLElement];
    expect(within(clone).getByRole("link", { name: "Clone detected" }).getAttribute("href")).toBe(
      `/incidents/${EXAMPLE_CLONE_INCIDENT.id}`,
    );
    const origin = within(clone).getByTestId("incident-origin");
    expect(origin.textContent).toBe("https://clone.example");
    expect(origin.className).toMatch(MONO);
    expect(origin.className).toContain("break-all");
    expect(origin.closest("a")).toBeNull();
    expect(within(clone).getAllByRole("link")).toHaveLength(1);
    expect(within(other).queryByTestId("incident-origin")).toBeNull();
  });
});
