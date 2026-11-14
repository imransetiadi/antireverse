import {
  type Build,
  type Detection,
  EXAMPLE_BUILD,
  EXAMPLE_INCIDENT,
  EXAMPLE_STORED_EVENT,
  EXAMPLE_TAMPER_DETECTION,
  EXAMPLE_TAMPER_INCIDENT,
  type Incident,
} from "@antireverse/protocol";
import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Slice 21a: a "Tampered Build" Incident on the Incident page and in the Incident list — rendered with the Server
// Actions replaced by fakes.

// The monospace named text styles (UIUX.md §4.3): identifiers, hashes, routes and data are set in Geist Mono.
const MONO = /\bcode-[1-3]\b/;

vi.mock("@/app/actions.ts", () => ({
  updateIncidentAction: vi.fn(),
  createContainmentAction: vi.fn(),
  liftContainmentAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import { BuildDetail } from "@/features/builds/build-detail.tsx";
import { IncidentDetail } from "@/features/incidents/incident-detail.tsx";
import { IncidentList } from "@/features/incidents/incident-list.tsx";

const NOW = Date.UTC(2026, 10, 10, 12, 0, 0);
const REGISTERED = EXAMPLE_BUILD.artifacts[0]?.sha256 ?? "";
const OBSERVED = EXAMPLE_TAMPER_INCIDENT.observed_sha256 ?? "";
const OTHER_OBSERVED = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
const HOSTILE_ORIGIN = "https://evil.example";
const appNames = new Map([[EXAMPLE_INCIDENT.app_id, "shop-web"]]);

/** Two reports: the opening one from a known network, a later one of another hash from an unknown network. */
const detections: Detection[] = [
  {
    ...EXAMPLE_TAMPER_DETECTION,
    id: "dtc_bbbbbbbbbbbbbbbbbbbbbbbb",
    ip_prefix: null,
    origin: HOSTILE_ORIGIN,
    observed_sha256: OTHER_OBSERVED,
    window_start: "2026-11-10T11:30:00.000Z",
    window_end: "2026-11-10T11:30:00.000Z",
    detected_at: "2026-11-10T11:30:00.000Z",
  },
  EXAMPLE_TAMPER_DETECTION,
];

beforeEach(() => {
  Object.defineProperty(navigator, "clipboard", { value: { writeText: vi.fn() }, configurable: true });
});

function show(more: Partial<Incident> = {}, build: Build | null = EXAMPLE_BUILD, confirmResolve = false) {
  render(
    <IncidentDetail
      incident={{ ...EXAMPLE_TAMPER_INCIDENT, detection_count: 2, ...more }}
      detections={detections}
      evidence={[EXAMPLE_STORED_EVENT]}
      appName="shop-web"
      confirmResolve={confirmResolve}
      canaryBuild={build}
      actors={[{ ip_hash: "iph_2932b22cf89905dbc929c64247ddad3e", events: 3 }]}
      containments={[]}
      now={NOW}
      block={{ kind: "prefix", ttl: 3600 }}
    />,
  );
}

describe("IncidentDetail — a Tampered Build Incident", () => {
  it("heads the page Tampered Build, High", () => {
    show();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Tampered Build");
    expect(screen.getByTestId("incident-severity").textContent).toBe("High");
  });

  it("lists the facts: App, Environment, rule, Build, File, both hashes, first and last seen, Reports — no Network, no Origin", () => {
    show();
    const facts = screen.getByTestId("incident-facts");
    const terms = within(facts)
      .getAllByRole("term")
      .map((term) => term.textContent);
    expect(terms).toEqual([
      "App",
      "Environment",
      "Detection rule",
      "Build",
      "File",
      "Registered hash",
      "Observed hash",
      "First seen",
      "Last seen",
      "Reports",
    ]);
    expect(within(facts).queryByTestId("fact-network")).toBeNull();
    expect(within(facts).queryByTestId("fact-origin")).toBeNull();
    expect(within(facts).getByTestId("fact-rule").textContent).toBe("Tampered Build");
    expect(within(facts).getByTestId("fact-detections").textContent).toBe("2");
  });

  it("links the Build by version with its id; by id alone when it could not be read", () => {
    show();
    const link = screen.getByTestId("fact-build-link");
    expect(link.getAttribute("href")).toBe(
      `/apps/${EXAMPLE_TAMPER_INCIDENT.app_id}/builds/${EXAMPLE_TAMPER_INCIDENT.build_id}`,
    );
    expect(link.textContent).toBe("Build 1.4.0");
    expect(screen.getByTestId("fact-build-id").textContent).toBe(EXAMPLE_TAMPER_INCIDENT.build_id);
  });

  it("names the file as monospace text that wraps", () => {
    const long = `dist/${"chunk-".repeat(30)}index.js`;
    show({ artifact_path: long });
    const file = screen.getByTestId("fact-file");
    expect(file.textContent).toBe(long);
    expect(file.className).toMatch(MONO);
    expect(file.className).toContain("break-all");
  });

  it("shows the registered and the observed hash shortened in monospace, the full value as title and for Copy", async () => {
    show();
    for (const [testId, full] of [
      ["fact-registered-hash", REGISTERED],
      ["fact-observed-hash", OBSERVED],
    ] as const) {
      const fact = screen.getByTestId(testId);
      const value = within(fact).getByTestId(`${testId}-value`);
      expect(value.textContent).toBe(`${full.slice(0, 12)}…`);
      expect(value.getAttribute("title")).toBe(full);
      expect(value.className).toMatch(MONO);
      const copy = within(fact).getByRole("button", { name: "Copy" });
      copy.click();
      expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith(full);
    }
    expect(REGISTERED).not.toBe(OBSERVED);
  });

  it("says the registered hash is not available when the Build could not be read or does not list the file", () => {
    show({}, null);
    const fact = screen.getByTestId("fact-registered-hash");
    expect(fact.textContent).toContain("Not available");
    expect(within(fact).queryByRole("button")).toBeNull();
    expect(screen.getByTestId("fact-build-link").textContent).toBe(EXAMPLE_TAMPER_INCIDENT.build_id);
  });

  it("does not show another file's digest as the registered hash", () => {
    show({ artifact_path: "dist/other.js" });
    expect(screen.getByTestId("fact-registered-hash").textContent).toContain("Not available");
  });

  it("shows the reports as the timeline, oldest first: file, observed hash, origin and reporter network", () => {
    show();
    const items = screen.getAllByTestId("detection-item");
    expect(items.map((item) => item.getAttribute("data-detection-id"))).toEqual([
      EXAMPLE_TAMPER_DETECTION.id,
      "dtc_bbbbbbbbbbbbbbbbbbbbbbbb",
    ]);
    const [first, second] = items as [HTMLElement, HTMLElement];
    expect(first.textContent).toContain("Detection: Tampered Build");
    expect(within(first).getByTestId("detection-time").textContent).toBe("Detected 2026-11-10 11:00:00 UTC");
    expect(within(first).getByTestId("detection-file").textContent).toBe("dist/index.js");
    const hash = within(first).getByTestId("detection-observed");
    expect(hash.textContent).toBe(`${OBSERVED.slice(0, 12)}…`);
    expect(hash.getAttribute("title")).toBe(OBSERVED);
    expect(within(first).getByTestId("detection-origin").textContent).toBe("https://shop.example");
    expect(within(first).getByTestId("detection-reporter").textContent).toBe("203.0.113.0/24");
    expect(within(second).getByTestId("detection-observed").getAttribute("title")).toBe(OTHER_OBSERVED);
    expect(within(second).getByTestId("detection-reporter").textContent).toBe("Unknown network");
    // A report is not a burst of Events: no Event count or window.
    expect(first.textContent).not.toContain("matching Events");
  });

  it("shows a report's origin as plain monospace text — never a link, anywhere on the page", () => {
    show();
    const origins = screen.getAllByTestId("detection-origin");
    expect(origins.map((origin) => origin.textContent)).toEqual(["https://shop.example", HOSTILE_ORIGIN]);
    for (const origin of origins) {
      expect(origin.className).toMatch(MONO);
      expect(origin.className).toContain("break-all");
      expect(origin.closest("a")).toBeNull();
      expect(origin.querySelector("a")).toBeNull();
    }
    for (const link of screen.getAllByRole("link")) {
      expect(link.getAttribute("href")).not.toContain("evil.example");
      expect(link.getAttribute("href")).not.toContain("shop.example");
    }
  });

  it("replaces the containment bar with a note that says why, and shows no Actors, blocks or Events evidence", () => {
    show();
    expect(screen.queryByTestId("containment-bar")).toBeNull();
    expect(screen.queryByTestId("containment-block-network")).toBeNull();
    expect(screen.queryByTestId("containment-confirm")).toBeNull();
    expect(screen.queryByTestId("containment-clone-note")).toBeNull();
    expect(screen.getByTestId("containment-tamper-note").textContent).toBe(
      "Containment does not apply to a tampered Build: the reports come from visitors who received changed files, not from an attacker's network. Check where the files are served from — the deployment, the CDN and any step that rewrites them after Harden.",
    );
    expect(screen.queryByRole("heading", { name: "Actors" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Blocks" })).toBeNull();
    expect(screen.queryByTestId("incident-evidence")).toBeNull();
  });

  it("keeps the status actions; resolving names the Build's files, not a network", () => {
    show({ detection_count: 1 }, EXAMPLE_BUILD, true);
    expect(screen.getByTestId("incident-acknowledge")).toBeTruthy();
    expect(screen.getByTestId("incident-confirm").textContent).toContain(
      "Resolve Tampered Build on shop-web (development)? A later mismatch of this Build's files will open a new Incident.",
    );
  });

  it("says a later mismatch opens a new one once resolved", () => {
    show({ status: "resolved" });
    expect(screen.getByTestId("incident-resolved-note").textContent).toBe(
      "This Incident is resolved. A later mismatch of this Build's files opens a new one.",
    );
    expect(screen.getByTestId("containment-tamper-note")).toBeTruthy();
  });
});

describe("IncidentDetail — a capped Tampered Build Incident", () => {
  it("says that more distinct hashes were reported than are recorded, only when the API says so", () => {
    show({ detections_capped: true });
    expect(screen.getByTestId("incident-capped-note").textContent).toBe(
      "More distinct hashes were reported than are recorded.",
    );
  });

  it("shows no such note otherwise", () => {
    show();
    expect(screen.queryByTestId("incident-capped-note")).toBeNull();
  });
});

describe("BuildDetail — the integrity marker", () => {
  const marked: Build = { ...EXAMPLE_BUILD, integrity: { files: ["dist/index.js"] }, integrity_first_match_at: null };

  it("says a Build with a marker is not yet seen unmodified until its first matching report", () => {
    render(<BuildDetail build={marked} appName="shop-web" />);
    const fact = screen.getByTestId("build-integrity");
    expect(fact.getAttribute("data-status")).toBe("waiting");
    expect(fact.textContent).toContain("Integrity marker");
    expect(screen.getByTestId("build-integrity-value").textContent).toBe("1 file · not yet seen unmodified");
  });

  it("says since when the Build is watched", () => {
    render(
      <BuildDetail
        build={{
          ...marked,
          integrity: { files: ["a.js", "b.js"] },
          integrity_first_match_at: "2026-11-10T11:00:00.000Z",
        }}
        appName="shop-web"
      />,
    );
    expect(screen.getByTestId("build-integrity").getAttribute("data-status")).toBe("watched");
    expect(screen.getByTestId("build-integrity-value").textContent).toBe(
      "2 files · watched since 2026-11-10 11:00:00 UTC",
    );
  });

  it("reads Off for a Build without a marker, or with an empty one", () => {
    render(<BuildDetail build={EXAMPLE_BUILD} appName="shop-web" />);
    expect(screen.getByTestId("build-integrity").getAttribute("data-status")).toBe("off");
    expect(screen.getByTestId("build-integrity-value").textContent).toBe("Off");
  });
});

describe("IncidentList — a Tampered Build Incident", () => {
  it("shows the rule's title and names the file under it, as plain monospace text", () => {
    render(
      <IncidentList incidents={[EXAMPLE_TAMPER_INCIDENT, EXAMPLE_INCIDENT]} appNames={appNames} status={undefined} />,
    );
    const [tamper, other] = screen.getAllByTestId("incident-row") as [HTMLElement, HTMLElement];
    expect(within(tamper).getByTestId("incident-link").textContent).toBe("Tampered Build");
    expect(tamper.getAttribute("data-severity")).toBe("high");
    const file = within(tamper).getByTestId("incident-artifact");
    expect(file.textContent).toBe("dist/index.js");
    expect(file.className).toMatch(MONO);
    expect(file.querySelector("a")).toBeNull();
    expect(within(tamper).queryByTestId("incident-origin")).toBeNull();
    expect(within(other).queryByTestId("incident-artifact")).toBeNull();
  });
});
