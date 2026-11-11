import { type Build, EXAMPLE_BUILD, EXAMPLE_CANARIES } from "@antireverse/protocol";
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AppNav } from "@/components/app-nav.tsx";
import { BuildDetail } from "@/features/builds/build-detail.tsx";
import { BuildList } from "@/features/builds/build-list.tsx";

// The monospace named text styles (UIUX.md §4.3): identifiers, hashes, routes and data are set in Geist Mono.
const MONO = /\bcode-[1-3]\b/;

const appId = EXAMPLE_BUILD.app_id;

// A within-budget Build, an over-budget Build, and one whose runtime was not measured.
const withinBudget: Build = EXAMPLE_BUILD;
const overBudget: Build = {
  ...EXAMPLE_BUILD,
  build_id: "bld_ffffffffffffffffffffffff",
  version: "2.0.0",
  costs: { size_overhead_pct: 42, run_overhead_pct: 20 },
  created_at: "2026-11-10T10:00:00.000Z",
  registered_at: "2026-11-10T10:00:01.000Z",
};
const runNull: Build = {
  ...EXAMPLE_BUILD,
  build_id: "bld_aaaaaaaaaaaaaaaaaaaaaaaa",
  version: "0.9.0",
  profile: "light",
  equivalence: "skipped",
  costs: { size_overhead_pct: 12.5, run_overhead_pct: null },
  created_at: "2026-11-09T08:00:00.000Z",
  registered_at: "2026-11-09T08:00:01.000Z",
};

// Slice 07: a Build with a clean leak scan and three Canaries (id and kind only — the API never returns values),
// one whose scan suppressed two allowlisted findings and planted none, and the older Builds above with neither.
const canaries = EXAMPLE_CANARIES.map(({ id, kind }) => ({ id, kind }));
const scanned: Build = {
  ...EXAMPLE_BUILD,
  build_id: "bld_cccccccccccccccccccccccc",
  version: "1.5.0",
  leak_scan: { status: "clean", suppressed: 0 },
  canaries,
};
const suppressed: Build = {
  ...scanned,
  build_id: "bld_dddddddddddddddddddddddd",
  version: "1.5.1",
  leak_scan: { status: "suppressed", suppressed: 2 },
  canaries: [],
};
const oneCanary: Build = { ...scanned, build_id: "bld_eeeeeeeeeeeeeeeeeeeeeeee", canaries: canaries.slice(0, 1) };

const buildRow = (buildId: string): HTMLElement => {
  const found = screen.getAllByTestId("build-row").find((element) => element.getAttribute("data-build-id") === buildId);
  if (!found) throw new Error(`no row for ${buildId}`);
  return found;
};

describe("BuildList", () => {
  it("lists the Builds newest first with version, profile, equivalence, cost and created-at", () => {
    // The API returns newest first; the list keeps that order.
    render(<BuildList appId={appId} appName="shop-web" builds={[overBudget, withinBudget, runNull]} />);

    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Version",
      "Profile",
      "Equivalence",
      "Size",
      "Run",
      "Canaries",
      "Created",
    ]);
    expect(screen.getAllByTestId("build-row").map((element) => element.getAttribute("data-build-id"))).toEqual([
      overBudget.build_id,
      withinBudget.build_id,
      runNull.build_id,
    ]);

    const first = within(buildRow(overBudget.build_id));
    const link = first.getByTestId("build-link");
    expect(link.textContent).toBe("2.0.0");
    expect(link.getAttribute("href")).toBe(`/apps/${appId}/builds/${overBudget.build_id}`);
    expect(first.getByTestId("build-profile").textContent).toBe("balanced");
    expect(first.getByTestId("build-equivalence").textContent).toBe("Passed");
    expect(first.getByTestId("build-size").textContent).toBe("+42 %");
    expect(first.getByTestId("build-run").textContent).toBe("+20 %");

    const withinRow = buildRow(withinBudget.build_id);
    expect(withinRow.querySelector("time")?.getAttribute("dateTime")).toBe("2026-11-10T08:30:00.000Z");
  });

  it("shows an em dash for a run overhead that was not measured", () => {
    render(<BuildList appId={appId} appName="shop-web" builds={[runNull]} />);
    const row = within(buildRow(runNull.build_id));
    expect(row.getByTestId("build-run").textContent).toBe("—");
    expect(row.getByTestId("build-equivalence").textContent).toBe("Skipped");
    expect(row.getByTestId("build-profile").textContent).toBe("light");
  });

  it("shows each Build's Canary count, and an em dash for a Build from before Canaries", () => {
    render(<BuildList appId={appId} appName="shop-web" builds={[scanned, suppressed, withinBudget]} />);
    expect(within(buildRow(scanned.build_id)).getByTestId("build-canaries").textContent).toBe("3");
    expect(within(buildRow(suppressed.build_id)).getByTestId("build-canaries").textContent).toBe("0");
    expect(within(buildRow(withinBudget.build_id)).getByTestId("build-canaries").textContent).toBe("—");
  });

  it("reads the empty-state message and shows no table when there is no Build", () => {
    render(<BuildList appId={appId} appName="shop-web" builds={[]} />);
    expect(screen.getByTestId("builds-empty").textContent).toBe(
      "No Builds yet. Run harden with --register to add one.",
    );
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("BuildDetail", () => {
  it("heads the page with the version, the profile and the Environment", () => {
    render(<BuildDetail build={withinBudget} appName="shop-web" />);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("1.4.0");
    expect(screen.getByTestId("build-profile").textContent).toBe("balanced");
    expect(screen.getByTestId("environment-tag").textContent).toBe("Development");
    expect(screen.getByTestId("build-id").textContent).toBe(withinBudget.build_id);
  });

  it("shows each cost against its budget, reading normally while within it", () => {
    render(<BuildDetail build={withinBudget} appName="shop-web" />);
    const cost = within(screen.getByTestId("build-cost"));

    const size = within(cost.getByTestId("cost-size"));
    expect(size.getByText("Size overhead")).toBeTruthy();
    expect(size.getByTestId("cost-value").textContent).toBe("+12.5 %");
    expect(size.getByText("Budget 35 %")).toBeTruthy();
    expect(cost.getByTestId("cost-size").getAttribute("data-overbudget")).toBe("false");
    expect(size.queryByTestId("cost-overbudget")).toBeNull();

    const run = within(cost.getByTestId("cost-run"));
    expect(run.getByText("Run overhead")).toBeTruthy();
    expect(run.getByTestId("cost-value").textContent).toBe("+3.2 %");
    expect(run.getByText("Budget 15 %")).toBeTruthy();
    expect(cost.getByTestId("cost-run").getAttribute("data-overbudget")).toBe("false");
  });

  it("marks a cost over its budget with a word, not colour alone", () => {
    render(<BuildDetail build={overBudget} appName="shop-web" />);
    const cost = within(screen.getByTestId("build-cost"));

    expect(cost.getByTestId("cost-size").getAttribute("data-overbudget")).toBe("true");
    expect(within(cost.getByTestId("cost-size")).getByTestId("cost-overbudget").textContent).toContain("Over budget");
    expect(within(cost.getByTestId("cost-size")).getByTestId("cost-value").textContent).toBe("+42 %");

    expect(cost.getByTestId("cost-run").getAttribute("data-overbudget")).toBe("true");
    expect(within(cost.getByTestId("cost-run")).getByTestId("cost-overbudget").textContent).toContain("Over budget");
  });

  it("shows a run overhead that was not measured as an em dash and never over budget", () => {
    render(<BuildDetail build={runNull} appName="shop-web" />);
    const run = within(screen.getByTestId("cost-run"));
    expect(run.getByTestId("cost-value").textContent).toBe("—");
    expect(screen.getByTestId("cost-run").getAttribute("data-overbudget")).toBe("false");
    expect(run.queryByTestId("cost-overbudget")).toBeNull();
  });

  it("lists what the transform did and whether integrity ran", () => {
    render(<BuildDetail build={withinBudget} appName="shop-web" />);
    const transform = within(screen.getByTestId("build-transform"));
    expect(transform.getByTestId("transform-mangled").textContent).toContain("Local names mangled");
    expect(transform.getByTestId("transform-mangled").textContent).toContain("42");
    expect(transform.getByTestId("transform-strings").textContent).toContain("Strings encrypted");
    expect(transform.getByTestId("transform-strings").textContent).toContain("12");
    expect(transform.getByTestId("transform-mangleOnly").textContent).toContain("Files with mangling only");
    expect(transform.getByTestId("transform-mangleOnly").textContent).toContain("1");
    expect(transform.getByTestId("transform-integrity").textContent).toContain("Integrity check");
    expect(transform.getByTestId("transform-integrity").textContent).toContain("Off");
  });

  it("lists each artifact with its path, size and short SHA-256 in monospace", () => {
    render(<BuildDetail build={withinBudget} appName="shop-web" />);
    const artifacts = within(screen.getByTestId("build-artifacts"));
    expect(artifacts.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Path",
      "Bytes",
      "SHA-256",
    ]);
    const row = within(screen.getAllByTestId("artifact-row")[0] as HTMLElement);
    expect(row.getByTestId("artifact-path").textContent).toBe("dist/index.js");
    expect(row.getByTestId("artifact-bytes").textContent).toBe("2,048");
    const hash = row.getByTestId("artifact-hash");
    expect(hash.textContent).toBe("e3b0c44298fc");
    expect(hash.className).toMatch(MONO);
  });
});

describe("BuildDetail — leak scan and Canaries", () => {
  it("reads Clean for a clean leak scan", () => {
    render(<BuildDetail build={scanned} appName="shop-web" />);
    const markers = within(screen.getByTestId("build-markers"));
    expect(markers.getByRole("heading", { level: 2, name: "Markers" })).toBeTruthy();
    const fact = markers.getByTestId("build-leak-scan");
    expect(fact.textContent).toContain("Leak scan");
    expect(markers.getByTestId("build-leak-scan-value").textContent).toBe("Clean");
    expect(fact.getAttribute("data-status")).toBe("clean");
  });

  it("reads Clean with the suppressed count when allowlisted findings were suppressed", () => {
    render(<BuildDetail build={suppressed} appName="shop-web" />);
    expect(screen.getByTestId("build-leak-scan-value").textContent).toBe("Clean · 2 suppressed");
    expect(screen.getByTestId("build-leak-scan").getAttribute("data-status")).toBe("suppressed");
  });

  it("reads Not scanned for a Build registered before the leak scan existed", () => {
    render(<BuildDetail build={withinBudget} appName="shop-web" />);
    expect(screen.getByTestId("build-leak-scan-value").textContent).toBe("Not scanned");
    expect(screen.getByTestId("build-leak-scan").getAttribute("data-status")).toBe("none");
  });

  it("lists the Canaries with their count, each by kind word and id, never a value", () => {
    render(<BuildDetail build={scanned} appName="shop-web" />);
    const panel = within(screen.getByTestId("build-canaries"));
    expect(panel.getByRole("heading", { level: 3, name: "Canaries" })).toBeTruthy();
    expect(panel.getByTestId("canary-count").textContent).toBe("3 Canaries");
    expect(panel.getAllByRole("columnheader").map((header) => header.textContent)).toEqual(["Kind", "Canary ID"]);
    const rows = panel.getAllByTestId("canary-row");
    expect(rows.map((row) => row.getAttribute("data-canary-id"))).toEqual(canaries.map((canary) => canary.id));
    expect(rows.map((row) => within(row).getByTestId("canary-kind").textContent)).toEqual([
      "Decoy key",
      "Decoy route",
      "Decoy route",
    ]);
    const id = within(rows[0] as HTMLElement).getByTestId("canary-id");
    expect(id.textContent).toBe(canaries[0]?.id);
    expect(id.className).toMatch(MONO);
    for (const canary of EXAMPLE_CANARIES) expect(document.body.textContent).not.toContain(canary.value);
  });

  it("says 1 Canary for a single one", () => {
    render(<BuildDetail build={oneCanary} appName="shop-web" />);
    expect(screen.getByTestId("canary-count").textContent).toBe("1 Canary");
  });

  it("explains an empty Canaries panel for a Build without Canaries", () => {
    for (const build of [withinBudget, suppressed]) {
      const { unmount } = render(<BuildDetail build={build} appName="shop-web" />);
      const panel = within(screen.getByTestId("build-canaries"));
      expect(panel.getByTestId("canary-count").textContent).toBe("0 Canaries");
      expect(panel.getByTestId("canaries-empty").textContent).toBe(
        "No Canaries in this Build. Harden plants them in Builds registered with a version that supports Canaries.",
      );
      expect(panel.queryByRole("table")).toBeNull();
      unmount();
    }
  });
});

describe("AppNav — Builds", () => {
  it("offers Builds beside Live and Policy and marks the current section", () => {
    render(<AppNav appId={appId} current="builds" />);
    const nav = screen.getByTestId("app-nav");
    const builds = within(nav).getByRole("link", { name: "Builds" });
    expect(builds.getAttribute("href")).toBe(`/apps/${appId}/builds`);
    expect(builds.getAttribute("aria-current")).toBe("page");
    expect(builds.getAttribute("data-testid")).toBe("app-nav-builds");
    expect(within(nav).getByRole("link", { name: "Live" }).getAttribute("aria-current")).toBeNull();
    expect(within(nav).getByRole("link", { name: "Policy" }).getAttribute("aria-current")).toBeNull();
  });
});
