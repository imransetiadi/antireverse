import type { ProbeStatus } from "@antireverse/protocol";
import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OPS_TOKEN, sloReport } from "./helpers/slo.ts";

// Slice 18g: the "Synthetic probes" section of the operator dashboard — off (with the switch named), on before the
// first cycle, a good cycle and each way a leg can fail — and its place on `/ops`, above the SLO panels. The text says
// what the number is: measured inside this API instance against one Shield of its own.

vi.mock("@/app/ops/actions.ts", () => ({
  opsSignInAction: vi.fn(),
  opsSignOutAction: vi.fn(),
  proveSwitchAction: vi.fn(),
}));
vi.mock("@/app/actions.ts", () => ({ signOutAction: vi.fn() }));
vi.mock("@/lib/ops-session.ts", () => ({ readOpsSession: vi.fn(async () => OPS_TOKEN) }));
vi.mock("@/lib/api.ts", () => {
  class ApiError extends Error {
    readonly status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
    }
  }
  class UnauthorizedError extends ApiError {}
  class NotFoundError extends ApiError {}
  const getProveOperatorState = vi.fn(async () => {
    throw new NotFoundError("404", 404);
  });
  return { getSloReport: vi.fn(), getProveOperatorState, ApiError, UnauthorizedError, NotFoundError };
});

import OpsPage from "@/app/ops/page.tsx";
import { ProbeStatusSection } from "@/features/ops/probe-status.tsx";
import * as api from "@/lib/api.ts";

const STATUS: ProbeStatus = {
  interval_s: 60,
  runs: 12,
  failures: 0,
  consecutive_failures: 0,
  setup_failures: 0,
  last_run_at: "2026-11-20T08:12:03.000Z",
  enforcement: { outcome: "good", ms: 4_210.4 },
  freshness: { outcome: "good", ms: 1_120 },
};
const leg = (name: "enforcement" | "freshness"): HTMLElement => screen.getByTestId(`ops-probe-${name}`);

beforeEach(() => {
  vi.mocked(api.getSloReport).mockReset();
});

describe("the Synthetic probes section", () => {
  it("says probes are off, that SLO-06 is not measured, and names the switch", () => {
    render(<ProbeStatusSection probes={null} />);
    const section = screen.getByTestId("ops-probes");
    expect(section.dataset.state).toBe("off");
    expect(within(section).getByRole("heading", { level: 2 }).textContent).toBe("Synthetic probes");
    const off = screen.getByTestId("ops-probes-off");
    expect(off.getAttribute("role")).toBe("status");
    expect(off.textContent).toContain("AR_PROBES=1");
    expect(off.textContent).toContain("SLO-06");
    expect(screen.queryByTestId("ops-probe-enforcement")).toBeNull();
  });

  it("states what the measurement is and is not", () => {
    render(<ProbeStatusSection probes={STATUS} />);
    const scope = screen.getByTestId("ops-probes-scope").textContent ?? "";
    expect(scope).toMatch(/inside this API instance/);
    expect(scope).toMatch(/one Shield of its own/);
    expect(scope).toMatch(/not a measurement per region/);
    expect(scope).toMatch(/customers' Shields/);
  });

  it("shows the last cycle: both legs within their bounds, with the time, the counts and the interval", () => {
    render(<ProbeStatusSection probes={STATUS} />);
    expect(screen.getByTestId("ops-probes").dataset.state).toBe("ok");
    expect(leg("enforcement").dataset.outcome).toBe("good");
    expect(leg("enforcement").textContent).toContain("Within bound");
    expect(leg("enforcement").textContent).toContain("4.2 s");
    expect(leg("enforcement").textContent).toContain("bound 30 s");
    expect(leg("freshness").textContent).toContain("1.1 s");
    expect(leg("freshness").textContent).toContain("bound 5 s");
    const last = screen.getByTestId("ops-probes-last");
    expect(last.querySelector("time")?.getAttribute("datetime")).toBe("2026-11-20T08:12:03.000Z");
    expect(last.textContent).toContain("2026-11-20 08:12:03 UTC");
    expect(screen.getByTestId("ops-probes-runs").textContent).toBe("12 run, 0 failed");
    expect(screen.getByTestId("ops-probes-consecutive").textContent).toBe("0");
    expect(screen.getByTestId("ops-probes-interval").textContent).toBe("One cycle every 60 s.");
  });

  it("says no cycle has finished before the first one", () => {
    render(
      <ProbeStatusSection probes={{ ...STATUS, runs: 0, last_run_at: null, enforcement: null, freshness: null }} />,
    );
    expect(screen.getByTestId("ops-probes").dataset.state).toBe("idle");
    expect(screen.getByTestId("ops-probes-last").textContent).toBe("No cycle has finished yet");
    expect(leg("enforcement").dataset.outcome).toBe("none");
    expect(leg("freshness").textContent).toContain("No cycle has finished yet");
  });

  it("marks a failing probe with words and an icon, not colour alone: gave up, skipped, late and could not run", () => {
    const { unmount } = render(
      <ProbeStatusSection
        probes={{
          ...STATUS,
          failures: 3,
          consecutive_failures: 3,
          enforcement: { outcome: "timeout", ms: 60_000 },
          freshness: { outcome: "skipped", ms: null },
        }}
      />,
    );
    expect(screen.getByTestId("ops-probes").dataset.state).toBe("failing");
    expect(leg("enforcement").dataset.outcome).toBe("timeout");
    expect(leg("enforcement").textContent).toContain("Gave up after 1 min");
    expect(leg("enforcement").querySelector("svg")).not.toBeNull();
    expect(leg("freshness").textContent).toContain("Not measured in this cycle: the block was not enforced");
    expect(screen.getByTestId("ops-probes-consecutive").textContent).toBe("3");
    expect(screen.getByTestId("ops-probes-runs").textContent).toBe("12 run, 3 failed");
    unmount();

    render(
      <ProbeStatusSection
        probes={{
          ...STATUS,
          failures: 1,
          consecutive_failures: 1,
          enforcement: { outcome: "failed", ms: null },
          freshness: { outcome: "late", ms: 6_500 },
        }}
      />,
    );
    expect(leg("enforcement").textContent).toContain("Could not run");
    expect(leg("freshness").dataset.outcome).toBe("late");
    expect(leg("freshness").textContent).toContain("Late");
    expect(leg("freshness").textContent).toContain("6.5 s");
    expect(leg("freshness").textContent).toContain("bound 5 s");
  });
});

describe("review: a prober that cannot be set up, and what the probes do not count", () => {
  it("says the probe could not be set up, how often, and that it counts as failing from the fourth cycle", () => {
    render(
      <ProbeStatusSection
        probes={{
          ...STATUS,
          failures: 5,
          consecutive_failures: 5,
          setup_failures: 5,
          enforcement: { outcome: "failed", ms: null },
          freshness: { outcome: "skipped", ms: null },
        }}
      />,
    );
    const note = screen.getByTestId("ops-probes-setup");
    expect(note.getAttribute("role")).toBe("alert");
    expect(note.textContent).toContain("could not be set up in the last 5 cycles");
    expect(note.textContent).toContain("from the fourth");
    expect(note.textContent).toContain("SLO-06");
    expect(screen.getByTestId("ops-probes").dataset.state).toBe("failing");
  });

  it("shows no such note while the probe is set up", () => {
    render(<ProbeStatusSection probes={STATUS} />);
    expect(screen.queryByTestId("ops-probes-setup")).toBeNull();
  });

  it("says the probes' own requests and Events are not counted in the other SLOs", () => {
    render(<ProbeStatusSection probes={STATUS} />);
    expect(screen.getByTestId("ops-probes-scope").textContent).toMatch(
      /own requests and Events are not counted in any other SLO/,
    );
  });
});

describe("/ops with probes", () => {
  it("shows the section between the summary and the SLO panels, off when the report has no probe status", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(sloReport());
    render(await OpsPage());
    const section = screen.getByTestId("ops-probes");
    expect(section.dataset.state).toBe("off");
    const summary = screen.getByTestId("ops-summary");
    const first = screen.getAllByTestId("slo-panel")[0] as HTMLElement;
    expect(summary.compareDocumentPosition(section) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(section.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("shows SLO-06 as measured, with its probe status, when the API runs probes", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce({
      ...sloReport({
        "SLO-06": {
          measured: true,
          not_measured_reason: null,
          good: 12,
          total: 12,
          attainment: 1,
          budget_remaining: 1,
          burn: { "5m": 0, "30m": 0, "1h": 0, "6h": 0, "3d": 0 },
          latency: [
            { variant: "all", percentile: 95, target_ms: 30_000, observed_ms: 5_000, met: true },
            { variant: "all", percentile: 99, target_ms: 60_000, observed_ms: 10_000, met: true },
          ],
        },
      }),
      probes: STATUS,
    });
    render(await OpsPage());
    expect(screen.getByTestId("ops-probes").dataset.state).toBe("ok");
    const panel = screen.getAllByTestId("slo-panel").find((element) => element.dataset.sloId === "SLO-06");
    expect(panel?.dataset.state).toBe("ok");
    expect(within(panel as HTMLElement).queryByTestId("slo-not-measured")).toBeNull();
    // The panel's own text says what the number is.
    expect(within(panel as HTMLElement).getByTestId("slo-indicator").textContent).toMatch(/not per region/);
  });
});
