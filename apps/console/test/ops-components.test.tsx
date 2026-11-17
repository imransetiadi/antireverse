import { SLO_CATALOG } from "@antireverse/protocol";
import { render, screen, within } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GENERATED_AT, OPS_TOKEN, sloReport } from "./helpers/slo.ts";

// Slice 18d: the operator dashboard `/ops` and its sign-in page — one panel per SLO in catalog order, the summary, each
// state of an SLO (normal, firing, overspent, no traffic, not measured) and each way the read can fail; rendered with
// the API client and the operator session replaced.

vi.mock("@/app/ops/actions.ts", () => ({
  opsSignInAction: vi.fn(),
  opsSignOutAction: vi.fn(),
  proveSwitchAction: vi.fn(),
}));
vi.mock("@/app/actions.ts", () => ({ signOutAction: vi.fn() }));
const opsSession = vi.hoisted(() => ({ token: undefined as string | undefined }));
vi.mock("@/lib/ops-session.ts", () => ({ readOpsSession: vi.fn(async () => opsSession.token) }));
vi.mock("@/lib/api.ts", () => {
  class ApiError extends Error {
    readonly status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
    }
  }
  class UnauthorizedError extends ApiError {
    constructor(message: string) {
      super(message, 401);
    }
  }
  class NotFoundError extends ApiError {
    constructor(message: string) {
      super(message, 404);
    }
  }
  // Slice 15a: the Campaign switches are read beside the report; here, an API that does not have them (404).
  const getProveOperatorState = vi.fn(async () => {
    throw new NotFoundError("404");
  });
  return { getSloReport: vi.fn(), getProveOperatorState, ApiError, UnauthorizedError, NotFoundError };
});
vi.mock("next/navigation", async (original) => ({
  ...(await original<typeof import("next/navigation")>()),
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import OpsPage from "@/app/ops/page.tsx";
import OpsSignInPage, { metadata as signInMetadata } from "@/app/ops/sign-in/page.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { formatBurn, formatDuration, formatObjective, formatPercent } from "@/features/ops/format.ts";
import * as api from "@/lib/api.ts";

const organization = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };
const open = async () => render(await OpsPage());
const panel = (id: string): HTMLElement => {
  const found = screen.getAllByTestId("slo-panel").find((element) => element.dataset.sloId === id);
  if (found === undefined) throw new Error(`no panel ${id}`);
  return found;
};

beforeEach(() => {
  vi.mocked(api.getSloReport).mockReset();
  opsSession.token = OPS_TOKEN;
});

describe("formatting", () => {
  it("writes objectives, attainment, budget, burn and durations plainly", () => {
    expect(formatObjective(0.9999)).toBe("99.99 %");
    expect(formatObjective(0.95)).toBe("95 %");
    // Attainment is never rounded up to the objective it misses.
    expect(formatPercent(0.99989, 3)).toBe("99.989 %");
    expect(formatPercent(0.999_999_9, 3)).toBe("99.999 %");
    expect(formatPercent(1, 3)).toBe("100.000 %");
    expect(formatBurn(14.4)).toBe("14.4×");
    expect(formatBurn(0.5)).toBe("0.50×");
    expect(formatBurn(0)).toBe("0.00×");
    expect(formatBurn(123.456)).toBe("123.4×");
    // Truncated, never rounded up to a threshold it misses (review M1)…
    expect(formatBurn(14.36)).toBe("14.3×");
    expect(formatBurn(5.999)).toBe("5.99×");
    // …but a rounding error below a threshold the API counts as reached still shows it (SLO-07: 9 bad of 625).
    expect(formatBurn(9 / 625 / (1 - 0.999))).toBe("14.4×");
    // A relative epsilon only: 99.98999999995 % is not 99.990 % (review L2).
    expect(formatPercent(0.999899999995, 3)).toBe("99.989 %");
    expect(formatPercent(0.29, 1)).toBe("29.0 %");
    expect(formatDuration(120)).toBe("120 ms");
    expect(formatDuration(5_000)).toBe("5 s");
    expect(formatDuration(1_800_000)).toBe("30 min");
    expect(formatDuration(3_600_000)).toBe("1 h");
  });
});

describe("/ops", () => {
  it("sends a visitor without an operator session to operator sign-in", async () => {
    opsSession.token = undefined;
    await expect(OpsPage()).rejects.toThrow("REDIRECT /ops/sign-in");
    expect(api.getSloReport).not.toHaveBeenCalled();
  });

  it("clears a token the API no longer accepts, through /ops/expired", async () => {
    vi.mocked(api.getSloReport).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(OpsPage()).rejects.toThrow("REDIRECT /ops/expired");
  });

  it("says operator access is off when the API answers 404", async () => {
    vi.mocked(api.getSloReport).mockRejectedValueOnce(new api.NotFoundError("404"));
    await open();
    expect(screen.getByTestId("ops-disabled").textContent).toContain("Operator access is not enabled on this API.");
    expect(screen.queryAllByTestId("slo-panel")).toHaveLength(0);
    expect(screen.getByRole("button", { name: "Sign out" })).toBeTruthy();
  });

  it("says when the API answered outside the contract (502)", async () => {
    vi.mocked(api.getSloReport).mockRejectedValueOnce(new api.ApiError("contract", 502));
    await open();
    expect(screen.getByTestId("ops-unavailable").textContent).toContain("The API answered in an unexpected way.");
  });

  it("says when the report cannot be read", async () => {
    vi.mocked(api.getSloReport).mockRejectedValueOnce(new api.ApiError("down", 0));
    await open();
    expect(screen.getByTestId("ops-unavailable")).toBeTruthy();
  });

  it("shows one panel per SLO in catalog order, the summary, a refresh link and sign-out", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(sloReport());
    await open();
    expect(api.getSloReport).toHaveBeenCalledWith(OPS_TOKEN);
    const panels = screen.getAllByTestId("slo-panel");
    expect(panels.map((element) => element.dataset.sloId)).toEqual(SLO_CATALOG.map((def) => def.id));
    expect(screen.getByTestId("ops-count-firing").textContent).toBe("0");
    expect(screen.getByTestId("ops-count-missed").textContent).toBe("0");
    expect(screen.getByTestId("ops-count-ok").textContent).toBe("8");
    expect(screen.getByTestId("ops-count-not-measured").textContent).toBe("2");
    expect(screen.getByTestId("ops-scope").textContent).toContain("this API instance");
    expect(screen.getByTestId("ops-generated").textContent).toContain("2026-11-14 09:30:00 UTC");
    expect(screen.getByTestId("ops-generated").querySelector("time")?.getAttribute("datetime")).toBe(GENERATED_AT);
    expect(screen.getByTestId("ops-refresh").getAttribute("href")).toBe("/ops");
    expect(screen.getByRole("button", { name: "Sign out" })).toBeTruthy();
    // No tenant navigation on the operator page.
    expect(screen.queryByRole("navigation")).toBeNull();
  });

  it("shows a normal SLO: objective against attainment, counts, budget, burn, latency, alerts and runbook", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(sloReport());
    await open();
    const slo = panel("SLO-01");
    expect(slo.dataset.state).toBe("ok");
    expect(within(slo).getByRole("heading", { level: 2 }).textContent).toContain("Attestation");
    expect(within(slo).getByRole("heading", { level: 2 }).textContent).toContain("SLO-01");
    expect(within(slo).getByTestId("slo-status").textContent).toBe("OK");
    expect(within(slo).getByTestId("slo-indicator").textContent).toContain("POST /v1/attest");
    expect(within(slo).getByTestId("slo-objective").textContent).toBe("99.99 %");
    expect(within(slo).getByTestId("slo-attainment").textContent).toBe("99.995 %");
    expect(within(slo).getByTestId("slo-counts").textContent).toBe("99,995 good of 100,000");
    expect(within(slo).getByTestId("slo-budget").textContent).toContain("50.0 % left");
    expect(within(slo).getByTestId("slo-runbook").textContent).toContain("RB-03");
    expect(within(slo).getByTestId("slo-burn-1h").textContent).toContain("0.25×");
    expect(within(slo).getByTestId("slo-burn-1h").dataset.over).toBe("false");
    const latency = within(slo).getAllByTestId("slo-latency-row");
    expect(latency).toHaveLength(2);
    expect(latency[1]?.textContent).toContain("p99");
    expect(latency[1]?.textContent).toContain("120 ms");
    expect(latency[1]?.textContent).toContain("Met");
    const alerts = within(slo).getAllByTestId("slo-alert");
    expect(alerts.map((alert) => alert.dataset.rule)).toEqual(["fast", "slow", "ticket"]);
    expect(alerts.every((alert) => alert.dataset.state === "ok")).toBe(true);
    expect(alerts[0]?.textContent).toContain("14.4× over 1 h");
    expect(alerts[0]?.textContent).toContain("Page");
    expect(alerts[2]?.textContent).toContain("Ticket");
  });

  it("shows a firing SLO: firing since, the burn windows over their thresholds, the summary count", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(
      sloReport({
        "SLO-07": {
          good: 900,
          total: 1000,
          attainment: 0.9,
          budget_remaining: -99,
          burn: { "5m": 15, "30m": 5, "1h": 20, "6h": 6, "3d": 1 },
          latency: [
            { variant: "read", percentile: 95, target_ms: 200, observed_ms: 150, met: true },
            { variant: "write", percentile: 95, target_ms: 500, observed_ms: 750, met: false },
          ],
          alerts: [
            { rule: "fast", severity: "page", state: "firing", since: "2026-11-14T09:12:00.000Z" },
            { rule: "slow", severity: "page", state: "ok", since: null },
            { rule: "ticket", severity: "ticket", state: "firing", since: "2026-11-13T22:00:00.000Z" },
          ],
        },
      }),
    );
    await open();
    const slo = panel("SLO-07");
    expect(slo.dataset.state).toBe("firing");
    expect(within(slo).getByTestId("slo-status").textContent).toBe("Firing");
    expect(screen.getByTestId("ops-count-firing").textContent).toBe("1");
    expect(screen.getByTestId("ops-count-ok").textContent).toBe("7");
    // 5 m and 1 h against 14.4, 30 m and 6 h against 6, 3 d against 1 — at or over is over.
    const over = (window: string) => within(slo).getByTestId(`slo-burn-${window}`).dataset.over;
    expect([over("5m"), over("30m"), over("1h"), over("6h"), over("3d")]).toEqual([
      "true",
      "false",
      "true",
      "true",
      "true",
    ]);
    expect(within(slo).getByTestId("slo-burn-5m").textContent).toContain("at or over 14.4×");
    const [fast, slow, ticket] = within(slo).getAllByTestId("slo-alert");
    expect(fast?.dataset.state).toBe("firing");
    expect(fast?.textContent).toContain("Firing since 2026-11-14 09:12:00 UTC");
    expect(slow?.textContent).toContain("Not firing");
    expect(ticket?.textContent).toContain("Firing since 2026-11-13 22:00:00 UTC");
    const rows = within(slo).getAllByTestId("slo-latency-row");
    expect(rows[0]?.textContent).toContain("p95 reads");
    expect(rows[1]?.textContent).toContain("p95 writes");
    expect(rows[1]?.textContent).toContain("750 ms");
    expect(rows[1]?.textContent).toContain("Missed");
    expect(rows[1]?.dataset.met).toBe("false");
  });

  it("shows an overspent budget as overspent", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(
      sloReport({ "SLO-02": { good: 9986, total: 10_000, attainment: 0.9986, budget_remaining: -1.8 } }),
    );
    await open();
    const budget = within(panel("SLO-02")).getByTestId("slo-budget");
    expect(budget.textContent).toContain("Overspent by 180.0 %");
    expect(budget.dataset.overspent).toBe("true");
  });

  it("marks a burn exactly at its threshold as over, as the API's rule does (review M1)", async () => {
    const rate = 9 / 625 / (1 - 0.999);
    vi.mocked(api.getSloReport).mockResolvedValueOnce(
      sloReport({
        "SLO-07": {
          good: 616,
          total: 625,
          attainment: 616 / 625,
          budget_remaining: 1 - 9 / 625 / (1 - 0.999),
          burn: { "5m": rate, "30m": rate, "1h": rate, "6h": rate, "3d": rate },
          alerts: [
            { rule: "fast", severity: "page", state: "firing", since: "2026-11-14T09:12:00.000Z" },
            { rule: "slow", severity: "page", state: "firing", since: "2026-11-14T09:12:00.000Z" },
            { rule: "ticket", severity: "ticket", state: "firing", since: "2026-11-14T09:12:00.000Z" },
          ],
        },
      }),
    );
    await open();
    const burn = within(panel("SLO-07")).getByTestId("slo-burn-1h");
    expect(burn.dataset.over).toBe("true");
    expect(burn.textContent).toContain("14.4×");
    expect(burn.textContent).toContain("at or over 14.4×");
    expect(within(panel("SLO-07")).getByTestId("slo-burn-5m").dataset.over).toBe("true");
  });

  it("says the objective is missed when nothing fires but attainment is below it (review M2)", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(
      sloReport({
        "SLO-02": { good: 99_000, total: 100_000, attainment: 0.99, budget_remaining: 1 - 0.01 / (1 - 0.9995) },
      }),
    );
    await open();
    const slo = panel("SLO-02");
    expect(slo.dataset.state).toBe("objective-missed");
    expect(within(slo).getByTestId("slo-status").textContent).toBe("Objective missed");
    expect(within(slo).getByTestId("slo-status").parentElement?.querySelector("svg")).not.toBeNull();
    expect(screen.getByTestId("ops-count-missed").textContent).toBe("1");
    expect(screen.getByTestId("ops-count-ok").textContent).toBe("7");
    expect(screen.getByTestId("ops-count-firing").textContent).toBe("0");
  });

  it("does not call a budget spent exactly to the objective overspent (review L1)", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(
      sloReport({
        "SLO-02": {
          good: 9_995,
          total: 10_000,
          attainment: 9_995 / 10_000,
          budget_remaining: 1 - 5 / 10_000 / (1 - 0.9995),
        },
      }),
    );
    await open();
    const slo = panel("SLO-02");
    expect(slo.dataset.state).toBe("ok");
    const budget = within(slo).getByTestId("slo-budget");
    expect(budget.dataset.overspent).toBe("false");
    expect(budget.textContent).toContain("0.0 % left");
    expect(budget.textContent).not.toContain("Overspent");
  });

  it("says no traffic yet for a measured SLO without events", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(
      sloReport({
        "SLO-10": {
          good: 0,
          total: 0,
          attainment: null,
          budget_remaining: null,
          burn: { "5m": null, "30m": null, "1h": null, "6h": null, "3d": null },
          latency: [{ variant: "all", percentile: 95, target_ms: 1_800_000, observed_ms: null, met: null }],
        },
      }),
    );
    await open();
    const slo = panel("SLO-10");
    expect(slo.dataset.state).toBe("no-traffic");
    expect(within(slo).getByTestId("slo-status").textContent).toBe("No traffic yet");
    expect(within(slo).getByTestId("slo-attainment").textContent).toBe("No traffic yet");
    expect(within(slo).getByTestId("slo-burn-1h").textContent).toContain("No events");
    expect(within(slo).getByTestId("slo-latency-row").textContent).toContain("No events");
    // Counted as OK in the summary: nothing is firing.
    expect(screen.getByTestId("ops-count-ok").textContent).toBe("8");
  });

  it("shows why an SLO is not measured, and nothing else of it but its objective and runbook", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(sloReport());
    await open();
    const slo = panel("SLO-06");
    expect(slo.dataset.state).toBe("not-measured");
    expect(within(slo).getByTestId("slo-status").textContent).toBe("Not measured");
    expect(within(slo).getByTestId("slo-not-measured").textContent).toContain("synthetic probe");
    expect(within(slo).getByTestId("slo-objective").textContent).toBe("95 %");
    expect(within(slo).getByTestId("slo-runbook").textContent).toContain("RB-04");
    expect(within(slo).queryByTestId("slo-burn")).toBeNull();
    expect(within(slo).queryAllByTestId("slo-alert")).toHaveLength(0);
  });

  it("renders without client JavaScript: the whole dashboard is in the server HTML", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(sloReport());
    const html = renderToString(await OpsPage());
    expect(html.match(/data-testid="slo-panel"/g)).toHaveLength(10);
    expect(html).toContain('href="/ops"');
    expect(html).not.toContain(OPS_TOKEN);
  });
});

describe("/ops/sign-in", () => {
  it("asks for the operator token in a password field, and says when the saved one expired", async () => {
    render(await OpsSignInPage({ searchParams: Promise.resolve({ reason: "expired" }) }));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Sign in as an operator");
    const input = screen.getByLabelText("Operator token") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(input.name).toBe("token");
    const notice = screen.getByTestId("ops-signin-notice");
    expect(notice.textContent).toContain("no longer accepted");
    expect(notice.getAttribute("role")).toBe("status");
    expect(screen.queryByRole("navigation")).toBeNull();
  });

  it("asks search engines not to index it", () => {
    expect(signInMetadata.robots).toEqual({ index: false, follow: false });
  });

  it("shows no notice on a plain visit", async () => {
    render(await OpsSignInPage({ searchParams: Promise.resolve({}) }));
    expect(screen.queryByTestId("ops-signin-notice")).toBeNull();
  });
});

describe("tenant navigation", () => {
  it("never links to the operator dashboard", () => {
    const { container } = render(
      <AppShell organization={organization}>
        <p>content</p>
      </AppShell>,
    );
    const hrefs = [...container.querySelectorAll("a")].map((link) => link.getAttribute("href") ?? "");
    expect(hrefs.length).toBeGreaterThan(5);
    expect(hrefs.some((href) => href.startsWith("/ops"))).toBe(false);
  });
});
