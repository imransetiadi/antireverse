import { render, screen, within } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { APP_A, EMPTY_USAGE, USAGE } from "./helpers/usage.ts";

// Slice 17a: Settings → Usage — the month picker (a GET form), the totals, the per-App table and the daily requests
// chart with its table, and each way the read can fail; rendered with the API client and the session guard replaced.
vi.mock("@/app/actions.ts", () => ({ signOutAction: vi.fn() }));
const guard = vi.hoisted(() => ({ session: null as unknown }));
vi.mock("@/lib/guard.ts", () => ({ requireSession: vi.fn(async () => guard.session) }));
vi.mock("@/lib/api.ts", () => {
  class ApiError extends Error {
    readonly status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
    }
  }
  class UnauthorizedError extends ApiError {}
  class DeletionPendingError extends ApiError {}
  class RateLimitedError extends ApiError {
    readonly retryAfter: number | undefined;
    constructor(message: string, retryAfter: number | undefined) {
      super(message, 429);
      this.retryAfter = retryAfter;
    }
  }
  class ValidationError extends ApiError {
    readonly errors: { path: string; message: string }[];
    constructor(message: string, errors: { path: string; message: string }[]) {
      super(message, 400);
      this.errors = errors;
    }
  }
  return {
    getUsage: vi.fn(),
    ApiError,
    UnauthorizedError,
    DeletionPendingError,
    RateLimitedError,
    ValidationError,
  };
});
vi.mock("next/navigation", async (original) => ({
  ...(await original<typeof import("next/navigation")>()),
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import UsagePage from "@/app/settings/usage/page.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { DailyRequestsChart } from "@/features/usage/daily-requests-chart.tsx";
import { formatMinutes, monthName, usageMonthOptions, usageMonthParam } from "@/features/usage/query.ts";
import * as api from "@/lib/api.ts";
import { ROUTES } from "@/lib/routes.ts";

const organization = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };
const NOW = Date.parse("2026-11-14T09:00:00.000Z");

const open = async (params: Record<string, string | string[] | undefined> = {}) =>
  render(await UsagePage({ searchParams: Promise.resolve(params) }));
const cellsOf = (row: HTMLElement): string[] =>
  [...row.querySelectorAll("th, td")].map((cell) => (cell.textContent ?? "").trim());

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(NOW);
  vi.mocked(api.getUsage).mockReset();
  guard.session = { key: "k", organization };
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("the address and the months", () => {
  it("has a Usage address, with the month when one is chosen", () => {
    expect(ROUTES.usage()).toBe("/settings/usage");
    expect(ROUTES.usage("2026-10")).toBe("/settings/usage?month=2026-10");
  });

  it("offers the current UTC month and the 13 before it, newest first", () => {
    const months = usageMonthOptions(new Date(NOW));
    expect(months).toHaveLength(14);
    expect(months[0]).toBe("2026-11");
    expect(months[1]).toBe("2026-10");
    expect(months.at(-1)).toBe("2025-10");
    // Across a year, from the first instant of January (UTC).
    expect(usageMonthOptions(new Date("2027-01-01T00:00:00.000Z")).slice(0, 3)).toEqual([
      "2027-01",
      "2026-12",
      "2026-11",
    ]);
  });

  it("reads the month from the address as given, the first of several; empty means the current month", () => {
    expect(usageMonthParam({})).toBeUndefined();
    expect(usageMonthParam({ month: "" })).toBeUndefined();
    expect(usageMonthParam({ month: "2026-10" })).toBe("2026-10");
    expect(usageMonthParam({ month: "nonsense" })).toBe("nonsense");
    expect(usageMonthParam({ month: ["2026-09", "2026-08"] })).toBe("2026-09");
  });

  it("names a month and formats minutes", () => {
    expect(monthName("2026-11")).toBe("November 2026");
    expect(monthName("2026-01")).toBe("January 2026");
    expect(formatMinutes(0)).toBe("0");
    expect(formatMinutes(90.5)).toBe("90.5");
    expect(formatMinutes(1234.25)).toBe("1,234.25");
  });
});

describe("the shell", () => {
  it("has a Usage entry in the Settings navigation, before Data controls", () => {
    render(
      <AppShell organization={organization} current="usage">
        <p>body</p>
      </AppShell>,
    );
    const settings = screen.getByRole("navigation", { name: "Settings" });
    const link = within(settings).getByTestId("nav-usage");
    expect(link.textContent).toBe("Usage");
    expect(link.getAttribute("href")).toBe("/settings/usage");
    expect(link.getAttribute("aria-current")).toBe("page");
    expect(
      within(settings)
        .getAllByRole("link")
        .map((item) => item.textContent),
    ).toEqual(["Alerts", "Never block", "Audit log", "Usage", "Data controls"]);
  });
});

describe("Settings → Usage", () => {
  it("reads the month of the address with the session's key", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce(USAGE);
    await open({ month: "2026-11" });
    expect(api.getUsage).toHaveBeenCalledWith("k", "2026-11");
    vi.mocked(api.getUsage).mockResolvedValueOnce(USAGE);
    await open();
    expect(api.getUsage).toHaveBeenLastCalledWith("k", undefined);
  });

  it("offers the months in a GET form of the page, the shown month chosen", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce({ ...USAGE, month: "2026-10", closed: true });
    await open({ month: "2026-10" });
    const form = screen.getByTestId("usage-month-form") as HTMLFormElement;
    expect(form.getAttribute("method")).toBe("get");
    expect(form.getAttribute("action")).toBe("/settings/usage");
    const select = within(form).getByLabelText("Month") as HTMLSelectElement;
    expect(select.name).toBe("month");
    expect(select.value).toBe("2026-10");
    expect([...select.options].slice(0, 2).map((option) => [option.value, option.textContent])).toEqual([
      ["2026-11", "November 2026"],
      ["2026-10", "October 2026"],
    ]);
    expect(select.options).toHaveLength(14);
    expect(within(form).getByRole("button", { name: "Show" }).getAttribute("type")).toBe("submit");
  });

  it("chooses the API's month even when the Console's clock is still in the month before (review 17a, L1)", async () => {
    vi.mocked(Date.now).mockReturnValue(Date.parse("2026-11-30T23:59:59.999Z"));
    vi.mocked(api.getUsage).mockResolvedValueOnce({ ...USAGE, month: "2026-12" });
    await open();
    const select = screen.getByLabelText("Month") as HTMLSelectElement;
    expect(select.value).toBe("2026-12");
    expect([...select.options].slice(0, 2).map((option) => option.value)).toEqual(["2026-12", "2026-11"]);
  });

  it("works without JavaScript: the server render holds the form and the chosen month", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce(USAGE);
    const html = renderToString(await UsagePage({ searchParams: Promise.resolve({}) }));
    expect(html).toContain('method="get"');
    expect(html).toContain('name="month"');
    expect(html).toMatch(/<option value="2026-11" selected="">November 2026<\/option>/);
  });

  it("says that the current month is in progress, with counts so far", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce(USAGE);
    await open();
    expect(screen.getByTestId("usage-status").textContent).toBe(
      "November 2026 so far — the month is in progress (UTC). Counts grow until it ends.",
    );
  });

  it("shows the totals, with the note that requests Shield drops are not counted", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce(USAGE);
    await open();
    const totals = screen.getByTestId("usage-totals");
    expect(
      within(totals)
        .getAllByTestId("usage-total")
        .map((item) => [
          item.querySelector("dt")?.textContent,
          item.querySelector("[data-testid=usage-total-value]")?.textContent,
        ]),
    ).toEqual([
      ["Protected requests", "14,400"],
      ["Monthly active Guard devices", "1,250"],
      ["Prove sandbox minutes", "90.5"],
    ]);
    expect(within(totals).queryByTestId("usage-devices-capped")).toBeNull();
    expect(totals.textContent).toContain(
      "Requests that Shield drops before they reach Airverse (a full buffer, or giving up after retries) and batches the API refuses are not counted.",
    );
    // Review 17a, M1: only trusted or suspect verdicts count, with a daily cap per App.
    expect(totals.textContent).toContain(
      "Distinct devices whose Attestation Token had a trusted or suspect verdict (hostile ones are not counted), per App; at most 50,000 new devices per App per day.",
    );
  });

  it("shows the Apps count, the Event retention with a link to Data controls, and seats as not applicable", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce({ ...USAGE, event_retention_days: 90 });
    await open();
    const organizationFacts = screen.getByTestId("usage-organization");
    expect(within(organizationFacts).getByTestId("usage-apps-count").textContent).toBe("2");
    expect(within(organizationFacts).getByTestId("usage-retention").textContent).toContain("90 days");
    expect(within(organizationFacts).getByRole("link", { name: "Change in Data controls" }).getAttribute("href")).toBe(
      "/settings/data",
    );
    expect(within(organizationFacts).getByTestId("usage-seats").textContent).toBe(
      "Not applicable — no member accounts yet",
    );
  });

  it("lists every App with its requests, Guard devices and sandbox minutes", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce(USAGE);
    await open();
    const table = screen.getByTestId("usage-apps");
    expect(within(table).getByRole("columnheader", { name: "App" })).toBeTruthy();
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toEqual(["App", "Protected requests", "Guard devices", "Sandbox minutes"]);
    expect(within(table).getAllByTestId("usage-app-row").map(cellsOf)).toEqual([
      ["Storefront", "13,400", "1,250", "90.5"],
      ["Back office", "1,000", "0", "0"],
    ]);
    expect(within(table).getAllByTestId("usage-app-row")[0]?.getAttribute("data-app-id")).toBe(APP_A);
  });

  it("marks Guard devices as a lower bound when recording stopped at the daily cap", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce({
      ...USAGE,
      totals: { ...USAGE.totals, guard_devices_capped: true },
      apps: USAGE.apps.map((app, i) => ({ ...app, guard_devices_capped: i === 0 })),
    });
    await open();
    expect(screen.getAllByTestId("usage-total-value").map((value) => value.textContent)).toEqual([
      "14,400",
      "At least 1,250",
      "90.5",
    ]);
    expect(screen.getByTestId("usage-devices-capped").textContent).toBe(
      "Recording stopped at 50,000 new devices a day for an App on some day of this month, so this count is a lower bound.",
    );
    expect(screen.getAllByTestId("usage-app-row").map(cellsOf)).toEqual([
      ["Storefront", "13,400", "At least 1,250", "90.5"],
      ["Back office", "1,000", "0", "0"],
    ]);
  });

  it("says when there are no Apps yet", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce({ ...EMPTY_USAGE, apps: [], apps_count: 0 });
    await open({ month: "2026-02" });
    expect(screen.queryByTestId("usage-apps")).toBeNull();
    expect(screen.getByTestId("usage-apps-empty").textContent).toContain("No Apps yet.");
  });

  it("shows an empty, closed month calmly: zeros, no chart, and says so", async () => {
    vi.mocked(api.getUsage).mockResolvedValueOnce(EMPTY_USAGE);
    await open({ month: "2026-02" });
    expect(screen.getByTestId("usage-status").textContent).toBe("February 2026 — the month has ended (UTC).");
    expect(screen.getAllByTestId("usage-total-value").map((value) => value.textContent)).toEqual(["0", "0", "0"]);
    expect(screen.queryByTestId("usage-chart")).toBeNull();
    expect(screen.getByTestId("usage-daily-empty").textContent).toBe("No protected requests in February 2026.");
  });

  it("says why a month in the address cannot be shown, in the API's words, and keeps the picker", async () => {
    vi.mocked(api.getUsage).mockRejectedValueOnce(
      new api.ValidationError("400", [{ path: "month", message: "The month is in the future." }]),
    );
    await open({ month: "2027-03" });
    const alert = screen.getByRole("alert");
    expect(alert.getAttribute("data-testid")).toBe("usage-invalid");
    expect(alert.textContent).toBe(
      "This month cannot be shown: The month is in the future. Choose one of the listed months.",
    );
    expect((screen.getByLabelText("Month") as HTMLSelectElement).value).toBe("2026-11");
    expect(screen.queryByTestId("usage-totals")).toBeNull();
  });

  it("says when a malformed month is refused without a message of its own", async () => {
    vi.mocked(api.getUsage).mockRejectedValueOnce(new api.ValidationError("400", []));
    await open({ month: "nonsense" });
    expect(screen.getByTestId("usage-invalid").textContent).toBe(
      "This month cannot be shown: The month was not understood. Choose one of the listed months.",
    );
  });

  it("asks to wait a minute when the Organization's reads are spent", async () => {
    vi.mocked(api.getUsage).mockRejectedValueOnce(new api.RateLimitedError("429", 30));
    await open();
    expect(screen.getByTestId("usage-limited").textContent).toBe(
      "Too many reads for this Organization just now — usage shares a limit with the audit log and exports. Try again in a minute.",
    );
    expect(screen.getByTestId("usage-month-form")).toBeTruthy();
    expect(screen.queryByTestId("usage-totals")).toBeNull();
  });

  it("says when usage could not be read for another reason", async () => {
    vi.mocked(api.getUsage).mockRejectedValueOnce(new api.ApiError("500", 500));
    await open();
    expect(screen.getByTestId("usage-unavailable").textContent).toBe(
      "Usage could not be read. Reload the page to try again.",
    );
  });

  it("goes to sign-in when the key is no longer accepted", async () => {
    vi.mocked(api.getUsage).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(UsagePage({ searchParams: Promise.resolve({}) })).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });

  it("goes to Data controls when a deletion was requested meanwhile (D-084)", async () => {
    vi.mocked(api.getUsage).mockRejectedValueOnce(new api.DeletionPendingError("403"));
    await expect(UsagePage({ searchParams: Promise.resolve({}) })).rejects.toThrow("REDIRECT /settings/data?blocked=1");
  });
});

describe("DailyRequestsChart", () => {
  const chart = (closed = false) =>
    render(<DailyRequestsChart daily={USAGE.daily} month={USAGE.month} closed={closed} />);

  it("is an image with a summary that says the total and the busiest day", () => {
    chart();
    const image = screen.getByRole("img");
    expect(image.getAttribute("aria-label")).toBe(
      "Daily protected requests, November 2026 so far: 14,400 in all. Busiest day: 2026-11-03, with 4,200.",
    );
    chart(true);
    expect(screen.getAllByRole("img")[1]?.getAttribute("aria-label")).toBe(
      "Daily protected requests, November 2026: 14,400 in all. Busiest day: 2026-11-03, with 4,200.",
    );
  });

  it("draws one bar per day, the busiest full height, a day without requests none, each with its value on hover", () => {
    chart();
    const bars = screen.getAllByTestId("usage-bar");
    expect(bars).toHaveLength(30);
    expect(bars[2]?.getAttribute("height")).toBe("100%");
    expect(bars[2]?.getAttribute("y")).toBe("0%");
    expect(bars[0]?.getAttribute("y")).toBe(`${100 - (100 / 4200) * 100}%`);
    expect(bars[20]?.getAttribute("data-empty")).toBe("true");
    expect(bars[20]?.getAttribute("height")).toBe("0");
    // A tiny count keeps a visible stub.
    render(
      <DailyRequestsChart
        daily={[
          { day: "2026-11-01", requests: 10_000 },
          { day: "2026-11-02", requests: 1 },
        ]}
        month="2026-11"
        closed
      />,
    );
    expect(screen.getAllByTestId("usage-bar")[31]?.getAttribute("y")).toBe("98%");
    const days = screen.getAllByTestId("usage-day");
    expect(days[2]?.querySelector("title")?.textContent).toBe("2026-11-03: 4,200 requests");
    expect(days[0]?.querySelector("title")?.textContent).toBe("2026-11-01: 100 requests");
  });

  it("labels the scale and the days 1, 8, 15, 22 and 29", () => {
    chart();
    expect(screen.getByTestId("usage-chart-max").textContent).toBe("4,200");
    expect(screen.getAllByTestId("usage-chart-day").map((label) => label.textContent)).toEqual([
      "1",
      "8",
      "15",
      "22",
      "29",
    ]);
  });

  it("has a table of every day as its text equivalent", () => {
    chart();
    const table = screen.getByTestId("usage-daily-table");
    expect(table.closest("details")?.querySelector("summary")?.textContent).toBe("Show daily requests as a table");
    const rows = within(table).getAllByTestId("usage-daily-row");
    expect(rows).toHaveLength(30);
    expect(cellsOf(rows[2] as HTMLElement)).toEqual(["2026-11-03", "4,200"]);
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toEqual(["Day (UTC)", "Requests"]);
  });
});
