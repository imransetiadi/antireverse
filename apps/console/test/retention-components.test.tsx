import { EXAMPLE_INCIDENT } from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PENDING } from "./helpers/deletion.ts";
import { RETENTION, RETENTION_RUN } from "./helpers/retention.ts";

// Slice 18c: the Retention section of Settings → Data controls and the note of Incident evidence, rendered with the
// Server Actions replaced by fakes.
vi.mock("@/app/actions.ts", () => ({
  requestDeletionAction: vi.fn(),
  cancelDeletionAction: vi.fn(),
  eraseSubjectAction: vi.fn(),
  updateRetentionAction: vi.fn(),
  updateIncidentAction: vi.fn(),
  createContainmentAction: vi.fn(),
  liftContainmentAction: vi.fn(),
  signOutAction: vi.fn(),
}));
const guard = vi.hoisted(() => ({ session: null as unknown }));
vi.mock("@/lib/guard.ts", () => ({ requireSessionDuringDeletion: vi.fn(async () => guard.session) }));
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
  return { getRetention: vi.fn(), ApiError, UnauthorizedError, DeletionPendingError };
});
vi.mock("next/navigation", async (original) => ({
  ...(await original<typeof import("next/navigation")>()),
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import * as actions from "@/app/actions.ts";
import DataControlsPage from "@/app/settings/data/page.tsx";
import { ACTION_LABEL } from "@/features/audit/labels.ts";
import { RetentionSettings } from "@/features/data-controls/retention-settings.tsx";
import { IncidentDetail } from "@/features/incidents/incident-detail.tsx";
import * as api from "@/lib/api.ts";
import { t } from "@/lib/t.ts";

const organization = { id: PENDING.organization_id, name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };
const NOW = Date.parse("2026-11-14T09:00:00.000Z");
const REMOVED_BEFORE = "2026-11-07T09:00:00.000Z";

const rowsOf = (table: HTMLElement): string[][] =>
  within(table)
    .getAllByTestId("retention-row")
    .map((row) => [...row.querySelectorAll("th, td")].map((cell) => (cell.textContent ?? "").trim()));
const sent = (): Record<string, string> => {
  const data = vi.mocked(actions.updateRetentionAction).mock.calls.at(-1)?.[1] as FormData | undefined;
  return data ? (Object.fromEntries(data.entries()) as Record<string, string>) : {};
};
const choose = (days: string) =>
  fireEvent.change(screen.getByLabelText("Keep Events for"), { target: { value: days } });
const save = async () => {
  await act(async () => {
    fireEvent.click(screen.getByTestId("retention-save"));
  });
};

beforeEach(() => {
  vi.mocked(actions.updateRetentionAction).mockReset();
  vi.spyOn(Date, "now").mockReturnValue(NOW);
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("RetentionSettings", () => {
  it("lists what is kept and for how long, with the Organization's Event retention first", () => {
    render(<RetentionSettings retention={RETENTION} lastRun={null} />);
    expect(rowsOf(screen.getByTestId("retention-table"))).toEqual([
      ["Events (request metadata)", "30 days — set below"],
      ["Events carrying a Guard report", "At most 30 days"],
      ["Ended blocks", "30 days after they end — with the Events"],
      [
        "Incidents with their Detections and alert deliveries",
        "395 days after they were last seen; kept while a block still names them",
      ],
      ["Alert deliveries", "395 days"],
      ["Finished Assessments", "395 days after they finish"],
      ["Protected artifacts", "30 days after their last Assessment"],
      ["Audit log", "The Organization's lifetime"],
      ["Builds", "The Organization's lifetime"],
    ]);
  });

  it("offers the five periods with the current one chosen", () => {
    render(<RetentionSettings retention={{ ...RETENTION, event_retention_days: 395 }} lastRun={null} />);
    const select = screen.getByLabelText("Keep Events for") as HTMLSelectElement;
    expect(select.name).toBe("event_retention_days");
    expect([...select.options].map((option) => [option.value, option.textContent])).toEqual([
      ["7", "7 days"],
      ["30", "30 days"],
      ["90", "90 days"],
      ["180", "180 days"],
      ["395", "395 days"],
    ]);
    expect(select.value).toBe("395");
  });

  it("shows the last run: its time and the rows removed per table", () => {
    render(<RetentionSettings retention={RETENTION} lastRun={RETENTION_RUN} />);
    const run = screen.getByTestId("retention-last-run");
    expect(run.textContent).toContain("Last run: 2026-11-14 03:00:00 UTC");
    expect(
      within(run)
        .getAllByTestId("retention-count")
        .map((item) => item.textContent),
    ).toEqual([
      "Events: 1,200 removed",
      "Ended blocks: 1 removed",
      "Incidents: 3 removed",
      "Detections: 9 removed",
      "Alert deliveries: 4 removed",
      "Assessments: 2 removed",
    ]);
    expect(run.textContent).toContain("Protected artifacts are removed by the same run and are not counted here.");
    expect(within(run).queryByTestId("retention-incomplete")).toBeNull();
  });

  it("says when a run was cut short, when it removed nothing, and when none ran yet", () => {
    const { rerender } = render(
      <RetentionSettings
        retention={RETENTION}
        lastRun={{ ...RETENTION_RUN, complete: false, counts: { foo_bar: 2 } }}
      />,
    );
    expect(screen.getByTestId("retention-incomplete").textContent).toBe("Cut short — continues at the next run.");
    expect(screen.getByTestId("retention-count").textContent).toBe("foo_bar: 2 removed");
    rerender(<RetentionSettings retention={RETENTION} lastRun={{ ...RETENTION_RUN, counts: {} }} />);
    expect(screen.getByTestId("retention-last-run").textContent).toContain("Nothing was removed.");
    rerender(<RetentionSettings retention={RETENTION} lastRun={null} />);
    expect(screen.getByTestId("retention-last-run").textContent).toContain("No run yet. The retention job runs daily.");
    // Review 18c, L1: a table named like a member of Object.prototype is listed by its name.
    rerender(<RetentionSettings retention={RETENTION} lastRun={{ ...RETENTION_RUN, counts: { constructor: 3 } }} />);
    expect(screen.getByTestId("retention-count").textContent).toBe("constructor: 3 removed");
  });

  it("lengthening saves at once, without a confirmation step or a reason", async () => {
    vi.mocked(actions.updateRetentionAction).mockResolvedValueOnce({
      ok: true,
      days: 90,
      eventsRemovedBefore: "2026-08-16T09:00:00.000Z",
    });
    render(<RetentionSettings retention={RETENTION} lastRun={null} />);
    choose("90");
    await save();
    expect(actions.updateRetentionAction).toHaveBeenCalledTimes(1);
    expect(sent()).toEqual({ event_retention_days: "90" });
    expect(screen.queryByTestId("retention-confirm")).toBeNull();
    const done = screen.getByTestId("retention-done");
    expect(done.textContent).toBe(
      "Event retention set to 90 days. Events received before about 2026-08-16 09:00:00 UTC are removed at the next daily run, and from then on every Event older than 90 days.",
    );
    expect(document.activeElement).toBe(done);
    expect(screen.getByTestId("retention-result").getAttribute("role")).toBe("status");
  });

  it("shortening opens the confirmation step in place: focused, what goes, a required reason; Cancel returns", async () => {
    render(<RetentionSettings retention={RETENTION} lastRun={null} />);
    choose("7");
    await save();
    expect(actions.updateRetentionAction).not.toHaveBeenCalled();
    const panel = screen.getByTestId("retention-confirm");
    expect(document.activeElement).toBe(panel);
    expect(within(panel).getByTestId("confirm-question").textContent).toBe("Shorten the Event retention to 7 days?");
    expect(panel.textContent).toContain(
      "Events received before about 2026-11-07 09:00 UTC are removed at the next daily run",
    );
    expect(panel.textContent).toContain("blocks that ended more than 7 days ago");
    expect(panel.textContent).toContain("This cannot be undone.");
    expect(within(panel).queryByRole("link")).toBeNull();
    const reason = within(panel).getByLabelText("Reason") as HTMLInputElement;
    expect(reason.required).toBe(true);
    const hidden = panel.querySelectorAll<HTMLInputElement>('input[type="hidden"]');
    expect(Object.fromEntries([...hidden].map((input) => [input.name, input.value]))).toEqual({
      event_retention_days: "7",
      confirm: "shorten",
    });
    fireEvent.click(within(panel).getByTestId("confirm-cancel"));
    expect(screen.queryByTestId("retention-confirm")).toBeNull();
    expect(document.activeElement).toBe(screen.getByTestId("retention-save"));
  });

  it("sends the shortening with the reason, then closes the step and announces the date from the API", async () => {
    vi.mocked(actions.updateRetentionAction).mockResolvedValueOnce({
      ok: true,
      days: 7,
      eventsRemovedBefore: REMOVED_BEFORE,
    });
    render(<RetentionSettings retention={RETENTION} lastRun={null} />);
    choose("7");
    await save();
    const reason = within(screen.getByTestId("retention-confirm")).getByLabelText("Reason");
    fireEvent.change(reason, { target: { value: "Storage policy" } });
    await act(async () => {
      fireEvent.submit(reason.closest("form") as HTMLFormElement);
    });
    expect(sent()).toEqual({ event_retention_days: "7", confirm: "shorten", reason: "Storage policy" });
    expect(screen.queryByTestId("retention-confirm")).toBeNull();
    const done = screen.getByTestId("retention-done");
    expect(done.textContent).toContain(
      "Events received before about 2026-11-07 09:00:00 UTC are removed at the next daily run, and from then on every Event older than 7 days.",
    );
    expect(document.activeElement).toBe(done);
  });

  it("a save the API calls a shortening (stale tab) opens the step for that period; refusals show in the summary", async () => {
    vi.mocked(actions.updateRetentionAction).mockResolvedValueOnce({ ok: false, errors: [], confirm: 30 });
    render(<RetentionSettings retention={{ ...RETENTION, event_retention_days: 7 }} lastRun={null} />);
    choose("30");
    await save();
    const panel = screen.getByTestId("retention-confirm");
    expect(within(panel).getByTestId("confirm-question").textContent).toBe("Shorten the Event retention to 30 days?");
    expect(document.activeElement).toBe(panel);

    vi.mocked(actions.updateRetentionAction).mockResolvedValueOnce({
      ok: false,
      errors: [
        {
          path: "reason",
          message: "Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
        },
      ],
      reason: "kept",
      confirm: 30,
    });
    const reason = within(panel).getByLabelText("Reason") as HTMLInputElement;
    fireEvent.change(reason, { target: { value: "kept" } });
    await act(async () => {
      fireEvent.submit(reason.closest("form") as HTMLFormElement);
    });
    expect(screen.getByTestId("error-summary").textContent).toContain("Give a reason");
    expect((within(screen.getByTestId("retention-confirm")).getByLabelText("Reason") as HTMLInputElement).value).toBe(
      "kept",
    );
  });

  it("Cancel closes a step the action state opened, and Save opens it again for a shorter period", async () => {
    // A stale tab: it shows 30 days, the API holds 180, so 90 is a shortening the API asks to confirm.
    vi.mocked(actions.updateRetentionAction).mockResolvedValueOnce({ ok: false, errors: [], confirm: 90 });
    render(<RetentionSettings retention={RETENTION} lastRun={null} />);
    choose("90");
    await save();
    expect(actions.updateRetentionAction).toHaveBeenCalledTimes(1);
    fireEvent.click(within(screen.getByTestId("retention-confirm")).getByTestId("confirm-cancel"));
    expect(screen.queryByTestId("retention-confirm")).toBeNull();
    choose("7");
    await save();
    expect(within(screen.getByTestId("retention-confirm")).getByTestId("confirm-question").textContent).toBe(
      "Shorten the Event retention to 7 days?",
    );
  });

  it("a refused period shows on the field", async () => {
    vi.mocked(actions.updateRetentionAction).mockResolvedValueOnce({
      ok: false,
      errors: [{ path: "event_retention_days", message: "Choose one of the offered periods." }],
    });
    render(<RetentionSettings retention={RETENTION} lastRun={null} />);
    choose("90");
    await save();
    expect(screen.getByTestId("retention-days-error").textContent).toBe("Choose one of the offered periods.");
  });
});

describe("the Data controls page", () => {
  it("shows the Retention section from the API when no deletion is pending", async () => {
    vi.mocked(api.getRetention).mockResolvedValueOnce({ retention: RETENTION, last_run: RETENTION_RUN });
    guard.session = { key: "k", organization, deletion: null };
    render(await DataControlsPage({ searchParams: Promise.resolve({}) }));
    expect(screen.getByRole("heading", { level: 2, name: "Retention" })).toBeTruthy();
    expect(api.getRetention).toHaveBeenCalledWith("k");
    expect(screen.getByTestId("retention-table")).toBeTruthy();
    expect(screen.getByTestId("retention-last-run").textContent).toContain("2026-11-14 03:00:00 UTC");
  });

  it("says when the retention could not be read", async () => {
    vi.mocked(api.getRetention).mockRejectedValueOnce(new api.ApiError("500", 500));
    guard.session = { key: "k", organization, deletion: null };
    render(await DataControlsPage({ searchParams: Promise.resolve({}) }));
    expect(screen.getByTestId("retention-unavailable").textContent).toBe(
      "The retention settings could not be read. Reload the page to try again.",
    );
    expect(screen.queryByTestId("retention-table")).toBeNull();
  });

  it("a key no longer accepted goes to sign-in (review 18c, L2)", async () => {
    vi.mocked(api.getRetention).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    guard.session = { key: "k", organization, deletion: null };
    await expect(DataControlsPage({ searchParams: Promise.resolve({}) })).rejects.toThrow(
      "REDIRECT /sign-in?reason=expired",
    );
  });

  it("a deletion requested meanwhile opens Data controls with the pending notice (review 18c, L3)", async () => {
    vi.mocked(api.getRetention).mockRejectedValueOnce(new api.DeletionPendingError("403"));
    guard.session = { key: "k", organization, deletion: null };
    await expect(DataControlsPage({ searchParams: Promise.resolve({}) })).rejects.toThrow(
      "REDIRECT /settings/data?blocked=1",
    );
  });

  it("offers no Retention section while a deletion is pending (the API refuses it)", async () => {
    guard.session = { key: "k", organization: null, deletion: PENDING };
    render(await DataControlsPage({ searchParams: Promise.resolve({}) }));
    expect(screen.queryByRole("heading", { level: 2, name: "Retention" })).toBeNull();
    expect(api.getRetention).not.toHaveBeenCalled();
  });
});

describe("Incident evidence", () => {
  it("notes that Events older than the retention are removed, with a link to Data controls", () => {
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
    const note = screen.getByTestId("evidence-retention");
    expect(note.textContent).toBe(
      "Events older than the Organization's Event retention are removed, and Events carrying a Guard report after at most 30 days, so the evidence of an older Incident may be empty. Retention is set in Settings → Data controls.",
    );
    expect(within(note).getByRole("link", { name: "Settings → Data controls" }).getAttribute("href")).toBe(
      "/settings/data",
    );
  });
});

describe("the audit log", () => {
  it("names a change of the Event retention in words", () => {
    expect(t(ACTION_LABEL["organization.retention.update"])).toBe("Event retention changed");
  });
});
