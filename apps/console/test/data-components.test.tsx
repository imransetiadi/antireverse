import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ERASE_REPORT, IP_HASH, PENDING } from "./helpers/deletion.ts";
import { RETENTION } from "./helpers/retention.ts";

// Slice 18b: Settings → Data controls and the deletion banner of the shell, rendered with the Server Actions
// replaced by fakes.
vi.mock("@/app/actions.ts", () => ({
  requestDeletionAction: vi.fn(),
  cancelDeletionAction: vi.fn(),
  eraseSubjectAction: vi.fn(),
  updateRetentionAction: vi.fn(),
  signOutAction: vi.fn(),
}));
const guard = vi.hoisted(() => ({ session: null as unknown }));
vi.mock("@/lib/guard.ts", () => ({ requireSessionDuringDeletion: vi.fn(async () => guard.session) }));

import * as actions from "@/app/actions.ts";
import DataControlsPage from "@/app/settings/data/page.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { DataNotices } from "@/features/data-controls/data-notices.tsx";
import { DeleteOrganization } from "@/features/data-controls/delete-organization.tsx";
import { DeletionBanner } from "@/features/data-controls/deletion-banner.tsx";
import { dataQueryFrom } from "@/features/data-controls/query.ts";
import { SUBJECT_DRAFT_KEY, SubjectRequest } from "@/features/data-controls/subject-request.tsx";
import { ROUTES } from "@/lib/routes.ts";

const api = { calls: [] as string[], answer: null as unknown };
const organization = { id: PENDING.organization_id, name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };
const ERASED_AFTER = "2026-11-20 09:00:00 UTC";

beforeEach(() => {
  vi.mocked(actions.requestDeletionAction).mockReset();
  vi.mocked(actions.cancelDeletionAction).mockReset();
  vi.mocked(actions.eraseSubjectAction).mockReset();
  sessionStorage.clear();
  // No request leaves a unit test: the page's API calls are answered here (the API's default address is the owner's
  // port 8787, which a test must never reach). A test that expects a call sets `api.answer`.
  api.calls = [];
  api.answer = null;
  vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
    const url = String(input instanceof Request ? input.url : input);
    api.calls.push(url);
    if (api.answer === null) throw new Error(`unexpected request in a unit test: ${url}`);
    return new Response(JSON.stringify(api.answer), { status: 200, headers: { "content-type": "application/json" } });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("routes and the address of Data controls", () => {
  it("builds the page's addresses in a fixed order, never with an actor hash", () => {
    expect(ROUTES.dataControls()).toBe("/settings/data");
    expect(ROUTES.dataControls({ step: "delete" })).toBe("/settings/data?step=delete");
    expect(ROUTES.dataControls({ step: "cancel", done: "requested" })).toBe(
      "/settings/data?step=cancel&done=requested",
    );
    expect(ROUTES.dataControls({ blocked: true })).toBe("/settings/data?blocked=1");
    expect(ROUTES.dataExport).toBe("/api/data/export");
    expect(ROUTES.subjectExport).toBe("/api/data/subject-export");
  });

  it("reads only what it knows from the address; a subject or an erase step in it is ignored", () => {
    expect(dataQueryFrom({ step: "delete", blocked: "1", done: "cancelled" })).toEqual({
      step: "delete",
      done: "cancelled",
      blocked: true,
      subjectExport: undefined,
    });
    expect(dataQueryFrom({ subject: IP_HASH, step: "erase", done: "x", subject_export: "failed" })).toEqual({
      step: undefined,
      done: undefined,
      blocked: false,
      subjectExport: "failed",
    });
  });
});

describe("the shell", () => {
  it("has a Data controls entry in the Settings navigation", () => {
    render(
      <AppShell organization={organization} current="data">
        <p>body</p>
      </AppShell>,
    );
    const link = screen.getByTestId("nav-data");
    expect(link.textContent).toContain("Data controls");
    expect(link.getAttribute("href")).toBe("/settings/data");
    expect(link.getAttribute("aria-current")).toBe("page");
    const settings = screen.getByRole("navigation", { name: "Settings" });
    expect(within(settings).getByTestId("nav-data")).toBe(link);
    expect(screen.queryByTestId("deletion-banner")).toBeNull();
  });

  it("shows the deletion banner above everything while a deletion is pending, with the date and a link", () => {
    render(
      <AppShell organization={null} deletion={PENDING} current="data">
        <p>body</p>
      </AppShell>,
    );
    const banner = screen.getByTestId("deletion-banner");
    expect(banner.tagName).toBe("SECTION");
    expect(screen.getByRole("region", { name: "This Organization is scheduled for deletion" })).toBe(banner);
    expect(banner.textContent).toContain(`its data will be erased after ${ERASED_AFTER}`);
    expect(within(banner).getByRole("link", { name: "Cancel or review in Data controls" }).getAttribute("href")).toBe(
      "/settings/data",
    );
    // Without the Organization (the API refuses to name it while pending) the bar still offers navigation and sign-out.
    expect(screen.getByTestId("nav-data")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeTruthy();
    expect(screen.queryByTestId("organization-name")).toBeNull();
  });

  it("DeletionBanner renders nothing without a pending deletion", () => {
    const { container } = render(<DeletionBanner deletion={null} />);
    expect(container.innerHTML).toBe("");
  });
});

describe("DataNotices", () => {
  it("says why another page sent the person here, only while the deletion is pending (review 18b, L1)", () => {
    const { rerender } = render(<DataNotices query={dataQueryFrom({ blocked: "1" })} pending={true} />);
    expect(screen.getByTestId("data-blocked").textContent).toContain(
      "Other Console pages are unavailable while the deletion is pending",
    );
    expect(screen.getByTestId("data-blocked").getAttribute("role")).toBe("alert");
    rerender(<DataNotices query={dataQueryFrom({ blocked: "1" })} pending={false} />);
    expect(screen.queryByTestId("data-blocked")).toBeNull();
  });

  it("announces a request and a cancellation that match the state, and takes the focus", () => {
    const { rerender } = render(<DataNotices query={dataQueryFrom({ done: "requested" })} pending={true} />);
    const done = screen.getByTestId("data-done");
    expect(done.getAttribute("role")).toBe("status");
    expect(done.textContent).toContain("Deletion requested");
    expect(document.activeElement).toBe(done);
    rerender(<DataNotices query={dataQueryFrom({ done: "cancelled" })} pending={false} />);
    expect(screen.getByTestId("data-done").textContent).toContain("Deletion cancelled");
    // An old address that no longer matches says nothing.
    rerender(<DataNotices query={dataQueryFrom({ done: "requested" })} pending={false} />);
    expect(screen.queryByTestId("data-done")).toBeNull();
    rerender(<DataNotices query={dataQueryFrom({ done: "cancelled" })} pending={true} />);
    expect(screen.queryByTestId("data-done")).toBeNull();
  });

  it("the page claims no pending deletion from `?blocked=1` when none is pending", async () => {
    guard.session = { key: "k", organization, deletion: null };
    // Without a pending deletion the page reads the retention (slice 18c): answered here, at a test address.
    vi.stubEnv("AR_API_URL", "http://api.test");
    api.answer = { retention: RETENTION, last_run: null };
    render(await DataControlsPage({ searchParams: Promise.resolve({ blocked: "1", done: "requested" }) }));
    expect(api.calls).toEqual(["http://api.test/v1/organization/retention"]);
    expect(screen.queryByTestId("data-blocked")).toBeNull();
    expect(screen.queryByTestId("data-done")).toBeNull();
    expect(screen.queryByTestId("deletion-banner")).toBeNull();
    expect(screen.getByTestId("delete-start")).toBeTruthy();
  });
});

describe("SubjectRequest", () => {
  it("asks for the actor hash, explains where it comes from, and posts it to the export (never a GET)", () => {
    render(<SubjectRequest query={dataQueryFrom({})} />);
    const input = screen.getByLabelText("Actor hash") as HTMLInputElement;
    expect(input.name).toBe("subject");
    expect(input.required).toBe(true);
    expect(new RegExp(`^(?:${input.pattern})$`, "v").test(IP_HASH)).toBe(true);
    expect(new RegExp(`^(?:${input.pattern})$`, "v").test("iph_0123")).toBe(false);
    expect(screen.getByTestId("subject-help").textContent).toContain("actorHash");
    expect(screen.getByTestId("subject-help").textContent).toContain("Airverse never receives the address");
    const formElement = input.closest("form") as HTMLFormElement;
    expect(formElement.getAttribute("method")).toBe("post");
    expect(formElement.getAttribute("action")).toBe("/api/data/subject-export");
    expect((screen.getByTestId("subject-export") as HTMLButtonElement).type).toBe("submit");
    const erase = screen.getByTestId("subject-erase") as HTMLButtonElement;
    expect(erase.type).toBe("button");
    expect(erase.name).toBe("");
    expect(screen.queryByTestId("subject-confirm")).toBeNull();
  });

  it("says when the export failed, and gives back what was typed from this tab, never from the address", () => {
    sessionStorage.setItem(SUBJECT_DRAFT_KEY, IP_HASH);
    render(<SubjectRequest query={dataQueryFrom({ subject_export: "failed" })} />);
    expect(screen.getByTestId("subject-export-notice").getAttribute("role")).toBe("alert");
    expect((screen.getByLabelText("Actor hash") as HTMLInputElement).value).toBe(IP_HASH);
    expect(sessionStorage.getItem(SUBJECT_DRAFT_KEY)).toBeNull();
  });

  it("keeps the typed hash for this tab when the export is sent", () => {
    render(<SubjectRequest query={dataQueryFrom({})} />);
    const input = screen.getByLabelText("Actor hash") as HTMLInputElement;
    fireEvent.change(input, { target: { value: ` ${IP_HASH} ` } });
    fireEvent.submit(input.closest("form") as HTMLFormElement);
    expect(sessionStorage.getItem(SUBJECT_DRAFT_KEY)).toBe(IP_HASH);
  });

  it("shows a value that is not an actor hash as an error on the field, and opens no step", () => {
    render(<SubjectRequest query={dataQueryFrom({})} />);
    const input = screen.getByLabelText("Actor hash");
    fireEvent.change(input, { target: { value: "203.0.113.7" } });
    fireEvent.click(screen.getByTestId("subject-erase"));
    expect(screen.getByTestId("subject-input-error").textContent).toContain("iph_");
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(document.activeElement).toBe(input);
    expect(screen.queryByTestId("subject-confirm")).toBeNull();
  });

  it("asks in place before erasing, with a required reason; Cancel closes it and returns the focus", () => {
    render(<SubjectRequest query={dataQueryFrom({})} />);
    fireEvent.change(screen.getByLabelText("Actor hash"), { target: { value: IP_HASH } });
    fireEvent.click(screen.getByTestId("subject-erase"));
    const panel = screen.getByTestId("subject-confirm");
    expect(document.activeElement).toBe(panel);
    expect(within(panel).getByTestId("confirm-question").textContent).toContain(IP_HASH);
    expect(within(panel).queryByRole("link")).toBeNull();
    fireEvent.click(within(panel).getByTestId("confirm-cancel"));
    expect(screen.queryByTestId("subject-confirm")).toBeNull();
    expect(document.activeElement).toBe(screen.getByTestId("subject-erase"));
  });

  it("erases through the action with the hash in the form, and shows the report with the blocks kept", async () => {
    vi.mocked(actions.eraseSubjectAction).mockResolvedValueOnce({ ok: true, report: ERASE_REPORT });
    render(<SubjectRequest query={dataQueryFrom({})} />);
    fireEvent.change(screen.getByLabelText("Actor hash"), { target: { value: IP_HASH } });
    fireEvent.click(screen.getByTestId("subject-erase"));
    const panel = screen.getByTestId("subject-confirm");
    const reason = within(panel).getByLabelText("Reason") as HTMLInputElement;
    expect(reason.required).toBe(true);
    const hidden = panel.querySelectorAll<HTMLInputElement>('input[type="hidden"]');
    expect(Object.fromEntries([...hidden].map((input) => [input.name, input.value]))).toEqual({
      ip_hash: IP_HASH,
      confirm: IP_HASH,
    });
    fireEvent.change(reason, { target: { value: "Erasure request #42" } });
    await act(async () => {
      fireEvent.submit(reason.closest("form") as HTMLFormElement);
    });
    expect(actions.eraseSubjectAction).toHaveBeenCalledTimes(1);
    const report = screen.getByTestId("subject-report");
    expect(report.textContent).toContain("12 Events erased");
    expect(report.textContent).toContain("1 ended block erased");
    expect(report.textContent).toContain("1 active block kept until it ends");
    expect(within(report).getByTestId("subject-active").textContent).toContain("cnt_0123456789abcdef01234567");
    expect(within(report).getByTestId("subject-active").textContent).toContain("2026-11-14 10:00:00 UTC");
    expect(screen.queryByTestId("subject-confirm")).toBeNull();
    expect(screen.getByTestId("subject-result").getAttribute("role")).toBe("status");
    expect(document.activeElement).toBe(report);
    // What was typed stays in the field.
    expect((screen.getByLabelText("Actor hash") as HTMLInputElement).value).toBe(IP_HASH);
  });
});

describe("DeleteOrganization", () => {
  const erasedIfNow = "2026-11-21T10:00:00.000Z";

  it("says what a deletion does before it is asked for, and opens the step through a link", () => {
    render(<DeleteOrganization organization={organization} deletion={null} erasedIfNow={erasedIfNow} />);
    const section = screen.getByTestId("delete-organization");
    expect(section.textContent).toContain("Every key of the Organization stops working at once");
    expect(section.textContent).toContain("erased after about 2026-11-21 10:00 UTC");
    expect(section.textContent).toContain("You can cancel the deletion until then");
    expect(section.textContent).toContain("Export the data first");
    const start = screen.getByTestId("delete-start");
    expect(start.getAttribute("href")).toBe("/settings/data?step=delete");
    expect(screen.queryByTestId("delete-confirm")).toBeNull();
  });

  it("asks for the typed Organization name and a reason in the confirmation step", () => {
    render(<DeleteOrganization organization={organization} deletion={null} erasedIfNow={erasedIfNow} step="delete" />);
    const panel = screen.getByTestId("delete-confirm");
    const typed = within(panel).getByLabelText("Type Acme to confirm") as HTMLInputElement;
    expect(typed.name).toBe("confirm_name");
    expect(typed.required).toBe(true);
    expect((within(panel).getByLabelText("Reason") as HTMLInputElement).required).toBe(true);
    expect(within(panel).getByTestId("confirm-submit").textContent).toContain("Delete Organization");
    expect(within(panel).getByTestId("confirm-cancel").getAttribute("href")).toBe("/settings/data");
    expect(screen.queryByTestId("delete-start")).toBeNull();
  });

  it("while pending shows the date, the deletion id and Cancel deletion instead", () => {
    render(<DeleteOrganization organization={null} deletion={PENDING} erasedIfNow={erasedIfNow} />);
    const status = screen.getByTestId("deletion-status");
    expect(status.textContent).toContain(`erased after ${ERASED_AFTER}`);
    expect(screen.getByTestId("deletion-id").textContent).toContain(PENDING.id);
    expect(screen.getByTestId("deletion-cancel").getAttribute("href")).toBe("/settings/data?step=cancel");
    expect(screen.queryByTestId("delete-start")).toBeNull();
  });

  it("asks for a reason before cancelling", () => {
    render(<DeleteOrganization organization={null} deletion={PENDING} erasedIfNow={erasedIfNow} step="cancel" />);
    const panel = screen.getByTestId("cancel-confirm");
    expect((within(panel).getByLabelText("Reason") as HTMLInputElement).required).toBe(true);
    expect(within(panel).getByTestId("confirm-submit").textContent).toContain("Cancel deletion");
    expect(within(panel).getByTestId("confirm-cancel").textContent).toContain("Keep it scheduled");
  });
});
