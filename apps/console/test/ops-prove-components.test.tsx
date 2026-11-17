import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ORG_ID, operatorState } from "./helpers/campaigns.ts";
import { OPS_TOKEN, sloReport } from "./helpers/slo.ts";

// Slice 15a: the operator's Campaign switches on /ops — the state (enabled, killed, suspended Organizations, active
// count) and the controls Kill, Enable, Suspend and Resume, each with a required reason — rendered with the API client,
// the operator session and the Server Actions replaced.

vi.mock("@/app/ops/actions.ts", () => ({
  opsSignInAction: vi.fn(),
  opsSignOutAction: vi.fn(),
  proveSwitchAction: vi.fn(),
}));
vi.mock("@/app/actions.ts", () => ({ signOutAction: vi.fn() }));
const opsSession = vi.hoisted(() => ({ token: undefined as string | undefined }));
vi.mock("@/lib/ops-session.ts", () => ({ readOpsSession: vi.fn(async () => opsSession.token) }));
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  getSloReport: vi.fn(),
  getProveOperatorState: vi.fn(),
}));
vi.mock("next/navigation", async (original) => ({
  ...(await original<typeof import("next/navigation")>()),
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import * as actions from "@/app/ops/actions.ts";
import OpsPage from "@/app/ops/page.tsx";
import { ProveSwitch } from "@/features/ops/prove-switch.tsx";
import * as api from "@/lib/api.ts";

const fieldsOf = (data: FormData): Record<string, string> =>
  Object.fromEntries([...data.entries()].map(([k, v]) => [k, String(v)]));
const sent = (): Record<string, string> => {
  const data = vi.mocked(actions.proveSwitchAction).mock.calls.at(-1)?.[1];
  if (!data) throw new Error("the action was not called");
  return fieldsOf(data);
};
const open = async (query: Record<string, string | string[] | undefined> = {}) =>
  render(await OpsPage({ searchParams: Promise.resolve(query) }));

beforeEach(() => {
  vi.mocked(actions.proveSwitchAction).mockReset();
  vi.mocked(actions.proveSwitchAction).mockResolvedValue(null);
  vi.mocked(api.getSloReport).mockReset();
  vi.mocked(api.getSloReport).mockResolvedValue(sloReport());
  vi.mocked(api.getProveOperatorState).mockReset();
  opsSession.token = OPS_TOKEN;
});

describe("ProveSwitch", () => {
  it("shows the state: on, not killed, nothing suspended, the active count", () => {
    render(<ProveSwitch state={operatorState({ active: 2 })} />);
    expect(screen.getByTestId("prove-enabled").textContent).toBe("On");
    expect(screen.getByTestId("prove-killed").textContent).toBe("Not engaged");
    expect(screen.getByTestId("prove-killed").getAttribute("data-killed")).toBe("false");
    expect(screen.getByTestId("prove-active").textContent).toBe("2");
    expect(screen.getByTestId("prove-suspended").textContent).toBe("None");
  });

  it("shows a service with Campaigns off, an engaged kill switch and the suspended Organizations", () => {
    render(
      <ProveSwitch
        state={operatorState({
          enabled: false,
          killed: true,
          killed_at: "2026-11-16T10:00:00.000Z",
          suspended: [{ organization_id: ORG_ID, suspended_at: "2026-11-15T08:00:00.000Z" }],
        })}
      />,
    );
    expect(screen.getByTestId("prove-enabled").textContent).toBe(
      "Off: no Campaign can be created or started on this API.",
    );
    const killed = screen.getByTestId("prove-killed");
    expect(killed.textContent).toBe("Engaged since 2026-11-16 10:00:00 UTC");
    expect(killed.getAttribute("data-killed")).toBe("true");
    expect(killed.querySelector("svg")).not.toBeNull();
    const suspended = screen.getAllByTestId("prove-suspended-organization");
    expect(suspended).toHaveLength(1);
    expect(suspended[0]?.textContent).toContain(ORG_ID);
    expect(suspended[0]?.textContent).toContain("since 2026-11-15 08:00:00 UTC");
  });

  it("offers Kill with a required reason while not killed, and Enable instead once killed", async () => {
    const { unmount } = render(<ProveSwitch state={operatorState()} />);
    const kill = screen.getByTestId("prove-global-form");
    expect(within(kill).queryByRole("button", { name: "Enable Campaigns" })).toBeNull();
    const reason = within(kill).getByLabelText("Reason") as HTMLInputElement;
    expect(reason.required).toBe(true);
    expect(reason.maxLength).toBe(500);
    fireEvent.change(reason, { target: { value: "Incident 42" } });
    const button = within(kill).getByRole("button", { name: "Stop all Campaigns" }) as HTMLButtonElement;
    expect(button.type).toBe("submit");
    expect(button.name).toBe("change");
    expect(button.value).toBe("kill");
    await act(async () => {
      fireEvent.click(button);
    });
    expect(sent()).toEqual({ reason: "Incident 42", change: "kill" });
    unmount();

    render(<ProveSwitch state={operatorState({ killed: true, killed_at: "2026-11-16T10:00:00.000Z" })} />);
    const enable = screen.getByTestId("prove-global-form");
    expect(within(enable).queryByRole("button", { name: "Stop all Campaigns" })).toBeNull();
    fireEvent.change(within(enable).getByLabelText("Reason"), { target: { value: "Closed" } });
    await act(async () => {
      fireEvent.click(within(enable).getByRole("button", { name: "Enable Campaigns" }));
    });
    expect(sent()).toEqual({ reason: "Closed", change: "enable" });
  });

  it("suspends and resumes one Organization by id, each with a required reason", async () => {
    render(<ProveSwitch state={operatorState()} />);
    const form = screen.getByTestId("prove-organization-form");
    const id = within(form).getByLabelText("Organization id") as HTMLInputElement;
    expect(id.required).toBe(true);
    expect(id.pattern).toBe("org_[0-9a-f]{24}");
    const reason = within(form).getByLabelText("Reason") as HTMLInputElement;
    expect(reason.required).toBe(true);
    fireEvent.change(id, { target: { value: ORG_ID } });
    fireEvent.change(reason, { target: { value: "Abuse report" } });
    await act(async () => {
      fireEvent.click(within(form).getByRole("button", { name: "Suspend" }));
    });
    expect(sent()).toEqual({ organization: ORG_ID, reason: "Abuse report", change: "suspend" });
    fireEvent.change(within(form).getByLabelText("Organization id"), { target: { value: ORG_ID } });
    fireEvent.change(within(form).getByLabelText("Reason"), { target: { value: "Cleared" } });
    await act(async () => {
      fireEvent.click(within(form).getByRole("button", { name: "Resume" }));
    });
    expect(sent()).toEqual({ organization: ORG_ID, reason: "Cleared", change: "resume" });
  });

  it("shows a refusal at its field and keeps what was typed", async () => {
    vi.mocked(actions.proveSwitchAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "organization", message: "Nothing was changed. There is no such Organization." }],
      values: { change: "suspend", organization: ORG_ID, reason: "Abuse report" },
    });
    render(<ProveSwitch state={operatorState()} />);
    const form = screen.getByTestId("prove-organization-form");
    fireEvent.change(within(form).getByLabelText("Organization id"), { target: { value: ORG_ID } });
    fireEvent.change(within(form).getByLabelText("Reason"), { target: { value: "Abuse report" } });
    await act(async () => {
      fireEvent.click(within(form).getByRole("button", { name: "Suspend" }));
    });
    const id = within(form).getByLabelText("Organization id") as HTMLInputElement;
    expect(id.getAttribute("aria-invalid")).toBe("true");
    expect(id.value).toBe(ORG_ID);
    expect((within(form).getByLabelText("Reason") as HTMLInputElement).value).toBe("Abuse report");
    expect(form.textContent).toContain("There is no such Organization.");
    // The other form is untouched.
    expect(screen.getByTestId("prove-global-form").textContent).not.toContain("no such Organization");
  });

  it("says what the last change did", () => {
    const { rerender } = render(
      <ProveSwitch state={operatorState({ killed: true })} done={{ change: "kill", stopped: 2 }} />,
    );
    expect(screen.getByTestId("prove-done").textContent).toBe("All Campaigns are stopped. 2 were ended.");
    expect(screen.getByTestId("prove-done").getAttribute("role")).toBe("status");
    rerender(<ProveSwitch state={operatorState()} done={{ change: "enable" }} />);
    expect(screen.getByTestId("prove-done").textContent).toBe("Campaigns are enabled again.");
    rerender(<ProveSwitch state={operatorState()} done={{ change: "suspend", stopped: 0 }} />);
    expect(screen.getByTestId("prove-done").textContent).toBe(
      "The Organization is suspended. 0 of its Campaigns were ended.",
    );
    rerender(<ProveSwitch state={operatorState()} done={{ change: "resume" }} />);
    expect(screen.getByTestId("prove-done").textContent).toBe("The suspension is lifted.");
  });
});

describe("/ops with the Campaign switches", () => {
  it("shows the switches read with the operator token, above the SLO panels", async () => {
    vi.mocked(api.getProveOperatorState).mockResolvedValue(operatorState({ active: 1 }));
    await open();
    expect(api.getProveOperatorState).toHaveBeenCalledWith(OPS_TOKEN);
    const section = screen.getByTestId("ops-prove");
    expect(within(section).getByRole("heading", { name: "Pentest Campaigns" })).toBeTruthy();
    expect(within(section).getByTestId("prove-active").textContent).toBe("1");
    expect(screen.getAllByTestId("slo-panel").length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toContain(OPS_TOKEN);
  });

  it("says what a change did from the address, and ignores values it does not know", async () => {
    vi.mocked(api.getProveOperatorState).mockResolvedValue(operatorState({ killed: true }));
    const first = await open({ prove: "kill", stopped: "3" });
    expect(screen.getByTestId("prove-done").textContent).toBe("All Campaigns are stopped. 3 were ended.");
    first.unmount();
    const second = await open({ prove: "launch", stopped: "3" });
    expect(screen.queryByTestId("prove-done")).toBeNull();
    second.unmount();
    await open({ prove: "kill", stopped: "<b>" });
    expect(screen.getByTestId("prove-done").textContent).toBe("All Campaigns are stopped. 0 were ended.");
  });

  it("keeps the SLO report when the switches are not available or cannot be read, and says which", async () => {
    vi.mocked(api.getProveOperatorState).mockRejectedValueOnce(new api.NotFoundError("404"));
    const first = await open();
    expect(screen.getByTestId("ops-prove-disabled").textContent).toBe(
      "The operator switches of Campaigns are not available on this API.",
    );
    expect(screen.queryByTestId("prove-global-form")).toBeNull();
    expect(screen.getAllByTestId("slo-panel").length).toBeGreaterThan(0);
    first.unmount();
    vi.mocked(api.getProveOperatorState).mockRejectedValueOnce(new api.ApiError("down", 0));
    await open();
    expect(screen.getByTestId("ops-prove-unavailable").textContent).toBe(
      "The state of Campaigns could not be read. Use Refresh to try again.",
    );
  });

  it("clears a token the API no longer accepts, and needs the operator session", async () => {
    vi.mocked(api.getProveOperatorState).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(OpsPage({ searchParams: Promise.resolve({}) })).rejects.toThrow("REDIRECT /ops/expired");
    opsSession.token = undefined;
    await expect(OpsPage({ searchParams: Promise.resolve({}) })).rejects.toThrow("REDIRECT /ops/sign-in");
  });
});
