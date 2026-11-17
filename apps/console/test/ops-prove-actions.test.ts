// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ORG_ID, operatorState } from "./helpers/campaigns.ts";
import { OPS_TOKEN } from "./helpers/slo.ts";

// Slice 15a: the operator's Campaign switches on /ops. Each change needs the operator session and a reason; the
// token never travels in a redirect, the state or a log line; a form another site sent is refused.

vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  killCampaigns: vi.fn(),
  enableCampaigns: vi.fn(),
  suspendCampaigns: vi.fn(),
  resumeCampaigns: vi.fn(),
}));
const requestHeaders = vi.hoisted(() => ({
  value: new Headers({ host: "console.test", "sec-fetch-site": "same-origin" }),
}));
vi.mock("@/lib/ops-session.ts", async (original) => ({
  ...(await original<typeof import("@/lib/ops-session.ts")>()),
  readOpsSession: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: async () => requestHeaders.value }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import { redirect } from "next/navigation";
import { proveSwitchAction } from "@/app/ops/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/ops-session.ts";

const form = (fields: Record<string, string>): FormData => {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.set(name, value);
  return data;
};
async function redirectOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    const match = /^REDIRECT (.+)$/.exec((error as Error).message);
    if (match) return match[1] as string;
    throw error;
  }
  throw new Error("expected a redirect");
}
const CHANGES = [api.killCampaigns, api.enableCampaigns, api.suspendCampaigns, api.resumeCampaigns];

beforeEach(() => {
  for (const fn of CHANGES) vi.mocked(fn).mockReset();
  vi.mocked(session.readOpsSession).mockReset();
  vi.mocked(session.readOpsSession).mockResolvedValue(OPS_TOKEN);
  vi.mocked(redirect).mockClear();
  requestHeaders.value = new Headers({ host: "console.test", "sec-fetch-site": "same-origin" });
});

describe("proveSwitchAction", () => {
  it("stops all Campaigns with the reason and says how many were ended", async () => {
    vi.mocked(api.killCampaigns).mockResolvedValue(operatorState({ killed: true, stopped: 2 }));
    expect(await redirectOf(proveSwitchAction(null, form({ change: "kill", reason: "  Incident 42 " })))).toBe(
      "/ops?prove=kill&stopped=2",
    );
    expect(api.killCampaigns).toHaveBeenCalledWith(OPS_TOKEN, "Incident 42");
    expect(vi.mocked(redirect).mock.calls[0]?.[0]).not.toContain(OPS_TOKEN);
  });

  it("enables, suspends and resumes", async () => {
    vi.mocked(api.enableCampaigns).mockResolvedValue(operatorState());
    expect(await redirectOf(proveSwitchAction(null, form({ change: "enable", reason: "Closed" })))).toBe(
      "/ops?prove=enable",
    );
    vi.mocked(api.suspendCampaigns).mockResolvedValue(operatorState({ stopped: 1 }));
    expect(
      await redirectOf(
        proveSwitchAction(null, form({ change: "suspend", organization: ` ${ORG_ID} `, reason: "Abuse" })),
      ),
    ).toBe("/ops?prove=suspend&stopped=1");
    expect(api.suspendCampaigns).toHaveBeenCalledWith(OPS_TOKEN, ORG_ID, "Abuse");
    vi.mocked(api.resumeCampaigns).mockResolvedValue(operatorState());
    expect(
      await redirectOf(proveSwitchAction(null, form({ change: "resume", organization: ORG_ID, reason: "Cleared" }))),
    ).toBe("/ops?prove=resume");
    expect(api.resumeCampaigns).toHaveBeenCalledWith(OPS_TOKEN, ORG_ID, "Cleared");
  });

  it("needs a reason and, for one Organization, its id — before anything is sent, keeping what was typed", async () => {
    expect(await proveSwitchAction(null, form({ change: "kill", reason: "  " }))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: "Nothing was changed. Give a reason of 1 to 500 characters." }],
      values: { change: "kill", organization: "", reason: "" },
    });
    expect(await proveSwitchAction(null, form({ change: "kill", reason: "x".repeat(501) }))).toMatchObject({
      errors: [{ path: "reason" }],
    });
    expect(await proveSwitchAction(null, form({ change: "suspend", organization: "acme", reason: "Abuse" }))).toEqual({
      ok: false,
      errors: [
        {
          path: "organization",
          message: "Nothing was changed. Enter an Organization id, for example org_ followed by 24 characters.",
        },
      ],
      values: { change: "suspend", organization: "acme", reason: "Abuse" },
    });
    expect(await proveSwitchAction(null, form({ change: "restart", reason: "x" }))).toMatchObject({
      errors: [{ path: "", message: "Nothing was changed. Choose one of the offered changes." }],
    });
    // A reason that holds a key is refused here: it would be stored in audit logs.
    expect(
      await proveSwitchAction(null, form({ change: "kill", reason: `leaked ${"aro_"}${"A".repeat(43)}` })),
    ).toMatchObject({ errors: [{ path: "reason" }] });
    for (const fn of CHANGES) expect(fn).not.toHaveBeenCalled();
  });

  it("opens operator sign-in without an operator session, and clears a token the API no longer accepts", async () => {
    vi.mocked(session.readOpsSession).mockResolvedValueOnce(undefined);
    expect(await redirectOf(proveSwitchAction(null, form({ change: "kill", reason: "x" })))).toBe("/ops/sign-in");
    expect(api.killCampaigns).not.toHaveBeenCalled();
    vi.mocked(api.killCampaigns).mockRejectedValueOnce(new api.UnauthorizedError("refused"));
    expect(await redirectOf(proveSwitchAction(null, form({ change: "kill", reason: "x" })))).toBe("/ops/expired");
  });

  it("says when there is no such Organization, when the switches are not available, and when the API failed", async () => {
    vi.mocked(api.suspendCampaigns).mockRejectedValueOnce(new api.NotFoundError("refused"));
    expect(
      await proveSwitchAction(null, form({ change: "suspend", organization: ORG_ID, reason: "Abuse" })),
    ).toMatchObject({
      errors: [{ path: "organization", message: "Nothing was changed. There is no such Organization." }],
    });
    vi.mocked(api.killCampaigns).mockRejectedValueOnce(new api.NotFoundError("refused"));
    expect(await proveSwitchAction(null, form({ change: "kill", reason: "x" }))).toMatchObject({
      errors: [
        {
          path: "",
          message: "Nothing was changed. The operator switches of Campaigns are not available on this API.",
        },
      ],
    });
    vi.mocked(api.killCampaigns).mockRejectedValueOnce(
      new api.ValidationError("refused", [{ path: "reason", message: "x" }]),
    );
    expect(await proveSwitchAction(null, form({ change: "kill", reason: "x" }))).toMatchObject({
      errors: [{ path: "reason" }],
    });
    vi.mocked(api.killCampaigns).mockRejectedValueOnce(new api.ApiError("down", 0));
    expect(await proveSwitchAction(null, form({ change: "kill", reason: "x" }))).toMatchObject({
      errors: [
        {
          path: "",
          message: "Nothing was changed. The API could not be reached or reported a problem. Try again in a moment.",
        },
      ],
    });
  });

  it("refuses a form another site sent, before the session is read or the API called", async () => {
    requestHeaders.value = new Headers({ host: "console.test", origin: "https://evil.test" });
    expect(await proveSwitchAction(null, form({ change: "kill", reason: "x" }))).toMatchObject({
      errors: [{ path: "", message: "This form was not sent from this Console, so it was refused." }],
    });
    expect(session.readOpsSession).not.toHaveBeenCalled();
    expect(api.killCampaigns).not.toHaveBeenCalled();
  });
});
