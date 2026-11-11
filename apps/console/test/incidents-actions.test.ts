// @vitest-environment node
import { type AlertDelivery, EXAMPLE_ALERT_CHANNEL, EXAMPLE_INCIDENT } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The Incident and alert-channel actions, exercised through their interface with the API client, the
// session, the cache and the navigation replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  updateIncident: vi.fn(),
  createAlertChannel: vi.fn(),
  deleteAlertChannel: vi.fn(),
  testAlertChannel: vi.fn(),
}));
vi.mock("@/lib/session.ts", () => ({
  SESSION_COOKIE: "ar_admin",
  readSession: vi.fn(),
  writeSession: vi.fn(),
  clearSession: vi.fn(),
}));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import { revalidatePath } from "next/cache";
import {
  createAlertChannelAction,
  deleteAlertChannelAction,
  testAlertChannelAction,
  updateIncidentAction,
} from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const incidentId = EXAMPLE_INCIDENT.id;
const channelId = EXAMPLE_ALERT_CHANNEL.id;
const SECRET = `whsec_${"b".repeat(43)}`;
const SLACK_URL = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX";
const PAGE = `/incidents/${incidentId}`;

const STALE = "This Incident changed since the page was loaded, so nothing was saved. Reload the page and try again.";
const RESOLVE_UNCONFIRMED = "Nothing was changed. Confirm the change first.";
const REMOVE_UNCONFIRMED = "Nothing was removed. Confirm the change first.";
const CAP = "An organization holds at most 10 alert channels. Remove one before adding another.";
const URL_REFUSED = "This address cannot receive alerts. Use an https:// URL on a public host.";
const API_DOWN = "The Airverse API did not answer, so nothing was saved. Check that it is running, then try again.";
const API_FAILED = "The Airverse API reported a problem, so nothing was saved. Try again in a moment.";

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.append(name, value);
  return data;
}

beforeEach(() => {
  for (const fn of [api.updateIncident, api.createAlertChannel, api.deleteAlertChannel, api.testAlertChannel]) {
    vi.mocked(fn).mockReset();
  }
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(revalidatePath).mockReset();
});

describe("updateIncidentAction", () => {
  it("acknowledges an Incident at once and goes back to its page", async () => {
    vi.mocked(api.updateIncident).mockResolvedValue({ incident: { ...EXAMPLE_INCIDENT, status: "acknowledged" } });
    await expect(updateIncidentAction(null, form({ incidentId, status: "acknowledged" }))).rejects.toThrow(
      `REDIRECT ${PAGE}`,
    );
    expect(api.updateIncident).toHaveBeenCalledWith(admin.key, incidentId, "acknowledged");
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
    expect(revalidatePath).toHaveBeenCalledWith("/incidents");
  });

  it("refuses to resolve without the confirmation and never calls the API", async () => {
    expect(await updateIncidentAction(null, form({ incidentId, status: "resolved" }))).toEqual({
      ok: false,
      errors: [{ path: "confirm", message: RESOLVE_UNCONFIRMED }],
    });
    expect(await updateIncidentAction(null, form({ incidentId, status: "resolved", confirm: "yes" }))).toEqual({
      ok: false,
      errors: [{ path: "confirm", message: RESOLVE_UNCONFIRMED }],
    });
    expect(api.updateIncident).not.toHaveBeenCalled();
  });

  it("resolves with the confirmation (the Incident named in the question)", async () => {
    vi.mocked(api.updateIncident).mockResolvedValue({ incident: { ...EXAMPLE_INCIDENT, status: "resolved" } });
    await expect(
      updateIncidentAction(null, form({ incidentId, status: "resolved", confirm: incidentId })),
    ).rejects.toThrow(`REDIRECT ${PAGE}`);
    expect(api.updateIncident).toHaveBeenCalledWith(admin.key, incidentId, "resolved");
  });

  it("says the Incident changed when the API answers 409 or 404, and saves nothing", async () => {
    vi.mocked(api.updateIncident).mockRejectedValueOnce(new api.ConflictError("PATCH failed with status 409"));
    expect(await updateIncidentAction(null, form({ incidentId, status: "acknowledged" }))).toEqual({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
    vi.mocked(api.updateIncident).mockRejectedValueOnce(new api.NotFoundError("PATCH failed with status 404"));
    expect(await updateIncidentAction(null, form({ incidentId, status: "resolved", confirm: incidentId }))).toEqual({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("refuses a form this screen does not send", async () => {
    for (const fields of [
      { incidentId: "inc_nope", status: "acknowledged" },
      { incidentId, status: "open" },
      { incidentId, status: "" },
    ]) {
      expect(await updateIncidentAction(null, form(fields))).toEqual({
        ok: false,
        errors: [{ path: "", message: STALE }],
      });
    }
    expect(api.updateIncident).not.toHaveBeenCalled();
  });

  it("requires a session, and sends an expired one to sign-in", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(updateIncidentAction(null, form({ incidentId, status: "acknowledged" }))).rejects.toThrow(
      "REDIRECT /",
    );
    expect(api.updateIncident).not.toHaveBeenCalled();

    vi.mocked(api.updateIncident).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(updateIncidentAction(null, form({ incidentId, status: "acknowledged" }))).rejects.toThrow(
      "REDIRECT /sign-in?reason=expired",
    );
  });

  it("explains an API that did not answer or failed", async () => {
    vi.mocked(api.updateIncident).mockRejectedValueOnce(new api.ApiError("down", 0));
    expect(await updateIncidentAction(null, form({ incidentId, status: "acknowledged" }))).toEqual({
      ok: false,
      errors: [{ path: "", message: API_DOWN }],
    });
    vi.mocked(api.updateIncident).mockRejectedValueOnce(new api.ApiError("boom", 500));
    expect(await updateIncidentAction(null, form({ incidentId, status: "acknowledged" }))).toEqual({
      ok: false,
      errors: [{ path: "", message: API_FAILED }],
    });
  });
});

describe("createAlertChannelAction", () => {
  const webhook = { kind: "webhook", name: "  Ops webhook ", url: " https://hooks.example.com/k/ar " };

  it("creates a webhook channel and returns its signing secret once, through the action state only", async () => {
    vi.mocked(api.createAlertChannel).mockResolvedValue({ channel: EXAMPLE_ALERT_CHANNEL, signing_secret: SECRET });
    const state = await createAlertChannelAction(null, form(webhook));
    expect(api.createAlertChannel).toHaveBeenCalledWith(admin.key, {
      kind: "webhook",
      name: "Ops webhook",
      url: "https://hooks.example.com/k/ar",
    });
    expect(state).toEqual({ ok: true, channel: EXAMPLE_ALERT_CHANNEL, signingSecret: SECRET });
    expect(revalidatePath).toHaveBeenCalledWith("/settings/alerts");
  });

  it("creates a Slack channel with no secret", async () => {
    const slack = { ...EXAMPLE_ALERT_CHANNEL, kind: "slack" as const, host: "hooks.slack.com", url_last4: "XXXX" };
    vi.mocked(api.createAlertChannel).mockResolvedValue({ channel: slack });
    const state = await createAlertChannelAction(null, form({ kind: "slack", name: "Ops", url: SLACK_URL }));
    expect(state).toEqual({ ok: true, channel: slack });
    expect(JSON.stringify(state)).not.toContain(SLACK_URL);
  });

  it("checks kind, name and URL before calling the API, and never returns the URL", async () => {
    const state = await createAlertChannelAction(null, form({ kind: "email", name: "", url: "ftp://x" }));
    expect(state).toEqual({
      ok: false,
      errors: [
        { path: "kind", message: "Choose Webhook or Slack." },
        { path: "name", message: "Enter a name." },
        { path: "url", message: "Enter a full URL, for example https://hooks.example.com/alerts." },
      ],
      values: { kind: "email", name: "" },
    });
    expect(await createAlertChannelAction(null, form({ kind: "slack", name: "x".repeat(81), url: "" }))).toMatchObject({
      errors: [
        { path: "name", message: "Use 80 characters or fewer." },
        { path: "url", message: "Enter a URL." },
      ],
    });
    expect(
      await createAlertChannelAction(
        null,
        form({ kind: "slack", name: "Ops", url: `https://a.example/${"x".repeat(2048)}` }),
      ),
    ).toMatchObject({ errors: [{ path: "url", message: "Use 2,048 characters or fewer." }] });
    expect(api.createAlertChannel).not.toHaveBeenCalled();
  });

  it("shows a refused URL as a field error that does not echo the URL", async () => {
    vi.mocked(api.createAlertChannel).mockRejectedValue(
      new api.ValidationError("POST /v1/alert-channels failed with status 400", [
        { path: "url", message: "private address" },
      ]),
    );
    const state = await createAlertChannelAction(null, form({ kind: "slack", name: "Ops", url: SLACK_URL }));
    expect(state).toEqual({
      ok: false,
      errors: [{ path: "url", message: URL_REFUSED }],
      values: { kind: "slack", name: "Ops" },
    });
    expect(JSON.stringify(state)).not.toContain("hooks.slack.com");
  });

  it("says the 10-channel cap was reached on 409", async () => {
    vi.mocked(api.createAlertChannel).mockRejectedValue(new api.ConflictError("409"));
    expect(await createAlertChannelAction(null, form(webhook))).toEqual({
      ok: false,
      errors: [{ path: "", message: CAP }],
      values: { kind: "webhook", name: "Ops webhook" },
    });
  });

  it("requires a session", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(createAlertChannelAction(null, form(webhook))).rejects.toThrow("REDIRECT /");
    expect(api.createAlertChannel).not.toHaveBeenCalled();
  });
});

describe("deleteAlertChannelAction", () => {
  it("refuses to remove without the confirmation", async () => {
    expect(await deleteAlertChannelAction(null, form({ channelId }))).toEqual({
      ok: false,
      errors: [{ path: "confirm", message: REMOVE_UNCONFIRMED }],
    });
    expect(await deleteAlertChannelAction(null, form({ channelId, confirm: "chn_other" }))).toMatchObject({
      ok: false,
    });
    expect(api.deleteAlertChannel).not.toHaveBeenCalled();
  });

  it("removes with the confirmation and goes back to the plain settings address", async () => {
    vi.mocked(api.deleteAlertChannel).mockResolvedValue(undefined);
    await expect(deleteAlertChannelAction(null, form({ channelId, confirm: channelId }))).rejects.toThrow(
      "REDIRECT /settings/alerts",
    );
    expect(api.deleteAlertChannel).toHaveBeenCalledWith(admin.key, channelId);
    expect(revalidatePath).toHaveBeenCalledWith("/settings/alerts");
  });

  it("treats a channel that is already gone as removed", async () => {
    vi.mocked(api.deleteAlertChannel).mockRejectedValue(new api.NotFoundError("404"));
    await expect(deleteAlertChannelAction(null, form({ channelId, confirm: channelId }))).rejects.toThrow(
      "REDIRECT /settings/alerts",
    );
  });

  it("refuses a malformed channel id", async () => {
    expect(await deleteAlertChannelAction(null, form({ channelId: "chn_x", confirm: "chn_x" }))).toMatchObject({
      ok: false,
    });
    expect(api.deleteAlertChannel).not.toHaveBeenCalled();
  });
});

describe("testAlertChannelAction", () => {
  const delivery = (overrides: Partial<AlertDelivery>): AlertDelivery => ({
    id: "dlv_0123456789abcdef01234567",
    channel_id: channelId,
    incident_id: null,
    attempt: 1,
    outcome: "delivered",
    status_code: 200,
    at: "2026-11-10T08:30:00.000Z",
    ...overrides,
  });

  it("returns the delivery outcome and status code", async () => {
    vi.mocked(api.testAlertChannel).mockResolvedValueOnce({ delivery: delivery({}) });
    expect(await testAlertChannelAction(null, form({ channelId }))).toEqual({
      ok: true,
      outcome: "delivered",
      statusCode: 200,
    });
    vi.mocked(api.testAlertChannel).mockResolvedValueOnce({
      delivery: delivery({ outcome: "failed", status_code: 500 }),
    });
    expect(await testAlertChannelAction(null, form({ channelId }))).toEqual({
      ok: true,
      outcome: "failed",
      statusCode: 500,
    });
    expect(api.testAlertChannel).toHaveBeenCalledWith(admin.key, channelId);
  });

  it("explains a channel that is gone and an API that failed", async () => {
    vi.mocked(api.testAlertChannel).mockRejectedValueOnce(new api.NotFoundError("404"));
    expect(await testAlertChannelAction(null, form({ channelId }))).toEqual({
      ok: false,
      message: "This channel no longer exists. Reload the page to see the current list.",
    });
    vi.mocked(api.testAlertChannel).mockRejectedValueOnce(new api.ApiError("boom", 500));
    expect(await testAlertChannelAction(null, form({ channelId }))).toEqual({
      ok: false,
      message: "The Airverse API reported a problem, so no test alert was sent. Try again in a moment.",
    });
  });

  it("refuses a malformed channel id without calling the API", async () => {
    expect(await testAlertChannelAction(null, form({ channelId: "nope" }))).toMatchObject({ ok: false });
    expect(api.testAlertChannel).not.toHaveBeenCalled();
  });
});
