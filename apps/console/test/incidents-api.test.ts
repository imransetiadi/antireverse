// @vitest-environment node
import {
  type AlertDelivery,
  EXAMPLE_ALERT_CHANNEL,
  EXAMPLE_CONTAINMENT,
  EXAMPLE_DETECTION,
  EXAMPLE_INCIDENT,
  EXAMPLE_STORED_EVENT,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  ConflictError,
  createAlertChannel,
  deleteAlertChannel,
  getIncident,
  listAlertChannels,
  listIncidents,
  NotFoundError,
  testAlertChannel,
  UnauthorizedError,
  updateIncident,
  ValidationError,
} from "@/lib/api.ts";

const admin = generateKey("admin");
const key = admin.key;
const API = "http://api.test:9999";
const incidentId = EXAMPLE_INCIDENT.id;
const channelId = EXAMPLE_ALERT_CHANNEL.id;
const SECRET = `whsec_${"A".repeat(43)}`;
const SLACK_URL = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX";
const DELIVERY: AlertDelivery = {
  id: "dlv_0123456789abcdef01234567",
  channel_id: channelId,
  incident_id: null,
  attempt: 1,
  outcome: "delivered",
  status_code: 204,
  at: "2026-11-10T08:30:00.000Z",
};

const fetchMock = vi.fn<typeof fetch>();

function json(status: number, body: unknown, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}
function problem(status: number, extra: Record<string, unknown> = {}): Response {
  return json(status, { type: "about:blank", title: "Problem", status, ...extra }, "application/problem+json");
}
function lastCall(): { url: string; init: RequestInit; headers: Headers; body: unknown } {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const init = (call[1] ?? {}) as RequestInit;
  const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
  return { url: String(call[0]), init, headers: new Headers(init.headers), body };
}
async function caught(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected a rejection");
}
const visible = (error: Error): string =>
  JSON.stringify([error.message, error.stack, (error as Partial<ValidationError>).errors ?? []]);

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", API);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — Incidents", () => {
  it("lists Incidents with the session key, without caching and without a filter", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { incidents: [EXAMPLE_INCIDENT] }));
    expect(await listIncidents(key)).toEqual({ incidents: [EXAMPLE_INCIDENT] });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/incidents`);
    expect(init.method ?? "GET").toBe("GET");
    expect(init.cache).toBe("no-store");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("passes the App and status filters as query parameters", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { incidents: [] }));
    await listIncidents(key, { status: "acknowledged" });
    expect(lastCall().url).toBe(`${API}/v1/incidents?status=acknowledged`);

    fetchMock.mockResolvedValueOnce(json(200, { incidents: [] }));
    await listIncidents(key, { appId: EXAMPLE_INCIDENT.app_id, status: "open" });
    expect(lastCall().url).toBe(`${API}/v1/incidents?app_id=${EXAMPLE_INCIDENT.app_id}&status=open`);
  });

  it("reads one Incident with its Detections, evidence, Actors and blocks", async () => {
    const detail = {
      incident: EXAMPLE_INCIDENT,
      detections: [EXAMPLE_DETECTION],
      evidence: [EXAMPLE_STORED_EVENT],
      actors: [{ ip_hash: "iph_2932b22cf89905dbc929c64247ddad3e", events: 20 }],
      containments: [EXAMPLE_CONTAINMENT],
    };
    fetchMock.mockResolvedValueOnce(json(200, detail));
    expect(await getIncident(key, incidentId)).toEqual(detail);
    expect(lastCall().url).toBe(`${API}/v1/incidents/${incidentId}`);
  });

  it("encodes the identifier in the path", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    await caught(getIncident(key, "inc/../x"));
    expect(lastCall().url).toBe(`${API}/v1/incidents/inc%2F..%2Fx`);
  });

  it("changes the status with PATCH and returns the changed Incident", async () => {
    const changed = { ...EXAMPLE_INCIDENT, status: "acknowledged" as const };
    fetchMock.mockResolvedValueOnce(json(200, { incident: changed }));
    expect(await updateIncident(key, incidentId, "acknowledged")).toEqual({ incident: changed });
    const { url, init, headers, body } = lastCall();
    expect(url).toBe(`${API}/v1/incidents/${incidentId}`);
    expect(init.method).toBe("PATCH");
    expect(headers.get("content-type")).toBe("application/json");
    expect(body).toEqual({ status: "acknowledged" });
  });

  it("maps 404 to NotFoundError for an unknown or foreign Incident", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(getIncident(key, incidentId))).toBeInstanceOf(NotFoundError);
    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(updateIncident(key, incidentId, "resolved"))).toBeInstanceOf(NotFoundError);
  });

  it("maps 409 (a transition that is not allowed any more) to ConflictError", async () => {
    fetchMock.mockResolvedValueOnce(problem(409, { title: "Conflict" }));
    const error = await caught(updateIncident(key, incidentId, "acknowledged"));
    expect(error).toBeInstanceOf(ConflictError);
    expect((error as ApiError).status).toBe(409);
  });

  it("maps 401 to UnauthorizedError", async () => {
    fetchMock.mockResolvedValueOnce(problem(401));
    expect(await caught(listIncidents(key))).toBeInstanceOf(UnauthorizedError);
  });

  it("turns a response that fails the schema into ApiError 502", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { incidents: [{ ...EXAMPLE_INCIDENT, severity: "severe" }] }));
    const listError = await caught(listIncidents(key));
    expect(listError).toBeInstanceOf(ApiError);
    expect(listError).not.toBeInstanceOf(ValidationError);
    expect((listError as ApiError).status).toBe(502);

    fetchMock.mockResolvedValueOnce(
      json(200, { incident: EXAMPLE_INCIDENT, detections: "none", evidence: [], actors: [], containments: [] }),
    );
    expect(((await caught(getIncident(key, incidentId))) as ApiError).status).toBe(502);

    // Slice 09: the detail must carry its Actors and blocks.
    fetchMock.mockResolvedValueOnce(json(200, { incident: EXAMPLE_INCIDENT, detections: [], evidence: [] }));
    expect(((await caught(getIncident(key, incidentId))) as ApiError).status).toBe(502);

    fetchMock.mockResolvedValueOnce(json(200, { incident: { ...EXAMPLE_INCIDENT, status: "closed" } }));
    expect(((await caught(updateIncident(key, incidentId, "resolved"))) as ApiError).status).toBe(502);
  });
});

describe("api client — alert channels", () => {
  it("lists the channels", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { channels: [EXAMPLE_ALERT_CHANNEL], smtp_configured: true }));
    expect(await listAlertChannels(key)).toEqual({ channels: [EXAMPLE_ALERT_CHANNEL], smtp_configured: true });
    const { url, headers } = lastCall();
    expect(url).toBe(`${API}/v1/alert-channels`);
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("creates a webhook channel and returns its signing secret", async () => {
    fetchMock.mockResolvedValueOnce(json(201, { channel: EXAMPLE_ALERT_CHANNEL, signing_secret: SECRET }));
    const input = { kind: "webhook" as const, name: "Ops webhook", url: "https://hooks.example.com/k/ar" };
    expect(await createAlertChannel(key, input)).toEqual({ channel: EXAMPLE_ALERT_CHANNEL, signing_secret: SECRET });
    const { url, init, body } = lastCall();
    expect(url).toBe(`${API}/v1/alert-channels`);
    expect(init.method).toBe("POST");
    expect(body).toEqual(input);
  });

  it("creates a Slack channel without a signing secret", async () => {
    const slack = { ...EXAMPLE_ALERT_CHANNEL, kind: "slack" as const, host: "hooks.slack.com", url_last4: "XXXX" };
    fetchMock.mockResolvedValueOnce(json(201, { channel: slack }));
    const created = await createAlertChannel(key, { kind: "slack", name: "Ops", url: SLACK_URL });
    expect(created).toEqual({ channel: slack });
    expect("signing_secret" in created).toBe(false);
  });

  it("refuses a create response that breaks the secret rule (Slack with a secret, webhook without)", async () => {
    const slack = { ...EXAMPLE_ALERT_CHANNEL, kind: "slack" as const };
    fetchMock.mockResolvedValueOnce(json(201, { channel: slack, signing_secret: SECRET }));
    const error = await caught(createAlertChannel(key, { kind: "slack", name: "Ops", url: SLACK_URL }));
    expect((error as ApiError).status).toBe(502);
    expect(visible(error)).not.toContain(SECRET);

    fetchMock.mockResolvedValueOnce(json(201, { channel: EXAMPLE_ALERT_CHANNEL }));
    const missing = await caught(createAlertChannel(key, { kind: "webhook", name: "Ops", url: SLACK_URL }));
    expect((missing as ApiError).status).toBe(502);
  });

  it("maps 409 on create (the 10-channel cap) to ConflictError", async () => {
    fetchMock.mockResolvedValueOnce(problem(409, { title: "Too many alert channels" }));
    expect(await caught(createAlertChannel(key, { kind: "slack", name: "Ops", url: SLACK_URL }))).toBeInstanceOf(
      ConflictError,
    );
  });

  it("maps 400 at path url to ValidationError without the URL in the message or the errors", async () => {
    fetchMock.mockResolvedValueOnce(
      problem(400, {
        title: `Refused ${SLACK_URL}`,
        errors: [{ path: "url", message: `The destination ${SLACK_URL} resolves to a private address` }],
      }),
    );
    const error = await caught(createAlertChannel(key, { kind: "slack", name: "Ops", url: SLACK_URL }));
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).errors.map((entry) => entry.path)).toEqual(["url"]);
    expect(visible(error)).not.toContain(SLACK_URL);
    expect(visible(error)).not.toContain("hooks.slack.com/services");
  });

  it("deletes a channel: 204 with no body resolves", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(deleteAlertChannel(key, channelId)).resolves.toBeUndefined();
    const { url, init } = lastCall();
    expect(url).toBe(`${API}/v1/alert-channels/${channelId}`);
    expect(init.method).toBe("DELETE");
  });

  it("maps 404 on delete and on test to NotFoundError", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(deleteAlertChannel(key, channelId))).toBeInstanceOf(NotFoundError);
    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(testAlertChannel(key, channelId))).toBeInstanceOf(NotFoundError);
  });

  it("sends a test alert and returns the delivery", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { delivery: DELIVERY }));
    expect(await testAlertChannel(key, channelId)).toEqual({ delivery: DELIVERY });
    const { url, init } = lastCall();
    expect(url).toBe(`${API}/v1/alert-channels/${channelId}/test`);
    expect(init.method).toBe("POST");
  });

  it("turns a channel list or a delivery that fails the schema into ApiError 502", async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, { channels: [{ ...EXAMPLE_ALERT_CHANNEL, kind: "pager" }], smtp_configured: true }),
    );
    expect(((await caught(listAlertChannels(key))) as ApiError).status).toBe(502);
    fetchMock.mockResolvedValueOnce(json(200, { delivery: { ...DELIVERY, outcome: "maybe" } }));
    expect(((await caught(testAlertChannel(key, channelId))) as ApiError).status).toBe(502);
  });

  it("never puts a key, a signing secret or a URL into a thrown message, even when the API echoes them", async () => {
    const echo = `key ${key} secret ${SECRET} url ${SLACK_URL}`;
    const calls = [
      () => listIncidents(key),
      () => getIncident(key, incidentId),
      () => updateIncident(key, incidentId, "resolved"),
      () => listAlertChannels(key),
      () => createAlertChannel(key, { kind: "slack", name: "Ops", url: SLACK_URL }),
      () => deleteAlertChannel(key, channelId),
      () => testAlertChannel(key, channelId),
    ];
    for (const run of calls) {
      for (const status of [400, 404, 409, 500]) {
        fetchMock.mockResolvedValueOnce(
          problem(status, { title: echo, detail: echo, errors: [{ path: "url", message: echo }] }),
        );
        const text = visible(await caught(run()));
        expect(text).not.toContain(key);
        expect(text).not.toContain(key.slice(4));
        expect(text).not.toContain(SECRET);
        expect(text).not.toContain(SECRET.slice(6));
        expect(text).not.toContain(SLACK_URL);
      }
    }
  });
});
