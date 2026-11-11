// @vitest-environment node
import { EXAMPLE_STORED_EVENT } from "@antireverse/protocol";
import { generateKey, newId } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  apiBaseUrl,
  createApp,
  createOrganization,
  getApp,
  getOrganization,
  listApps,
  listEvents,
  NotFoundError,
  openEventStream,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";

const admin = generateKey("admin");
const key = admin.key;
const organization = { id: newId("org"), name: "Acme", created_at: "2026-11-10T08:00:00.000Z" };
const app = { id: newId("app"), name: "shop-web", created_at: "2026-11-10T08:01:00.000Z" };

const fetchMock = vi.fn<typeof fetch>();

function json(status: number, body: unknown, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}
function problem(status: number, extra: Record<string, unknown> = {}): Response {
  return json(status, { type: "about:blank", title: "Problem", status, ...extra }, "application/problem+json");
}
function lastCall(): { url: string; init: RequestInit; headers: Headers } {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const init = (call[1] ?? {}) as RequestInit;
  return { url: String(call[0]), init, headers: new Headers(init.headers) };
}
async function caught(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected a rejection");
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", "http://api.test:9999");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — requests", () => {
  it("defaults the base URL to http://127.0.0.1:8787 and honours AR_API_URL", () => {
    expect(apiBaseUrl()).toBe("http://api.test:9999");
    vi.stubEnv("AR_API_URL", "http://api.test:9999/");
    expect(apiBaseUrl()).toBe("http://api.test:9999");
    vi.stubEnv("AR_API_URL", "");
    expect(apiBaseUrl()).toBe("http://127.0.0.1:8787");
  });

  it("sends Authorization: Bearer <key> to AR_API_URL without caching", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { organization }));
    expect(await getOrganization(key)).toEqual({ organization });
    const { url, init, headers } = lastCall();
    expect(url).toBe("http://api.test:9999/v1/organization");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    expect(init.cache).toBe("no-store");
    expect(init.method ?? "GET").toBe("GET");
  });

  it("creates an Organization without a key", async () => {
    fetchMock.mockResolvedValueOnce(json(201, { organization, admin_key: admin }));
    const created = await createOrganization({ name: "Acme" });
    expect(created.admin_key.key).toBe(key);
    const { url, init, headers } = lastCall();
    expect(url).toBe("http://api.test:9999/v1/organizations");
    expect(init.method).toBe("POST");
    expect(headers.has("authorization")).toBe(false);
    expect(headers.get("content-type")).toBe("application/json");
    expect(JSON.parse(String(init.body))).toEqual({ name: "Acme" });
    expect(init.cache).toBe("no-store");
  });

  it("creates an App with the chosen Environment", async () => {
    const shield = generateKey("shield", "production");
    fetchMock.mockResolvedValueOnce(json(201, { app, shield_key: { ...shield, environment: "production" } }));
    const created = await createApp(key, { name: "shop-web", environment: "production" });
    expect(created.shield_key.key).toBe(shield.key);
    const { url, init, headers } = lastCall();
    expect(url).toBe("http://api.test:9999/v1/apps");
    expect(init.method).toBe("POST");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    expect(JSON.parse(String(init.body))).toEqual({ name: "shop-web", environment: "production" });
  });

  it("lists Apps, reads one App and lists its Events with a limit", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { apps: [app] }));
    expect(await listApps(key)).toEqual({ apps: [app] });
    expect(lastCall().url).toBe("http://api.test:9999/v1/apps");

    fetchMock.mockResolvedValueOnce(json(200, { app }));
    expect(await getApp(key, app.id)).toEqual({ app });
    expect(lastCall().url).toBe(`http://api.test:9999/v1/apps/${app.id}`);

    const event = { ...EXAMPLE_STORED_EVENT, app_id: app.id, organization_id: organization.id };
    fetchMock.mockResolvedValueOnce(json(200, { events: [{ ...event, secret: "stripped" }] }));
    expect(await listEvents(key, app.id, 50)).toEqual({ events: [event] });
    expect(lastCall().url).toBe(`http://api.test:9999/v1/apps/${app.id}/events?limit=50`);
  });

  it("opens the Event stream with the caller's abort signal and returns the raw response", async () => {
    const upstream = new Response("data: x\n\n", { headers: { "content-type": "text/event-stream" } });
    fetchMock.mockResolvedValueOnce(upstream);
    const controller = new AbortController();
    expect(await openEventStream(key, app.id, controller.signal)).toBe(upstream);
    const { url, init, headers } = lastCall();
    expect(url).toBe(`http://api.test:9999/v1/apps/${app.id}/events/stream`);
    expect(init.signal).toBe(controller.signal);
    expect(init.cache).toBe("no-store");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    expect(headers.get("accept")).toBe("text/event-stream");
  });
});

describe("api client — errors", () => {
  it("maps 401 to UnauthorizedError", async () => {
    fetchMock.mockResolvedValueOnce(problem(401));
    const error = await caught(getOrganization(key));
    expect(error).toBeInstanceOf(UnauthorizedError);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(401);
  });

  it("maps 404 to NotFoundError", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    const error = await caught(getApp(key, app.id));
    expect(error).toBeInstanceOf(NotFoundError);
    expect((error as ApiError).status).toBe(404);
  });

  it("maps 400 to ValidationError carrying the problem's errors", async () => {
    const errors = [{ path: "name", message: "Too small: expected string to have >=1 characters" }];
    fetchMock.mockResolvedValueOnce(problem(400, { errors }));
    const error = await caught(createApp(key, { name: "" }));
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).errors).toEqual(errors);
    expect((error as ApiError).status).toBe(400);
  });

  it("maps any other failure status to a plain ApiError, even with a body that is not JSON", async () => {
    fetchMock.mockResolvedValueOnce(new Response("<html>bad gateway</html>", { status: 502 }));
    const error = await caught(listApps(key));
    expect(error).toBeInstanceOf(ApiError);
    expect(error).not.toBeInstanceOf(UnauthorizedError);
    expect((error as ApiError).status).toBe(502);
  });

  it("turns a successful response that fails its schema into ApiError", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { organization: { id: "org_1", name: "Acme" } }));
    const error = await caught(getOrganization(key));
    expect(error).toBeInstanceOf(ApiError);
    expect(error).not.toBeInstanceOf(ValidationError);

    fetchMock.mockResolvedValueOnce(new Response("not json", { status: 200 }));
    expect(await caught(getOrganization(key))).toBeInstanceOf(ApiError);
  });

  it("turns a network failure into ApiError", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError(`fetch failed for Bearer ${key}`));
    const error = await caught(getOrganization(key));
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(0);
    expect(error.message).not.toContain(key);
    expect(error.cause).toBeUndefined();
  });

  it("never puts a key into an error message, even when the API echoes one", async () => {
    const shield = generateKey("shield", "development").key;
    const echo = `The key ${key} and ${shield} were refused`;
    const responses = [
      problem(401, { title: echo, detail: echo }),
      problem(404, { detail: echo }),
      problem(400, { detail: echo, errors: [{ path: "name", message: echo }] }),
      problem(500, { title: echo }),
      json(200, { organization: key }),
    ];
    for (const response of responses) {
      fetchMock.mockResolvedValueOnce(response);
      const error = await caught(getOrganization(key));
      const visible = JSON.stringify([error.message, error.stack, (error as Partial<ValidationError>).errors ?? []]);
      expect(visible).not.toContain(key);
      expect(visible).not.toContain(shield);
      expect(visible).not.toContain(key.slice(4));
    }
  });
});
