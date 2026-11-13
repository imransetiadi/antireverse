// @vitest-environment node
import { type AlertChannel, EXAMPLE_EMAIL_CHANNEL } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type ApiError,
  ConflictError,
  confirmAlertRecipient,
  createAlertChannel,
  listAlertChannels,
  NotFoundError,
  RateLimitedError,
  resendConfirmation,
} from "@/lib/api.ts";

// Slice 06b: the API client for email channels — the list with `smtp_configured`, the email create request, the
// resend of a confirmation mail and the public confirmation, which the Console calls server-side with no key.

const { key } = generateKey("admin");
const API = "http://api.test:9999";
const email = EXAMPLE_EMAIL_CHANNEL as Extract<AlertChannel, { kind: "email" }>;
const [confirmed, pending] = email.recipients as [(typeof email.recipients)[0], (typeof email.recipients)[0]];
const TOKEN = `${"Q".repeat(20)}_-${"z".repeat(21)}`;

const fetchMock = vi.fn<typeof fetch>();
function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
function problem(status: number, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ type: "about:blank", title: "Problem", status, ...extra }), {
    status,
    headers: { "content-type": "application/problem+json", ...headers },
  });
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

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", API);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — email channels", () => {
  it("lists email channels with their recipients and whether SMTP is configured", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { channels: [email], smtp_configured: false }));
    expect(await listAlertChannels(key)).toEqual({ channels: [email], smtp_configured: false });
  });

  it("refuses a list without smtp_configured as off contract (502)", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { channels: [email] }));
    expect(((await caught(listAlertChannels(key))) as ApiError).status).toBe(502);
  });

  it("creates an email channel with its recipients and no URL", async () => {
    fetchMock.mockResolvedValueOnce(json(201, { channel: email }));
    const input = { kind: "email" as const, name: "On-call email", recipients: ["oncall@example.com"] };
    expect(await createAlertChannel(key, input)).toEqual({ channel: email });
    expect(lastCall().body).toEqual(input);
  });

  it("maps 409 smtp-not-configured to a ConflictError with that reason", async () => {
    fetchMock.mockResolvedValueOnce(problem(409, { reason: "smtp-not-configured" }));
    const error = await caught(createAlertChannel(key, { kind: "email", name: "x", recipients: ["a@example.com"] }));
    expect(error).toBeInstanceOf(ConflictError);
    expect((error as ConflictError).reason).toBe("smtp-not-configured");
  });

  it("resends a confirmation by recipient id: POST, 202, the recipient back", async () => {
    fetchMock.mockResolvedValueOnce(json(202, { recipient: pending }));
    expect(await resendConfirmation(key, email.id, pending.id)).toEqual({ recipient: pending });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/alert-channels/${email.id}/recipients/${pending.id}/resend`);
    expect(init.method).toBe("POST");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("maps the refusals of a resend: 429 with Retry-After, 409 recipient-confirmed, 404", async () => {
    fetchMock.mockResolvedValueOnce(problem(429, {}, { "retry-after": "3600" }));
    const limited = await caught(resendConfirmation(key, email.id, pending.id));
    expect(limited).toBeInstanceOf(RateLimitedError);
    expect((limited as RateLimitedError).retryAfter).toBe(3600);

    fetchMock.mockResolvedValueOnce(problem(409, { reason: "recipient-confirmed" }));
    expect(((await caught(resendConfirmation(key, email.id, confirmed.id))) as ConflictError).reason).toBe(
      "recipient-confirmed",
    );

    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(resendConfirmation(key, email.id, pending.id))).toBeInstanceOf(NotFoundError);
  });

  it("refuses a resend answer that is not a recipient (502)", async () => {
    fetchMock.mockResolvedValueOnce(json(202, { recipient: { ...pending, token: undefined, status: "maybe" } }));
    expect(((await caught(resendConfirmation(key, email.id, pending.id))) as ApiError).status).toBe(502);
  });
});

describe("api client — public confirmation", () => {
  it("posts the token in the body, with no key and not in the address", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { confirmed: true }));
    expect(await confirmAlertRecipient(TOKEN)).toEqual({ confirmed: true });
    const { url, init, headers, body } = lastCall();
    expect(url).toBe(`${API}/v1/alert-recipients/confirm`);
    expect(url).not.toContain(TOKEN);
    expect(init.method).toBe("POST");
    expect(headers.get("authorization")).toBeNull();
    expect(body).toEqual({ token: TOKEN });
  });

  it("returns confirmed false as the API says it", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { confirmed: false }));
    expect(await confirmAlertRecipient(TOKEN)).toEqual({ confirmed: false });
  });

  it("maps 429 to RateLimitedError and never carries the token in an error, even when the API echoes it", async () => {
    fetchMock.mockResolvedValueOnce(problem(429, { title: `Too many ${TOKEN}` }, { "retry-after": "60" }));
    const limited = await caught(confirmAlertRecipient(TOKEN));
    expect(limited).toBeInstanceOf(RateLimitedError);
    expect(`${limited.message} ${limited.stack}`).not.toContain(TOKEN);

    for (const status of [400, 404, 409, 500]) {
      fetchMock.mockResolvedValueOnce(
        problem(status, { title: `bad ${TOKEN}`, detail: TOKEN, errors: [{ path: "token", message: TOKEN }] }),
      );
      const error = await caught(confirmAlertRecipient(TOKEN));
      expect(JSON.stringify([error.message, error.stack, (error as { errors?: unknown }).errors ?? []])).not.toContain(
        TOKEN,
      );
    }

    fetchMock.mockRejectedValueOnce(new Error(`connect failed for body ${TOKEN}`));
    const down = await caught(confirmAlertRecipient(TOKEN));
    expect((down as ApiError).status).toBe(0);
    expect(`${down.message} ${down.stack}`).not.toContain(TOKEN);
  });
});
