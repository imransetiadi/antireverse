import {
  type AlertDelivery,
  CreateAlertChannelResponseSchema,
  INCIDENT_LIMITS,
  ListAlertChannelsResponseSchema,
  TestAlertChannelResponseSchema,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Notifier } from "../src/notify/notifier.ts";
import type { Resolve } from "../src/notify/ssrf.ts";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
  within,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const WEBHOOK_URL = "https://hooks.example.com/services/ar/T0KEN-webhook-9f3a";
const SLACK_URL = "https://hooks.slack.com/services/T000/B000/XXXXsecretXXXXslack";

const resolve: Resolve = async (host) => {
  if (host === "internal.example.com") return [{ address: "10.0.0.8", family: 4 }];
  if (host === "nowhere.example.com") throw Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" });
  // A resolver that never answers (F3).
  if (host === "hanging.example.com") return new Promise(() => {});
  return [{ address: "93.184.216.34", family: 4 }];
};

function del(key: string): RequestInit {
  return { method: "DELETE", headers: bearer(key) };
}

describe("alert channels", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  /** The notifier the routes are given: it records which channels were test-sent, for which Organization. */
  const tested: { channelId: string; organizationId: string }[] = [];
  let adminA: string;
  let adminB: string;
  let shieldA: string;
  let organizationA: string;
  /** Every URL and secret that went into the API: none may come back out after creation, nor reach a log line. */
  const secrets: string[] = [WEBHOOK_URL, SLACK_URL];

  const notifier: Notifier = {
    incidentOpened: () => {},
    confirmations: () => {},
    drain: async () => {},
    async test(channelId, organizationId) {
      if (channelId === unknownToNotifier) return null;
      tested.push({ channelId, organizationId });
      return {
        id: newId("dlv"),
        channel_id: channelId,
        incident_id: null,
        attempt: 1,
        outcome: "failed",
        status_code: 502,
        at: new Date(clock.ms).toISOString(),
      } satisfies AlertDelivery;
    },
  };
  let unknownToNotifier = "";

  beforeAll(async () => {
    api = await makeTestApi({
      now: () => new Date(clock.ms),
      notifier,
      resolve,
      allowPrivateAlertUrls: false,
      alertLookupTimeoutMs: 100,
    });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    organizationA = a.organization.id;
    shieldA = (await createAppFor(api, adminA)).shield_key.key;
  });
  afterAll(async () => {
    await api.close();
  });

  async function create(body: unknown, key = adminA): Promise<Response> {
    return api.app.request("/v1/alert-channels", json(body, bearer(key)));
  }

  /** The response text never contains a URL or a secret given earlier. */
  function expectNoSecret(text: string, except?: string): void {
    for (const secret of secrets) {
      if (secret === except) continue;
      expect(text).not.toContain(secret);
    }
  }

  let webhookId: string;
  let slackId: string;

  it("creates a webhook channel and returns its signing secret once, never its URL", async () => {
    const res = await create({ kind: "webhook", name: "  Ops webhook  ", url: WEBHOOK_URL });
    expect(res.status).toBe(201);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const text = await res.text();
    expectNoSecret(text);
    const body = CreateAlertChannelResponseSchema.parse(JSON.parse(text));
    expect(body.channel).toEqual({
      id: expect.stringMatching(/^chn_[0-9a-f]{24}$/),
      kind: "webhook",
      name: "Ops webhook",
      host: "hooks.example.com",
      url_last4: "9f3a",
      active: true,
      created_at: new Date(T0).toISOString(),
    });
    expect(body.signing_secret).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    secrets.push(String(body.signing_secret));
    webhookId = body.channel.id;
  });

  it("creates a Slack channel without a signing secret", async () => {
    clock.ms += 1_000;
    const res = await create({ kind: "slack", name: "Security", url: SLACK_URL });
    expect(res.status).toBe(201);
    const text = await res.text();
    expectNoSecret(text);
    const body = CreateAlertChannelResponseSchema.parse(JSON.parse(text));
    expect(body.signing_secret).toBeUndefined();
    expect(body.channel).toMatchObject({ kind: "slack", host: "hooks.slack.com", url_last4: "lack" });
    slackId = body.channel.id;
  });

  it("lists the channels in creation order, with neither URL nor secret", async () => {
    const res = await api.app.request("/v1/alert-channels", { headers: bearer(adminA) });
    expect(res.status).toBe(200);
    const text = await res.text();
    expectNoSecret(text);
    expect(text).not.toContain('"url"');
    expect(text).not.toContain("signing_secret");
    const { channels } = ListAlertChannelsResponseSchema.parse(JSON.parse(text));
    expect(channels.map((channel) => channel.id)).toEqual([webhookId, slackId]);
  });

  it.each([
    ["http without the flag", "http://hooks.example.com/ar"],
    ["a loopback address", "https://127.0.0.1/ar"],
    ["a private address", "https://10.0.0.5/ar"],
    ["the metadata address", "https://169.254.169.254/latest"],
    ["IPv6 loopback", "https://[::1]/ar"],
    ["IPv4-mapped loopback", "https://[::ffff:127.0.0.1]/ar"],
    ["CGNAT", "https://100.64.0.1/ar"],
    ["a host resolving to a private address", "https://internal.example.com/ar"],
    ["a host that does not resolve", "https://nowhere.example.com/ar"],
  ])("refuses %s with 400 on url, without echoing it", async (_, url) => {
    const res = await create({ kind: "webhook", name: "Refused", url });
    const text = await res.text();
    expect(res.status).toBe(400);
    const problem = JSON.parse(text) as { errors?: { path: string; message: string }[] };
    expect(problem.errors).toEqual([{ path: "url", message: expect.any(String) }]);
    expect(text).not.toContain(url);
    expect(text).not.toContain(new URL(url).hostname);
  });

  it("bounds the host lookup: a resolver that never answers is a 400 on url within the bound (F3)", async () => {
    const started = Date.now();
    const res = await within(
      Promise.resolve(create({ kind: "webhook", name: "Hanging", url: "https://hanging.example.com/ar" })),
      2_000,
      "the bounded lookup",
    );
    expect(Date.now() - started).toBeLessThan(1_500);
    const problem = await expectProblem(res, 400);
    expect(problem.errors).toEqual([{ path: "url", message: "The host could not be resolved." }]);
  });

  it("refuses an invalid body with 400 naming each path", async () => {
    // An unknown kind is refused as such (the kind decides which other members apply; slice 06b added email).
    const unknownKind = await expectProblem(await create({ kind: "pagerduty", name: "", url: "not a url" }), 400);
    expect(unknownKind.errors?.map((error) => error.path)).toEqual(["kind"]);
    const problem = await expectProblem(await create({ kind: "webhook", name: "", url: "not a url" }), 400);
    expect(problem.errors?.map((error) => error.path).sort()).toEqual(["name", "url"]);
    const long = await expectProblem(
      await create({
        kind: "webhook",
        name: "Long",
        url: `https://hooks.example.com/${"a".repeat(INCIDENT_LIMITS.urlMax)}`,
      }),
      400,
    );
    expect(long.errors?.[0]?.path).toBe("url");
  });

  it(`refuses an eleventh channel with 409`, async () => {
    for (let i = 2; i < INCIDENT_LIMITS.channelsMax; i++) {
      const url = `https://hooks.example.com/ar/${i}`;
      secrets.push(url);
      expect((await create({ kind: "slack", name: `Channel ${i}`, url })).status).toBe(201);
    }
    const over = await create({ kind: "slack", name: "One too many", url: "https://hooks.example.com/ar/over" });
    expect((await expectProblem(over, 409)).type).toBe("https://antireverse.dev/problems/conflict");
    // Another Organization has its own allowance.
    expect((await create({ kind: "slack", name: "B", url: "https://hooks.example.com/ar/b" }, adminB)).status).toBe(
      201,
    );
  });

  it("test-sends a channel through the notifier and returns the delivery", async () => {
    const res = await api.app.request(`/v1/alert-channels/${webhookId}/test`, json({}, bearer(adminA)));
    expect(res.status).toBe(200);
    const { delivery } = TestAlertChannelResponseSchema.parse(await res.json());
    expect(delivery).toMatchObject({
      channel_id: webhookId,
      incident_id: null,
      attempt: 1,
      outcome: "failed",
      status_code: 502,
    });
    expect(tested).toEqual([{ channelId: webhookId, organizationId: organizationA }]);
    // A test-send needs no body.
    const bare = await api.app.request(`/v1/alert-channels/${webhookId}/test`, {
      method: "POST",
      headers: bearer(adminA),
    });
    expect(bare.status).toBe(200);
  });

  it("answers 404 when the channel vanished before the test-send", async () => {
    const res = await create({ kind: "slack", name: "Vanishing", url: "https://hooks.example.com/ar/vanish" }, adminB);
    unknownToNotifier = CreateAlertChannelResponseSchema.parse(await res.json()).channel.id;
    await expectProblem(
      await api.app.request(`/v1/alert-channels/${unknownToNotifier}/test`, json({}, bearer(adminB))),
      404,
    );
  });

  it("deletes a channel with 204; it is gone afterwards", async () => {
    const res = await api.app.request(`/v1/alert-channels/${slackId}`, del(adminA));
    expect(res.status).toBe(204);
    expect(await res.text()).toBe("");
    const list = ListAlertChannelsResponseSchema.parse(
      await (await api.app.request("/v1/alert-channels", { headers: bearer(adminA) })).json(),
    );
    expect(list.channels.map((channel) => channel.id)).not.toContain(slackId);
    await expectProblem(await api.app.request(`/v1/alert-channels/${slackId}`, del(adminA)), 404);
    await expectProblem(await api.app.request(`/v1/alert-channels/${slackId}/test`, json({}, bearer(adminA))), 404);
    // Room for one again.
    expect((await create({ kind: "slack", name: "Again", url: "https://hooks.example.com/ar/again" })).status).toBe(
      201,
    );
  });

  describe("tenancy and keys", () => {
    it("never lets another Organization list, test or delete a channel", async () => {
      const list = ListAlertChannelsResponseSchema.parse(
        await (await api.app.request("/v1/alert-channels", { headers: bearer(adminB) })).json(),
      );
      expect(list.channels.map((channel) => channel.id)).not.toContain(webhookId);
      const before = tested.length;
      await expectProblem(await api.app.request(`/v1/alert-channels/${webhookId}/test`, json({}, bearer(adminB))), 404);
      expect(tested.length).toBe(before);
      await expectProblem(await api.app.request(`/v1/alert-channels/${webhookId}`, del(adminB)), 404);
      // Still there for its owner.
      const mine = ListAlertChannelsResponseSchema.parse(
        await (await api.app.request("/v1/alert-channels", { headers: bearer(adminA) })).json(),
      );
      expect(mine.channels.map((channel) => channel.id)).toContain(webhookId);
    });

    it("answers 404 for a malformed channel id", async () => {
      await expectProblem(await api.app.request("/v1/alert-channels/not-a-channel", del(adminA)), 404);
      await expectProblem(
        await api.app.request("/v1/alert-channels/not-a-channel/test", json({}, bearer(adminA))),
        404,
      );
    });

    it("answers 403 to a Shield key and 401 without a key", async () => {
      await expectProblem(await api.app.request("/v1/alert-channels", { headers: bearer(shieldA) }), 403);
      await expectProblem(await create({ kind: "slack", name: "S", url: SLACK_URL }, shieldA), 403);
      await expectProblem(await api.app.request(`/v1/alert-channels/${webhookId}`, del(shieldA)), 403);
      await expectProblem(
        await api.app.request(`/v1/alert-channels/${webhookId}/test`, json({}, bearer(shieldA))),
        403,
      );
      await expectProblem(await api.app.request("/v1/alert-channels"), 401);
      await expectProblem(await api.app.request(`/v1/alert-channels/${webhookId}`, { method: "DELETE" }), 401);
    });
  });

  it("never logs a key, a channel URL or a signing secret", () => {
    expectNoKeyLogged(api);
    for (const line of api.logger.lines) expectNoSecret(line);
  });
});

describe("alert channels with private URLs allowed", () => {
  it("accepts http and loopback destinations when the flag is on", async () => {
    const api = await makeTestApi({ allowPrivateAlertUrls: true, resolve });
    try {
      const { admin_key } = await createOrganization(api);
      const res = await api.app.request(
        "/v1/alert-channels",
        json({ kind: "webhook", name: "Local", url: "http://127.0.0.1:39901/hook" }, bearer(admin_key.key)),
      );
      expect(res.status).toBe(201);
      expect(CreateAlertChannelResponseSchema.parse(await res.json()).channel).toMatchObject({ host: "127.0.0.1" });
    } finally {
      await api.close();
    }
  });
});
