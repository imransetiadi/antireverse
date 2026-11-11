import {
  EXAMPLE_EVENT_BATCH,
  EXAMPLE_SHIELD_EVENT,
  IngestResponseSchema,
  LIMITS,
  ListEventsResponseSchema,
  type StoredEvent,
} from "@antireverse/protocol";
import { actorHash, generateKey, hashKey, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.ts";
import type { Db } from "../src/db/db.ts";
import { listen } from "../src/server.ts";
import {
  batchOf,
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T08:00:00.000Z");

interface Tenant {
  organizationId: string;
  adminKey: string;
  appId: string;
  shieldKey: string;
}

describe("ingest", () => {
  let api: TestApi;
  const clock = { now: new Date(T0) };

  beforeAll(async () => {
    api = await makeTestApi({ now: () => clock.now });
  });
  afterAll(async () => {
    await api.close();
  });

  /** A fresh Organization with one App, so that every test counts only its own Events. */
  async function tenant(environment: "production" | "staging" | "development" = "production"): Promise<Tenant> {
    const organization = await createOrganization(api);
    const created = await createAppFor(api, organization.admin_key.key, { name: "Storefront", environment });
    return {
      organizationId: organization.organization.id,
      adminKey: organization.admin_key.key,
      appId: created.app.id,
      shieldKey: created.shield_key.key,
    };
  }

  function ingest(shieldKey: string, body: unknown): Promise<Response> {
    return Promise.resolve(api.app.request("/v1/events", json(body, bearer(shieldKey))));
  }

  async function list(t: Tenant): Promise<StoredEvent[]> {
    const res = await api.app.request(`/v1/apps/${t.appId}/events?limit=200`, { headers: bearer(t.adminKey) });
    expect(res.status).toBe(200);
    return ListEventsResponseSchema.parse(await res.json()).events;
  }

  async function storedRows(t: Tenant): Promise<Record<string, unknown>[]> {
    const { rows } = await api.db.tx({ organizationId: t.organizationId }, (q) =>
      q.query<Record<string, unknown>>("SELECT * FROM events ORDER BY event_id"),
    );
    return rows;
  }

  it("stores a valid batch of 3 and lists it newest first, stamped from the Shield key", async () => {
    const t = await tenant("staging");
    const events = [shieldEvent(T0 + 1), shieldEvent(T0 + 2), shieldEvent(T0 + 3)];
    clock.now = new Date(T0 + 500);

    const res = await ingest(t.shieldKey, batchOf(events));

    expect(res.status).toBe(202);
    expect(IngestResponseSchema.parse(await res.json())).toEqual({ accepted: 3, duplicates: 0 });
    const stamp = {
      organization_id: t.organizationId,
      app_id: t.appId,
      environment: "staging",
      received_at: new Date(T0 + 500).toISOString(),
    };
    expect(await list(t)).toEqual([
      { ...events[2], ...stamp },
      { ...events[1], ...stamp },
      { ...events[0], ...stamp },
    ]);
  });

  it("ignores an Organization, App or Environment the client supplies", async () => {
    const victim = await tenant("production");
    const sender = await tenant("development");
    const forged = { organization_id: victim.organizationId, app_id: victim.appId, environment: "production" };
    const event = shieldEvent(T0 + 10);

    const res = await ingest(sender.shieldKey, { ...batchOf([{ ...event, ...forged }]), ...forged });

    expect(res.status).toBe(202);
    expect(await list(victim)).toEqual([]);
    const own = await list(sender);
    expect(own).toHaveLength(1);
    expect(own[0]).toMatchObject({
      event_id: event.event_id,
      organization_id: sender.organizationId,
      app_id: sender.appId,
      environment: "development",
    });
    const rows = await storedRows(sender);
    expect(rows[0]).toMatchObject({
      organization_id: sender.organizationId,
      app_id: sender.appId,
      environment: "development",
    });
    expect(JSON.stringify(rows[0]?.payload)).not.toContain(victim.organizationId);
    expect(JSON.stringify(rows[0]?.payload)).not.toContain(victim.appId);
  });

  it("counts a batch sent again as duplicates and stores nothing twice", async () => {
    const t = await tenant();
    const batch = batchOf([shieldEvent(T0 + 1), shieldEvent(T0 + 2), shieldEvent(T0 + 3)]);

    expect(await (await ingest(t.shieldKey, batch)).json()).toEqual({ accepted: 3, duplicates: 0 });
    const again = await ingest(t.shieldKey, batch);

    expect(again.status).toBe(202);
    expect(await again.json()).toEqual({ accepted: 0, duplicates: 3 });
    expect(await storedRows(t)).toHaveLength(3);
  });

  it("counts new Events and duplicates in one batch, also when an identifier repeats inside it", async () => {
    const t = await tenant();
    const known = shieldEvent(T0 + 1);
    const fresh = shieldEvent(T0 + 2);
    await ingest(t.shieldKey, batchOf([known]));

    const res = await ingest(
      t.shieldKey,
      batchOf([known, fresh, fresh, { ...fresh, event_id: fresh.event_id.toUpperCase() }]),
    );

    expect(await res.json()).toEqual({ accepted: 1, duplicates: 3 });
    expect((await list(t)).map((event) => event.event_id)).toEqual([fresh.event_id, known.event_id]);
  });

  it("keeps event identifiers per Organization: the same identifier is new for another Organization", async () => {
    const first = await tenant();
    const second = await tenant();
    const event = shieldEvent(T0 + 1);

    expect(await (await ingest(first.shieldKey, batchOf([event]))).json()).toEqual({ accepted: 1, duplicates: 0 });
    expect(await (await ingest(second.shieldKey, batchOf([event]))).json()).toEqual({ accepted: 1, duplicates: 0 });

    expect((await list(first))[0]?.organization_id).toBe(first.organizationId);
    expect((await list(second))[0]?.organization_id).toBe(second.organizationId);
  });

  it("refuses a whole batch when one Event is invalid, naming the first invalid Event, and stores nothing", async () => {
    const t = await tenant();
    const valid = shieldEvent(T0 + 1);
    const invalid = { ...shieldEvent(T0 + 2), request: { ...EXAMPLE_SHIELD_EVENT.request, status: 99 } };

    const res = await ingest(t.shieldKey, batchOf([valid, invalid, shieldEvent(T0 + 3)]));

    const problem = await expectProblem(res, 400);
    expect(problem.errors?.[0]?.path).toBe("events.1.request.status");
    expect(problem.errors?.every((error) => error.path.startsWith("events.1"))).toBe(true);
    expect(await storedRows(t)).toHaveLength(0);
  });

  it.each([
    ["501 Events", batchOf(Array.from({ length: 501 }, (_, index) => shieldEvent(T0 + index))), "events"],
    ["no Events", batchOf([]), "events"],
    ["another protocol version", { ...EXAMPLE_EVENT_BATCH, protocol: 2 }, "protocol"],
    ["a body without a batch", {}, "protocol"],
  ])("refuses %s", async (_label, body, path) => {
    const t = await tenant();
    const problem = await expectProblem(await ingest(t.shieldKey, body), 400);
    expect(problem.errors?.[0]?.path).toBe(path);
    expect(await storedRows(t)).toHaveLength(0);
  });

  it("accepts a batch of exactly 500 Events", async () => {
    const t = await tenant();
    const res = await ingest(t.shieldKey, batchOf(Array.from({ length: 500 }, (_, index) => shieldEvent(T0 + index))));
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 500, duplicates: 0 });
  });

  it("refuses malformed JSON", async () => {
    const t = await tenant();
    const res = await api.app.request("/v1/events", {
      method: "POST",
      headers: { "content-type": "application/json", ...bearer(t.shieldKey) },
      body: '{"protocol": 1, "events": [',
    });
    expect((await expectProblem(res, 400)).title).toBe("Malformed JSON");
  });

  describe("body limit", () => {
    const padded = (bytes: number): string => {
      const empty = JSON.stringify({ ...EXAMPLE_EVENT_BATCH, padding: "" });
      return JSON.stringify({ ...EXAMPLE_EVENT_BATCH, padding: "x".repeat(bytes - Buffer.byteLength(empty)) });
    };

    it("accepts a body of exactly 262,144 bytes and refuses one byte more (no content-length)", async () => {
      const t = await tenant();
      const post = (body: string) =>
        api.app.request("/v1/events", {
          method: "POST",
          headers: { "content-type": "application/json", ...bearer(t.shieldKey) },
          body,
        });
      expect(Buffer.byteLength(padded(LIMITS.bodyBytesMax))).toBe(262_144);

      const atLimit = await post(padded(LIMITS.bodyBytesMax));
      expect(atLimit.status).toBe(202);

      const over = await post(padded(LIMITS.bodyBytesMax + 1));
      const problem = await expectProblem(over, 413);
      expect(problem.detail).toContain("262144");
      expect(over.headers.get("connection")).toBeNull();
      expect(await storedRows(t)).toHaveLength(1);
    });

    it("stops reading a body far beyond the limit and closes the connection", async () => {
      const t = await tenant();
      const chunk = new Uint8Array(64 * 1024).fill(0x20);
      const total = 100;
      let pulled = 0;
      const endless = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (pulled === total) return controller.close();
          pulled++;
          controller.enqueue(chunk);
        },
      });

      const res = await api.app.request("/v1/events", {
        method: "POST",
        headers: { "content-type": "application/json", ...bearer(t.shieldKey) },
        body: endless,
        duplex: "half",
      } as RequestInit);

      await expectProblem(res, 413);
      expect(res.headers.get("connection")).toBe("close");
      // 6.4 MB were offered; the API gave up after the limit plus the bounded drain (about 1.3 MB).
      expect(pulled * chunk.byteLength).toBeLessThan(6 * LIMITS.bodyBytesMax);
      expect(pulled).toBeLessThan(total);
    });

    it("answers 413 over a real socket, with and without content-length, and keeps the connection usable", async () => {
      const t = await tenant();
      const { server, url } = await listen(api.app, { port: 0 });
      let connections = 0;
      server.on("connection", () => connections++);
      const headers = { "content-type": "application/json", ...bearer(t.shieldKey) };
      try {
        for (let round = 0; round < 3; round++) {
          // fetch sends a string body with a content-length header…
          const declared = await fetch(`${url}/v1/events`, {
            method: "POST",
            headers,
            body: padded(LIMITS.bodyBytesMax + 1 + round * 100_000),
          });
          await expectProblem(declared, 413);

          // …and a stream body chunked, without one.
          const text = padded(LIMITS.bodyBytesMax + 50_000);
          const chunked = await fetch(`${url}/v1/events`, {
            method: "POST",
            headers,
            body: new Blob([text]).stream(),
            duplex: "half",
          } as RequestInit);
          await expectProblem(chunked, 413);

          const next = await fetch(`${url}/v1/events`, {
            method: "POST",
            headers,
            body: JSON.stringify(batchOf([shieldEvent(T0 + round)])),
          });
          expect(next.status).toBe(202);
          await next.arrayBuffer();
        }
        expect(await storedRows(t)).toHaveLength(3);
        // No request lost its connection to a reset: far fewer sockets than requests were opened.
        expect(connections).toBeLessThanOrEqual(3);
      } finally {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
      }
    });

    it("answers a refused key cleanly over a real socket even when the body was never read", async () => {
      const { server, url } = await listen(api.app, { port: 0 });
      const unknown = generateKey("shield", "production").key;
      api.issuedKeys.push(unknown);
      try {
        for (let round = 0; round < 3; round++) {
          const res = await fetch(`${url}/v1/events`, {
            method: "POST",
            headers: { "content-type": "application/json", ...bearer(unknown) },
            body: padded(200_000),
          });
          await expectProblem(res, 401);
        }
      } finally {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
      }
    });
  });

  it("answers 401 without a key, 403 for an admin key and 401 for a revoked Shield key", async () => {
    const t = await tenant();
    const batch = batchOf([shieldEvent(T0 + 1)]);

    const none = await api.app.request("/v1/events", json(batch));
    await expectProblem(none, 401);
    expect(none.headers.get("www-authenticate")).toBe("Bearer");

    await expectProblem(await ingest(t.adminKey, batch), 403);

    await api.db.tx({ organizationId: t.organizationId }, (q) =>
      q.query("UPDATE api_keys SET revoked_at = now() WHERE key_hash = $1", [hashKey(t.shieldKey)]),
    );
    const revoked = await ingest(t.shieldKey, batch);
    await expectProblem(revoked, 401);
    expect(revoked.headers.get("www-authenticate")).toBe("Bearer");

    expect(await storedRows(t)).toHaveLength(0);
  });

  it("stores only the allowlisted members of an Event, whatever else is sent", async () => {
    const t = await tenant();
    const base = shieldEvent(T0 + 1);
    const event = {
      ...base,
      decision: { ...base.decision, action: "block" as const, mode: "enforce" as const, containment_id: newId("cnt") },
      actor: { ip_prefix: "203.0.113.0/24", ip_hash: actorHash(t.shieldKey, "203.0.113.77") },
      attestation: { status: "valid" as const, verdict: "suspect" as const, risk: 70 },
      signature: { status: "valid" as const, body: "checked" as const },
    };
    const noisy = {
      ...event,
      ip: "203.0.113.77",
      headers: { authorization: "Bearer leaked", cookie: "session=leaked" },
      query: "token=leaked",
      body: "leaked",
      request: { ...event.request, query: "token=leaked", url: "/api/products/42?token=leaked", headers: {} },
      decision: { ...event.decision, reason: "leaked" },
      actor: { ...event.actor, ip: "203.0.113.77", user_agent: "leaked", account: "leaked" },
      signals: [{ id: "sig", confidence: 0.5, evidence: "leaked" }],
      attestation: { ...event.attestation, token: "leaked", claims: { sub: "leaked" }, kid: "leaked" },
      signature: { ...event.signature, header: "leaked", nonce: "leaked", content_sha256: "leaked" },
    };

    const res = await ingest(t.shieldKey, { ...batchOf([noisy]), hostname: "leaked" });
    expect(res.status).toBe(202);

    const rows = await storedRows(t);
    expect(rows).toHaveLength(1);
    const payload = rows[0]?.payload as Record<string, Record<string, unknown>>;
    expect(payload).toEqual({ ...event, signals: [{ id: "sig", confidence: 0.5 }] });
    expect(Object.keys(payload).sort()).toEqual(
      [
        "actor",
        "attestation",
        "decision",
        "event_id",
        "request",
        "signals",
        "signature",
        "surface",
        "ts",
        "type",
      ].sort(),
    );
    expect(Object.keys(payload.attestation ?? {}).sort()).toEqual(["risk", "status", "verdict"]);
    expect(payload.signature).toEqual({ status: "valid", body: "checked" });
    expect(Object.keys(payload.request ?? {}).sort()).toEqual(["latency_ms", "method", "route", "status"]);
    expect(Object.keys(payload.actor ?? {}).sort()).toEqual(["ip_hash", "ip_prefix"]);
    expect(payload.actor?.ip_hash).toMatch(/^iph_[0-9a-f]{32}$/);
    expect(Object.keys(payload.decision ?? {}).sort()).toEqual(
      ["action", "containment_id", "mode", "patch_body", "patch_id", "policy_version", "rule_id"].sort(),
    );
    expect(JSON.stringify(rows)).not.toMatch(/leaked|203\.0\.113\.77|token|headers|query|user_agent/);
    expect(JSON.stringify(await list(t))).not.toMatch(/leaked|203\.0\.113\.77/);
  });

  it("still ingests an Event from an older Shield without ip_hash or containment_id, storing both as null", async () => {
    const t = await tenant();
    const { ip_hash: _hash, ...oldActor } = EXAMPLE_SHIELD_EVENT.actor;
    const { containment_id: _containment, ...oldDecision } = EXAMPLE_SHIELD_EVENT.decision;
    const old = { ...shieldEvent(T0 + 1), actor: oldActor, decision: oldDecision };

    const res = await ingest(t.shieldKey, batchOf([old]));
    expect(res.status).toBe(202);
    const rows = await storedRows(t);
    expect(rows).toHaveLength(1);
    const payload = rows[0]?.payload as { actor: unknown; decision: { containment_id: unknown } };
    expect(payload.actor).toEqual({ ip_prefix: EXAMPLE_SHIELD_EVENT.actor.ip_prefix, ip_hash: null });
    expect(payload.decision.containment_id).toBeNull();
  });

  it("stores the signature of an Event, and null for an Event from a Shield before slice 04", async () => {
    const t = await tenant();
    const { signature: _signature, ...old } = shieldEvent(T0 + 1);
    const signed = shieldEvent(T0 + 2, { signature: { status: "replayed", body: "unchecked" } });
    const unsigned = shieldEvent(T0 + 3, { signature: { status: "missing", body: null } });

    const res = await ingest(t.shieldKey, batchOf([old, signed, unsigned]));
    expect(res.status).toBe(202);
    const rows = await storedRows(t);
    const byId = new Map(rows.map((row) => [(row.payload as { event_id: string }).event_id, row.payload]));
    expect((byId.get(old.event_id) as { signature: unknown }).signature).toBeNull();
    expect((byId.get(signed.event_id) as { signature: unknown }).signature).toEqual({
      status: "replayed",
      body: "unchecked",
    });
    expect((byId.get(unsigned.event_id) as { signature: unknown }).signature).toEqual({
      status: "missing",
      body: null,
    });
  });

  it("stores, lists and publishes the attestation of each Event; an Event without one has null", async () => {
    const t = await tenant();
    const published: StoredEvent[] = [];
    const stop = api.bus.subscribe({ organizationId: t.organizationId, appId: t.appId }, (e) => published.push(e));
    const attestations = [
      { status: "valid", verdict: "trusted", risk: 5 },
      { status: "valid", verdict: "hostile", risk: 100 },
      { status: "missing", verdict: null, risk: null },
      { status: "invalid", verdict: null, risk: null },
      { status: "expired", verdict: null, risk: null },
    ] as const;
    const events = attestations.map((attestation, index) => shieldEvent(T0 + 10 + index, { attestation }));
    const { attestation: _none, ...older } = shieldEvent(T0 + 20);

    const res = await ingest(t.shieldKey, batchOf([...events, older]));
    stop();

    expect(res.status).toBe(202);
    const listed = await list(t);
    const byId = new Map(listed.map((e) => [e.event_id, e.attestation]));
    attestations.forEach((attestation, index) => {
      expect(byId.get(events[index]?.event_id ?? "")).toEqual(attestation);
    });
    expect(byId.get(older.event_id)).toBeNull();
    expect(published.map((e) => [e.event_id, e.attestation])).toEqual([
      ...events.map((e) => [e.event_id, e.attestation]),
      [older.event_id, null],
    ]);
  });

  it.each([
    ["a valid status without a verdict", { status: "valid", verdict: null, risk: null }],
    ["a verdict on a missing token", { status: "missing", verdict: "trusted", risk: 5 }],
    ["an unknown status", { status: "forged", verdict: null, risk: null }],
    ["a risk above 100", { status: "valid", verdict: "hostile", risk: 101 }],
  ])("refuses an Event whose attestation has %s", async (_label, attestation) => {
    const t = await tenant();
    const res = await ingest(t.shieldKey, batchOf([{ ...shieldEvent(T0 + 1), attestation }]));
    await expectProblem(res, 400);
    expect(await storedRows(t)).toHaveLength(0);
  });

  it("publishes each newly stored Event once, and nothing for duplicates", async () => {
    const t = await tenant();
    const published: StoredEvent[] = [];
    const unsubscribe = api.bus.subscribe({ organizationId: t.organizationId, appId: t.appId }, (event) =>
      published.push(event),
    );
    const first = shieldEvent(T0 + 1);
    const second = shieldEvent(T0 + 2);

    await ingest(t.shieldKey, batchOf([first, second, second]));
    expect(published.map((event) => event.event_id)).toEqual([first.event_id, second.event_id]);
    expect(published).toEqual([...(await list(t))].reverse());

    const third = shieldEvent(T0 + 3);
    await ingest(t.shieldKey, batchOf([first, second, third]));
    expect(published.map((event) => event.event_id)).toEqual([first.event_id, second.event_id, third.event_id]);
    unsubscribe();
  });

  it("publishes nothing when the transaction fails", async () => {
    const t = await tenant();
    const published: StoredEvent[] = [];
    const unsubscribe = api.bus.subscribe({ organizationId: t.organizationId, appId: t.appId }, (event) =>
      published.push(event),
    );
    // Authentication works; the transaction that stores Events runs and then fails to commit.
    const failingOnWrite: Db = {
      tx: (scope, fn) =>
        scope === "none"
          ? api.db.tx(scope, fn)
          : api.db.tx(scope, async (q) => {
              await fn(q);
              throw new Error("commit failed");
            }),
      close: () => Promise.resolve(),
    };
    const app = createApp({ db: failingOnWrite, bus: api.bus, signer: api.signer, logger: captureLogger() });

    const res = await app.request("/v1/events", json(batchOf([shieldEvent(T0 + 1)]), bearer(t.shieldKey)));

    await expectProblem(res, 500);
    expect(published).toHaveLength(0);
    expect(await storedRows(t)).toHaveLength(0);
    unsubscribe();
  });

  it("never logs a key or anything from a request body", () => {
    expectNoKeyLogged(api);
    const log = api.logger.lines.join("\n");
    expect(log).not.toContain(EXAMPLE_SHIELD_EVENT.request.route);
    expect(log).not.toMatch(/leaked|shield-node|padding/);
    expect(log).toContain("route=/v1/events status=202");
  });
});
