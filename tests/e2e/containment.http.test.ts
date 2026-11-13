// Slice 09 over HTTP: an attacker's burst through Shield on the reference target (ar-range) opens a Blocked-burst
// Incident whose Actors name the attacker's keyed address hash; blocking that Actor for 1 hour reaches the running
// Shield through its own poller within 30 s (PB-15) while a bystander in the same /24 still passes; the contained
// requests carry the Containment's id and open no new Incident; lifting lets the attacker through again. A network
// block needs the prefix typed and blocks both clients; the never-block list exempts an address from it and makes
// an overlapping network block a conflict. Another App and another Organization see none of it; a Shield key
// cannot contain.
//
// Two clients in one /24: macOS configures only 127.0.0.1 on lo0 (binding 127.0.0.2 fails with EADDRNOTAVAIL),
// so the customer's Shield is configured as behind a trusted reverse proxy — Shield's public `clientAddress`
// option reads the address the proxy put in X-Forwarded-For — and the test plays that proxy for two documentation
// addresses of 198.51.100.0/24. Everything else (sockets, Shield, poller, API) is the real path.
import { randomBytes } from "node:crypto";
import http, { type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  AllowlistEntryResponseSchema,
  BLOCK_RESPONSE_BODY,
  BundlePayloadSchema,
  type Containment,
  ContainmentResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  type Incident,
  IncidentDetailResponseSchema,
  ListAllowlistResponseSchema,
  ListContainmentsResponseSchema,
  ListEventsResponseSchema,
  ListIncidentsResponseSchema,
  PolicyResponseSchema,
  ProblemSchema,
  SignedBundleSchema,
} from "@antireverse/protocol";
import { actorHash } from "@antireverse/protocol/server";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield } from "@antireverse/shield-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-15: a containment is enforced by every Shield of the App and Environment within 30 s. */
const ENFORCE_BUDGET_MS = 30_000;
/** PB-14: a Detection is recorded within 10 s of the Event that completes it. */
const DETECTION_BUDGET_MS = 10_000;
/** The managed rule "Blocked burst": 20 enforced blocks from one network prefix within 5 minutes. */
const BURST = 20;
/** How long to wait for a Detection that must not come, once the Events behind it are stored. */
const QUIET_MS = 3_000;
const CONSOLE_URL = "http://127.0.0.1:39941";

const ATTACKER = "198.51.100.7";
const BYSTANDER = "198.51.100.8";
const PREFIX = "198.51.100.0/24";
/**
 * The customer-held actor key (owner decision on review finding F1): Shield keys actor hashes with it, never with
 * the Shield key. 43 base64url characters, fresh per run.
 */
const ACTOR_KEY = randomBytes(32).toString("base64url");
/** The never-block range of the bystander: exactly its address. */
const BYSTANDER_CIDR = `${BYSTANDER}/32`;

/** Shield's clientAddress: the address the (trusted) proxy forwarded, else the socket's. */
function forwardedFor(req: unknown): string | undefined {
  const request = req as IncomingMessage;
  const forwarded = request.headers["x-forwarded-for"];
  return typeof forwarded === "string" && forwarded !== "" ? forwarded : request.socket?.remoteAddress;
}

let api: RunningApi;
let adminKey: string;
/** The id of the admin key, learned from the first block it created (the key's creation shows no id). */
let adminKeyId: string;
let shieldKey: string;
let appId: string;
let attackerHash: string;
let incident: Incident;
let actorBlock: Containment;
let prefixBlock: Containment;
let allowlistId: string;
/** The customer's server of the App under attack, and of a second App of the same Organization. */
let shield: Shield;
let range: http.Server;
let rangeUrl: string;
let otherAppShieldKey: string;
let otherAppShield: Shield;
let otherAppRange: http.Server;
let otherAppRangeUrl: string;
/** Another Organization with an App. */
let otherOrgAdminKey: string;
let otherOrgShieldKey: string;
const timings: { containMs?: number; liftMs?: number; prefixMs?: number; allowlistMs?: number } = {};

function call(path: string, init: { method?: string; key?: string; body?: unknown } = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
  // Slice 18a: every change carries a reason, as an operator gives one; sensitive changes refuse to go without.
  if (init.key && (init.method ?? "GET") !== "GET") headers["x-airverse-reason"] = "End-to-end test";
  if (init.body !== undefined) headers["content-type"] = "application/json";
  return fetch(`${api.url}${path}`, {
    method: init.method ?? "GET",
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
}

async function until<T>(what: string, budgetMs: number, probe: () => Promise<T | undefined>): Promise<T> {
  const started = Date.now();
  for (;;) {
    const value = await probe();
    if (value !== undefined) return value;
    if (Date.now() - started > budgetMs) throw new Error(`${what}: not within ${budgetMs} ms`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/** One request through a customer's server from `client`; the status and body. */
async function visit(base: string, client: string, path = "/"): Promise<{ status: number; body: string }> {
  const response = await fetch(`${base}${path}`, { headers: { "x-forwarded-for": client } });
  return { status: response.status, body: await response.text() };
}

const isContained = (r: { status: number; body: string }) => r.status === 403 && r.body === BLOCK_RESPONSE_BODY;

/** Polls `client`'s requests to the unruled home page until `wanted` holds; the time it took. */
async function untilVisit(
  what: string,
  client: string,
  wanted: (r: { status: number; body: string }) => boolean,
  base = rangeUrl,
): Promise<number> {
  const started = Date.now();
  await until(what, ENFORCE_BUDGET_MS, async () => (wanted(await visit(base, client)) ? true : undefined));
  return Date.now() - started;
}

async function blockedIncidents(): Promise<Incident[]> {
  const response = await call(`/v1/incidents?app_id=${appId}`, { key: adminKey });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents.filter((i) => i.rule === "blocked-burst");
}

async function detail(id = incident.id) {
  const response = await call(`/v1/incidents/${id}`, { key: adminKey });
  expect(response.status).toBe(200);
  return IncidentDetailResponseSchema.parse(await response.json());
}

/** The bundle the API serves to a Shield key, decoded. */
async function bundleOf(key: string) {
  const response = await call("/v1/policy-bundle", { key });
  expect(response.status).toBe(200);
  return BundlePayloadSchema.parse(JSON.parse(SignedBundleSchema.parse(await response.json()).bundle));
}

function contain(body: unknown, key = adminKey, id = incident.id): Promise<Response> {
  return call(`/v1/incidents/${id}/containments`, { method: "POST", key, body });
}

async function conflictReason(response: Response): Promise<string | undefined> {
  expect(response.status).toBe(409);
  return ProblemSchema.parse(await response.json()).reason;
}

async function publishAdminRule(app: string): Promise<number> {
  const published = await call(`/v1/apps/${app}/policies/development`, {
    method: "PUT",
    key: adminKey,
    body: { rules: [{ name: "Admin area", path: "/api/admin/**", mode: "enforce" }] },
  });
  expect(published.status).toBe(201);
  return PolicyResponseSchema.parse(await published.json()).policy.version;
}

/** A Shield with its default poll interval (5 s) in front of a range server. */
async function customer(key: string, publicKey: string): Promise<{ shield: Shield; server: http.Server; url: string }> {
  // Built apart from the call so that the test compiles before and after `actorKey` joins ShieldConfig.
  const config = {
    key,
    endpoint: api.url,
    policyPublicKey: publicKey,
    clientAddress: forwardedFor,
    actorKey: ACTOR_KEY,
    flushIntervalMs: 200,
    logger: { warn() {} },
  };
  const s = createShield(config);
  await s.refreshPolicy();
  expect(s.stats().lastPolicyError).toBeNull();
  const server = http.createServer(createRangeServer({ shield: s }));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { shield: s, server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

beforeAll(async () => {
  api = await startApi({
    allowPrivateAlertUrls: true,
    alertBackoffMs: 10,
    consoleUrl: CONSOLE_URL,
    logger: { info() {}, warn() {} },
  });

  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Acme" } })).json(),
  );
  adminKey = organization.admin_key.key;
  const created = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json(),
  );
  appId = created.app.id;
  shieldKey = created.shield_key.key;
  attackerHash = actorHash(ACTOR_KEY, ATTACKER) ?? "";
  expect(attackerHash).toMatch(/^iph_[0-9a-f]{32}$/);
  // Keyed with the actor key, never with the Shield key (F1).
  expect(attackerHash).not.toBe(actorHash(shieldKey, ATTACKER));

  const other = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-admin" } })).json(),
  );
  otherAppShieldKey = other.shield_key.key;

  const otherOrg = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
  );
  otherOrgAdminKey = otherOrg.admin_key.key;
  otherOrgShieldKey = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: otherOrgAdminKey, body: { name: "shop-web" } })).json(),
  ).shield_key.key;

  // The Enforce Rule of the range's admin area, on both Apps of the Organization.
  const version = await publishAdminRule(appId);
  await publishAdminRule(other.app.id);

  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  ({ shield, server: range, url: rangeUrl } = await customer(shieldKey, signingKey.public_key));
  expect(shield.stats()).toMatchObject({ policyVersion: version, lastPolicyError: null });
  ({
    shield: otherAppShield,
    server: otherAppRange,
    url: otherAppRangeUrl,
  } = await customer(otherAppShieldKey, signingKey.public_key));
});

afterAll(async () => {
  for (const s of [shield, otherAppShield]) await s?.close();
  for (const server of [range, otherAppRange]) {
    if (!server) continue;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await api?.close();
});

describe("slice 09 containment over HTTP", () => {
  it("lists the attacker of a burst through Shield as the Incident's Actor, by its keyed address hash", async () => {
    expect(await visit(rangeUrl, BYSTANDER)).toMatchObject({ status: 200 });
    for (let i = 0; i < BURST; i++) {
      const response = await visit(rangeUrl, ATTACKER, "/api/admin/reports");
      expect(response).toEqual({ status: 403, body: BLOCK_RESPONSE_BODY });
    }
    incident = await until("Incident opened", DETECTION_BUDGET_MS, async () => (await blockedIncidents())[0]);
    expect(incident).toMatchObject({ app_id: appId, environment: "development", status: "open", ip_prefix: PREFIX });

    const { actors, containments } = await detail();
    // Only the attacker's blocked requests are evidence: the bystander's page view is no Actor of the Incident.
    expect(actors).toEqual([{ ip_hash: attackerHash, events: BURST }]);
    expect(containments).toEqual([]);
    expect(attackerHash).not.toBe(actorHash(ACTOR_KEY, BYSTANDER));
    // Keyed with the customer's actor key: neither the Shield key nor another actor key gives this hash.
    expect(actors[0]?.ip_hash).not.toBe(actorHash(shieldKey, ATTACKER));
    expect(actorHash(randomBytes(32).toString("base64url"), ATTACKER)).not.toBe(attackerHash);
  });

  it("refuses a Shield key, an unknown Actor and another Organization", async () => {
    const body = { target: { kind: "actor", ip_hash: attackerHash }, ttl_s: 3600 };
    expect((await contain(body, shieldKey)).status).toBe(403);
    expect((await call("/v1/containments", { key: shieldKey })).status).toBe(403);
    expect((await call("/v1/allowlist", { key: shieldKey })).status).toBe(403);
    expect(
      (await call("/v1/allowlist", { method: "POST", key: shieldKey, body: { cidr: BYSTANDER_CIDR, note: "" } }))
        .status,
    ).toBe(403);
    // The bystander never appears in the evidence: not an Actor of this Incident.
    const bystander = { target: { kind: "actor", ip_hash: actorHash(ACTOR_KEY, BYSTANDER) }, ttl_s: 3600 };
    expect(await conflictReason(await contain(bystander))).toBe("actor-unknown");
    // Another Organization cannot see the Incident.
    expect((await contain(body, otherOrgAdminKey)).status).toBe(404);
    expect((await detail()).containments).toEqual([]);
  });

  it("blocks the Actor for 1 hour: Shield enforces it within 30 s while a bystander in the same /24 passes", async () => {
    expect(await visit(rangeUrl, ATTACKER)).toMatchObject({ status: 200 });

    const response = await contain({ target: { kind: "actor", ip_hash: attackerHash }, ttl_s: 3600 });
    expect(response.status).toBe(201);
    actorBlock = ContainmentResponseSchema.parse(await response.json()).containment;
    const createdAt = Date.now();
    adminKeyId = actorBlock.created_by;
    expect(adminKeyId).toMatch(/^key_[0-9a-f]{24}$/);
    expect(actorBlock).toMatchObject({
      app_id: appId,
      environment: "development",
      incident_id: incident.id,
      target: { kind: "actor", ip_hash: attackerHash },
      status: "active",
      created_by: adminKeyId,
      lifted_at: null,
      lifted_by: null,
    });
    // Expiry, without waiting for it: exactly the TTL after creation.
    expect(Date.parse(actorBlock.expires_at) - Date.parse(actorBlock.created_at)).toBe(3_600_000);

    // The same target again: the active block, 200, no second block.
    const again = await contain({ target: { kind: "actor", ip_hash: attackerHash }, ttl_s: 900 });
    expect(again.status).toBe(200);
    expect(ContainmentResponseSchema.parse(await again.json()).containment.id).toBe(actorBlock.id);

    // The bundle of the App and Environment carries it, with the same expiry Shield enforces offline.
    expect((await bundleOf(shieldKey)).blocks).toEqual([
      { id: actorBlock.id, kind: "actor", ip_hash: attackerHash, expires_at: actorBlock.expires_at },
    ]);

    // Shield's own poller (default 5 s) picks it up; the attacker's next request to an unruled page is blocked.
    await untilVisit("attacker contained", ATTACKER, isContained);
    timings.containMs = Date.now() - createdAt;
    expect(timings.containMs).toBeLessThanOrEqual(ENFORCE_BUDGET_MS);
    expect(await visit(rangeUrl, BYSTANDER)).toMatchObject({ status: 200 });
    expect(await visit(rangeUrl, BYSTANDER, "/api/products/7")).toMatchObject({ status: 200 });

    // Scope: the other App of the Organization, and another Organization, carry no block.
    expect((await bundleOf(otherAppShieldKey)).blocks ?? []).toEqual([]);
    expect((await bundleOf(otherOrgShieldKey)).blocks ?? []).toEqual([]);
    expect(await visit(otherAppRangeUrl, ATTACKER)).toMatchObject({ status: 200 });

    const listed = await call(`/v1/containments?app_id=${appId}&environment=development&status=active`, {
      key: adminKey,
    });
    expect(listed.status).toBe(200);
    expect(ListContainmentsResponseSchema.parse(await listed.json()).containments.map((c) => c.id)).toEqual([
      actorBlock.id,
    ]);
    const foreign = await call("/v1/containments", { key: otherOrgAdminKey });
    expect(ListContainmentsResponseSchema.parse(await foreign.json()).containments).toEqual([]);
    expect(
      (await call(`/v1/containments/${actorBlock.id}/lift`, { method: "POST", key: otherOrgAdminKey })).status,
    ).toBe(404);
    expect((await call(`/v1/containments/${actorBlock.id}/lift`, { method: "POST", key: shieldKey })).status).toBe(403);
    expect((await detail()).containments.map((c) => [c.id, c.status])).toEqual([[actorBlock.id, "active"]]);
  }, 60_000);

  it("records the Containment on the contained requests' Events, and opens no new Blocked-burst Incident", async () => {
    const before = await blockedIncidents();
    expect(before.map((i) => [i.id, i.detection_count])).toEqual([[incident.id, 1]]);

    for (let i = 0; i < 25; i++) expect(isContained(await visit(rangeUrl, ATTACKER))).toBe(true);

    const contained = await until("contained Events stored", DETECTION_BUDGET_MS, async () => {
      const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
      const { events } = ListEventsResponseSchema.parse(await response.json());
      const hits = events.filter((e) => e.decision.containment_id === actorBlock.id);
      return hits.length >= 25 ? { hits, raw: JSON.stringify(events) } : undefined;
    });
    for (const event of contained.hits) {
      expect(event.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: null });
      expect(event.actor).toMatchObject({ ip_prefix: PREFIX, ip_hash: attackerHash });
      expect(event.request).toMatchObject({ route: "(unmatched)", status: 403 });
    }
    // The full address never leaves the customer's server.
    expect(contained.raw).not.toContain(ATTACKER);
    expect(contained.raw).not.toContain(BYSTANDER);

    // 25 contained blocks from the prefix: no new Detection, no new Incident (one attack, one Incident).
    await new Promise((resolve) => setTimeout(resolve, QUIET_MS));
    expect((await blockedIncidents()).map((i) => [i.id, i.detection_count])).toEqual([[incident.id, 1]]);
  }, 30_000);

  it("lifts the block: the attacker passes again within 30 s; a second lift is a conflict", async () => {
    const response = await call(`/v1/containments/${actorBlock.id}/lift`, { method: "POST", key: adminKey });
    expect(response.status).toBe(200);
    const liftedAt = Date.now();
    const lifted = ContainmentResponseSchema.parse(await response.json()).containment;
    expect(lifted).toMatchObject({ id: actorBlock.id, status: "lifted", lifted_by: adminKeyId });
    expect(lifted.lifted_at).not.toBeNull();
    expect((await bundleOf(shieldKey)).blocks ?? []).toEqual([]);

    await untilVisit("attacker passes", ATTACKER, (r) => r.status === 200);
    timings.liftMs = Date.now() - liftedAt;
    expect(timings.liftMs).toBeLessThanOrEqual(ENFORCE_BUDGET_MS);

    const twice = await call(`/v1/containments/${actorBlock.id}/lift`, { method: "POST", key: adminKey });
    expect(await conflictReason(twice)).toBe("containment-ended");
  }, 60_000);

  it("blocks the network only with its prefix typed, and then blocks both clients", async () => {
    expect((await contain({ target: { kind: "prefix" }, ttl_s: 900 })).status).toBe(400);
    expect((await contain({ target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: "198.51.101.0/24" })).status).toBe(
      400,
    );
    expect((await call(`/v1/containments?app_id=${appId}&status=active`, { key: adminKey })).status).toBe(200);
    expect((await bundleOf(shieldKey)).blocks ?? []).toEqual([]);

    const response = await contain({ target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: PREFIX });
    expect(response.status).toBe(201);
    const createdAt = Date.now();
    prefixBlock = ContainmentResponseSchema.parse(await response.json()).containment;
    // Learned here too, so that a failure of the actor block does not cascade into the tests below.
    adminKeyId ??= prefixBlock.created_by;
    expect(prefixBlock).toMatchObject({ target: { kind: "prefix", ip_prefix: PREFIX }, status: "active" });
    expect(Date.parse(prefixBlock.expires_at) - Date.parse(prefixBlock.created_at)).toBe(900_000);
    expect((await bundleOf(shieldKey)).blocks).toEqual([
      { id: prefixBlock.id, kind: "prefix", ip_prefix: PREFIX, expires_at: prefixBlock.expires_at },
    ]);

    await untilVisit("bystander contained by the network block", BYSTANDER, isContained);
    timings.prefixMs = Date.now() - createdAt;
    expect(isContained(await visit(rangeUrl, ATTACKER))).toBe(true);
    // Only this App: the other App of the Organization still serves both.
    expect((await bundleOf(otherAppShieldKey)).blocks ?? []).toEqual([]);
    expect(await visit(otherAppRangeUrl, ATTACKER)).toMatchObject({ status: 200 });
    expect(await visit(otherAppRangeUrl, BYSTANDER)).toMatchObject({ status: 200 });
  }, 60_000);

  it("never blocks an allowlisted address, and refuses a network block that overlaps the allowlist", async () => {
    // Canonical CIDR only.
    const sloppy = await call("/v1/allowlist", {
      method: "POST",
      key: adminKey,
      body: { cidr: `${BYSTANDER}/24`, note: "" },
    });
    expect(sloppy.status).toBe(400);

    const added = await call("/v1/allowlist", {
      method: "POST",
      key: adminKey,
      body: { cidr: BYSTANDER_CIDR, note: "Office gateway" },
    });
    expect(added.status).toBe(201);
    const addedAt = Date.now();
    const { entry } = AllowlistEntryResponseSchema.parse(await added.json());
    allowlistId = entry.id;
    expect(entry).toMatchObject({ cidr: BYSTANDER_CIDR, note: "Office gateway", created_by: adminKeyId });
    const duplicate = await call("/v1/allowlist", {
      method: "POST",
      key: adminKey,
      body: { cidr: BYSTANDER_CIDR, note: "" },
    });
    expect(await conflictReason(duplicate)).toBe("allowlist-duplicate");

    // The Organization's allowlist rides in every bundle of the Organization, and in no other.
    expect((await bundleOf(shieldKey)).allowlist).toEqual([BYSTANDER_CIDR]);
    expect((await bundleOf(otherAppShieldKey)).allowlist).toEqual([BYSTANDER_CIDR]);
    expect((await bundleOf(otherOrgShieldKey)).allowlist ?? []).toEqual([]);
    const foreign = await call("/v1/allowlist", { key: otherOrgAdminKey });
    expect(ListAllowlistResponseSchema.parse(await foreign.json()).entries).toEqual([]);
    expect((await call(`/v1/allowlist/${allowlistId}`, { method: "DELETE", key: otherOrgAdminKey })).status).toBe(404);

    // Despite the active network block, the bystander passes; the attacker stays blocked.
    await untilVisit("allowlisted bystander passes", BYSTANDER, (r) => r.status === 200);
    timings.allowlistMs = Date.now() - addedAt;
    expect(isContained(await visit(rangeUrl, ATTACKER))).toBe(true);
    // The allowlist exempts from containment only, never from Rules.
    expect(await visit(rangeUrl, BYSTANDER, "/api/admin/reports")).toEqual({ status: 403, body: BLOCK_RESPONSE_BODY });

    // A network block that shares an address with the allowlist is refused.
    const overlapping = await contain({ target: { kind: "prefix" }, ttl_s: 3600, confirm_prefix: PREFIX });
    expect(await conflictReason(overlapping)).toBe("prefix-allowlisted");
  }, 60_000);

  it("cleans up: lift the network block, remove the range; a resolved Incident can no longer be contained", async () => {
    const lifted = await call(`/v1/containments/${prefixBlock.id}/lift`, { method: "POST", key: adminKey });
    expect(lifted.status).toBe(200);
    expect((await call(`/v1/allowlist/${allowlistId}`, { method: "DELETE", key: adminKey })).status).toBe(204);
    const list = await call("/v1/allowlist", { key: adminKey });
    expect(ListAllowlistResponseSchema.parse(await list.json()).entries).toEqual([]);
    const bundle = await bundleOf(shieldKey);
    expect(bundle.blocks ?? []).toEqual([]);
    expect(bundle.allowlist ?? []).toEqual([]);
    await untilVisit("attacker passes after the network block is lifted", ATTACKER, (r) => r.status === 200);

    // Both blocks stay on record, newest first, with who created and lifted them.
    expect((await detail()).containments.map((c) => [c.id, c.status, c.lifted_by])).toEqual([
      [prefixBlock.id, "lifted", adminKeyId],
      [actorBlock.id, "lifted", adminKeyId],
    ]);

    const resolved = await call(`/v1/incidents/${incident.id}`, {
      method: "PATCH",
      key: adminKey,
      body: { status: "resolved" },
    });
    expect(resolved.status).toBe(200);
    const late = await contain({ target: { kind: "actor", ip_hash: attackerHash }, ttl_s: 3600 });
    expect(await conflictReason(late)).toBe("incident-resolved");

    console.info(
      `containment e2e: create -> attacker blocked ${timings.containMs} ms; lift -> attacker passes ${timings.liftMs} ms; ` +
        `network block -> bystander blocked ${timings.prefixMs} ms; allowlist -> bystander passes ${timings.allowlistMs} ms`,
    );
  }, 60_000);
});
