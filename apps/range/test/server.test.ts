import { createHash, generateKeyPairSync, sign } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { createShield, type Shield, type Transport } from "@antireverse/shield-node";
import { afterEach, describe, expect, it } from "vitest";
import { createRangeServer } from "../src/server.ts";

/** Synthetic and well-formed. */
const KEY = `ark_dev_${"Zq9".repeat(14)}Z`;

/** The part of an Event these tests read. The wire contract itself is tested in shield-node. */
interface ShieldEvent {
  request: { method: string; route: string; status: number };
  decision: {
    action: string;
    mode: string;
    rule_id: string | null;
    policy_version: number;
    containment_id: string | null;
    patch_id: string | null;
    patch_body: string | null;
  };
  actor: { ip_prefix: string | null };
}

interface Harness {
  base: string;
  shield: Shield;
  bodies: string[];
  /** Waits for `count` recorded Events, flushes, and returns everything the fake transport received. */
  events(count: number): Promise<ShieldEvent[]>;
}

const servers: http.Server[] = [];
const shields: Shield[] = [];

/** The key pair of a synthetic API, and the Policy it serves: one Rule, signed as the API signs a bundle. */
const signing = generateKeyPairSync("ed25519");
const POLICY_PUBLIC_KEY = signing.publicKey.export({ format: "jwk" }).x as string;
const RULE_ID = "rul_0123456789abcdef01234567";

function signedBundle(mode: "monitor" | "enforce"): string {
  const bundle = JSON.stringify({
    format: 1,
    audience: createHash("sha256").update(KEY, "utf8").digest("hex").slice(0, 32),
    epoch: "fedcba9876543210fedcba9876543210",
    app_id: "app_89abcdef0123456789abcdef",
    environment: "development",
    version: 1,
    issued_at: new Date().toISOString(),
    not_after: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    rules: [{ id: RULE_ID, path: "/api/admin/**", methods: [], action: "block", mode }],
  });
  const signature = sign(null, Buffer.from(bundle, "utf8"), signing.privateKey).toString("base64url");
  return JSON.stringify({ bundle, signature, key_id: "0123456789abcdef" });
}

/** `policy` gives Shield the public key and a Policy with one Rule for /api/admin/** in that mode. */
async function start(policy?: "monitor" | "enforce"): Promise<Harness> {
  const bodies: string[] = [];
  const transport: Transport = async (request) => {
    if (request.method === "GET") {
      return policy === undefined ? { status: 404 } : { status: 200, body: signedBundle(policy), etag: '"1"' };
    }
    // Shield's runtime inventory (slice 19) goes to its own endpoint; `bodies` holds Event batches only.
    if (request.url.endsWith("/v1/inventory")) return { status: 202 };
    bodies.push(request.body ?? "");
    return { status: 202 };
  };
  const shield = createShield({
    key: KEY,
    endpoint: "http://ingest.test",
    transport,
    flushIntervalMs: 3_600_000,
    logger: { warn: () => {} },
    ...(policy === undefined ? {} : { policyPublicKey: POLICY_PUBLIC_KEY, policyPollIntervalMs: 3_600_000 }),
  });
  shields.push(shield);
  if (policy !== undefined) {
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyVersion: 1, policyRules: 1, lastPolicyError: null });
  }
  const server = http.createServer(createRangeServer({ shield }));
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    shield,
    bodies,
    async events(count) {
      const recorded = (): number => shield.stats().buffered + shield.stats().sent;
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return bodies.flatMap((body) => (JSON.parse(body) as { events: ShieldEvent[] }).events);
    },
  };
}

afterEach(async () => {
  for (const shield of shields.splice(0)) await shield.close();
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
});

describe("ar-range, the reference target", () => {
  it("answers 200, 200 and 401 and yields three Events with the route templates", async () => {
    const range = await start();

    const home = await fetch(`${range.base}/`);
    expect(home.status).toBe(200);
    expect(home.headers.get("content-type")).toMatch(/^text\/html/);
    expect(await home.text()).toContain("<title>");

    const product = await fetch(`${range.base}/api/products/7`);
    expect(product.status).toBe(200);
    expect(product.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await product.json()).toMatchObject({ id: "7", name: expect.any(String) });

    const login = await fetch(`${range.base}/api/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "synthetic-user", password: "synthetic-password" }),
    });
    expect(login.status).toBe(401);
    expect(login.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await login.json()).toEqual({ error: "invalid_credentials" });

    const events = await range.events(3);
    expect(events.map((event) => [event.request.method, event.request.route, event.request.status])).toEqual([
      ["GET", "/", 200],
      ["GET", "/api/products/:id", 200],
      ["POST", "/api/login", 401],
    ]);
    for (const event of events) {
      expect(event.decision).toEqual({
        action: "allow",
        mode: "monitor",
        rule_id: null,
        policy_version: 0,
        containment_id: null,
        patch_id: null,
        patch_body: null,
      });
      expect(event.actor.ip_prefix).toBe("127.0.0.0/24");
    }
    const sent = range.bodies.join("\n");
    expect(sent).not.toContain("synthetic-user");
    expect(sent).not.toContain("synthetic-password");
  });

  it("rejects every login, whatever is sent, without reading it back", async () => {
    const range = await start();
    for (const body of ['{"username":"admin","password":"admin"}', "not json", ""]) {
      const response = await fetch(`${range.base}/api/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      expect(response.status).toBe(401);
      const text = await response.text();
      expect(JSON.parse(text)).toEqual({ error: "invalid_credentials" });
      expect(text).not.toContain("admin");
    }
  });

  it("serves products as JSON and never reflects the identifier into HTML", async () => {
    const range = await start();
    const odd = await fetch(`${range.base}/api/products/${encodeURIComponent("<script>alert(1)</script>")}`);
    expect(odd.status).toBe(404);
    expect(odd.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await odd.json()).toEqual({ error: "not_found" });

    const first = await (await fetch(`${range.base}/api/products/1`)).json();
    const again = await (await fetch(`${range.base}/api/products/1`)).json();
    expect(first).toEqual(again); // synthetic and deterministic
    expect(first).toMatchObject({ id: "1", name: expect.any(String), price_cents: expect.any(Number) });
    await range.events(3);
  });

  it("has a health route that Shield does not record", async () => {
    const range = await start();
    const health = await fetch(`${range.base}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: "ok" });
    await fetch(`${range.base}/api/products/7`);
    const events = await range.events(1);
    await sleep(30);
    expect(events.map((event) => event.request.route)).toEqual(["/api/products/:id"]);
    expect(range.shield.stats().buffered).toBe(0);
  });

  it("answers unknown paths with 404 and records them as (unmatched)", async () => {
    const range = await start();
    const response = await fetch(`${range.base}/admin/secret-panel?debug=1`);
    expect(response.status).toBe(404);
    const events = await range.events(1);
    expect(events[0]?.request).toMatchObject({ route: "(unmatched)", status: 404 });
    expect(range.bodies.join("\n")).not.toContain("secret-panel");
  });

  it("serves synthetic admin reports as JSON: the route that demonstrates blocking", async () => {
    const range = await start();
    const response = await fetch(`${range.base}/api/admin/reports`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/^application\/json/);
    const body = (await response.json()) as { reports: { id: string; title: string; rows: number }[] };
    expect(body.reports.length).toBeGreaterThan(0);
    for (const report of body.reports) {
      expect(report).toEqual({ id: expect.any(String), title: expect.any(String), rows: expect.any(Number) });
    }
    expect(await (await fetch(`${range.base}/api/admin/reports`)).json()).toEqual(body); // synthetic and deterministic
    const events = await range.events(2);
    expect(events[0]?.request).toMatchObject({ method: "GET", route: "/api/admin/reports", status: 200 });
    expect(events[0]?.decision).toEqual({
      action: "allow",
      mode: "monitor",
      rule_id: null,
      policy_version: 0,
      containment_id: null,
      patch_id: null,
      patch_body: null,
    });

    const home = await (await fetch(`${range.base}/`)).text();
    expect(home).toContain("/api/admin/reports");
  });

  it("answers 403 for /api/admin/reports once an Enforce Rule for /api/admin/** is applied, and nothing else changes", async () => {
    const range = await start("enforce");
    for (const path of ["/api/admin/reports", "/API/Admin/Reports/", "/api/admin/reports?format=csv", "/api/admin"]) {
      const blocked = await fetch(range.base + path);
      expect(blocked.status, path).toBe(403);
      expect(blocked.headers.get("content-type"), path).toBe("application/json");
      expect(await blocked.text(), path).toBe('{"error":"request_blocked"}');
    }
    expect((await fetch(`${range.base}/api/products/7`)).status).toBe(200);
    expect((await fetch(`${range.base}/api/login`, { method: "POST" })).status).toBe(401);
    expect((await fetch(`${range.base}/healthz`)).status).toBe(200);

    const events = await range.events(6);
    expect(events.map((event) => [event.request.route, event.request.status, event.decision.action])).toEqual([
      ["/api/admin/**", 403, "block"],
      ["/api/admin/**", 403, "block"],
      ["/api/admin/**", 403, "block"],
      ["/api/admin/**", 403, "block"],
      ["/api/products/:id", 200, "allow"],
      ["/api/login", 401, "allow"],
    ]);
    expect(events[0]?.decision).toEqual({
      action: "block",
      mode: "enforce",
      rule_id: RULE_ID,
      policy_version: 1,
      containment_id: null,
      patch_id: null,
      patch_body: null,
    });
    expect(events[4]?.decision).toEqual({
      action: "allow",
      mode: "enforce",
      rule_id: null,
      policy_version: 1,
      containment_id: null,
      patch_id: null,
      patch_body: null,
    });
    const sent = range.bodies.join("\n");
    expect(sent).not.toContain("reports");
    expect(sent).not.toContain("csv");
  });

  it("serves /api/admin/reports unchanged under a Monitor Rule and marks the Event", async () => {
    const range = await start("monitor");
    const plain = await start();
    const marked = await fetch(`${range.base}/api/admin/reports`);
    const unmarked = await fetch(`${plain.base}/api/admin/reports`);
    expect(marked.status).toBe(200);
    expect(await marked.text()).toBe(await unmarked.text());
    const events = await range.events(1);
    expect(events[0]?.request).toMatchObject({ route: "/api/admin/reports", status: 200 });
    expect(events[0]?.decision).toEqual({
      action: "block",
      mode: "monitor",
      rule_id: RULE_ID,
      policy_version: 1,
      containment_id: null,
      patch_id: null,
      patch_body: null,
    });
  });

  it("works the same with a disabled Shield", async () => {
    const warnings: string[] = [];
    const shield = createShield({
      key: "",
      endpoint: "http://ingest.test",
      logger: { warn: (m) => void warnings.push(m) },
    });
    const server = http.createServer(createRangeServer({ shield }));
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    expect((await fetch(`${base}/api/products/7`)).status).toBe(200);
    expect((await fetch(`${base}/api/login`, { method: "POST" })).status).toBe(401);
    expect((await fetch(`${base}/api/admin/reports`)).status).toBe(200);
    expect(warnings).toHaveLength(1);
  });
});
