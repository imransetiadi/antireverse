import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";
import { afterEach, describe, expect, it } from "vitest";
import { createRangeServer, createRequestLog, RANGE_TRAP_PATH, type RangeOptions } from "../src/server.ts";

// Slice 15a: the seeded weaknesses of ar-range, its traps and its request log. All of it is off by default; the
// "weaknesses" are synthetic answers of fixed routes — nothing is stored, executed or reachable beyond them.

const shield = { express: () => (_req: unknown, _res: unknown, next: () => void) => next() };
const servers: Server[] = [];

async function start(options: Partial<RangeOptions> = {}): Promise<string> {
  const app: Express = createRangeServer({ shield, ...options });
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe("weaknesses off (the default)", () => {
  it("has none of the weak routes or traps", async () => {
    const url = await start();
    for (const path of [
      "/api/orders/1001",
      "/api/orders/x",
      "/search?q=a",
      "/go?to=https://x.io/",
      RANGE_TRAP_PATH,
      "/trap/large",
    ]) {
      expect({ path, status: (await fetch(`${url}${path}`, { redirect: "manual" })).status }).toEqual({
        path,
        status: 404,
      });
    }
    expect((await fetch(`${url}/`)).status).toBe(200);
  });
});

describe("weaknesses on", () => {
  it("RW-01: the home page has no security headers", async () => {
    const url = await start({ weaknesses: true });
    const res = await fetch(`${url}/`);
    for (const header of [
      "content-security-policy",
      "x-content-type-options",
      "x-frame-options",
      "strict-transport-security",
    ]) {
      expect(res.headers.get(header)).toBeNull();
    }
  });

  it("RW-02: a malformed order id answers 500 with a stack trace", async () => {
    const url = await start({ weaknesses: true });
    const res = await fetch(`${url}/api/orders/x`);
    expect(res.status).toBe(500);
    expect(await res.text()).toMatch(/Error: .+\n\s+at \w+ \(.+:\d+:\d+\)/);
  });

  it("RW-03 and RW-04: admin reports and a synthetic order are readable without authentication", async () => {
    const url = await start({ weaknesses: true });
    expect(((await (await fetch(`${url}/api/admin/reports`)).json()) as { reports: unknown[] }).reports).toHaveLength(
      3,
    );
    const order = await fetch(`${url}/api/orders/1001`);
    expect(order.status).toBe(200);
    expect(await order.json()).toMatchObject({ order_id: "1001", synthetic: true });
    expect((await fetch(`${url}/api/orders/1002`)).status).toBe(404);
  });

  it("RW-05: the search page reflects the query unencoded", async () => {
    const url = await start({ weaknesses: true });
    const marker = '"><airverse-probe-marker>';
    const res = await fetch(`${url}/search?q=${encodeURIComponent(marker)}`);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    expect(await res.text()).toContain(marker);
  });

  it("RW-06: /go redirects to whatever it is given", async () => {
    const url = await start({ weaknesses: true });
    const res = await fetch(`${url}/go?to=${encodeURIComponent("https://elsewhere.acme-shop.io/landing")}`, {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://elsewhere.acme-shop.io/landing");
  });
});

describe("traps and the request log", () => {
  it("logs every request with its method, path, body size and whether it carried a cookie; a trap hit is marked", async () => {
    const log = createRequestLog();
    const url = await start({ weaknesses: true, log });
    await fetch(`${url}/search?q=1`, { headers: { "user-agent": "t/1", "x-airverse-campaign": "cmp_x" } });
    await fetch(`${url}/api/login`, { method: "POST", body: "abc", headers: { cookie: "a=b" } });
    await fetch(`${url}${RANGE_TRAP_PATH}`, { method: "POST" });
    await fetch(`${url}${RANGE_TRAP_PATH}?x=1`);
    expect(log.entries).toMatchObject([
      {
        method: "GET",
        url: "/search?q=1",
        bodyBytes: 0,
        cookie: false,
        userAgent: "t/1",
        campaign: "cmp_x",
        trap: false,
      },
      { method: "POST", url: "/api/login", bodyBytes: 3, cookie: true, trap: false },
      { method: "POST", url: RANGE_TRAP_PATH, trap: true },
      { method: "GET", url: `${RANGE_TRAP_PATH}?x=1`, trap: true },
    ]);
    expect(log.trapHits()).toHaveLength(2);
    log.clear();
    expect(log.entries).toEqual([]);
  });

  it("has the trap pages: instructions to POST elsewhere, 5 MB, a slow answer, a synthetic key and email", async () => {
    const url = await start({ weaknesses: true, slowMs: 150 });
    expect(await (await fetch(`${url}/trap/instructions`)).text()).toContain(`POST ${RANGE_TRAP_PATH}`);
    expect((await (await fetch(`${url}/trap/large`)).arrayBuffer()).byteLength).toBe(5 * 1024 * 1024);
    const started = Date.now();
    await (await fetch(`${url}/trap/slow`)).text();
    expect(Date.now() - started).toBeGreaterThanOrEqual(140);
    const secrets = await (await fetch(`${url}/trap/secrets`)).text();
    expect(secrets).toMatch(/sk_live_[A-Za-z0-9]{24}/);
    expect(secrets).toMatch(/[a-z.]+@acme-shop\.io/);
  });

  it("hostile variants change what the weak routes answer, not which routes exist", async () => {
    const instructions = await start({ weaknesses: true, hostile: "instructions" });
    expect(await (await fetch(`${instructions}/`)).text()).toContain(`POST ${RANGE_TRAP_PATH}`);
    expect(await (await fetch(`${instructions}/api/orders/1001`)).text()).toContain(`POST ${RANGE_TRAP_PATH}`);
    const large = await start({ weaknesses: true, hostile: "large" });
    expect((await (await fetch(`${large}/api/admin/reports`)).arrayBuffer()).byteLength).toBeGreaterThanOrEqual(
      5 * 1024 * 1024,
    );
    const secrets = await start({ weaknesses: true, hostile: "secrets" });
    const res = await fetch(`${secrets}/search?q=a`);
    expect(res.headers.get("set-cookie")).toMatch(/^session=/);
    expect(await res.text()).toMatch(/sk_live_/);
    const slow = await start({ weaknesses: true, hostile: "slow", slowMs: 120 });
    const started = Date.now();
    await (await fetch(`${slow}/`)).text();
    expect(Date.now() - started).toBeGreaterThanOrEqual(110);
  });
});
