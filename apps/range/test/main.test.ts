import { type ChildProcess, spawn } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const MAIN = fileURLToPath(new URL("../src/main.ts", import.meta.url));
/** Synthetic and well-formed. */
const KEY = `ark_dev_${"Zq9".repeat(14)}Z`;

const children: ChildProcess[] = [];
const servers: http.Server[] = [];
afterEach(async () => {
  for (const child of children.splice(0)) child.kill("SIGKILL");
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
});

/** A synthetic API: serves one signed bundle (an Enforce Rule for /api/admin/**) to the Shield key and accepts Events. */
async function fakeApi(): Promise<{ url: string; publicKey: string; policyRequests: () => string[] }> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const bundle = JSON.stringify({
    format: 1,
    audience: createHash("sha256").update(KEY, "utf8").digest("hex").slice(0, 32),
    epoch: "fedcba9876543210fedcba9876543210",
    app_id: "app_89abcdef0123456789abcdef",
    environment: "development",
    version: 1,
    issued_at: new Date().toISOString(),
    not_after: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    rules: [
      { id: "rul_0123456789abcdef01234567", path: "/api/admin/**", methods: [], action: "block", mode: "enforce" },
    ],
  });
  const body = JSON.stringify({
    bundle,
    signature: sign(null, Buffer.from(bundle, "utf8"), privateKey).toString("base64url"),
    key_id: "0123456789abcdef",
  });
  const authorizations: string[] = [];
  const server = http.createServer((req, res) => {
    req.resume();
    if (req.method === "GET" && req.url === "/v1/policy-bundle") {
      authorizations.push(String(req.headers.authorization));
      res.writeHead(200, { "content-type": "application/json", etag: '"1"' }).end(body);
      return;
    }
    res.writeHead(202, { "content-type": "application/json" }).end('{"accepted":0,"duplicates":0}');
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    publicKey: publicKey.export({ format: "jwk" }).x as string,
    policyRequests: () => authorizations,
  };
}

interface Running {
  child: ChildProcess;
  output: () => string;
  /** Resolves with the first line that matches. */
  line(pattern: RegExp): Promise<string>;
  exit: Promise<number | null>;
}

function run(env: Record<string, string>): Running {
  const child = spawn(process.execPath, ["--import", "tsx", MAIN], {
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(child);
  let output = "";
  const waiters: (() => void)[] = [];
  const onData = (chunk: Buffer): void => {
    output += chunk.toString();
    for (const waiter of waiters) waiter();
  };
  child.stdout?.on("data", onData);
  child.stderr?.on("data", onData);
  const exit = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
  return {
    child,
    output: () => output,
    exit,
    line(pattern) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no line matching ${pattern} in:\n${output}`)), 8_000);
        const check = (): void => {
          const found = output.split("\n").find((line) => pattern.test(line));
          if (found === undefined) return;
          clearTimeout(timer);
          resolve(found);
        };
        waiters.push(check);
        check();
      });
    },
  };
}

describe("ar-range main", () => {
  it("serves on HOST and PORT (0 = any free port), says whether Shield is active, never prints the key, exits on SIGTERM", async () => {
    const range = run({ AR_SHIELD_KEY: KEY, AR_API_URL: "http://127.0.0.1:9", HOST: "127.0.0.1", PORT: "0" });
    const line = await range.line(/listening/);
    const address = /http:\/\/127\.0\.0\.1:(\d+)/.exec(line);
    expect(address).not.toBeNull();
    expect(Number(address?.[1])).toBeGreaterThan(0);
    expect(line).toMatch(/Shield active/);
    expect(line).toMatch(/observes only/); // no AR_POLICY_PUBLIC_KEY
    expect(line).toMatch(/actor hashing off/);

    const health = await fetch(`${address?.[0]}/healthz`);
    expect(await health.json()).toEqual({ status: "ok" });
    expect((await fetch(`${address?.[0]}/api/products/7`)).status).toBe(200);

    const started = performance.now();
    range.child.kill("SIGTERM");
    expect(await range.exit).toBe(0);
    expect(performance.now() - started).toBeLessThan(3_000); // ingest is unreachable: shutdown does not wait for it
    expect(range.output()).not.toContain(KEY);
    expect(range.output()).not.toContain(KEY.slice(-12));
  }, 20_000);

  it("passes AR_ACTOR_KEY to Shield, says whether actor hashing is on, never prints the key; an unusable one is warned about", async () => {
    const actorKey = "ck_range_test_0123456789abcdefghijklmnopq";
    const range = run({ AR_SHIELD_KEY: KEY, AR_ACTOR_KEY: actorKey, AR_API_URL: "http://127.0.0.1:9", PORT: "0" });
    expect(await range.line(/listening/)).toMatch(/actor hashing on/);
    range.child.kill("SIGTERM");
    expect(await range.exit).toBe(0);
    expect(range.output()).not.toContain(actorKey);
    expect(range.output()).not.toMatch(/actor key .* is not usable/);

    const short = run({
      AR_SHIELD_KEY: KEY,
      AR_ACTOR_KEY: "short-actor-key",
      AR_API_URL: "http://127.0.0.1:9",
      PORT: "0",
    });
    expect(await short.line(/listening/)).toMatch(/actor hashing off/); // set, but not usable
    expect(await short.line(/actor key .* is not usable/)).not.toContain("short-actor-key");
    short.child.kill("SIGTERM");
    expect(await short.exit).toBe(0);
    expect(short.output()).not.toContain("short-actor-key");
  }, 20_000);

  it("with AR_POLICY_PUBLIC_KEY it fetches the Policy of the App and blocks what an Enforce Rule matches", async () => {
    const api = await fakeApi();
    const range = run({
      AR_SHIELD_KEY: KEY,
      AR_API_URL: api.url,
      AR_POLICY_PUBLIC_KEY: api.publicKey,
      HOST: "127.0.0.1",
      PORT: "0",
    });
    const line = await range.line(/listening/);
    expect(line).toMatch(/Shield active/);
    expect(line).not.toMatch(/observes only/);
    const base = /http:\/\/127\.0\.0\.1:\d+/.exec(line)?.[0];

    // Shield asks for the bundle shortly after it was created; nothing here waits for a poll interval.
    let status = 0;
    for (let i = 0; i < 300 && status !== 403; i++) {
      status = (await fetch(`${base}/api/admin/reports`)).status;
      if (status !== 403) await sleep(10);
    }
    expect(status).toBe(403);
    const blocked = await fetch(`${base}/api/admin/reports`);
    expect(blocked.headers.get("content-type")).toBe("application/json");
    expect(await blocked.text()).toBe('{"error":"request_blocked"}');
    expect((await fetch(`${base}/api/products/7`)).status).toBe(200);
    expect(api.policyRequests()[0]).toBe(`Bearer ${KEY}`);

    range.child.kill("SIGTERM");
    expect(await range.exit).toBe(0);
    expect(range.output()).not.toContain(KEY);
    expect(range.output()).not.toContain(api.publicKey);
  }, 20_000);

  it("runs without a key: Shield is reported as disabled and the server still answers", async () => {
    const range = run({ PORT: "0" });
    const line = await range.line(/listening/);
    expect(line).toMatch(/Shield disabled/);
    const address = /http:\/\/127\.0\.0\.1:(\d+)/.exec(line);
    expect((await fetch(`${address?.[0]}/api/login`, { method: "POST" })).status).toBe(401);
    range.child.kill("SIGINT");
    expect(await range.exit).toBe(0);
  }, 20_000);
});
