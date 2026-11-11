// The runtime component inventory through the public API of Shield: options, timing, stats, request path, logs.
// Real timers: the lockfile is read from disk, which fake timers cannot wait for.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { InventorySchema } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createShield, type Shield, type ShieldConfig, type Transport } from "../src/index.ts";
import { INVENTORY_FALLBACK_MS, INVENTORY_START_DELAY_MS } from "../src/inventory.ts";
import { listen } from "./helpers.ts";
import { createSigner, payload, signed } from "./policy-helpers.ts";

const KEY = generateKey("shield", "development").key;
const signer = createSigner();
const LOCKFILE = readFileSync(new URL("./fixtures/lockfiles/v3.json", import.meta.url), "utf8");
const NAMES = ["example-parser", "@example/ui", "JSONStream", "example-test-runner", "example-real"];

type Sent = Parameters<Transport>[0];
const isInventory = (request: Sent): boolean => request.url.endsWith("/v1/inventory");

let root: string;
const shields: Shield[] = [];

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "shield-inventory-"));
  writeFileSync(join(root, "package-lock.json"), LOCKFILE);
});

afterEach(async () => {
  await Promise.all(shields.splice(0).map((shield) => shield.close()));
  rmSync(root, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

interface Options {
  /** The status of the policy endpoint; 200 serves a valid bundle. */
  policyStatus?: number;
  /** What the inventory endpoint answers, or a promise that never settles. */
  inventory?: () => Promise<{ status: number }>;
}

function harness(config: Partial<ShieldConfig> = {}, options: Options = {}) {
  const sent: Sent[] = [];
  const warnings: string[] = [];
  let policyStatus = options.policyStatus ?? 200;
  const bundle = JSON.stringify(
    signed(signer, payload(KEY, { version: 1, rules: [], issued_at: new Date().toISOString() })),
  );
  const transport: Transport = async (request) => {
    sent.push(request);
    if (request.method === "GET") {
      return policyStatus === 200 ? { status: 200, body: bundle, etag: '"b1"' } : { status: policyStatus, body: "" };
    }
    if (isInventory(request) && options.inventory !== undefined) return options.inventory();
    return { status: 202 };
  };
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport,
    projectRoot: root,
    logger: { warn: (message) => void warnings.push(message) },
    ...config,
  });
  shields.push(shield);
  return {
    shield,
    sent,
    warnings,
    inventories: () => sent.filter(isInventory),
    setPolicyStatus(status: number) {
      policyStatus = status;
    },
  };
}

async function until(condition: () => boolean, ms = 3_000): Promise<void> {
  for (let waited = 0; waited < ms && !condition(); waited += 10) await sleep(10);
}

describe("the inventory option", () => {
  it("is on by default: stats() says pending until it was sent, then sent", async () => {
    const { shield, inventories } = harness({ policyPublicKey: signer.publicKey });
    expect(shield.stats().inventory).toBe("pending");
    await until(() => shield.stats().inventory === "sent");
    expect(shield.stats().inventory).toBe("sent");
    expect(inventories()).toHaveLength(1);
  });

  it("inventory: false turns it off", async () => {
    const { shield, inventories } = harness({ policyPublicKey: signer.publicKey, inventory: false });
    expect(shield.stats().inventory).toBe("off");
    await sleep(400);
    expect(inventories()).toHaveLength(0);
  });

  it("AR_SHIELD_INVENTORY=0 turns it off", async () => {
    vi.stubEnv("AR_SHIELD_INVENTORY", "0");
    const { shield, inventories } = harness({ policyPublicKey: signer.publicKey });
    expect(shield.stats().inventory).toBe("off");
    await sleep(400);
    expect(inventories()).toHaveLength(0);
  });

  it("the option wins over the environment", async () => {
    vi.stubEnv("AR_SHIELD_INVENTORY", "0");
    const { shield } = harness({ policyPublicKey: signer.publicKey, inventory: true });
    expect(shield.stats().inventory).toBe("pending");
    await until(() => shield.stats().inventory === "sent");
    expect(shield.stats().inventory).toBe("sent");

    vi.stubEnv("AR_SHIELD_INVENTORY", "1");
    expect(harness({ policyPublicKey: signer.publicKey, inventory: false }).shield.stats().inventory).toBe("off");
  });

  it("a disabled Shield reports off and reads nothing", () => {
    const shield = createShield({ key: "", endpoint: "http://api.test", logger: { warn: () => {} } });
    expect(shield.stats().inventory).toBe("off");
  });
});

describe("when the inventory is sent", () => {
  it("after the first successful Policy fetch, with the components of the lockfile and the Shield key", async () => {
    const { shield, sent, inventories } = harness({ policyPublicKey: signer.publicKey });
    await until(() => inventories().length > 0);
    const index = sent.findIndex(isInventory);
    expect(sent.slice(0, index).some((request) => request.method === "GET")).toBe(true);
    const request = inventories()[0] as Sent;
    expect(request).toMatchObject({
      method: "POST",
      url: "http://api.test/v1/inventory",
      headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
    });
    const body = InventorySchema.parse(JSON.parse(request.body ?? ""));
    expect(body.components.map((c) => c.name)).toEqual(expect.arrayContaining(NAMES));
    expect(body.components).toContainEqual({ name: "example-test-runner", version: "9.1.0", dev: true });
    await until(() => shield.stats().inventory === "sent");
  });

  it("not while the Policy cannot be fetched", async () => {
    const { shield, inventories, setPolicyStatus } = harness(
      { policyPublicKey: signer.publicKey },
      { policyStatus: 503 },
    );
    await sleep(INVENTORY_START_DELAY_MS + 300);
    expect(inventories()).toHaveLength(0);
    expect(shield.stats().inventory).toBe("pending");
    setPolicyStatus(200);
    await shield.refreshPolicy();
    await until(() => inventories().length > 0);
    expect(inventories()).toHaveLength(1);
  });

  it("shortly after start when no Policy is fetched (observe only)", async () => {
    const { inventories } = harness();
    await sleep(INVENTORY_START_DELAY_MS / 2);
    expect(inventories()).toHaveLength(0);
    await until(() => inventories().length > 0, INVENTORY_START_DELAY_MS + 2_000);
    expect(inventories()).toHaveLength(1);
  });

  it("once only, however many Policy fetches follow", async () => {
    const { shield, inventories } = harness({ policyPublicKey: signer.publicKey, policyPollIntervalMs: 100 });
    await until(() => inventories().length > 0);
    await shield.refreshPolicy();
    await shield.refreshPolicy();
    await sleep(400);
    expect(inventories()).toHaveLength(1);
  });

  it("close() before the start sends nothing", async () => {
    const { shield, inventories } = harness();
    await shield.close();
    await sleep(INVENTORY_START_DELAY_MS + 300);
    expect(inventories()).toHaveLength(0);
  });
});

describe("the fallback when no Policy fetch succeeds", () => {
  // Only setTimeout is faked: the lockfile is read from disk, and readInventory yields with setImmediate.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.spyOn(Math, "random").mockReturnValue(0);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  /** Lets real I/O finish without moving the fake clock. */
  async function settle(condition: () => boolean): Promise<void> {
    for (let i = 0; i < 5_000 && !condition(); i++) await new Promise<void>((resolve) => setImmediate(resolve));
  }

  it("sends the inventory 60 s after start when no fetch has succeeded", async () => {
    const { shield, inventories } = harness({ policyPublicKey: signer.publicKey }, { policyStatus: 503 });
    expect(INVENTORY_FALLBACK_MS).toBe(60_000);
    await vi.advanceTimersByTimeAsync(INVENTORY_FALLBACK_MS - 1);
    await settle(() => false);
    expect(inventories()).toHaveLength(0);
    expect(shield.stats().inventory).toBe("pending");
    await vi.advanceTimersByTimeAsync(1);
    await settle(() => inventories().length > 0);
    expect(inventories()).toHaveLength(1);
    expect(InventorySchema.safeParse(JSON.parse(inventories()[0]?.body ?? "")).success).toBe(true);
    await settle(() => shield.stats().inventory === "sent");
    expect(shield.stats().inventory).toBe("sent");
    await vi.advanceTimersByTimeAsync(600_000);
    await settle(() => false);
    expect(inventories()).toHaveLength(1);
  });

  it("a fetch that succeeds at 2 s sends it then; the fallback does nothing", async () => {
    const { shield, inventories, setPolicyStatus } = harness(
      { policyPublicKey: signer.publicKey },
      { policyStatus: 503 },
    );
    await vi.advanceTimersByTimeAsync(2_000);
    expect(inventories()).toHaveLength(0);
    setPolicyStatus(200);
    await shield.refreshPolicy();
    await settle(() => inventories().length > 0);
    expect(inventories()).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(INVENTORY_FALLBACK_MS * 2);
    await settle(() => false);
    expect(inventories()).toHaveLength(1);
  });

  it("close() before 60 s: nothing is sent and no inventory timer is left", async () => {
    const { shield, inventories } = harness({ policyPublicKey: signer.publicKey }, { policyStatus: 503 });
    await vi.advanceTimersByTimeAsync(30_000);
    await shield.close();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(INVENTORY_FALLBACK_MS * 2);
    await settle(() => false);
    expect(inventories()).toHaveLength(0);
  });
});

describe("the inventory and the application", () => {
  it("is never on the request path: requests are served while the inventory hangs", async () => {
    const { shield, inventories } = harness(
      { policyPublicKey: signer.publicKey },
      { inventory: () => new Promise(() => {}) },
    );
    const app = express();
    app.use(shield.express());
    app.get("/api/products/:id", (req, res) => void res.json({ id: req.params.id }));
    const server = await listen(app);
    try {
      await until(() => inventories().length > 0);
      expect(shield.stats().inventory).toBe("pending");
      for (let i = 0; i < 5; i++) {
        const response = await fetch(`${server.base}/api/products/${i}`);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ id: String(i) });
      }
      expect(shield.stats().inventory).toBe("pending");
    } finally {
      await server.stop();
    }
  });

  it("without a lockfile: one warning line, no package names, failed", async () => {
    rmSync(join(root, "package-lock.json"));
    const { shield, warnings, inventories } = harness({ policyPublicKey: signer.publicKey });
    await until(() => shield.stats().inventory === "failed");
    expect(shield.stats().inventory).toBe("failed");
    expect(inventories()).toHaveLength(0);
    expect(warnings.filter((line) => /inventory/.test(line))).toEqual([
      "[shield] component inventory skipped: no readable lockfile",
    ]);
  });

  it("never logs a package name when the API refuses the inventory", async () => {
    const { shield, warnings } = harness(
      { policyPublicKey: signer.publicKey },
      { inventory: async () => ({ status: 400 }) },
    );
    await until(() => shield.stats().inventory === "failed");
    expect(shield.stats().inventory).toBe("failed");
    expect(warnings.some((line) => /inventory/.test(line))).toBe(true);
    for (const line of warnings) for (const name of NAMES) expect(line).not.toContain(name);
  });
});
