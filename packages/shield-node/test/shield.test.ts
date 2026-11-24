import { spawn } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { sep } from "node:path";
import { fileURLToPath } from "node:url";
import { SHIELD_KEY_PATTERN } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createShield, SDK_NAME, SDK_VERSION, type ShieldConfig, type Transport } from "../src/index.ts";
import { SHIELD_KEY_FORMAT } from "../src/shield.ts";

const KEY = generateKey("shield", "development").key;
const ENDPOINT = "http://127.0.0.1:8787";

function capture() {
  const warnings: string[] = [];
  const sent: Parameters<Transport>[0][] = [];
  const transport: Transport = async (request) => {
    sent.push(request);
    return { status: 202 };
  };
  return { warnings, sent, transport, logger: { warn: (message: string) => void warnings.push(message) } };
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("createShield: a usable configuration", () => {
  it.each(["production", "staging", "development"] as const)("accepts a %s Shield key", async (environment) => {
    const { warnings, logger, transport } = capture();
    const shield = createShield({ key: generateKey("shield", environment).key, endpoint: ENDPOINT, logger, transport });
    expect(shield.stats()).toEqual({
      buffered: 0,
      sent: 0,
      dropped: 0,
      failedBatches: 0,
      internalErrors: 0,
      disabledReason: null,
      lastError: null,
      policyVersion: 0,
      policyStale: false,
      policyRules: 0,
      lastPolicyError: null,
      actorHashing: false,
      inventory: "pending",
    });
    // Without a policyPublicKey Shield says once that it observes only; nothing else is logged.
    expect(warnings).toEqual([expect.stringMatching(/observes only/)]);
    await shield.close();
  });

  it("decides synchronously: allow, in Monitor mode", async () => {
    const { logger, transport } = capture();
    const shield = createShield({ key: KEY, endpoint: ENDPOINT, logger, transport });
    const decision: unknown = shield.decide({ method: "GET", path: "/api/products/42" });
    expect(decision).not.toBeInstanceOf(Promise);
    expect(decision).toEqual({ action: "allow", mode: "monitor", ruleId: null, policyVersion: 0 });
    await shield.close();
  });

  it("flush() and close() resolve with nothing buffered and create no timer", async () => {
    vi.useFakeTimers();
    try {
      const { logger, transport, sent } = capture();
      // The inventory's start timer is the subject of the next test.
      const shield = createShield({ key: KEY, endpoint: ENDPOINT, logger, transport, inventory: false });
      expect(vi.getTimerCount()).toBe(0);
      await expect(shield.flush()).resolves.toBeUndefined();
      await expect(shield.close()).resolves.toBeUndefined();
      await expect(shield.close()).resolves.toBeUndefined();
      expect(vi.getTimerCount()).toBe(0);
      expect(sent).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("with the inventory on, the one timer is the inventory's unref'd start, and close() clears it", async () => {
    vi.useFakeTimers();
    try {
      const { logger, transport, sent } = capture();
      const spy = vi.spyOn(globalThis, "setTimeout");
      const shield = createShield({ key: KEY, endpoint: ENDPOINT, logger, transport });
      expect(vi.getTimerCount()).toBe(1);
      const timer = spy.mock.results[0]?.value as NodeJS.Timeout;
      expect(timer.hasRef()).toBe(false);
      await expect(shield.close()).resolves.toBeUndefined();
      expect(vi.getTimerCount()).toBe(0);
      await vi.advanceTimersByTimeAsync(600_000);
      expect(sent).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("validates the key with the protocol's Shield key format, without importing the protocol at run time", () => {
    expect(SHIELD_KEY_FORMAT.source).toBe(SHIELD_KEY_PATTERN.source);
    expect(SHIELD_KEY_FORMAT.flags).toBe(SHIELD_KEY_PATTERN.flags);
  });

  it("reports the name and version of its own package", () => {
    const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      name: string;
      version: string;
      dependencies?: Record<string, string>;
    };
    expect(manifest.name).toBe(`@antireverse/${SDK_NAME}`);
    expect(SDK_VERSION).toBe(manifest.version);
    expect(manifest.dependencies ?? {}).toEqual({}); // zero runtime dependencies
  });

  it("imports nothing at run time but Node built-ins and its own modules: the protocol is imported as types only", () => {
    const root = new URL("../src/", import.meta.url);
    const files = readdirSync(root, { recursive: true, encoding: "utf8" }).filter((name) => name.endsWith(".ts"));
    expect(files).toContain("policy/verify.ts".replaceAll("/", sep));
    const offending: string[] = [];
    for (const file of files) {
      const source = readFileSync(new URL(file.replaceAll(sep, "/"), root), "utf8");
      for (const match of source.matchAll(/^\s*(import|export)\b([^;]*?)\bfrom\s+"([^"]+)"/gm)) {
        const [, , clause, specifier] = match as unknown as [string, string, string, string];
        const typeOnly = /^\s+type\b/.test(clause);
        if (specifier.startsWith("node:") || specifier.startsWith("./") || specifier.startsWith("../")) continue;
        if (!typeOnly) offending.push(`${file}: ${specifier}`);
      }
      expect(source, file).not.toMatch(/\b(require|import)\s*\(/); // no dynamic way around it
    }
    expect(offending).toEqual([]);
  });
});

describe("createShield: a disabled Shield", () => {
  const adminKey = generateKey("admin").key;
  const cases: [string, () => Partial<ShieldConfig> | undefined | null][] = [
    ["no key", () => ({ key: undefined as unknown as string })],
    ["an empty key", () => ({ key: "" })],
    ["a key that is not a string", () => ({ key: 42 as unknown as string })],
    ["a truncated key", () => ({ key: KEY.slice(0, -1) })],
    ["a key with an unknown Environment tag", () => ({ key: `ark_xxx_${"A".repeat(43)}` })],
    ["an admin key", () => ({ key: adminKey })],
    ["a key with surrounding whitespace", () => ({ key: ` ${KEY}\n` })],
    ["disabled: true", () => ({ disabled: true })],
    ["an endpoint that is not a URL", () => ({ endpoint: "not a url" })],
    ["an endpoint that is not http(s)", () => ({ endpoint: "ftp://ingest.test" })],
    ["no endpoint", () => ({ endpoint: undefined as unknown as string })],
    ["no configuration at all", () => undefined],
    ["a null configuration", () => null],
  ];

  it.each(cases)("%s: never throws, sets disabledReason, logs one warning, records nothing", async (_name, make) => {
    const { warnings, logger, transport, sent } = capture();
    const override = make();
    const config = override == null ? override : { key: KEY, endpoint: ENDPOINT, logger, transport, ...override };
    const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const shield = createShield(config as ShieldConfig);

    expect(shield.stats().disabledReason).toEqual(expect.any(String));
    expect(shield.stats().disabledReason).not.toBe("");
    const lines = override == null ? consoleWarn.mock.calls.map((call) => String(call[0])) : warnings;
    expect(lines).toHaveLength(1);
    for (const secret of [KEY, KEY.slice(0, -1), adminKey]) expect(lines[0]).not.toContain(secret);

    // The middleware of a disabled Shield only calls next().
    let nexts = 0;
    const touched: string[] = [];
    const request = new Proxy({}, { get: (_t, name) => void touched.push(String(name)) });
    const response = new Proxy({}, { get: (_t, name) => void touched.push(String(name)) });
    shield.express()(request as never, response as never, () => {
      nexts += 1;
    });
    expect(nexts).toBe(1);
    expect(touched).toEqual([]);

    expect(shield.decide({ method: "GET", path: "/" })).toEqual({
      action: "allow",
      mode: "monitor",
      ruleId: null,
      policyVersion: 0,
    });
    await expect(shield.flush()).resolves.toBeUndefined();
    await expect(shield.close()).resolves.toBeUndefined();
    expect(sent).toEqual([]);
    expect(shield.stats()).toMatchObject({ buffered: 0, sent: 0, dropped: 0, failedBatches: 0, internalErrors: 0 });
    expect(lines).toHaveLength(1);
  });

  it("is disabled by AR_SHIELD_DISABLED=1, and an explicit disabled: false wins over the variable", async () => {
    vi.stubEnv("AR_SHIELD_DISABLED", "1");
    const first = capture();
    const disabled = createShield({ key: KEY, endpoint: ENDPOINT, logger: first.logger, transport: first.transport });
    expect(disabled.stats().disabledReason).toContain("AR_SHIELD_DISABLED");
    expect(first.warnings).toHaveLength(1);

    const second = capture();
    const enabled = createShield({
      key: KEY,
      endpoint: ENDPOINT,
      disabled: false,
      logger: second.logger,
      transport: second.transport,
    });
    expect(enabled.stats().disabledReason).toBeNull();
    expect(second.warnings).toEqual([expect.stringMatching(/observes only/)]); // nothing about being disabled
    await enabled.close();

    vi.stubEnv("AR_SHIELD_DISABLED", "0");
    const third = capture();
    const other = createShield({ key: KEY, endpoint: ENDPOINT, logger: third.logger, transport: third.transport });
    expect(other.stats().disabledReason).toBeNull();
    await other.close();
  });

  it("survives a logger that throws", () => {
    const logger = {
      warn: () => {
        throw new Error("logger exploded");
      },
    };
    expect(() => createShield({ key: "", endpoint: ENDPOINT, logger })).not.toThrow();
    expect(createShield({ key: "", endpoint: ENDPOINT, logger }).stats().disabledReason).toEqual(expect.any(String));
  });

  it("falls back to the defaults for nonsense numbers instead of failing", async () => {
    const { warnings, logger, transport } = capture();
    const shield = createShield({
      key: KEY,
      endpoint: ENDPOINT,
      logger,
      transport,
      flushIntervalMs: Number.NaN,
      maxBatchSize: -5,
      maxBufferSize: 0,
      requestTimeoutMs: Number.POSITIVE_INFINITY,
      policyPollIntervalMs: Number.NaN,
    });
    expect(shield.stats().disabledReason).toBeNull();
    expect(warnings).toEqual([expect.stringMatching(/observes only/)]);
    await shield.close();
  });
});

describe("Shield never keeps the process alive", () => {
  const fixture = fileURLToPath(new URL("./fixtures/exit.mjs", import.meta.url));

  async function silentServer(): Promise<{ endpoint: string; requests: () => number; stop: () => Promise<void> }> {
    let requests = 0;
    const server = http.createServer(() => {
      requests += 1; // never answers
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return {
      endpoint: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
      requests: () => requests,
      stop: () =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        }),
    };
  }

  function run(mode: string, endpoint: string): Promise<{ code: number | null; ms: number; out: string; err: string }> {
    return new Promise((resolve, reject) => {
      const started = performance.now();
      // On the compiled output (slice 23) the fixture imports the compiled files: plain node, no type stripping.
      const flags = process.env.AR_SDK_COMPILED_ROOT ? [] : ["--experimental-strip-types", "--no-warnings"];
      const child = spawn(process.execPath, [...flags, fixture, mode, endpoint], {
        env: { ...process.env, AR_SHIELD_DISABLED: "" },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let out = "";
      let err = "";
      child.stdout.on("data", (chunk: Buffer) => {
        out += chunk.toString();
      });
      child.stderr.on("data", (chunk: Buffer) => {
        err += chunk.toString();
      });
      const guard = setTimeout(() => child.kill("SIGKILL"), 10_000);
      child.on("error", reject);
      child.on("close", (code) => {
        clearTimeout(guard);
        resolve({ code, ms: performance.now() - started, out, err });
      });
    });
  }

  it.each(["emitter", "shield"])(
    "a child process (%s) with a flush in flight against a silent ingest exits with code 0 within 2 s",
    async (mode) => {
      const ingest = await silentServer();
      try {
        const result = await run(mode, ingest.endpoint);
        expect(result.err).toBe("");
        expect(result.code).toBe(0);
        expect(result.ms).toBeLessThan(2_000);
        // the flush had started: the Event left the buffer and the request reached the silent server
        expect(JSON.parse(result.out)).toMatchObject({ buffered: 0, sent: 0 });
        expect(ingest.requests()).toBe(1);
      } finally {
        await ingest.stop();
      }
    },
    15_000,
  );

  it("a child process with a Policy request in flight against a silent API and the poll timer armed exits with code 0 within 2 s", async () => {
    const api = await silentServer();
    try {
      const result = await run("policy", api.endpoint);
      expect(result.err).toBe("");
      expect(result.code).toBe(0);
      expect(result.ms).toBeLessThan(2_000);
      expect(JSON.parse(result.out)).toMatchObject({ policyVersion: 0, policyRules: 0, lastPolicyError: null });
      expect(api.requests()).toBe(1); // the Policy request reached the silent server and was never answered
    } finally {
      await api.stop();
    }
  }, 15_000);
});
