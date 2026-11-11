import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ATTESTATION_PATTERNS, AttestRequestSchema } from "../../protocol/src/index.ts";
import { jwkThumbprint, verifyAttestationToken } from "../../protocol/src/server.ts";
import { createGuard, type GuardFetch, type GuardOptions } from "../src/index.js";
import {
  APP_ID,
  ATTEST_URL,
  CHALLENGE_URL,
  cleanNavigator,
  ENDPOINT,
  fakeService,
  KEYS,
  memoryStorage,
  response,
  spyCrypto,
  throwingStorage,
} from "./helpers.ts";

function setup(overrides: Partial<GuardOptions> = {}) {
  const service = fakeService();
  const spy = spyCrypto();
  const storage = memoryStorage();
  const guard = createGuard({
    appId: APP_ID,
    endpoint: ENDPOINT,
    fetch: service.fetch,
    crypto: spy.crypto,
    storage,
    navigator: cleanNavigator(),
    ...overrides,
  });
  return { guard, service, spy, storage };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("attest flow", () => {
  it("runs challenge then attest with the exact URLs, bodies and fetch options, and keeps the token", async () => {
    const { guard, service, storage } = setup();
    const token = await guard.attest();
    guard.stop();

    expect(token).toEqual(expect.any(String));
    expect(service.requests.map((request) => request.url)).toEqual([CHALLENGE_URL, ATTEST_URL]);
    for (const request of service.requests) {
      expect(request.init).toEqual({
        method: "POST",
        headers: { "content-type": "application/json" },
        body: expect.any(String),
        credentials: "omit",
        signal: expect.any(AbortSignal),
      });
    }
    expect(service.requests[0]?.body).toEqual({ app_id: APP_ID });
    const attest = service.requests[1]?.body as Record<string, unknown>;
    expect(Object.keys(attest).sort()).toEqual(["app_id", "cnf", "device", "nonce", "signals"]);
    expect(attest).toEqual({
      app_id: APP_ID,
      nonce: "00000000000000000000000000000001",
      device: storage.data.get("ar.device"),
      signals: [],
      cnf: {
        jkt: expect.stringMatching(ATTESTATION_PATTERNS.jkt),
        jwk: {
          kty: "EC",
          crv: "P-256",
          x: expect.stringMatching(ATTESTATION_PATTERNS.coordinate),
          y: expect.stringMatching(ATTESTATION_PATTERNS.coordinate),
        },
      },
    });
    expect(AttestRequestSchema.safeParse(attest).success).toBe(true);

    expect(guard.token()).toBe(token);
    expect(guard.headers()).toEqual({ "ar-attestation": token });
    const verified = verifyAttestationToken(token ?? "", KEYS, { appId: APP_ID, nowS: Math.floor(Date.now() / 1000) });
    expect(verified.status).toBe("valid");
  });

  it("accepts an endpoint with a trailing slash", async () => {
    const { guard, service } = setup({ endpoint: `${ENDPOINT}/` });
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
    expect(service.requests.map((request) => request.url)).toEqual([CHALLENGE_URL, ATTEST_URL]);
  });

  it("sends the signal ids the navigator shows, never their values", async () => {
    const { guard, service } = setup({ navigator: cleanNavigator({ webdriver: true }) });
    expect(guard.signals()).toEqual(["automation.webdriver"]);
    await guard.attest();
    guard.stop();
    const body = service.requests[1]?.body as { signals: unknown };
    expect(body.signals).toEqual(["automation.webdriver"]);
    expect(JSON.stringify(service.requests.map((request) => request.body))).not.toContain("Mozilla");
  });

  it("headers() and token() are empty before the first attest", () => {
    const { guard } = setup();
    expect(guard.token()).toBeNull();
    expect(guard.headers()).toEqual({});
  });

  it("is lazy: creating a Guard sends nothing", () => {
    const { service, spy } = setup();
    expect(service.fetch).not.toHaveBeenCalled();
    expect(spy.generateKey).not.toHaveBeenCalled();
  });
});

describe("session key", () => {
  it("is a non-extractable ECDSA P-256 signing key", async () => {
    const { guard, spy } = setup();
    await guard.attest();
    guard.stop();
    expect(spy.generateKey).toHaveBeenCalledTimes(1);
    expect(spy.generateKey).toHaveBeenCalledWith({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    expect(spy.pairs[0]?.privateKey.extractable).toBe(false);
  });

  it("binds the token by the RFC 7638 thumbprint of the public key, equal to the protocol's", async () => {
    const { guard, service, spy } = setup();
    await guard.attest();
    guard.stop();
    const pair = spy.pairs[0];
    if (!pair) throw new Error("no key pair generated");
    const jwk = (await webcrypto.subtle.exportKey("jwk", pair.publicKey)) as { x: string; y: string };
    const expected = jwkThumbprint({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y });
    expect(service.requests[1]?.body).toMatchObject({ cnf: { jkt: expected } });
  });

  it("sends the public JWK (kty, crv, x, y only, never d) whose thumbprint is jkt, and the token carries it", async () => {
    const { guard, service, spy } = setup();
    const token = await guard.attest();
    guard.stop();
    const body = service.requests[1]?.body as {
      cnf: { jkt: string; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string } };
    };
    const cnf = body.cnf;
    expect(Object.keys(cnf).sort()).toEqual(["jkt", "jwk"]);
    expect(Object.keys(cnf.jwk).sort()).toEqual(["crv", "kty", "x", "y"]);
    expect(cnf.jwk).not.toHaveProperty("d");
    expect(jwkThumbprint(cnf.jwk)).toBe(cnf.jkt);
    const pair = spy.pairs[0];
    if (!pair) throw new Error("no key pair generated");
    const exported = (await webcrypto.subtle.exportKey("jwk", pair.publicKey)) as { x: string; y: string };
    expect(cnf.jwk).toEqual({ kty: "EC", crv: "P-256", x: exported.x, y: exported.y });
    const verified = verifyAttestationToken(token ?? "", KEYS, { appId: APP_ID, nowS: Math.floor(Date.now() / 1000) });
    if (verified.status !== "valid") throw new Error("token did not verify");
    expect(verified.claims.cnf.jwk).toEqual(cnf.jwk);
  });

  it("is kept across re-attests", async () => {
    const { guard, service, spy } = setup();
    await guard.attest();
    await guard.attest();
    guard.stop();
    expect(spy.generateKey).toHaveBeenCalledTimes(1);
    const jkts = service.requests.filter((r) => r.url === ATTEST_URL).map((r) => (r.body as { cnf: unknown }).cnf);
    expect(jkts[0]).toEqual(jkts[1]);
  });

  it("works with the real Node WebCrypto object injected as is", async () => {
    const { guard } = setup({ crypto: webcrypto as unknown as GuardOptions["crypto"] });
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
  });
});

describe("device id", () => {
  it("is 128 random bits as 22 base64url characters, persisted under ar.device and reused", async () => {
    const service = fakeService();
    const spy = spyCrypto();
    const storage = memoryStorage();
    const options = { appId: APP_ID, endpoint: ENDPOINT, fetch: service.fetch, crypto: spy.crypto, storage };
    const first = createGuard(options);
    await first.attest();
    first.stop();
    const stored = storage.data.get("ar.device");
    expect(stored).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(spy.getRandomValues.mock.calls.some(([array]) => array instanceof Uint8Array && array.length === 16)).toBe(
      true,
    );

    const second = createGuard(options);
    await second.attest();
    second.stop();
    const devices = service.requests
      .filter((r) => r.url === ATTEST_URL)
      .map((r) => (r.body as { device: unknown }).device);
    expect(devices).toEqual([stored, stored]);
  });

  it("replaces a malformed stored id", async () => {
    const storage = memoryStorage({ "ar.device": "not a device id" });
    const { guard } = setup({ storage });
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
    expect(storage.data.get("ar.device")).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("is a fresh in-memory id per Guard when storage throws, and attestation still succeeds", async () => {
    const service = fakeService();
    const options = { appId: APP_ID, endpoint: ENDPOINT, fetch: service.fetch, crypto: spyCrypto().crypto };
    const first = createGuard({ ...options, storage: throwingStorage });
    const second = createGuard({ ...options, storage: throwingStorage });
    expect(await first.attest()).not.toBeNull();
    expect(await first.attest()).not.toBeNull();
    expect(await second.attest()).not.toBeNull();
    first.stop();
    second.stop();
    const devices = service.requests
      .filter((r) => r.url === ATTEST_URL)
      .map((r) => (r.body as { device: string }).device);
    for (const device of devices) expect(device).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(devices[0]).toBe(devices[1]); // the same Guard keeps its in-memory id
    expect(devices[2]).not.toBe(devices[0]); // another Guard gets a new one
  });

  it("is in memory when storage is explicitly null", async () => {
    const { guard } = setup({ storage: null });
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
  });
});

describe("in-flight dedupe", () => {
  it("concurrent attest() calls share one handshake and one result", async () => {
    const { guard, service } = setup();
    const results = await Promise.all([guard.attest(), guard.attest(), guard.attest()]);
    guard.stop();
    expect(service.challenges()).toBe(1);
    expect(new Set(results).size).toBe(1);
    expect(results[0]).not.toBeNull();
  });

  it("a call after the handshake settled starts a new one", async () => {
    const { guard, service } = setup();
    await guard.attest();
    await guard.attest();
    guard.stop();
    expect(service.challenges()).toBe(2);
  });
});

describe("never throws", () => {
  async function expectFailure(overrides: Partial<GuardOptions>) {
    const { guard } = setup(overrides);
    const result = guard.attest();
    await expect(result).resolves.toBeNull();
    expect(guard.token()).toBeNull();
    expect(guard.headers()).toEqual({});
    guard.stop();
    return guard;
  }

  const failing = (impl: GuardFetch) => vi.fn<GuardFetch>(impl);

  it("when fetch rejects", async () => {
    await expectFailure({ fetch: failing(async () => Promise.reject(new TypeError("Failed to fetch"))) });
  });

  it("when fetch throws synchronously", async () => {
    await expectFailure({
      fetch: failing(() => {
        throw new TypeError("blocked");
      }),
    });
  });

  it("when the challenge is not 2xx", async () => {
    await expectFailure({ fetch: failing(async () => response(429, { title: "Too many requests" })) });
  });

  it("when the attest call is not 2xx", async () => {
    const service = fakeService();
    await expectFailure({
      fetch: failing(async (url, init) => (url === ATTEST_URL ? response(400, {}) : service.fetch(url, init))),
    });
  });

  it("when a response is not JSON", async () => {
    await expectFailure({
      fetch: failing(async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError("Unexpected token <");
        },
      })),
    });
  });

  it.each([
    ["null", null],
    ["an array", []],
    ["a nonce of the wrong shape", { nonce: "xyz", expires_at: "2026-11-11T00:00:00.000Z" }],
    ["no nonce", { expires_at: "2026-11-11T00:00:00.000Z" }],
  ])("when the challenge answers %s", async (_name, body) => {
    await expectFailure({ fetch: failing(async () => response(200, body)) });
  });

  it.each([
    ["no token", { expires_at: new Date(Date.now() + 300_000).toISOString() }],
    ["a token that is not a JWS", { token: "not-a-jws", expires_at: new Date(Date.now() + 300_000).toISOString() }],
    [
      "a token over 2048 characters",
      {
        token: `${"a".repeat(2000)}.${"b".repeat(40)}.${"c".repeat(86)}`,
        expires_at: new Date(Date.now() + 300_000).toISOString(),
      },
    ],
    ["no expiry", { token: "aaa.bbb.ccc" }],
    ["an expiry that is not a date", { token: "aaa.bbb.ccc", expires_at: "soon" }],
  ])("when the attest call answers %s", async (_name, body) => {
    const service = fakeService();
    await expectFailure({
      fetch: failing(async (url, init) => (url === ATTEST_URL ? response(200, body) : service.fetch(url, init))),
    });
  });

  it("when crypto.subtle is missing", async () => {
    const guard = await expectFailure({ crypto: { getRandomValues: (array) => webcrypto.getRandomValues(array) } });
    expect(guard.signals()).toEqual([]);
  });

  it("when crypto is missing entirely", async () => {
    vi.stubGlobal("crypto", undefined);
    await expectFailure({ crypto: null });
  });

  it("when key generation rejects", async () => {
    const spy = spyCrypto();
    const crypto = {
      ...spy.crypto,
      subtle: { ...spy.crypto.subtle, generateKey: async () => Promise.reject(new Error("NotSupportedError")) },
    } as GuardOptions["crypto"];
    await expectFailure({ crypto });
  });

  it("when fetch is missing", async () => {
    vi.stubGlobal("fetch", undefined);
    await expectFailure({ fetch: null });
  });

  it("when navigator is missing: no signals, and attestation still succeeds", async () => {
    const { guard, service } = setup({ navigator: null });
    expect(guard.signals()).toEqual([]);
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
    expect(service.requests[1]?.body).toMatchObject({ signals: [] });
  });

  it("when the navigator's getters throw", async () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error("getter trap");
        },
      },
    );
    const { guard } = setup({ navigator: hostile });
    expect(guard.signals()).toEqual([]);
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
  });

  it("when the options are missing or wrong", async () => {
    expect(() => createGuard(undefined as unknown as GuardOptions)).not.toThrow();
    const guard = createGuard(undefined as unknown as GuardOptions);
    await expect(guard.attest()).resolves.toBeNull();
    const noEndpoint = createGuard({ appId: APP_ID } as GuardOptions);
    await expect(noEndpoint.attest()).resolves.toBeNull();
    guard.stop();
    noEndpoint.stop();
  });

  it("when the injected clock throws or lies, falling back to Date.now", async () => {
    for (const now of [
      () => {
        throw new Error("clock");
      },
      () => Number.NaN,
    ]) {
      const { guard } = setup({ now });
      const token = await guard.attest();
      expect(token).not.toBeNull();
      expect(() => guard.headers()).not.toThrow();
      expect(guard.token()).toBe(token);
      guard.stop();
    }
  });

  it("a failed re-attest drops the previous token", async () => {
    const service = fakeService();
    let down = false;
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => {
        if (down) throw new TypeError("offline");
        return service.fetch(url, init);
      }),
    });
    expect(await guard.attest()).not.toBeNull();
    down = true;
    expect(await guard.attest()).toBeNull();
    expect(guard.token()).toBeNull();
    expect(guard.headers()).toEqual({});
    guard.stop();
  });

  it("logs nothing", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((level) => vi.spyOn(console, level));
    await expectFailure({ fetch: vi.fn<GuardFetch>(async () => Promise.reject(new Error("down"))) });
    const { guard } = setup();
    await guard.attest();
    guard.stop();
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    for (const spy of spies) spy.mockRestore();
  });
});

describe("browser defaults", () => {
  it("uses globalThis crypto, localStorage and navigator when none are injected", async () => {
    const service = fakeService();
    const storage = memoryStorage();
    vi.stubGlobal("localStorage", storage);
    vi.stubGlobal("navigator", cleanNavigator({ webdriver: true }));
    const guard = createGuard({ appId: APP_ID, endpoint: ENDPOINT, fetch: service.fetch });
    expect(guard.signals()).toEqual(["automation.webdriver"]);
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
    expect(storage.data.get("ar.device")).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("calls the global fetch with globalThis as receiver", async () => {
    const service = fakeService();
    const receivers: unknown[] = [];
    vi.stubGlobal("fetch", function (this: unknown, url: string, init: Parameters<GuardFetch>[1]) {
      receivers.push(this);
      return service.fetch(url, init);
    });
    const guard = createGuard({ appId: APP_ID, endpoint: ENDPOINT, crypto: spyCrypto().crypto, storage: null });
    expect(await guard.attest()).not.toBeNull();
    guard.stop();
    expect(receivers.length).toBe(2);
    expect(receivers.every((receiver) => receiver === globalThis)).toBe(true);
  });

  it("survives a localStorage getter that throws (sandboxed frame)", async () => {
    const service = fakeService();
    const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      get() {
        throw new Error("SecurityError");
      },
    });
    try {
      const guard = createGuard({
        appId: APP_ID,
        endpoint: ENDPOINT,
        fetch: service.fetch,
        crypto: spyCrypto().crypto,
      });
      expect(await guard.attest()).not.toBeNull();
      guard.stop();
    } finally {
      if (original) Object.defineProperty(globalThis, "localStorage", original);
      else Reflect.deleteProperty(globalThis, "localStorage");
    }
  });
});

describe("hostile options", () => {
  /** An inert Guard: everything answers "nothing" and nothing throws or goes out. */
  async function expectInert(guard: ReturnType<typeof createGuard>, fetch?: ReturnType<typeof vi.fn>) {
    await expect(guard.attest()).resolves.toBeNull();
    expect(guard.token()).toBeNull();
    expect(guard.headers()).toEqual({});
    expect(guard.signals()).toEqual([]);
    expect(() => guard.start()).not.toThrow();
    expect(() => guard.stop()).not.toThrow();
    if (fetch) expect(fetch).not.toHaveBeenCalled();
  }

  it.each(["appId", "endpoint", "storage", "now", "fetch", "crypto", "navigator"])(
    "a throwing getter on %s gives an inert Guard",
    async (key) => {
      const service = fakeService();
      vi.stubGlobal("fetch", service.fetch);
      const options: Record<string, unknown> = {
        appId: APP_ID,
        endpoint: ENDPOINT,
        fetch: service.fetch,
        crypto: spyCrypto().crypto,
        storage: memoryStorage(),
        navigator: cleanNavigator({ webdriver: true }),
        now: () => Date.now(),
      };
      Object.defineProperty(options, key, {
        enumerable: true,
        get() {
          throw new Error("boom");
        },
      });
      let guard: ReturnType<typeof createGuard> | undefined;
      expect(() => {
        guard = createGuard(options as unknown as GuardOptions);
      }).not.toThrow();
      if (!guard) throw new Error("no guard");
      await expectInert(guard, service.fetch);
    },
  );

  it("a Proxy whose every trap throws gives an inert Guard", async () => {
    const thrower = () => {
      throw new Error("px");
    };
    const options = new Proxy(
      {},
      {
        get: thrower,
        has: thrower,
        ownKeys: thrower,
        getOwnPropertyDescriptor: thrower,
        getPrototypeOf: thrower,
        defineProperty: thrower,
        set: thrower,
        deleteProperty: thrower,
        isExtensible: thrower,
        preventExtensions: thrower,
        setPrototypeOf: thrower,
      },
    );
    let guard: ReturnType<typeof createGuard> | undefined;
    expect(() => {
      guard = createGuard(options as unknown as GuardOptions);
    }).not.toThrow();
    if (!guard) throw new Error("no guard");
    await expectInert(guard);
  });

  it.each([
    ["null", null],
    ["a number", 42],
    ["a string", "app_89abcdef0123456789abcdef"],
    ["an array", [APP_ID, ENDPOINT]],
    ["a function", () => APP_ID],
  ])("options that are %s give an inert Guard", async (_name, options) => {
    const service = fakeService();
    vi.stubGlobal("fetch", service.fetch);
    let guard: ReturnType<typeof createGuard> | undefined;
    expect(() => {
      guard = createGuard(options as unknown as GuardOptions);
    }).not.toThrow();
    if (!guard) throw new Error("no guard");
    await expectInert(guard, service.fetch);
  });
});
