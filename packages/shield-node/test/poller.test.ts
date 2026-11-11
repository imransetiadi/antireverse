import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createPoller, type PollerOptions } from "../src/policy/poller.ts";
import { createPolicyStore, type PolicyStore } from "../src/policy/store.ts";
import { audienceOf, importPublicKey } from "../src/policy/verify.ts";
import { POLICY_DEFAULTS, SHIELD_DEFAULTS, type Transport } from "../src/types.ts";
import { createSigner, DAY_MS, flip, payload, rule, signed } from "./policy-helpers.ts";

const KEY = generateKey("shield", "development").key;
const OTHER_KEY = generateKey("shield", "development").key;
const ENDPOINT = "http://api.test";
const signer = createSigner();
const stranger = createSigner();

type Sent = Parameters<Transport>[0];
type Answer = Awaited<ReturnType<Transport>>;

/** A 200 response carrying a bundle of `version`, signed by the configured key. */
function bundle(version: number, etag = `"v${version}"`, overrides: Parameters<typeof payload>[1] = {}): Answer {
  return { status: 200, etag, body: JSON.stringify(signed(signer, payload(KEY, { version, ...overrides }))) };
}

interface Harness {
  poller: ReturnType<typeof createPoller>;
  store: PolicyStore;
  calls: Sent[];
  /** Milliseconds since the harness was created, at each transport call. */
  times: number[];
  /** The first message of each condition, in order: Shield prints one line per condition (createOnceLogger). */
  warnings: [condition: string, message: string][];
}

/** `respond` decides the outcome of the n-th transport call (0-based): an answer, or an Error to reject with. */
function harness(
  respond: (call: number, request: Sent) => Answer | Error | Promise<Answer>,
  overrides: Partial<PollerOptions> = {},
): Harness {
  const calls: Sent[] = [];
  const times: number[] = [];
  const warnings: [string, string][] = [];
  const t0 = Date.now();
  const store = createPolicyStore();
  const transport: Transport = async (request) => {
    const outcome = respond(calls.length, request);
    calls.push(request);
    times.push(Date.now() - t0);
    if (outcome instanceof Error) throw outcome;
    return outcome;
  };
  const publicKey = importPublicKey(signer.publicKey);
  if (publicKey === null) throw new Error("the test key could not be imported");
  const poller = createPoller({
    key: KEY,
    endpoint: ENDPOINT,
    publicKey,
    audience: audienceOf(KEY),
    intervalMs: POLICY_DEFAULTS.pollIntervalMs,
    requestTimeoutMs: SHIELD_DEFAULTS.requestTimeoutMs,
    transport,
    now: () => Date.now(),
    warn: (condition, message) => {
      if (!warnings.some(([seen]) => seen === condition)) warnings.push([condition, message]);
    },
    store,
    ...overrides,
  });
  return { poller, store, calls, times, warnings };
}

const unhandled: unknown[] = [];
const onUnhandled = (reason: unknown): void => {
  unhandled.push(reason);
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-11-10T08:00:00.000Z"));
  vi.spyOn(Math, "random").mockReturnValue(0); // no jitter unless a test asks for it
  unhandled.length = 0;
  process.on("unhandledRejection", onUnhandled);
});

afterEach(async () => {
  await vi.advanceTimersByTimeAsync(0);
  process.off("unhandledRejection", onUnhandled);
  vi.restoreAllMocks();
  vi.useRealTimers();
  expect(unhandled).toEqual([]);
});

describe("defaults", () => {
  it("are the documented Policy defaults", () => {
    expect(POLICY_DEFAULTS).toEqual({ pollIntervalMs: 5_000, responseBytesMax: 131_072 });
  });
});

describe("poller: fetching", () => {
  it("fetches nothing while it is created, and the bundle shortly afterwards", async () => {
    const { calls, store, poller } = harness(() => bundle(3));
    expect(calls).toHaveLength(0);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(99);
    expect(calls).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      method: "GET",
      url: "http://api.test/v1/policy-bundle",
      headers: { authorization: `Bearer ${KEY}`, accept: "application/json" },
      timeoutMs: 5_000,
    });
    expect(store.current().version).toBe(3);
    expect(store.current().rules.map((r) => r.path)).toEqual(["/api/admin/**"]);
    expect(poller.lastError()).toBeNull();
    poller.close();
  });

  it("joins the endpoint and the path with exactly one slash, and passes requestTimeoutMs on", async () => {
    const { calls, poller } = harness(() => bundle(1), { endpoint: "http://api.test/base/", requestTimeoutMs: 1_234 });
    await vi.advanceTimersByTimeAsync(100);
    expect(calls[0]?.url).toBe("http://api.test/base/v1/policy-bundle");
    expect(calls[0]?.timeoutMs).toBe(1_234);
    poller.close();
  });

  it("then fetches every 5,000 ms", async () => {
    const { times, poller } = harness((call) => (call === 0 ? bundle(1) : { status: 304 }));
    await vi.advanceTimersByTimeAsync(20_100);
    expect(times).toEqual([100, 5_100, 10_100, 15_100, 20_100]);
    expect(vi.getTimerCount()).toBe(1); // one timer at a time, armed after each fetch
    poller.close();
  });

  it("adds jitter to the interval, so that many Shields do not ask in step", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0.999);
    const { times, poller } = harness((call) => (call === 0 ? bundle(1) : { status: 304 }));
    await vi.advanceTimersByTimeAsync(30_000);
    const gaps = times.slice(1).map((t, i) => t - (times[i] as number));
    expect(gaps.length).toBeGreaterThanOrEqual(3);
    for (const gap of gaps) {
      expect(gap).toBeGreaterThan(5_000);
      expect(gap).toBeLessThanOrEqual(6_250);
    }
    poller.close();
  });

  it("uses the configured interval, and the default for nonsense", async () => {
    const fast = harness((call) => (call === 0 ? bundle(1) : { status: 304 }), { intervalMs: 250 });
    await vi.advanceTimersByTimeAsync(1_100);
    expect(fast.times).toEqual([100, 350, 600, 850, 1_100]);
    fast.poller.close();

    for (const intervalMs of [Number.NaN, -1, 0, Number.POSITIVE_INFINITY]) {
      const { times, poller } = harness((call) => (call === 0 ? bundle(1) : { status: 304 }), { intervalMs });
      await vi.advanceTimersByTimeAsync(10_100);
      expect(times).toEqual([100, 5_100, 10_100]);
      poller.close();
    }
  });

  it("never polls more often than every 100 ms", async () => {
    const { times, poller } = harness((call) => (call === 0 ? bundle(1) : { status: 304 }), { intervalMs: 1 });
    await vi.advanceTimersByTimeAsync(400);
    expect(times).toEqual([100, 200, 300, 400]);
    poller.close();
  });
});

describe("poller: conditional requests", () => {
  it("sends If-None-Match once it applied a bundle that came with an ETag", async () => {
    const { calls, poller } = harness((call) => (call === 0 ? bundle(1, '"abc"') : { status: 304 }));
    await vi.advanceTimersByTimeAsync(5_100);
    expect(calls[0]?.headers["if-none-match"]).toBeUndefined();
    expect(calls[1]?.headers).toEqual({
      authorization: `Bearer ${KEY}`,
      accept: "application/json",
      "if-none-match": '"abc"',
    });
    poller.close();
  });

  it("a 304 changes nothing: the same Policy stays applied and no error is reported", async () => {
    const { store, poller, warnings } = harness((call) => (call === 0 ? bundle(4) : { status: 304, body: "" }));
    await vi.advanceTimersByTimeAsync(100);
    const applied = store.current();
    await vi.advanceTimersByTimeAsync(15_000);
    expect(store.current()).toBe(applied);
    expect(poller.lastError()).toBeNull();
    expect(warnings).toEqual([]);
    poller.close();
  });

  it("applies a newer bundle and sends its ETag from then on", async () => {
    const { calls, store, poller } = harness((call) =>
      call === 0 ? bundle(1, '"one"') : call === 1 ? bundle(2, '"two"', { rules: [] }) : { status: 304 },
    );
    await vi.advanceTimersByTimeAsync(10_100);
    expect(store.current().version).toBe(2);
    expect(store.current().rules).toEqual([]);
    expect(calls.map((call) => call.headers["if-none-match"])).toEqual([undefined, '"one"', '"two"']);
    poller.close();
  });

  it("works without ETags: every answer is verified and applied again", async () => {
    const { calls, store, poller } = harness((call) => ({
      status: 200,
      body: JSON.stringify(signed(signer, payload(KEY, { version: call + 1 }))),
    }));
    await vi.advanceTimersByTimeAsync(10_100);
    expect(store.current().version).toBe(3);
    expect(calls.every((call) => call.headers["if-none-match"] === undefined)).toBe(true);
    poller.close();
  });

  it("ignores an ETag that is not a short printable header value", async () => {
    const { calls, poller } = harness((call) =>
      call === 0
        ? { ...bundle(1), etag: `"${"x".repeat(600)}"` }
        : call === 1
          ? { ...bundle(1), etag: '"a\r\nx: y"' }
          : { status: 304 },
    );
    await vi.advanceTimersByTimeAsync(10_100);
    expect(calls.map((call) => call.headers["if-none-match"])).toEqual([undefined, undefined, undefined]);
    poller.close();
  });
});

describe("poller: failures", () => {
  it("backs off while the API cannot be reached, never rejects, and warns once", async () => {
    const { times, store, poller, warnings } = harness(() => new Error("connect ECONNREFUSED 127.0.0.1:8787"));
    await vi.advanceTimersByTimeAsync(300_000);
    expect(times.slice(0, 7)).toEqual([100, 10_100, 30_100, 70_100, 130_100, 190_100, 250_100]);
    expect(store.current().version).toBe(0);
    expect(poller.lastError()).toMatch(/unreachable/);
    expect(warnings.map(([condition]) => condition)).toEqual(["policy-unreachable"]);
    poller.close();
  });

  it("adds jitter to the backoff", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0.999);
    const { times, poller } = harness(() => new Error("socket hang up"));
    await vi.advanceTimersByTimeAsync(40_000);
    const [first, second, third] = times as [number, number, number];
    expect(second - first).toBeGreaterThan(10_000);
    expect(second - first).toBeLessThanOrEqual(12_500);
    expect(third - second).toBeGreaterThan(20_000);
    expect(third - second).toBeLessThanOrEqual(25_000);
    poller.close();
  });

  it("keeps the applied Policy through an outage and returns to the interval when the API is back", async () => {
    const { times, store, poller } = harness((call) => {
      if (call === 0) return bundle(2, '"two"');
      if (call < 4) return new Error("connect ETIMEDOUT");
      return call === 4 ? bundle(3, '"three"') : { status: 304 };
    });
    await vi.advanceTimersByTimeAsync(100);
    expect(store.current().version).toBe(2);
    await vi.advanceTimersByTimeAsync(5_000 + 10_000 + 20_000);
    expect(store.current().version).toBe(2);
    expect(poller.lastError()).toMatch(/unreachable/);
    await vi.advanceTimersByTimeAsync(40_000 + 5_000 + 5_000);
    expect(times).toEqual([100, 5_100, 15_100, 35_100, 75_100, 80_100, 85_100]);
    expect(store.current().version).toBe(3);
    expect(poller.lastError()).toBeNull();
    poller.close();
  });

  it.each([500, 502, 503, 429, 404, 301, 204])("backs off after a %i and says so in lastError", async (status) => {
    const { times, poller, warnings, store } = harness(() => ({ status, body: "<html>proxy</html>" }));
    await vi.advanceTimersByTimeAsync(30_100);
    expect(times).toEqual([100, 10_100, 30_100]);
    expect(poller.lastError()).toContain(String(status));
    expect(warnings.map(([condition]) => condition)).toEqual(["policy-rejected"]);
    expect(store.current().version).toBe(0);
    poller.close();
  });

  it.each([401, 403])("after a %i asks again only after 60,000 ms, and warns once", async (status) => {
    const { times, poller, warnings, store } = harness((call) => (call < 2 ? { status } : bundle(1)));
    await vi.advanceTimersByTimeAsync(59_999 + 100);
    expect(times).toEqual([100]);
    expect(poller.lastError()).toContain(String(status));
    await vi.advanceTimersByTimeAsync(1);
    expect(times).toEqual([100, 60_100]);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(times).toEqual([100, 60_100, 120_100]);
    expect(store.current().version).toBe(1);
    expect(poller.lastError()).toBeNull();
    expect(warnings.map(([condition]) => condition)).toEqual(["policy-unauthorized"]);
    for (const [, message] of warnings) expect(message).not.toContain(KEY);
    poller.close();
  });

  it("survives a transport that throws, returns nonsense or answers without a status", async () => {
    const answers: unknown[] = [undefined, null, {}, { status: "200" }, 42];
    const { calls, poller, store } = harness((call) => answers[call % answers.length] as Answer);
    await vi.advanceTimersByTimeAsync(200_000);
    expect(calls.length).toBeGreaterThanOrEqual(4);
    expect(poller.lastError()).toEqual(expect.any(String));
    expect(store.current().version).toBe(0);
    poller.close();

    const throwing = createPoller({
      key: KEY,
      endpoint: ENDPOINT,
      publicKey: importPublicKey(signer.publicKey) as NonNullable<ReturnType<typeof importPublicKey>>,
      audience: audienceOf(KEY),
      intervalMs: 5_000,
      requestTimeoutMs: 5_000,
      transport: () => {
        throw new Error("synchronous failure");
      },
      now: () => Date.now(),
      warn: () => {
        throw new Error("logger exploded");
      },
      store: createPolicyStore(),
    });
    await vi.advanceTimersByTimeAsync(100);
    await expect(throwing.refresh()).resolves.toBeUndefined();
    expect(throwing.lastError()).toMatch(/unreachable/);
    throwing.close();
  });

  it("survives a clock that throws", async () => {
    let broken = false;
    const { poller, calls } = harness(() => ({ status: 401 }), {
      now: () => {
        if (broken) throw new Error("clock exploded");
        return Date.now();
      },
    });
    broken = true;
    await vi.advanceTimersByTimeAsync(100);
    await expect(poller.refresh()).resolves.toBeUndefined();
    expect(calls.length).toBeGreaterThanOrEqual(1);
    poller.close();
  });
});

describe("poller: a bundle that is refused", () => {
  const refusals: [name: string, answer: () => Answer, reason: string][] = [
    [
      "a flipped byte in the bundle",
      () => {
        const good = signed(signer, payload(KEY, { version: 9 }));
        return { status: 200, etag: '"bad"', body: JSON.stringify({ ...good, bundle: flip(good.bundle) }) };
      },
      "signature",
    ],
    [
      "a flipped byte in the signature",
      () => {
        const good = signed(signer, payload(KEY, { version: 9 }));
        return { status: 200, etag: '"bad"', body: JSON.stringify({ ...good, signature: flip(good.signature) }) };
      },
      "signature",
    ],
    [
      "a bundle signed by another key",
      () => ({ status: 200, etag: '"bad"', body: JSON.stringify(signed(stranger, payload(KEY, { version: 9 }))) }),
      "signature",
    ],
    [
      "the bundle of another Shield key",
      () => ({ status: 200, etag: '"bad"', body: JSON.stringify(signed(signer, payload(OTHER_KEY, { version: 9 }))) }),
      "audience",
    ],
    ["an older version", () => bundle(1, '"bad"'), "version"],
    [
      "a bundle that expired",
      () => bundle(9, '"bad"', { issued_at: new Date(Date.now() - 8 * DAY_MS).toISOString() }),
      "expired",
    ],
    ["51 Rules", () => bundle(9, '"bad"', { rules: Array.from({ length: 51 }, (_, i) => rule(i)) }), "invalid"],
    ["a malformed pattern", () => bundle(9, '"bad"', { rules: [rule(1, { path: "/a/**/b" })] }), "invalid"],
    ["a response that is not JSON", () => ({ status: 200, etag: '"bad"', body: "<html>" }), "invalid"],
    [
      "a response of 1 MB",
      () => ({ status: 200, etag: '"bad"', body: JSON.stringify({ bundle: "x".repeat(1_048_576), signature: "y" }) }),
      "invalid",
    ],
    ["a response without a body", () => ({ status: 200, etag: '"bad"' }), "invalid"],
    [
      "another format",
      () => ({
        status: 200,
        etag: '"bad"',
        body: JSON.stringify(signed(signer, { ...payload(KEY, { version: 9 }), format: 2 })),
      }),
      "format",
    ],
  ];

  it.each(refusals)(
    "%s: the previous Policy stays applied, the cause is reported once, and Shield backs off",
    async (_name, answer, reason) => {
      const { calls, times, store, poller, warnings } = harness((call) =>
        call === 0 ? bundle(2, '"good"') : answer(),
      );
      await vi.advanceTimersByTimeAsync(100);
      const applied = store.current();
      expect(applied.version).toBe(2);

      await vi.advanceTimersByTimeAsync(5_000 + 10_000 + 20_000);
      expect(times).toEqual([100, 5_100, 15_100, 35_100]);
      expect(store.current()).toBe(applied);
      expect(poller.lastError()).toContain(`Policy refused (${reason})`);
      expect(warnings.map(([condition]) => condition)).toEqual([`policy-refused-${reason}`]);
      for (const [, message] of warnings) {
        expect(message).not.toContain(KEY);
        expect(message).not.toContain(signer.publicKey);
        expect(message).toMatch(/last valid Policy|version 2/);
      }
      // The ETag of a refused answer is not remembered: Shield keeps asking with the ETag of what it applied.
      expect(calls.slice(1).map((call) => call.headers["if-none-match"])).toEqual(['"good"', '"good"', '"good"']);
      poller.close();
    },
  );

  it("reports distinct causes distinctly, one warning each", async () => {
    const order = [
      "a flipped byte in the bundle",
      "the bundle of another Shield key",
      "an older version",
      "a bundle that expired",
      "51 Rules",
      "a response that is not JSON",
      "a response of 1 MB",
      "another format",
    ];
    const answers = order.map((name) => refusals.find((entry) => entry[0] === name)?.[1] as () => Answer);
    const { store, poller, warnings } = harness((call) =>
      call === 0 ? bundle(2) : (answers[call - 1] as () => Answer)(),
    );
    await vi.advanceTimersByTimeAsync(100);
    const errors: (string | null)[] = [];
    for (let i = 0; i < answers.length; i++) {
      await poller.refresh();
      errors.push(poller.lastError());
    }
    expect(new Set(errors).size).toBe(answers.length);
    expect(errors.every((error) => typeof error === "string" && error.startsWith("Policy refused"))).toBe(true);
    expect(store.current().version).toBe(2);
    expect(warnings.map(([condition]) => condition)).toEqual([
      "policy-refused-signature",
      "policy-refused-audience",
      "policy-refused-version",
      "policy-refused-expired",
      "policy-refused-invalid",
      "policy-refused-format",
    ]);
    poller.close();
  });

  it("applies a valid bundle again after a refused one and clears the error", async () => {
    const { store, poller } = harness((call) =>
      call === 0 ? { status: 200, body: "nonsense" } : call === 1 ? bundle(6) : { status: 304 },
    );
    await vi.advanceTimersByTimeAsync(100);
    expect(poller.lastError()).toContain("Policy refused (invalid)");
    await vi.advanceTimersByTimeAsync(10_000);
    expect(store.current().version).toBe(6);
    expect(poller.lastError()).toBeNull();
    poller.close();
  });
});

describe("poller: refresh() and close()", () => {
  it("refresh() fetches at once and resolves when the answer is applied", async () => {
    const { calls, store, poller, times } = harness((call) => bundle(call + 1));
    await poller.refresh();
    expect(calls).toHaveLength(1);
    expect(times).toEqual([0]);
    expect(store.current().version).toBe(1);
    await poller.refresh();
    expect(store.current().version).toBe(2);
    // the timer starts again from the refresh
    await vi.advanceTimersByTimeAsync(4_999);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(3);
    poller.close();
  });

  it("refresh() ignores a backoff and the pause after a 401", async () => {
    const { calls, poller, store } = harness((call) => (call === 0 ? { status: 401 } : bundle(1)));
    await vi.advanceTimersByTimeAsync(100);
    expect(calls).toHaveLength(1);
    await poller.refresh();
    expect(calls).toHaveLength(2);
    expect(store.current().version).toBe(1);
    poller.close();
  });

  it("refresh() during a fetch waits for it and then fetches once more: its answer was requested after the call", async () => {
    const releases: ((answer: Answer) => void)[] = [];
    const { calls, store, poller } = harness(() => new Promise<Answer>((resolve) => releases.push(resolve)));
    await vi.advanceTimersByTimeAsync(100);
    expect(calls).toHaveLength(1); // the scheduled fetch is in flight
    let settled = 0;
    const first = poller.refresh().then(() => {
      settled += 1;
    });
    const second = poller.refresh().then(() => {
      settled += 1;
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toHaveLength(1);
    releases[0]?.(bundle(1));
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toHaveLength(2); // one follow-up fetch for both callers
    expect(settled).toBe(0);
    releases[1]?.(bundle(2));
    await Promise.all([first, second]);
    expect(store.current().version).toBe(2);
    expect(calls).toHaveLength(2);
    poller.close();
  });

  it("refresh() never rejects", async () => {
    const { poller } = harness(() => new Error("connect ECONNREFUSED"));
    await expect(poller.refresh()).resolves.toBeUndefined();
    await expect(poller.refresh()).resolves.toBeUndefined();
    poller.close();
  });

  it("close() stops the timer; afterwards nothing is fetched, not even by refresh()", async () => {
    const { calls, poller } = harness(() => bundle(1));
    expect(vi.getTimerCount()).toBe(1);
    poller.close();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(poller.refresh()).resolves.toBeUndefined();
    expect(calls).toHaveLength(0);
    poller.close(); // twice is fine
  });

  it("a request that fails because Shield was closed meanwhile is not reported: no error, no warning", async () => {
    const failures: ((error: Error) => void)[] = [];
    const { poller, warnings } = harness(() => new Promise<never>((_resolve, reject) => failures.push(reject)));
    await vi.advanceTimersByTimeAsync(100);
    poller.close(); // closing Shield drops its connections: the request in flight ends with an error
    failures[0]?.(Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }));
    await vi.advanceTimersByTimeAsync(0);
    expect(poller.lastError()).toBeNull();
    expect(warnings).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("an answer that arrives after close() is not applied and arms no timer", async () => {
    const releases: ((answer: Answer) => void)[] = [];
    const { store, poller } = harness(() => new Promise<Answer>((resolve) => releases.push(resolve)));
    await vi.advanceTimersByTimeAsync(100);
    poller.close();
    releases[0]?.(bundle(5));
    await vi.advanceTimersByTimeAsync(0);
    expect(store.current().version).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});
