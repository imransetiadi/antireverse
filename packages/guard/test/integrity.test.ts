// Slice 21b: Guard's integrity collector. The marker is planted with Harden's own statement; the page is the
// happy-dom document (script and modulepreload elements) plus a stubbed Resource Timing list, which by default holds
// an entry for every element the tests add, as a browser's does for what it loaded; the files come from a stubbed
// global fetch, the attestation from the fake service (which validates with the protocol's schemas).
import { createHash, webcrypto } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { markerStatement } from "../../harden/src/marker.ts";
import { AttestRequestSchema, IntegrityReportSchema } from "../../protocol/src/index.ts";
import { INTEGRITY } from "../src/constants.js";
import { createGuard, type GuardCrypto, type GuardFetch, type GuardOptions } from "../src/index.js";
import { collect, plan } from "../src/integrity.js";
import {
  APP_ID,
  ATTEST_URL,
  CHALLENGE_URL,
  cleanNavigator,
  ENDPOINT,
  fakeService,
  memoryStorage,
  response,
  spyCrypto,
  throwingStorage,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-14T08:00:00.000Z");
const ORIGIN = "https://shop.example";
const BUILD = "bld_0123456789abcdef01234567";
const OTHER = "bld_89abcdef0123456789abcdef";
const KEY = Symbol.for("ar.build");
/** The page-wide claims of the Builds being collected. */
const CLAIMS = Symbol.for("ar.integrity");
const registry = globalThis as unknown as Record<symbol, unknown>;
const MB = 1024 * 1024;

const bytes = (text: string) => new TextEncoder().encode(text);
const hashOf = (body: Uint8Array) => createHash("sha256").update(body).digest("base64url");

/** Plants a marker exactly as a hardened bundle does. */
function plant(build: string, files: string[]) {
  new Function(markerStatement(build, files))();
}

interface Entry {
  name: string;
  initiatorType: string;
  decodedBodySize?: number;
}

/** What Resource Timing lists. */
const entries: Entry[] = [];
const resolved = (url: string) => new URL(url, location.href).href.replace(/#.*$/, "");

/** A script element; `loaded: false` leaves it out of Resource Timing (the browser did not request it). */
function script(src: string, options: { type?: string; loaded?: boolean } = {}) {
  const element = document.createElement("script");
  if (options.type !== undefined) element.setAttribute("type", options.type);
  element.setAttribute("src", src);
  document.head.appendChild(element);
  if (options.loaded !== false) entries.push({ name: resolved(src), initiatorType: "script" });
}

function preload(href: string) {
  const element = document.createElement("link");
  element.setAttribute("rel", "modulepreload");
  element.setAttribute("href", href);
  document.head.appendChild(element);
  entries.push({ name: resolved(href), initiatorType: "link" });
}

/** Further Resource Timing entries. */
function timing(more: Entry[]) {
  entries.push(...more);
}

/** The headers of a script answer: `Content-Type` JavaScript, no `Content-Length`. */
const jsHeaders = {
  get: (name: string) => (name.toLowerCase() === "content-type" ? "text/javascript; charset=utf-8" : null),
};

/** How memo and page-wide claims name a Build: with the App that reports it. */
const memoKey = (build: string, app = APP_ID) => `${app}/${build}`;

interface Served {
  body?: Uint8Array;
  /** The Content-Type header (default: JavaScript); null for none. */
  contentType?: string | null;
  redirected?: boolean;
  status?: number;
  type?: string;
  contentLength?: string;
  error?: Error;
  hang?: boolean;
}

/** The global fetch of the page: serves `files` by exact URL and records every call. */
function pageFetch(files: Record<string, Served | Uint8Array>) {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
  const buffered: string[] = [];
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const found = files[url];
    const served: Served = found instanceof Uint8Array ? { body: found } : (found ?? { status: 404 });
    if (served.error) throw served.error;
    if (served.hang) return new Promise(() => {});
    const status = served.status ?? 200;
    const body = served.body ?? new Uint8Array();
    return {
      ok: status >= 200 && status < 300,
      status,
      type: served.type ?? "basic",
      redirected: served.redirected ?? false,
      headers: {
        get: (name: string) =>
          name.toLowerCase() === "content-length"
            ? (served.contentLength ?? null)
            : name.toLowerCase() === "content-type"
              ? served.contentType === undefined
                ? "text/javascript; charset=utf-8"
                : served.contentType
              : null,
      },
      arrayBuffer: async () => {
        buffered.push(url);
        return body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength);
      },
      text: async () => {
        throw new Error("text() must never be used: it would decode the bytes");
      },
    };
  });
  vi.stubGlobal("fetch", fetch);
  return { fetch, calls, buffered, urls: () => calls.map((call) => call.url) };
}

function setup(overrides: Partial<GuardOptions> = {}, service = fakeService({ nowMs: () => Date.now() })) {
  const storage = memoryStorage();
  const guard = createGuard({
    appId: APP_ID,
    endpoint: ENDPOINT,
    fetch: service.fetch,
    crypto: spyCrypto().crypto,
    storage,
    navigator: cleanNavigator(),
    now: () => Date.now(),
    ...overrides,
  });
  return { guard, service, storage };
}

type Service = ReturnType<typeof fakeService>;
const attestBodies = (service: Service) =>
  service.requests
    .filter((request) => request.url === ATTEST_URL)
    .map((request) => request.body as Record<string, unknown>);
const reports = (service: Service) =>
  attestBodies(service)
    .map((body) => body.integrity)
    .filter((report) => report !== undefined);

/** The real timer: `setTimeout` is faked while a test runs. */
const realSetTimeout = globalThis.setTimeout;

/**
 * Lets real asynchronous work (WebCrypto runs on other threads, off the fake clock) finish, without moving the fake
 * clock. The last rounds wait in real time, for when the machine is busy with other test files.
 */
async function settle(rounds = 20) {
  for (let i = 0; i < rounds; i += 1) {
    await new Promise((resolve) => (i < rounds - 4 ? setImmediate(resolve) : realSetTimeout(resolve, 3)));
    await vi.advanceTimersByTimeAsync(0);
  }
}

/** Moves the fake clock, then lets the work it started finish. */
async function advance(ms: number) {
  await vi.advanceTimersByTimeAsync(ms);
  await settle();
}

const happyDom = (
  window as unknown as {
    happyDOM: { setURL(url: string): void; settings: { handleDisabledFileLoadingAsSuccess: boolean } };
  }
).happyDOM;
let visibility = "visible";
const idle = new Set<number>();
let idleHandles = 0;
const unhandled: unknown[] = [];
const onUnhandled = (reason: unknown) => unhandled.push(reason);

beforeEach(() => {
  vi.useFakeTimers({ now: T0, toFake: ["setTimeout", "clearTimeout", "Date"] });
  // Idle time comes at once (as a microtask), so the fake clock tells exactly when the collector starts.
  idle.clear();
  vi.stubGlobal("requestIdleCallback", (task: () => void) => {
    const handle = ++idleHandles;
    idle.add(handle);
    queueMicrotask(() => {
      if (idle.delete(handle)) task();
    });
    return handle;
  });
  vi.stubGlobal("cancelIdleCallback", (handle: number) => void idle.delete(handle));
  // happy-dom loads no script file; without this it reports every <script src> the tests add as a failed load.
  happyDom.settings.handleDisabledFileLoadingAsSuccess = true;
  happyDom.setURL(`${ORIGIN}/app/index.html`);
  visibility = "visible";
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => visibility });
  entries.length = 0;
  vi.spyOn(performance, "getEntriesByType").mockImplementation((type) =>
    type === "resource" ? ([...entries] as unknown as PerformanceEntryList) : [],
  );
  unhandled.length = 0;
  process.on("unhandledRejection", onUnhandled);
});

afterEach(() => {
  process.off("unhandledRejection", onUnhandled);
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  delete registry[KEY];
  delete registry[CLAIMS];
  document.head.innerHTML = "";
  Reflect.deleteProperty(document, "visibilityState");
});

describe("when the collector runs and what it sends", () => {
  it("the first handshake carries no report and waits for no file; the report follows 30 s after the first token", async () => {
    const main = bytes("console.log('main')");
    const chunk = bytes("export const a = 1;\n");
    plant(BUILD, ["src/main.js", "src/chunk.js", "src/never-loaded.js"]);
    script("/assets/src/main.js");
    script("/assets/src/chunk.js?v=3");
    const page = pageFetch({
      [`${ORIGIN}/assets/src/main.js`]: main,
      [`${ORIGIN}/assets/src/chunk.js?v=3`]: chunk,
    });
    const { guard, service } = setup();

    const first = await guard.attest();
    expect(first).not.toBeNull();
    expect(page.fetch).not.toHaveBeenCalled();
    expect(Object.keys(attestBodies(service)[0] ?? {}).sort()).toEqual(["app_id", "cnf", "device", "nonce", "signals"]);

    await advance(INTEGRITY.delayMs - 1);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(service.challenges()).toBe(1);

    await advance(1);
    // Only the listed files the page loaded, with the exact URL the page used, one request each.
    expect(page.calls).toEqual([
      {
        url: `${ORIGIN}/assets/src/main.js`,
        init: expect.objectContaining({ cache: "force-cache", credentials: "same-origin" }),
      },
      {
        url: `${ORIGIN}/assets/src/chunk.js?v=3`,
        init: expect.objectContaining({ cache: "force-cache", credentials: "same-origin" }),
      },
    ]);
    expect(page.buffered).toHaveLength(2);
    expect(service.challenges()).toBe(2);
    const body = attestBodies(service)[1] ?? {};
    expect(Object.keys(body).sort()).toEqual(["app_id", "cnf", "device", "integrity", "nonce", "signals"]);
    // A listed file the page never loaded is absent: neither hashed nor skipped.
    expect(body.integrity).toEqual({
      build: BUILD,
      files: [
        { i: 0, h: hashOf(main) },
        { i: 1, h: hashOf(chunk) },
      ],
      skipped: 0,
    });
    expect(IntegrityReportSchema.safeParse(body.integrity).success).toBe(true);
    expect(AttestRequestSchema.parse(body).integrity).toEqual(body.integrity);
    // No URL, path or content leaves the browser.
    const wire = JSON.stringify(service.requests.map((request) => request.body));
    for (const secret of ["main.js", "chunk.js", "assets", "shop.example", "console.log"])
      expect(wire).not.toContain(secret);
    // The token was replaced by the early re-attest and the regular schedule follows it.
    expect(guard.token()).not.toBe(first);
    await advance(240_000);
    expect(service.challenges()).toBe(3);
    expect(reports(service)).toHaveLength(1);
    guard.stop();
    expect(unhandled).toEqual([]);
  });

  it("reads the registry lazily: a marker registered after the first token is still found", async () => {
    const main = bytes("late");
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: main });
    const { guard, service } = setup();
    await guard.attest();
    await advance(10_000);
    plant(BUILD, ["main.js"]);
    await advance(20_000);
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(main) }], skipped: 0 }]);
    guard.stop();
  });

  it("without requestIdleCallback the collection still runs, from a timer", async () => {
    vi.stubGlobal("requestIdleCallback", undefined);
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.fetch).not.toHaveBeenCalled();
    await advance(1); // a timer set inside a timer runs a millisecond later on the fake clock
    expect(reports(service)).toHaveLength(1);
    guard.stop();
  });

  it("the collection is handed to requestIdleCallback, never run in the timer's own task", async () => {
    const tasks: Array<() => void> = [];
    vi.stubGlobal("requestIdleCallback", (task: () => void) => tasks.push(task));
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(tasks).toHaveLength(1);
    expect(performance.getEntriesByType).not.toHaveBeenCalled();
    expect(page.fetch).not.toHaveBeenCalled();
    tasks[0]?.();
    await settle();
    expect(reports(service)).toHaveLength(1);
    guard.stop();
  });

  it("sends nothing and re-attests no sooner when no marker is registered", async () => {
    script("/main.js");
    const page = pageFetch({});
    const { guard, service } = setup();
    await guard.attest();
    await advance(239_999);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(service.challenges()).toBe(1);
    await advance(1);
    expect(service.challenges()).toBe(2);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("a report with no hashed file is not sent, and nothing is brought forward", async () => {
    plant(BUILD, ["main.js", "gone.js"]);
    script("/main.js");
    script("/gone.js");
    pageFetch({ [`${ORIGIN}/main.js`]: { status: 500 } });
    const { guard, service } = setup();
    await guard.attest();
    await advance(60_000);
    expect(service.challenges()).toBe(1);
    await advance(180_000);
    expect(service.challenges()).toBe(2);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("integrity: false disables everything: no timer, no enumeration, no fetch", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const { guard, service } = setup({ integrity: false });
    await guard.attest();
    expect(vi.getTimerCount()).toBe(1); // only the regular re-attest
    await advance(239_999);
    expect(service.challenges()).toBe(1);
    expect(performance.getEntriesByType).not.toHaveBeenCalled();
    expect(page.fetch).not.toHaveBeenCalled();
    guard.stop();
  });

  it("stop() cancels the pending collection", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const { guard, service } = setup();
    await guard.attest();
    guard.stop();
    expect(vi.getTimerCount()).toBe(0);
    await advance(600_000);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(service.challenges()).toBe(1);
  });

  it("a full report of 32 files keeps the attest body under 4 KB", async () => {
    const files = Array.from({ length: 32 }, (_, i) => `chunks/chunk-${i}.js`);
    plant(BUILD, files);
    const served: Record<string, Uint8Array> = {};
    for (const file of files) {
      script(`/${file}`);
      served[`${ORIGIN}/${file}`] = bytes(file);
    }
    pageFetch(served);
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    await settle(80);
    const sent = service.requests.filter((request) => request.url === ATTEST_URL)[1];
    expect((sent?.body as { integrity?: { files: unknown[] } } | undefined)?.integrity?.files).toHaveLength(32);
    expect(new TextEncoder().encode(sent?.init.body ?? "").byteLength).toBeLessThan(4096);
    guard.stop();
  });
});

describe("which files are fetched", () => {
  it("only same-origin URLs whose path ends with '/' + a listed path, from scripts, modulepreload and script timings", async () => {
    plant(BUILD, ["src/main.js", "src/a.js", "src/b.js", "src/c.js", "src/d.js", "src/e.js"]);
    script("https://cdn.example/src/main.js"); // cross-origin: never fetched
    script("/v2/src/main.js#frag"); // same-origin: the one that counts
    script("/v2/src/main.js"); // the same file again
    script("/xsrc/a.js"); // not on a path boundary
    script("/other.js"); // not listed
    preload("/v2/src/b.js");
    timing([
      { name: `${ORIGIN}/v2/src/c.js?x=1`, initiatorType: "script" },
      { name: `${ORIGIN}/v2/src/d.js`, initiatorType: "fetch" }, // not a script the page ran
      { name: `${ORIGIN}/v2/src/main.js`, initiatorType: "script" }, // already known
      { name: "https://cdn.example/src/e.js", initiatorType: "script" },
    ]);
    const body = bytes("same");
    const page = pageFetch({
      [`${ORIGIN}/v2/src/main.js`]: body,
      [`${ORIGIN}/v2/src/b.js`]: body,
      [`${ORIGIN}/v2/src/c.js?x=1`]: body,
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/v2/src/main.js`, `${ORIGIN}/v2/src/b.js`, `${ORIGIN}/v2/src/c.js?x=1`]);
    expect(reports(service)).toEqual([
      {
        build: BUILD,
        files: [
          { i: 0, h: hashOf(body) },
          { i: 2, h: hashOf(body) },
          { i: 3, h: hashOf(body) },
        ],
        skipped: 0,
      },
    ]);
    guard.stop();
  });
});

describe("budgets and failures", () => {
  it("does nothing under Save-Data", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const { guard, service } = setup({ navigator: { ...cleanNavigator(), connection: { saveData: true } } });
    await guard.attest();
    await advance(239_999);
    expect(performance.getEntriesByType).not.toHaveBeenCalled();
    expect(page.fetch).not.toHaveBeenCalled();
    expect(service.challenges()).toBe(1);
    guard.stop();
  });

  it("skips a file over 2 MB: from Resource Timing before fetching, from Content-Length, and from the body", async () => {
    plant(BUILD, ["ok.js", "timed.js", "declared.js", "long.js"]);
    for (const name of ["ok.js", "timed.js", "declared.js", "long.js"]) script(`/${name}`);
    timing([
      { name: `${ORIGIN}/timed.js`, initiatorType: "script", decodedBodySize: 2 * MB + 1 },
      { name: `${ORIGIN}/ok.js`, initiatorType: "script", decodedBodySize: 2 * MB },
    ]);
    const ok = bytes("ok");
    const page = pageFetch({
      [`${ORIGIN}/ok.js`]: ok,
      [`${ORIGIN}/timed.js`]: bytes("never read"),
      [`${ORIGIN}/declared.js`]: { body: bytes("small after all"), contentLength: String(2 * MB + 1) },
      [`${ORIGIN}/long.js`]: { body: new Uint8Array(2 * MB + 1) },
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/ok.js`, `${ORIGIN}/declared.js`, `${ORIGIN}/long.js`]);
    expect(page.buffered).toEqual([`${ORIGIN}/ok.js`, `${ORIGIN}/long.js`]); // the declared one is never buffered
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(ok) }], skipped: 3 }]);
    guard.stop();
  });

  it("a failed, refused, opaque or cross-origin-redirected fetch counts as skipped and nothing throws", async () => {
    plant(BUILD, ["ok.js", "blocked.js", "missing.js", "opaque.js", "cors.js"]);
    for (const name of ["ok.js", "blocked.js", "missing.js", "opaque.js", "cors.js"]) script(`/${name}`);
    const ok = bytes("ok");
    pageFetch({
      [`${ORIGIN}/ok.js`]: ok,
      [`${ORIGIN}/blocked.js`]: { error: new TypeError("Refused to connect: Content Security Policy") },
      [`${ORIGIN}/missing.js`]: { status: 404 },
      [`${ORIGIN}/opaque.js`]: { status: 0, type: "opaque" },
      [`${ORIGIN}/cors.js`]: { body: bytes("elsewhere"), type: "cors" },
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(ok) }], skipped: 4 }]);
    expect(unhandled).toEqual([]);
    guard.stop();
  });

  it("stops after about 5 s of wall time: a hanging file is aborted and what is left is skipped", async () => {
    plant(BUILD, ["ok.js", "slow.js", "late.js"]);
    for (const name of ["ok.js", "slow.js", "late.js"]) script(`/${name}`);
    const ok = bytes("ok");
    const page = pageFetch({
      [`${ORIGIN}/ok.js`]: ok,
      [`${ORIGIN}/slow.js`]: { hang: true },
      [`${ORIGIN}/late.js`]: bytes("late"),
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/ok.js`, `${ORIGIN}/slow.js`]);
    const signal = page.calls[1]?.init?.signal;
    expect(signal?.aborted).toBe(false);
    await advance(INTEGRITY.budgetMs - 1);
    expect(service.challenges()).toBe(1);
    await advance(1);
    expect(signal?.aborted).toBe(true);
    expect(page.urls()).toEqual([`${ORIGIN}/ok.js`, `${ORIGIN}/slow.js`]); // late.js is never fetched
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(ok) }], skipped: 2 }]);
    guard.stop();
  });

  it("without crypto.subtle (an insecure context) nothing is enumerated or fetched", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const crypto = { getRandomValues: <T extends Uint8Array>(array: T) => array };
    expect(await collect(APP_ID, crypto, cleanNavigator(), null, Date.now, { aborted: false })).toBeNull();
    expect(await collect(APP_ID, null, cleanNavigator(), null, Date.now, { aborted: false })).toBeNull();
    expect(performance.getEntriesByType).not.toHaveBeenCalled();
    expect(page.fetch).not.toHaveBeenCalled();
  });
});

describe("a missing, malformed or hostile registry", () => {
  const thrower = () => {
    throw new Error("hostile");
  };
  const hostile: Array<[string, () => unknown]> = [
    ["not an array", () => ({ b: BUILD, f: ["main.js"] })],
    ["a string", () => "bld"],
    ["null", () => null],
    ["an array whose length throws", () => new Proxy([], { get: thrower })],
    ["an entry whose getters throw", () => [Object.defineProperties({}, { b: { get: thrower }, f: { get: thrower } })]],
    ["an entry whose files throw on access", () => [{ b: BUILD, f: new Proxy([], { get: thrower }) }]],
    [
      "entries of the wrong shape",
      () => [null, 7, "x", [], { b: 1, f: ["main.js"] }, { b: BUILD }, { b: BUILD, f: "main.js" }],
    ],
    [
      "a Build id that is not one",
      () => [
        { b: "bld_XYZ", f: ["main.js"] },
        { b: `${BUILD}0`, f: ["main.js"] },
      ],
    ],
    ["paths that are not strings", () => [{ b: BUILD, f: [1, null, {}, "", ["main.js"]] }]],
  ];

  it.each(hostile)("%s is ignored without throwing", async (_name, make) => {
    registry[KEY] = make();
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    expect(() => plan(() => false)).not.toThrow();
    expect(plan(() => false)).toEqual([]);
    const { guard, service } = setup();
    await guard.attest();
    await advance(60_000);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(service.challenges()).toBe(1);
    expect(guard.token()).not.toBeNull();
    expect(unhandled).toEqual([]);
    guard.stop();
  });

  it("a getter on globalThis that throws is ignored", () => {
    Object.defineProperty(globalThis, KEY, { configurable: true, get: thrower });
    expect(plan(() => false)).toEqual([]);
  });

  it("good entries among bad ones still count; an index is the position in the marker's list", async () => {
    registry[KEY] = [null, { b: "nope", f: ["main.js"] }, { b: BUILD, f: [7, "main.js", null, "lib.js"] }];
    script("/main.js");
    script("/lib.js");
    const body = bytes("x");
    pageFetch({ [`${ORIGIN}/main.js`]: body, [`${ORIGIN}/lib.js`]: body });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toEqual([
      {
        build: BUILD,
        files: [
          { i: 1, h: hashOf(body) },
          { i: 3, h: hashOf(body) },
        ],
        skipped: 0,
      },
    ]);
    guard.stop();
  });

  it("more than 32 files: only the first 32 are considered", () => {
    const files = Array.from({ length: 40 }, (_, i) => `f${i}.js`);
    registry[KEY] = [{ b: BUILD, f: files }];
    for (const file of files) script(`/${file}`);
    const [only] = plan(() => false);
    expect(only?.files.map((file) => file.i)).toEqual(Array.from({ length: 32 }, (_, i) => i));
  });

  it("a Build registered twice is read once (its first marker)", () => {
    registry[KEY] = [
      { b: BUILD, f: ["main.js"] },
      { b: BUILD, f: ["other.js", "main.js"] },
    ];
    script("/main.js");
    expect(plan(() => false)).toEqual([{ build: BUILD, files: [{ i: 0, url: `${ORIGIN}/main.js`, size: 0 }] }]);
  });
});

describe("visibility", () => {
  it("a hidden tab waits: the collection and the early re-attest run when it becomes visible", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const main = bytes("x");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: main });
    const { guard, service } = setup();
    await guard.attest();
    visibility = "hidden";
    await advance(100_000);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(service.challenges()).toBe(1);
    expect(vi.getTimerCount()).toBe(1); // only the regular re-attest: no timer of the collector while hidden

    document.dispatchEvent(new Event("visibilitychange")); // still hidden
    await settle();
    expect(page.fetch).not.toHaveBeenCalled();

    visibility = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
    await settle();
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(main) }], skipped: 0 }]);
    document.dispatchEvent(new Event("visibilitychange")); // the listener is gone
    await settle();
    expect(service.challenges()).toBe(2);
    guard.stop();
  });

  it("stop() while waiting for visibility removes the listener", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const { guard } = setup();
    await guard.attest();
    visibility = "hidden";
    await advance(INTEGRITY.delayMs);
    guard.stop();
    visibility = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
    await settle();
    expect(page.fetch).not.toHaveBeenCalled();
  });
});

describe("the 24-hour memo", () => {
  function onePage() {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    return pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
  }

  it("a device reports a Build once in 24 hours: the memo is kept in first-party storage, keyed by Build", async () => {
    const page = onePage();
    const first = setup();
    await first.guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(first.service)).toHaveLength(1);
    first.guard.stop();
    expect(JSON.parse(first.storage.data.get("ar.integrity") ?? "")).toEqual({
      [memoKey(BUILD)]: T0 + INTEGRITY.delayMs,
    });

    // The next page view, 23 h 59 min later: nothing is fetched and nothing is brought forward.
    delete registry[CLAIMS];
    vi.setSystemTime(T0 + INTEGRITY.memoMs - 60_000);
    page.fetch.mockClear();
    const second = setup({ storage: first.storage });
    await second.guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(second.service.challenges()).toBe(1);
    second.guard.stop();

    // A day after the report: once more.
    delete registry[CLAIMS];
    vi.setSystemTime(T0 + INTEGRITY.delayMs + INTEGRITY.memoMs);
    const third = setup({ storage: first.storage });
    await third.guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(third.service)).toHaveLength(1);
    third.guard.stop();
  });

  it.each([
    ["not JSON", "{"],
    ["not an object", "[1]"],
    ["a time in the future", JSON.stringify({ [memoKey(BUILD)]: T0 + 3_600_000 })],
    ["a time that is no number", JSON.stringify({ [memoKey(BUILD)]: "soon" })],
  ])("a memo that is %s is ignored", async (_name, stored) => {
    onePage();
    const { guard, service, storage } = setup({ storage: memoryStorage({ "ar.integrity": stored }) });
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toHaveLength(1);
    expect(storage).toBeDefined();
    guard.stop();
  });

  it.each([
    ["throws", throwingStorage],
    ["is null", null],
  ])("when storage %s the memo falls back to memory: one report per page view", async (_name, storage) => {
    onePage();
    const { guard, service } = setup({ storage });
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toHaveLength(1);
    await advance(600_000);
    expect(service.challenges()).toBeGreaterThanOrEqual(4);
    expect(reports(service)).toHaveLength(1);
    expect(unhandled).toEqual([]);
    guard.stop();
  });

  it("a report is remembered for 24 hours only once the API accepted the attestation", async () => {
    const page = onePage();
    const service = fakeService({ nowMs: () => Date.now() });
    let down = false;
    const { guard, storage } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => (down ? response(503, {}) : service.fetch(url, init))),
    });
    await guard.attest();
    down = true;
    await advance(INTEGRITY.delayMs);
    guard.stop();
    expect(page.urls()).toHaveLength(1);
    // What storage holds is the short claim of the collection, not a report: it is over after `claimMs`.
    const claim = JSON.parse(storage.data.get("ar.integrity") ?? "{}")[memoKey(BUILD)];
    expect(claim).toBe(T0 + INTEGRITY.delayMs + INTEGRITY.claimMs - INTEGRITY.memoMs);

    // Another page view of this device, once the claim is over: the Build is collected and reported.
    delete registry[CLAIMS];
    down = false;
    vi.setSystemTime(T0 + INTEGRITY.delayMs + INTEGRITY.claimMs);
    const next = setup({ storage });
    await next.guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toHaveLength(2);
    expect(reports(next.service)).toHaveLength(1);
    next.guard.stop();
  });
});

describe("a failed early re-attest", () => {
  it("keeps the token and the regular schedule; the report goes with the next regular re-attest", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const main = bytes("x");
    pageFetch({ [`${ORIGIN}/main.js`]: main });
    const service = fakeService({ nowMs: () => Date.now() });
    let down = false;
    let refused = 0;
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => {
        if (!down) return service.fetch(url, init);
        refused += 1;
        return response(503, {});
      }),
    });
    const first = await guard.attest();
    down = true;
    await advance(INTEGRITY.delayMs);
    expect(refused).toBe(1); // the early re-attest was tried and failed at its challenge
    expect(guard.token()).toBe(first);
    expect(guard.headers()).toEqual({ "ar-attestation": first });

    down = false;
    await advance(240_000 - INTEGRITY.delayMs - 1);
    expect(service.challenges()).toBe(1);
    await advance(1); // 240 s after the first token: the regular re-attest, unchanged
    expect(service.challenges()).toBe(2);
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(main) }], skipped: 0 }]);
    expect(guard.token()).not.toBe(first);
    guard.stop();
  });

  it("an attest call that fails with the report attached also keeps the token", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const service = fakeService({ nowMs: () => Date.now() });
    let down = false;
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) =>
        down && url === ATTEST_URL ? response(500, {}) : service.fetch(url, init),
      ),
    });
    const first = await guard.attest();
    down = true;
    await advance(INTEGRITY.delayMs);
    expect(service.requests.filter((request) => request.url === CHALLENGE_URL)).toHaveLength(2);
    expect(guard.token()).toBe(first);
    down = false;
    await advance(240_000 - INTEGRITY.delayMs);
    expect(reports(service)).toHaveLength(1);
    guard.stop();
  });
});

describe("several markers", () => {
  it("one Build per attestation: the first not yet reported, the next with the following regular re-attest", async () => {
    plant(BUILD, ["app.js"]);
    plant(OTHER, ["widget.js"]);
    script("/app.js");
    script("/widget.js");
    const app = bytes("app");
    const widget = bytes("widget");
    const page = pageFetch({ [`${ORIGIN}/app.js`]: app, [`${ORIGIN}/widget.js`]: widget });
    const { guard, service, storage } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(app) }], skipped: 0 }]);
    expect(service.challenges()).toBe(2); // one early re-attest, not one per Build

    await advance(239_999);
    expect(service.challenges()).toBe(2);
    await advance(1);
    expect(service.challenges()).toBe(3);
    expect(reports(service)[1]).toEqual({ build: OTHER, files: [{ i: 0, h: hashOf(widget) }], skipped: 0 });
    expect(Object.keys(JSON.parse(storage.data.get("ar.integrity") ?? "")).sort()).toEqual(
      [memoKey(BUILD), memoKey(OTHER)].sort(),
    );

    await advance(480_000);
    expect(reports(service)).toHaveLength(2);
    expect(page.urls()).toEqual([`${ORIGIN}/app.js`, `${ORIGIN}/widget.js`]);
    guard.stop();
  });

  it("stop() during the early re-attest: the next Build is not collected and nothing stays scheduled", async () => {
    plant(BUILD, ["app.js"]);
    plant(OTHER, ["widget.js"]);
    script("/app.js");
    script("/widget.js");
    const page = pageFetch({ [`${ORIGIN}/app.js`]: bytes("app"), [`${ORIGIN}/widget.js`]: bytes("widget") });
    const service = fakeService({ nowMs: () => Date.now() });
    let release: (() => void) | undefined;
    let hold = false;
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => {
        if (hold && url === ATTEST_URL) await new Promise<void>((resolve) => (release = resolve));
        return service.fetch(url, init);
      }),
    });
    await guard.attest();
    hold = true;
    await advance(INTEGRITY.delayMs);
    expect(release).toBeDefined(); // the early re-attest is waiting for its answer
    guard.stop();
    release?.();
    await settle();
    expect(reports(service)).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
    expect(idle.size).toBe(0);
    await advance(600_000);
    expect(page.urls()).toEqual([`${ORIGIN}/app.js`]);
  });

  it("a Build already reported today is passed over for the next one", async () => {
    plant(BUILD, ["app.js"]);
    plant(OTHER, ["widget.js"]);
    script("/app.js");
    script("/widget.js");
    const widget = bytes("widget");
    const page = pageFetch({ [`${ORIGIN}/app.js`]: bytes("app"), [`${ORIGIN}/widget.js`]: widget });
    const { guard, service } = setup({
      storage: memoryStorage({ "ar.integrity": JSON.stringify({ [memoKey(BUILD)]: T0 - 1000 }) }),
    });
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/widget.js`]);
    expect(reports(service)).toEqual([{ build: OTHER, files: [{ i: 0, h: hashOf(widget) }], skipped: 0 }]);
    guard.stop();
  });
});

describe("synchronous cost (PB-06)", () => {
  it("enumerating and matching a large page is one short task, and is bounded", () => {
    const files = Array.from({ length: 32 }, (_, i) => `assets/chunk-${i}.js`);
    registry[KEY] = Array.from({ length: 50 }, (_, n) => ({ b: `bld_${String(n).padStart(24, "0")}`, f: files }));
    const names = Array.from({ length: 5000 }, (_, i) => `${ORIGIN}/static/assets/chunk-${i}.js?v=${i}`);
    const scripts = names.map((src) => ({ src, getAttribute: () => null }));
    vi.spyOn(Document.prototype, "querySelectorAll").mockImplementation(((selector: string) =>
      selector.startsWith("script") ? scripts : []) as unknown as typeof document.querySelectorAll);
    timing(names.map((name) => ({ name, initiatorType: "script", decodedBodySize: 1000 })));
    // The best of five runs: the other test files run in parallel and would otherwise be what is measured.
    let planned = plan(() => false);
    let elapsed = Number.POSITIVE_INFINITY;
    for (let run = 0; run < 5; run += 1) {
      const started = performance.now();
      planned = plan(() => false);
      elapsed = Math.min(elapsed, performance.now() - started);
    }
    console.info(`guard integrity plan(): ${elapsed.toFixed(2)} ms for 5000 scripts, 5000 timings, 50 markers`);
    expect(planned.length).toBeLessThanOrEqual(INTEGRITY.buildsMax);
    expect(planned[0]?.files).toHaveLength(32);
    // PB-06 allows no single task over 25 ms on a mid-tier phone. This is a desktop measurement (about 2 ms): a
    // tripwire for a regression, not the lab metric on a throttled device profile.
    expect(elapsed).toBeLessThan(25);
  });
});

// The findings of the independent review of slice 21b.

describe("one base per Build (review F1, F14)", () => {
  it("'index.js' is never hashed from /assets/utils/index.js: two bases explain one file each, so nothing is sent", async () => {
    plant(BUILD, ["index.js", "utils/index.js"]);
    script("/assets/utils/index.js");
    const page = pageFetch({ [`${ORIGIN}/assets/utils/index.js`]: bytes("utils") });
    expect(plan(() => false)).toEqual([]);
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("two places a Build's only loaded file could be: the Build is ambiguous and nothing is sent for it", async () => {
    plant(BUILD, ["main.js"]);
    script("/legacy/vendor/main.js"); // another bundle of the site
    script("/app/main.js");
    const page = pageFetch({
      [`${ORIGIN}/legacy/vendor/main.js`]: bytes("theirs"),
      [`${ORIGIN}/app/main.js`]: bytes("ours"),
    });
    expect(plan(() => false)).toEqual([]);
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("one base explains every loaded file: each is taken from it exactly; unrelated scripts do not matter", () => {
    plant(BUILD, ["main.js", "chunks/a.js", "chunks/b.js"]);
    script("/legacy/vendor/other.js");
    script("/app/main.js?v=1");
    script("/app/chunks/a.js");
    expect(plan(() => false)).toEqual([
      {
        build: BUILD,
        files: [
          { i: 0, url: `${ORIGIN}/app/main.js?v=1`, size: 0 },
          { i: 1, url: `${ORIGIN}/app/chunks/a.js`, size: 0 },
        ],
      },
    ]);
  });

  it("a second base that explains even one listed file skips the Build, however many files it explains (R1)", async () => {
    plant(BUILD, ["main.js", "polyfills.js", "runtime.js"]);
    script("/a/main.js"); // the Build
    script("/b/main.js"); // another app of the site…
    script("/b/polyfills.js"); // …which would explain more files
    const page = pageFetch({
      [`${ORIGIN}/a/main.js`]: bytes("a"),
      [`${ORIGIN}/b/main.js`]: bytes("b"),
      [`${ORIGIN}/b/polyfills.js`]: bytes("p"),
    });
    expect(plan(() => false)).toEqual([]);
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("a URL that ends like two listed paths gives no evidence: the base comes from the other files", async () => {
    plant(BUILD, ["index.js", "utils/index.js", "app.js"]);
    script("/assets/utils/index.js"); // 'utils/index.js' under /assets/, or 'index.js' under /assets/utils/
    script("/assets/app.js"); // only 'app.js' under /assets/
    const utils = bytes("utils");
    const app = bytes("app");
    const page = pageFetch({ [`${ORIGIN}/assets/utils/index.js`]: utils, [`${ORIGIN}/assets/app.js`]: app });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/assets/utils/index.js`, `${ORIGIN}/assets/app.js`]);
    // index.js was not loaded: absent, neither hashed nor skipped.
    expect(reports(service)).toEqual([
      {
        build: BUILD,
        files: [
          { i: 1, h: hashOf(utils) },
          { i: 2, h: hashOf(app) },
        ],
        skipped: 0,
      },
    ]);
    guard.stop();
  });

  it("a Build that lists index.js and utils/index.js and loads both, with a third file, reports all three", () => {
    plant(BUILD, ["index.js", "utils/index.js", "app.js"]);
    script("/assets/index.js");
    script("/assets/utils/index.js");
    script("/assets/app.js");
    expect(plan(() => false)[0]?.files).toEqual([
      { i: 0, url: `${ORIGIN}/assets/index.js`, size: 0 },
      { i: 1, url: `${ORIGIN}/assets/utils/index.js`, size: 0 },
      { i: 2, url: `${ORIGIN}/assets/app.js`, size: 0 },
    ]);
  });

  it("a second copy of the Build under the colliding directory makes two bases: skipped", () => {
    plant(BUILD, ["index.js", "utils/index.js", "app.js"]);
    script("/assets/utils/index.js");
    script("/assets/app.js");
    script("/assets/utils/app.js");
    expect(plan(() => false)).toEqual([]);
  });

  it("a URL two Builds would both name is hashed for neither: it counts as skipped in both (R1)", async () => {
    plant(BUILD, ["main.js", "a.js"]);
    plant(OTHER, ["main.js", "b.js"]);
    for (const name of ["main.js", "a.js", "b.js"]) script(`/app/${name}`);
    const a = bytes("a");
    const b = bytes("b");
    const page = pageFetch({
      [`${ORIGIN}/app/main.js`]: bytes("m"),
      [`${ORIGIN}/app/a.js`]: a,
      [`${ORIGIN}/app/b.js`]: b,
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    await advance(240_000);
    expect(page.urls()).toEqual([`${ORIGIN}/app/a.js`, `${ORIGIN}/app/b.js`]);
    expect(reports(service)).toEqual([
      { build: BUILD, files: [{ i: 1, h: hashOf(a) }], skipped: 1 },
      { build: OTHER, files: [{ i: 1, h: hashOf(b) }], skipped: 1 },
    ]);
    guard.stop();
  });

  it("a URL shared with a Build already reported today is still not used", () => {
    plant(BUILD, ["main.js", "a.js"]);
    plant(OTHER, ["main.js", "b.js"]);
    for (const name of ["main.js", "a.js", "b.js"]) script(`/app/${name}`);
    expect(plan((build) => build === OTHER)).toEqual([
      {
        build: BUILD,
        files: [
          { i: 0, url: `${ORIGIN}/app/main.js`, size: Number.POSITIVE_INFINITY },
          { i: 1, url: `${ORIGIN}/app/a.js`, size: 0 },
        ],
      },
    ]);
  });

  it("a path listed twice names one file: no URL is mapped to two indexes", () => {
    registry[KEY] = [{ b: BUILD, f: ["main.js", "main.js", "lib.js"] }];
    script("/main.js");
    script("/lib.js");
    expect(plan(() => false)[0]?.files.map((file) => file.i)).toEqual([0, 2]);
  });

  it("/x%2Fmain.js is not the Build's main.js; an encoded character inside a segment still matches", () => {
    plant(BUILD, ["main.js", "my file.js"]);
    script("/x%2Fmain.js");
    expect(plan(() => false)).toEqual([]);
    script("/app/my%20file.js");
    expect(plan(() => false)[0]?.files).toEqual([{ i: 1, url: `${ORIGIN}/app/my%20file.js`, size: 0 }]);
  });
});

describe("the 2 MB cap bounds what is downloaded (review F2)", () => {
  /** A fetch answering every URL with `chunks` chunks of 1 MB, without Content-Length; counts what was pulled. */
  function streaming(chunks: number) {
    const state = { pulled: 0, cancelled: false, aborted: false };
    vi.stubGlobal("fetch", async (_url: string, init?: RequestInit) => {
      init?.signal?.addEventListener("abort", () => {
        state.aborted = true;
      });
      let sent = 0;
      const body = new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            if (sent >= chunks) return controller.close();
            sent += 1;
            state.pulled += MB;
            controller.enqueue(new Uint8Array(MB).fill(sent));
          },
          cancel() {
            state.cancelled = true;
          },
        },
        { highWaterMark: 0 },
      );
      return new Response(body, { status: 200, headers: { "content-type": "text/javascript" } });
    });
    return state;
  }

  it("a 64 MB body without Content-Length is dropped after the cap plus one chunk, and the request is ended", async () => {
    plant(BUILD, ["big.js"]);
    script("/big.js");
    const state = streaming(64);
    vi.useRealTimers();
    const report = await collect(APP_ID, webcrypto as unknown as GuardCrypto, cleanNavigator(), null, Date.now, {
      aborted: false,
    });
    expect(report).toBeNull();
    expect(state.pulled).toBeLessThanOrEqual(INTEGRITY.fileMaxBytes + MB);
    expect(state.cancelled).toBe(true);
    expect(state.aborted).toBe(true);
  });

  it("a body under the cap is read from the stream and hashed as its exact bytes", async () => {
    plant(BUILD, ["ok.js"]);
    script("/ok.js");
    streaming(2);
    vi.useRealTimers();
    const expected = new Uint8Array(2 * MB);
    expected.fill(1, 0, MB);
    expected.fill(2, MB);
    const report = await collect(APP_ID, webcrypto as unknown as GuardCrypto, cleanNavigator(), null, Date.now, {
      aborted: false,
    });
    expect(report).toEqual({ build: BUILD, files: [{ i: 0, h: hashOf(expected) }], skipped: 0 });
  });
});

describe("only what the browser loaded as a script (review F6)", () => {
  it("a data block (<script type='application/json' src>) is never fetched", async () => {
    registry[KEY] = [{ b: BUILD, f: ["export.json", "me"] }];
    script("/account/export.json", { type: "application/json", loaded: false });
    script("/api/me", { type: "text/plain", loaded: false });
    const page = pageFetch({ [`${ORIGIN}/account/export.json`]: bytes("{}"), [`${ORIGIN}/api/me`]: bytes("me") });
    expect(plan(() => false)).toEqual([]);
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("a data block is not fetched even when something else requested its URL", () => {
    registry[KEY] = [{ b: BUILD, f: ["export.json"] }];
    script("/account/export.json", { type: "application/json", loaded: false });
    timing([{ name: `${ORIGIN}/account/export.json`, initiatorType: "fetch" }]);
    expect(plan(() => false)).toEqual([]);
  });

  it.each(["", "module", "text/javascript", "application/javascript", " Text/JavaScript ", "application/ecmascript"])(
    "a script element of type '%s' counts",
    (type) => {
      plant(BUILD, ["main.js"]);
      script("/main.js", { type });
      expect(plan(() => false)).toHaveLength(1);
    },
  );

  it.each(["importmap", "speculationrules", "text/template", "application/ld+json"])(
    "a script element of type '%s' does not",
    (type) => {
      plant(BUILD, ["main.js"]);
      script("/main.js", { type, loaded: false });
      expect(plan(() => false)).toEqual([]);
    },
  );

  it("a script element the browser has no Resource Timing entry for is not fetched", () => {
    plant(BUILD, ["main.js", "late.js"]);
    script("/main.js");
    script("/late.js", { loaded: false });
    expect(plan(() => false)[0]?.files.map((file) => file.i)).toEqual([0]);
  });

  it("an element whose URL was loaded by a preload (initiator 'link') counts", () => {
    plant(BUILD, ["main.js"]);
    script("/main.js", { loaded: false });
    timing([{ name: `${ORIGIN}/main.js`, initiatorType: "link", decodedBodySize: 10 }]);
    expect(plan(() => false)[0]?.files).toEqual([{ i: 0, url: `${ORIGIN}/main.js`, size: 10 }]);
  });

  it("when the Resource Timing buffer is full, a listed element without an entry counts as skipped, unfetched", async () => {
    plant(BUILD, ["main.js", "late.js"]);
    script("/main.js");
    script("/late.js", { loaded: false });
    timing(
      Array.from({ length: INTEGRITY.timingFull }, (_, i) => ({
        name: `${ORIGIN}/img/${i}.png`,
        initiatorType: "img",
      })),
    );
    const main = bytes("main");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: main, [`${ORIGIN}/late.js`]: bytes("late") });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/main.js`]);
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(main) }], skipped: 1 }]);
    guard.stop();
  });
});

describe("each source of URLs stands alone (review F3, F15)", () => {
  it("Resource Timing that throws leaves the document's elements", () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    vi.spyOn(performance, "getEntriesByType").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(plan(() => false)).toHaveLength(1);
  });

  it("Resource Timing that is missing leaves the document's elements", () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    vi.stubGlobal("performance", {});
    expect(plan(() => false)).toHaveLength(1);
  });

  it("a document that cannot be queried leaves the Resource Timing scripts", () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    vi.spyOn(Document.prototype, "querySelectorAll").mockImplementation(() => {
      throw new Error("no");
    });
    expect(plan(() => false)).toHaveLength(1);
  });

  it("an element named 'scripts' or 'querySelectorAll' (DOM clobbering) does not switch the collector off", () => {
    plant(BUILD, ["main.js"]);
    script("/main.js", { loaded: false });
    vi.stubGlobal("performance", {}); // so that only the document can tell
    const real = document;
    const clobbered = new Proxy(real, {
      get: (target, key) =>
        key === "scripts" || key === "querySelectorAll" ? real.createElement("img") : Reflect.get(target, key, target),
    });
    vi.stubGlobal("document", clobbered);
    expect(plan(() => false)).toHaveLength(1);
  });
});

describe("stop() during a collection (review F4, F13)", () => {
  /** Three files; each request waits for `release`. */
  function gated() {
    plant(BUILD, ["a.js", "b.js", "c.js"]);
    for (const name of ["a.js", "b.js", "c.js"]) script(`/${name}`);
    const calls: Array<{ url: string; signal: AbortSignal | null | undefined }> = [];
    let open: Array<() => void> = [];
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      calls.push({ url, signal: init?.signal });
      await new Promise<void>((resolve) => open.push(resolve));
      return {
        ok: true,
        status: 200,
        type: "basic",
        headers: jsHeaders,
        arrayBuffer: async () => bytes(url).buffer,
      };
    });
    const release = () => {
      for (const resolve of open) resolve();
      open = [];
    };
    return { calls, release };
  }

  it("ends the request in flight and fetches no further file; nothing is sent", async () => {
    const page = gated();
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.calls.map((call) => call.url)).toEqual([`${ORIGIN}/a.js`]);
    guard.stop();
    expect(page.calls[0]?.signal?.aborted).toBe(true);
    page.release();
    await advance(600_000);
    expect(page.calls).toHaveLength(1);
    expect(reports(service)).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("then start(): the Build is collected and reported by this page after all", async () => {
    const page = gated();
    const { guard, service, storage } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    guard.stop();
    page.release();
    await advance(1_000);
    expect(JSON.parse(storage.data.get("ar.integrity") ?? "{}")[memoKey(BUILD)]).toBeUndefined(); // the claim is given back
    guard.start();
    await advance(1);
    expect(guard.token()).not.toBeNull();
    await advance(INTEGRITY.delayMs);
    for (let file = 0; file < 3; file += 1) {
      page.release();
      await settle();
    }
    expect(page.calls.map((call) => call.url).slice(1)).toEqual([`${ORIGIN}/a.js`, `${ORIGIN}/b.js`, `${ORIGIN}/c.js`]);
    expect(reports(service)).toHaveLength(1);
    guard.stop();
  });
});

describe("several Guards and tabs (review F5)", () => {
  function slowPage() {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      await new Promise((resolve) => setTimeout(resolve, 200)); // a cache miss
      return {
        ok: true,
        status: 200,
        type: "basic",
        headers: jsHeaders,
        arrayBuffer: async () => bytes("x").buffer,
      };
    });
    return urls;
  }

  it.each([
    ["sharing localStorage", () => memoryStorage()],
    ["without storage", () => null],
  ])("two Guards on one page %s fetch each file once and report the Build once", async (_name, storage) => {
    const urls = slowPage();
    const service = fakeService({ nowMs: () => Date.now() });
    const shared = storage();
    const one = setup({ storage: shared }, service).guard;
    const two = setup({ storage: shared }, service).guard;
    await one.attest();
    await advance(10);
    await two.attest();
    await advance(INTEGRITY.delayMs + 1_000);
    expect(urls).toHaveLength(1);
    expect(reports(service)).toHaveLength(1);
    one.stop();
    two.stop();
  });

  it("another tab does not collect a Build while this one does: the memo holds a short claim", async () => {
    const urls = slowPage();
    const { guard, storage } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs + 100); // collecting
    expect(urls).toHaveLength(1);
    // The other tab: its own page (no page-wide claim), the same storage.
    delete registry[CLAIMS];
    const report = await collect(APP_ID, webcrypto as unknown as GuardCrypto, cleanNavigator(), storage, Date.now, {
      aborted: false,
    });
    expect(report).toBeNull();
    expect(urls).toHaveLength(1);
    guard.stop();
  });

  it("a hostile value in the page-wide claim slot is ignored without throwing", () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    Object.defineProperty(globalThis, CLAIMS, {
      configurable: true,
      get: () => {
        throw new Error("hostile");
      },
    });
    expect(() => plan(() => false)).not.toThrow();
  });
});

describe("the early re-attest only while the tab is visible (review F10)", () => {
  function slow() {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    vi.stubGlobal("fetch", async () => {
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      return {
        ok: true,
        status: 200,
        type: "basic",
        headers: jsHeaders,
        arrayBuffer: async () => bytes("x").buffer,
      };
    });
  }

  it("a tab hidden while the files are hashed sends the report when it is visible again", async () => {
    slow();
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    visibility = "hidden";
    document.dispatchEvent(new Event("visibilitychange"));
    await advance(3_000);
    expect(service.challenges()).toBe(1);
    visibility = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
    await settle();
    expect(service.challenges()).toBe(2);
    expect(reports(service)).toHaveLength(1);
    guard.stop();
  });

  it("a tab that stays hidden sends it with the regular re-attest, once", async () => {
    slow();
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    visibility = "hidden";
    await advance(3_000); // the file arrives and is hashed (in real time, so before the clock moves on)
    expect(service.challenges()).toBe(1);
    await advance(240_000 - INTEGRITY.delayMs - 3_000);
    expect(service.challenges()).toBe(2);
    expect(reports(service)).toHaveLength(1);
    visibility = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
    await settle();
    expect(service.challenges()).toBe(2); // nothing left to bring forward
    guard.stop();
  });
});

describe("the 5 s budget does not follow the wall clock (review F11)", () => {
  it("a clock set back during the collection does not extend the budget", async () => {
    plant(BUILD, ["quick.js", "slow.js"]);
    script("/quick.js");
    script("/slow.js");
    let signal: AbortSignal | null | undefined;
    vi.stubGlobal("fetch", (url: string, init?: RequestInit) => {
      if (url.endsWith("/quick.js")) {
        return new Promise((resolve) =>
          setTimeout(resolve, 100, {
            ok: true,
            type: "basic",
            headers: jsHeaders,
            arrayBuffer: async () => new ArrayBuffer(1),
          }),
        );
      }
      signal = init?.signal;
      return new Promise(() => {});
    });
    let skew = 3_600_000; // the device's clock is an hour ahead…
    const { guard, service } = setup({ now: () => Date.now() + skew });
    await guard.attest();
    await advance(INTEGRITY.delayMs + 50);
    skew = 0; // …and is corrected during the collection
    await advance(50);
    expect(signal?.aborted).toBe(false);
    await advance(INTEGRITY.budgetMs - 100);
    expect(signal?.aborted).toBe(true);
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(new Uint8Array(1)) }], skipped: 1 }]);
    guard.stop();
  });
});

describe("a hostile registry costs nothing (review F7)", () => {
  it("no method of a registry object is called", () => {
    const called: string[] = [];
    const spying = <T extends object>(target: T) =>
      new Proxy(target, {
        get: (object, key) => {
          const value = Reflect.get(object, key);
          if (typeof value !== "function") return value;
          called.push(String(key));
          return () => ({
            entries: () => ({ [Symbol.iterator]: () => ({ next: () => ({ done: false, value: [0, "main.js"] }) }) }),
          });
        },
      });
    registry[KEY] = spying([spying({ b: BUILD, f: spying(["main.js"]) })]);
    script("/main.js");
    expect(plan(() => false)).toEqual([{ build: BUILD, files: [{ i: 0, url: `${ORIGIN}/main.js`, size: 0 }] }]);
    expect(called).toEqual([]);
  });

  it("megabyte path strings do not make plan() a long task", () => {
    const big = "a".repeat(8 * MB);
    registry[KEY] = Array.from({ length: 4 }, (_, n) => ({
      b: `bld_${String(n).padStart(24, "0")}`,
      f: Array.from({ length: 32 }, (_, i) => `${big}${i}.js`),
    }));
    for (let i = 0; i < 300; i += 1) script(`/assets/chunk-${i}.js`);
    let elapsed = Number.POSITIVE_INFINITY;
    for (let run = 0; run < 3; run += 1) {
      const started = performance.now();
      expect(plan(() => false)).toEqual([]);
      elapsed = Math.min(elapsed, performance.now() - started);
    }
    expect(elapsed).toBeLessThan(25);
  });
});

// The findings of the second review (of the rewritten collector).

describe("only an answer that is the script is hashed (R2)", () => {
  it.each([
    ["an HTML answer (an SPA fallback)", { body: bytes("<!doctype html>"), contentType: "text/html; charset=utf-8" }],
    ["a redirected answer (a login page)", { body: bytes("x"), redirected: true }],
    ["an answer without a content type", { body: bytes("x"), contentType: null }],
    ["a JSON answer", { body: bytes("{}"), contentType: "application/json" }],
  ])("%s counts as skipped", async (_name, served) => {
    plant(BUILD, ["ok.js", "odd.js"]);
    script("/ok.js");
    script("/odd.js");
    const ok = bytes("ok");
    const page = pageFetch({ [`${ORIGIN}/ok.js`]: ok, [`${ORIGIN}/odd.js`]: served });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.buffered).toEqual([`${ORIGIN}/ok.js`]); // the other body is not even read
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(ok) }], skipped: 1 }]);
    guard.stop();
  });

  it.each([
    "text/javascript",
    "application/javascript",
    "Application/X-JavaScript; charset=utf-8",
    "text/ecmascript",
    "application/ecmascript",
    " text/javascript ;charset=UTF-8",
  ])("content type '%s' is a script", async (contentType) => {
    plant(BUILD, ["ok.js"]);
    script("/ok.js");
    pageFetch({ [`${ORIGIN}/ok.js`]: { body: bytes("ok"), contentType } });
    const report = await collect(APP_ID, webcrypto as unknown as GuardCrypto, cleanNavigator(), null, Date.now, {
      aborted: false,
    });
    expect(report?.files).toHaveLength(1);
  });
});

describe("two Apps on one page (R8)", () => {
  const SECOND_APP = "app_0123456789abcdef01234567";

  it("each App's Guard reports the Build: claims and memo are kept per App", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const page = pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const service = fakeService({ nowMs: () => Date.now() });
    const storage = memoryStorage();
    const one = setup({ storage }, service).guard;
    const two = setup({ storage, appId: SECOND_APP }, service).guard;
    await one.attest();
    await two.attest();
    await advance(INTEGRITY.delayMs);
    const sent = service.requests
      .filter((request) => request.url === ATTEST_URL)
      .map((request) => request.body as { app_id: string; integrity?: { build: string } })
      .filter((body) => body.integrity !== undefined);
    expect(sent.map((body) => [body.app_id, body.integrity?.build]).sort()).toEqual(
      [
        [APP_ID, BUILD],
        [SECOND_APP, BUILD],
      ].sort(),
    );
    expect(page.urls()).toHaveLength(2);
    expect(Object.keys(JSON.parse(storage.data.get("ar.integrity") ?? "{}")).sort()).toEqual(
      [memoKey(BUILD), memoKey(BUILD, SECOND_APP)].sort(),
    );
    one.stop();
    two.stop();
  });

  it("a memo entry of the old shape (a bare Build id) is ignored", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const { guard, service } = setup({
      storage: memoryStorage({ "ar.integrity": JSON.stringify({ [BUILD]: T0 - 1 }) }),
    });
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toHaveLength(1);
    guard.stop();
  });
});

describe("reading a body (R3, R7)", () => {
  /** A fetch whose body is `read`'s chunks; says whether the reader was cancelled. */
  function bodyOf(read: () => Promise<{ done: boolean; value?: unknown }>) {
    const state = { cancelled: 0, reads: 0 };
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      status: 200,
      type: "basic",
      redirected: false,
      headers: jsHeaders,
      body: {
        getReader: () => ({
          read: () => {
            state.reads += 1;
            return read();
          },
          cancel: async () => {
            state.cancelled += 1;
          },
        }),
      },
    }));
    return state;
  }

  it("a chunk that is not a Uint8Array skips the file: zeros are never hashed", async () => {
    plant(BUILD, ["odd.js"]);
    script("/odd.js");
    let sent = false;
    const state = bodyOf(async () => {
      if (sent) return { done: true };
      sent = true;
      return { done: false, value: { byteLength: 4 } };
    });
    vi.useRealTimers();
    const report = await collect(APP_ID, webcrypto as unknown as GuardCrypto, cleanNavigator(), null, Date.now, {
      aborted: false,
    });
    expect(report).toBeNull();
    expect(state.cancelled).toBeGreaterThanOrEqual(1);
  });

  it("stop() ends the read of a body even when fetch ignores the abort signal", async () => {
    plant(BUILD, ["slow.js"]);
    script("/slow.js");
    // Chunks keep coming, one per tick, whatever the signal says.
    const state = bodyOf(
      () => new Promise((resolve) => setTimeout(resolve, 100, { done: false, value: new Uint8Array(8) })),
    );
    const { guard } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs + 250);
    expect(state.reads).toBeGreaterThanOrEqual(2);
    guard.stop();
    await settle();
    expect(state.cancelled).toBeGreaterThanOrEqual(1);
    const reads = state.reads;
    await advance(1_000);
    expect(state.reads).toBeLessThanOrEqual(reads + 1); // the read in flight may still answer; no further one is made
  });

  it("the budget ends the read of a body that never finishes", async () => {
    plant(BUILD, ["slow.js"]);
    script("/slow.js");
    const state = bodyOf(
      () => new Promise((resolve) => setTimeout(resolve, 100, { done: false, value: new Uint8Array(8) })),
    );
    const { guard } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs + INTEGRITY.budgetMs);
    expect(state.cancelled).toBeGreaterThanOrEqual(1);
    const reads = state.reads;
    await advance(1_000);
    expect(state.reads).toBeLessThanOrEqual(reads + 1);
    guard.stop();
  });
});

describe("a Resource Timing that answers oddly (R4)", () => {
  it("a list that is not an array counts as no Resource Timing: the elements alone tell", () => {
    plant(BUILD, ["main.js"]);
    script("/main.js", { loaded: false });
    vi.spyOn(performance, "getEntriesByType").mockReturnValue({ length: 1 } as unknown as PerformanceEntryList);
    expect(plan(() => false)).toHaveLength(1);
  });

  it("an entry whose getters throw is passed over; the others still count", () => {
    plant(BUILD, ["main.js", "lib.js"]);
    script("/main.js");
    script("/lib.js");
    const hostile = Object.defineProperties(
      {},
      {
        name: {
          get: () => {
            throw new Error("hostile");
          },
        },
      },
    );
    entries.splice(1, 0, hostile as unknown as Entry);
    expect(plan(() => false)[0]?.files.map((file) => file.i)).toEqual([0, 1]);
  });
});

describe("stop() leaves nothing behind (R5, R9)", () => {
  it("a stop() while a handshake is in flight after the collection adds no visibility listener", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const service = fakeService({ nowMs: () => Date.now() });
    let release: (() => void) | undefined;
    let hold = false;
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => {
        if (hold) await new Promise<void>((resolve) => (release = resolve));
        return service.fetch(url, init);
      }),
    });
    await guard.attest();
    await advance(INTEGRITY.delayMs - 1);
    hold = true;
    const explicit = guard.attest(); // a handshake of the page's own, in flight when the collection ends
    await advance(1);
    visibility = "hidden";
    const added = vi.spyOn(document, "addEventListener");
    guard.stop();
    hold = false;
    release?.();
    await explicit;
    await settle();
    expect(added.mock.calls.filter(([type]) => type === "visibilitychange")).toEqual([]);
  });

  it("every visibility listener the collector adds is removed by stop()", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const added = vi.spyOn(document, "addEventListener");
    const removed = vi.spyOn(document, "removeEventListener");
    const { guard } = setup();
    visibility = "hidden";
    await guard.attest();
    await advance(INTEGRITY.delayMs); // waits for visibility
    await guard.attest(); // a new token while waiting must not add a second wait
    await advance(INTEGRITY.delayMs);
    guard.stop();
    const count = (spy: typeof added) => spy.mock.calls.filter(([type]) => type === "visibilitychange").length;
    expect(count(added)).toBe(1);
    expect(count(removed)).toBe(count(added));
  });

  it("a stop() right as the collection ends does not lose the report: it goes with the next handshake", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const main = bytes("x");
    // The last thing the collection awaits is the digest: stop() is called from inside it, so that it lands in the
    // gap between collect() resolving and Guard taking the report.
    const spy = spyCrypto();
    const digest = spy.crypto.subtle?.digest;
    let stopNow: (() => void) | undefined;
    const crypto: GuardCrypto = {
      getRandomValues: spy.crypto.getRandomValues,
      subtle: {
        ...(spy.crypto.subtle as NonNullable<GuardCrypto["subtle"]>),
        digest: async (algorithm, data) => {
          const result = await (digest as NonNullable<typeof digest>)(algorithm, data);
          if (data.byteLength === main.byteLength) queueMicrotask(() => queueMicrotask(() => stopNow?.()));
          return result;
        },
      },
    };
    pageFetch({ [`${ORIGIN}/main.js`]: main });
    for (let gap = 0; gap < 6; gap += 1) {
      delete registry[CLAIMS];
      const { guard, service } = setup({ crypto });
      let hops = gap;
      stopNow = () => {
        if (hops-- > 0) queueMicrotask(() => stopNow?.());
        else guard.stop();
      };
      await guard.attest();
      await advance(INTEGRITY.delayMs);
      stopNow = undefined;
      guard.start();
      await advance(1);
      // Either the report was kept and went with that handshake, or the Build was given back and is collected again.
      await advance(INTEGRITY.delayMs);
      await advance(240_000);
      expect(reports(service), `stop() ${gap} microtasks after the digest`).toHaveLength(1);
      guard.stop();
      vi.setSystemTime(Date.now() + INTEGRITY.memoMs);
    }
  });
});

describe("bounded work (R6, R10, T1 and the budget)", () => {
  it("the element scan reads no src once scanMax values were read", () => {
    plant(BUILD, ["main.js"]);
    let reads = 0;
    const elements = Array.from({ length: 5 * INTEGRITY.scanMax }, (_, i) => ({
      getAttribute: () => null,
      get src() {
        reads += 1;
        return `${ORIGIN}/s/${i}.js`;
      },
    }));
    vi.spyOn(Document.prototype, "querySelectorAll").mockImplementation(((selector: string) =>
      selector.startsWith("script") ? elements : []) as unknown as typeof document.querySelectorAll);
    plan(() => false);
    expect(reads).toBe(INTEGRITY.scanMax);
  });

  it("a URL longer than 2,048 characters is not a candidate", () => {
    plant(BUILD, ["main.js"]);
    script(`/${"a".repeat(2_100)}/main.js`);
    expect(plan(() => false)).toEqual([]);
  });

  it("the worst page stays one short task: long URLs that all end like a listed path (PB-06)", () => {
    const files = Array.from({ length: 32 }, (_, i) => `chunk-${i}.js`);
    registry[KEY] = Array.from({ length: 64 }, (_, n) => ({ b: `bld_${String(n).padStart(24, "0")}`, f: files }));
    const long = "d/".repeat(750); // 1.5 KB of path
    const names = Array.from(
      { length: 3 * INTEGRITY.scanMax },
      (_, i) => `${ORIGIN}/${i % 7}/${long}chunk-${i % 32}.js?${i}`,
    );
    const elements = names.map((src) => ({ src, href: src, getAttribute: () => null }));
    vi.spyOn(Document.prototype, "querySelectorAll").mockImplementation(
      (() => elements) as unknown as typeof document.querySelectorAll,
    );
    timing(names.map((name) => ({ name, initiatorType: "script" })));
    let elapsed = Number.POSITIVE_INFINITY;
    for (let run = 0; run < 5; run += 1) {
      const started = performance.now();
      plan(() => false);
      elapsed = Math.min(elapsed, performance.now() - started);
    }
    console.info(`guard integrity plan(), hostile shape: ${elapsed.toFixed(2)} ms`);
    expect(elapsed).toBeLessThan(25);
  });

  it("the budget holds on the monotonic clock when its timer does not fire (a throttled tab)", async () => {
    const files = ["a.js", "b.js", "c.js", "d.js"];
    plant(BUILD, files);
    const served: Record<string, Uint8Array> = {};
    for (const file of files) {
      script(`/${file}`);
      served[`${ORIGIN}/${file}`] = bytes(file);
    }
    const page = pageFetch(served);
    // Each file takes 2.6 s on the monotonic clock; no timer fires (the fake clock stands still).
    vi.spyOn(performance, "now").mockImplementation(() => page.calls.length * 2_600);
    const report = await collect(APP_ID, webcrypto as unknown as GuardCrypto, cleanNavigator(), null, Date.now, {
      aborted: false,
    });
    expect(page.urls()).toEqual([`${ORIGIN}/a.js`, `${ORIGIN}/b.js`]);
    expect(report).toEqual({
      build: BUILD,
      files: [
        { i: 0, h: hashOf(bytes("a.js")) },
        { i: 1, h: hashOf(bytes("b.js")) },
      ],
      skipped: 2,
    });
  });

  it("a Build the budget did not reach is not claimed: another collection may take it", async () => {
    plant(BUILD, ["slow.js"]);
    plant(OTHER, ["next.js"]);
    script("/a/slow.js");
    script("/b/next.js");
    // The budget is spent while the first Build's file is fetched: the second Build is never started.
    const slow = pageFetch({ [`${ORIGIN}/a/slow.js`]: { status: 500 }, [`${ORIGIN}/b/next.js`]: bytes("next") });
    vi.spyOn(performance, "now").mockImplementation(() => slow.calls.length * INTEGRITY.budgetMs);
    const storage = memoryStorage();
    const job = { aborted: false };
    expect(
      await collect(APP_ID, webcrypto as unknown as GuardCrypto, cleanNavigator(), storage, Date.now, job),
    ).toBeNull();
    expect(Object.keys(JSON.parse(storage.data.get("ar.integrity") ?? "{}"))).toEqual([memoKey(BUILD)]);
    expect(Object.keys(registry[CLAIMS] as object)).toEqual([memoKey(BUILD)]);
  });

  it("a stuffed memo is cut to its newest entries when read", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const stuffed: Record<string, number> = {};
    for (let i = 0; i < 100_000; i += 1) stuffed[`${APP_ID}/bld_${String(i).padStart(24, "0")}`] = T0 - 1 - i;
    const storage = memoryStorage({ "ar.integrity": JSON.stringify(stuffed) });
    const { guard, service } = setup({ storage });
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toHaveLength(1);
    const kept = Object.keys(JSON.parse(storage.data.get("ar.integrity") ?? "{}"));
    expect(kept.length).toBeLessThanOrEqual(INTEGRITY.memoMax);
    expect(kept).toContain(memoKey(BUILD));
    expect(kept).toContain(`${APP_ID}/bld_${"0".repeat(24)}`); // the newest stay
    guard.stop();
  });
});
