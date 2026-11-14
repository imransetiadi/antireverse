// Slice 21b: Guard's integrity collector. The marker is planted with Harden's own statement; the page is the
// happy-dom document (script and modulepreload elements) plus a stubbed Resource Timing list, which by default holds
// an entry for every element the tests add, as a browser's does for what it loaded; the files come from a stubbed
// global fetch, the attestation from the fake service (which validates with the protocol's schemas).
import { createHash, webcrypto } from "node:crypto";
import { transformSync } from "esbuild";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { markerStatement } from "../../harden/src/marker.ts";
import { AttestRequestSchema, IntegrityReportSchema } from "../../protocol/src/index.ts";
import { INTEGRITY } from "../src/constants.js";
import { createGuard, type GuardCrypto, type GuardFetch, type GuardOptions } from "../src/index.js";
import { collect, locate, plan, remember } from "../src/integrity.js";
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

/** A file without any Build id: someone else's script. */
const plain = (text: string) => new TextEncoder().encode(text);
/** What Guard looks for in a Build's first file: the marker's own literal, as Harden writes it. */
const needle = (build: string) => `b:"${build}",f:[`;
/**
 * A file as Harden leaves the planted one: it holds the marker statement (here of both test Builds, so that any file
 * can be a Build's first). Only a marker's first file is searched for it; in any other file it changes nothing.
 */
const bytes = (text: string) => plain(`${markerStatement(BUILD, ["x.js"])}${markerStatement(OTHER, ["x.js"])}${text}`);
const hashOf = (body: Uint8Array) => createHash("sha256").update(body).digest("base64url");

/**
 * The files a Build maps to once its first file is known to be the candidate at `anchor` (a path; default: the only
 * candidate): what collect() does after it found the Build id in that file.
 */
function mapped(anchor?: string, skip: (build: string) => boolean = () => false) {
  const [planned] = plan(skip);
  const candidate = planned?.candidates.find((script) => anchor === undefined || script.url === `${ORIGIN}${anchor}`);
  const first = planned?.paths[0];
  if (!planned || !candidate || typeof first !== "string") return [];
  return locate(planned, candidate);
}

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
    script("/assets/src/main.js?v=3");
    script("/assets/src/chunk.js?v=3");
    const page = pageFetch({
      [`${ORIGIN}/assets/src/main.js?v=3`]: main,
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
        url: `${ORIGIN}/assets/src/main.js?v=3`,
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
      { name: `${ORIGIN}/v2/src/c.js`, initiatorType: "script" },
      { name: `${ORIGIN}/v2/src/d.js`, initiatorType: "fetch" }, // not a script the page ran
      { name: `${ORIGIN}/v2/src/main.js`, initiatorType: "script" }, // already known
      { name: "https://cdn.example/src/e.js", initiatorType: "script" },
    ]);
    const body = bytes("same");
    const page = pageFetch({
      [`${ORIGIN}/v2/src/main.js`]: body,
      [`${ORIGIN}/v2/src/b.js`]: body,
      [`${ORIGIN}/v2/src/c.js`]: body,
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/v2/src/main.js`, `${ORIGIN}/v2/src/b.js`, `${ORIGIN}/v2/src/c.js`]);
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
    registry[KEY] = [null, { b: "nope", f: ["main.js"] }, { b: BUILD, f: ["main.js", 7, null, "lib.js"] }];
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
          { i: 0, h: hashOf(body) },
          { i: 3, h: hashOf(body) },
        ],
        skipped: 0,
      },
    ]);
    guard.stop();
  });

  it("a marker whose first path is not a string has no anchor: nothing is sent for it", () => {
    registry[KEY] = [{ b: BUILD, f: [7, "main.js"] }];
    script("/main.js");
    expect(plan(() => false)).toEqual([]);
  });

  it("more than 32 files: only the first 32 are considered", () => {
    const files = Array.from({ length: 40 }, (_, i) => `f${i}.js`);
    registry[KEY] = [{ b: BUILD, f: files }];
    for (const file of files) script(`/${file}`);
    expect(mapped().map((file) => file.i)).toEqual(Array.from({ length: 32 }, (_, i) => i));
  });

  it("a Build registered twice is read once (its first marker)", () => {
    registry[KEY] = [
      { b: BUILD, f: ["main.js"] },
      { b: BUILD, f: ["other.js", "main.js"] },
    ];
    script("/main.js");
    script("/other.js");
    expect(plan(() => false).map((planned) => [planned.build, planned.paths])).toEqual([[BUILD, ["main.js"]]]);
    expect(mapped()).toEqual([{ i: 0, url: `${ORIGIN}/main.js`, size: 0 }]);
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
    // What storage holds is the claim of the waiting report, not a report: it is over after `pendingMs`.
    const claim = JSON.parse(storage.data.get("ar.integrity") ?? "{}")[memoKey(BUILD)];
    expect(claim).toBe(T0 + INTEGRITY.delayMs + INTEGRITY.pendingMs - INTEGRITY.memoMs);

    // Another page view of this device, once the claim is over: the Build is collected and reported.
    delete registry[CLAIMS];
    down = false;
    vi.setSystemTime(T0 + INTEGRITY.delayMs + INTEGRITY.pendingMs);
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
    expect(planned[0]?.candidates.map((script) => script.url)).toEqual([names[0]]);
    expect(mapped()).toHaveLength(32);
    // PB-06 allows no single task over 25 ms on a mid-tier phone. This is a desktop measurement (about 2 ms): a
    // tripwire for a regression, not the lab metric on a throttled device profile.
    expect(elapsed).toBeLessThan(25);
  });
});

// The findings of the independent review of slice 21b.

describe("the content anchor: a Build's first file is the one that holds its id", () => {
  const LEGACY = plain("/* the site's own, unhardened main.js */");

  it("a single-file bundle is reported", async () => {
    plant(BUILD, ["bundle.js"]);
    script("/dist/bundle.js");
    const bundle = bytes("everything");
    const page = pageFetch({ [`${ORIGIN}/dist/bundle.js`]: bundle });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/dist/bundle.js`]); // fetched once: its bytes are searched and hashed
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(bundle) }], skipped: 0 }]);
    guard.stop();
  });

  it("a script that only shares the name is fetched, found without the id, and nothing is sent", async () => {
    plant(BUILD, ["main.js", "vendor.js"]);
    script("/js/main.js");
    script("/js/vendor.js");
    const page = pageFetch({ [`${ORIGIN}/js/main.js`]: LEGACY, [`${ORIGIN}/js/vendor.js`]: plain("vendor") });
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(page.urls()).toEqual([`${ORIGIN}/js/main.js`]);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("the real first file among namesakes settles the base; every other file is taken from exactly base + path", async () => {
    plant(BUILD, ["main.js", "chunks/a.js", "chunks/b.js", "polyfills.js"]);
    script("/legacy/main.js");
    script("/legacy/polyfills.js"); // ends like a listed path, under the wrong base
    script("/legacy/chunks/a.js");
    script("/app/main.js");
    script("/app/chunks/a.js");
    const main = bytes("main");
    const a = plain("a");
    const page = pageFetch({
      [`${ORIGIN}/legacy/main.js`]: LEGACY,
      [`${ORIGIN}/legacy/polyfills.js`]: plain("legacy polyfills"),
      [`${ORIGIN}/legacy/chunks/a.js`]: plain("legacy a"),
      [`${ORIGIN}/app/main.js`]: main,
      [`${ORIGIN}/app/chunks/a.js`]: a,
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual([`${ORIGIN}/legacy/main.js`, `${ORIGIN}/app/main.js`, `${ORIGIN}/app/chunks/a.js`]);
    // chunks/b.js and polyfills.js were not loaded under /app/: absent.
    expect(reports(service)).toEqual([
      {
        build: BUILD,
        files: [
          { i: 0, h: hashOf(main) },
          { i: 1, h: hashOf(a) },
        ],
        skipped: 0,
      },
    ]);
    guard.stop();
  });

  it("a changed first file that still holds the id is reported: the mismatch reaches the wire", async () => {
    plant(BUILD, ["main.js", "lib.js"]);
    script("/app/main.js");
    script("/app/lib.js");
    const tampered = bytes("main(); stealCards();");
    const lib = plain("lib");
    pageFetch({ [`${ORIGIN}/app/main.js`]: tampered, [`${ORIGIN}/app/lib.js`]: lib });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toEqual([
      {
        build: BUILD,
        files: [
          { i: 0, h: hashOf(tampered) },
          { i: 1, h: hashOf(lib) },
        ],
        skipped: 0,
      },
    ]);
    guard.stop();
  });

  it("a first file whose marker was stripped anchors nothing: nothing is sent, the other files are not fetched", async () => {
    plant(BUILD, ["main.js", "lib.js"]);
    script("/app/main.js");
    script("/app/lib.js");
    const page = pageFetch({ [`${ORIGIN}/app/main.js`]: plain("main();"), [`${ORIGIN}/app/lib.js`]: plain("lib") });
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(page.urls()).toEqual([`${ORIGIN}/app/main.js`]);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("the id of another Build does not anchor this one", async () => {
    plant(BUILD, ["main.js"]);
    script("/app/main.js");
    pageFetch({ [`${ORIGIN}/app/main.js`]: plain(`${markerStatement(OTHER, ["main.js"])} main();`) });
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("two copies that both hold the id (/a/ and /b/): the Build is skipped", async () => {
    plant(BUILD, ["main.js", "lib.js"]);
    for (const base of ["/a/", "/b/"]) for (const name of ["main.js", "lib.js"]) script(`${base}${name}`);
    const page = pageFetch({
      [`${ORIGIN}/a/main.js`]: bytes("a"),
      [`${ORIGIN}/b/main.js`]: bytes("b"),
      [`${ORIGIN}/a/lib.js`]: plain("lib"),
      [`${ORIGIN}/b/lib.js`]: plain("lib"),
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(page.urls()).toEqual([`${ORIGIN}/a/main.js`, `${ORIGIN}/b/main.js`]);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("five candidates for the first file: the Build is skipped and nothing is fetched", async () => {
    plant(BUILD, ["main.js"]);
    const served: Record<string, Uint8Array> = {};
    for (const base of ["/1/", "/2/", "/3/", "/4/", "/5/"]) {
      script(`${base}main.js`);
      served[`${ORIGIN}${base}main.js`] = bytes(base);
    }
    const page = pageFetch(served);
    expect(plan(() => false)).toEqual([]);
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("four candidates are read; one path with several query strings is one candidate (the first seen)", async () => {
    plant(BUILD, ["main.js"]);
    for (const base of ["/1/", "/2/", "/3/"]) script(`${base}main.js`);
    script("/4/main.js?v=1");
    script("/4/main.js?v=2");
    const real = bytes("real");
    const page = pageFetch({
      [`${ORIGIN}/1/main.js`]: LEGACY,
      [`${ORIGIN}/2/main.js`]: LEGACY,
      [`${ORIGIN}/3/main.js`]: LEGACY,
      [`${ORIGIN}/4/main.js?v=1`]: real,
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(page.urls()).toEqual(
      ["/1/", "/2/", "/3/"].map((base) => `${ORIGIN}${base}main.js`).concat(`${ORIGIN}/4/main.js?v=1`),
    );
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(real) }], skipped: 0 }]);
    guard.stop();
  });

  it("nested names map exactly: index.js, utils/index.js and app.js under the base the first file gives", async () => {
    plant(BUILD, ["index.js", "utils/index.js", "app.js"]);
    script("/assets/utils/index.js"); // 'utils/index.js' under /assets/; also a candidate for 'index.js'
    script("/assets/index.js");
    script("/assets/app.js");
    const index = bytes("index");
    const utils = plain("utils");
    const app = plain("app");
    pageFetch({
      [`${ORIGIN}/assets/index.js`]: index,
      [`${ORIGIN}/assets/utils/index.js`]: utils,
      [`${ORIGIN}/assets/app.js`]: app,
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    expect(reports(service)).toEqual([
      {
        build: BUILD,
        files: [
          { i: 0, h: hashOf(index) },
          { i: 1, h: hashOf(utils) },
          { i: 2, h: hashOf(app) },
        ],
        skipped: 0,
      },
    ]);
    guard.stop();
  });

  it("nested names without the first file loaded: nothing is sent", async () => {
    plant(BUILD, ["index.js", "utils/index.js", "app.js"]);
    script("/assets/utils/index.js");
    script("/assets/app.js");
    pageFetch({ [`${ORIGIN}/assets/utils/index.js`]: plain("utils"), [`${ORIGIN}/assets/app.js`]: plain("app") });
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it.each<[string, Served]>([
    ["is not found", { status: 404 }],
    ["is redirected", { body: plain("x"), redirected: true }],
    ["is not served as JavaScript", { body: plain("x"), contentType: "text/html" }],
    ["is too large", { body: new Uint8Array(2 * MB + 1) }],
  ])("a candidate that %s was not examined: nothing is sent for the Build (fail closed)", async (_name, served) => {
    plant(BUILD, ["main.js"]);
    script("/odd/main.js");
    script("/app/main.js");
    pageFetch({ [`${ORIGIN}/odd/main.js`]: served, [`${ORIGIN}/app/main.js`]: bytes("main") });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    await advance(240_000);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("a candidate Resource Timing could not vouch for (its buffer may be full) is not examined: nothing is fetched", async () => {
    // A combining endpoint serves the planted file at a URL that ends like its path; the true file is only an element.
    plant(BUILD, ["app/main.js"]);
    timing(Array.from({ length: 249 }, (_, k) => ({ name: `${ORIGIN}/img/${k}.png`, initiatorType: "img" })));
    script("/min/f=js/jquery.js,app/main.js");
    script("/app/main.js", { loaded: false });
    expect(entries.length).toBe(250);
    const page = pageFetch({
      [`${ORIGIN}/min/f=js/jquery.js,app/main.js`]: bytes("jquery + main"),
      [`${ORIGIN}/app/main.js`]: bytes("main"),
    });
    expect(plan(() => false)).toEqual([]);
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(page.fetch).not.toHaveBeenCalled();
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("a candidate Resource Timing says is over 2 MB is not examined either", () => {
    plant(BUILD, ["main.js"]);
    script("/big/main.js");
    script("/app/main.js");
    timing([{ name: `${ORIGIN}/big/main.js`, initiatorType: "script", decodedBodySize: 2 * MB + 1 }]);
    expect(plan(() => false)).toEqual([]);
  });

  it("the bare Build id is not the marker: a JSONP answer that echoes it anchors nothing", async () => {
    plant(BUILD, ["main.js"]);
    script(`/api/jsonp/main.js?callback=${BUILD}`);
    pageFetch({ [`${ORIGIN}/api/jsonp/main.js?callback=${BUILD}`]: plain(`/**/${BUILD}({"ok":true});`) });
    const { guard, service } = setup();
    await guard.attest();
    await advance(240_000);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("the needle is what Harden's marker statement holds, also after esbuild --minify", () => {
    const statement = markerStatement(BUILD, ["main.js", "chunk.js"]);
    expect(statement).toContain(needle(BUILD));
    const minified = transformSync(`const app = 1;\n${statement}\nconsole.log(app);`, { minify: true }).code;
    expect(minified).not.toBe(statement);
    expect(minified).toContain(needle(BUILD));
    // The two shapes, pinned: what Harden writes, and what esbuild 's minifier makes of it.
    expect(statement).toBe(
      `;(function(){try{var s=Symbol.for("ar.build"),g=globalThis;(g[s]||(g[s]=[])).push({b:"${BUILD}",f:["main.js","chunk.js"]})}catch(e){}})();`,
    );
    expect(minified).toContain(`.push({b:"${BUILD}",f:["main.js","chunk.js"]})`);
  });

  it("when the budget ends before every candidate was read, the Build is undecided: nothing is sent", async () => {
    plant(BUILD, ["main.js"]);
    script("/app/main.js");
    script("/slow/main.js");
    pageFetch({ [`${ORIGIN}/app/main.js`]: bytes("main"), [`${ORIGIN}/slow/main.js`]: { hang: true } });
    const { guard, service, storage } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs + INTEGRITY.budgetMs);
    // The Build was not decided: its claims are given back, so that another collection may take it.
    expect(Object.keys((registry[CLAIMS] ?? {}) as object)).toEqual([]);
    expect(Object.keys(JSON.parse(storage.data.get("ar.integrity") ?? "{}"))).toEqual([]);
    await advance(240_000);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });

  it("stop() while a file is hashed starts no further request", async () => {
    plant(BUILD, ["a.js", "b.js", "c.js"]);
    for (const name of ["a.js", "b.js", "c.js"]) script(`/${name}`);
    const a = bytes("a");
    const page = pageFetch({ [`${ORIGIN}/a.js`]: a, [`${ORIGIN}/b.js`]: plain("b"), [`${ORIGIN}/c.js`]: plain("c") });
    const spy = spyCrypto();
    let stop: (() => void) | undefined;
    const crypto: GuardCrypto = {
      getRandomValues: spy.crypto.getRandomValues,
      subtle: {
        ...(spy.crypto.subtle as NonNullable<GuardCrypto["subtle"]>),
        digest: async (algorithm, data) => {
          if (data.byteLength === a.byteLength) stop?.(); // while a.js is hashed
          return (spy.crypto.subtle as NonNullable<GuardCrypto["subtle"]>).digest(algorithm, data);
        },
      },
    };
    const { guard, service } = setup({ crypto });
    await guard.attest();
    stop = () => guard.stop();
    await advance(INTEGRITY.delayMs);
    await advance(10_000);
    expect(page.urls()).toEqual([`${ORIGIN}/a.js`]);
    expect(reports(service)).toEqual([]);
  });

  describe("other files and query strings", () => {
    function served(urls: string[]) {
      const files: Record<string, Uint8Array> = {};
      for (const url of urls) {
        script(url);
        files[`${ORIGIN}${url}`] = url.includes("main.js") ? bytes(url) : plain(url);
      }
      return pageFetch(files);
    }
    async function report() {
      const { guard, service } = setup();
      await guard.attest();
      await advance(INTEGRITY.delayMs);
      guard.stop();
      return reports(service)[0] as { files: { i: number; h: string }[]; skipped: number } | undefined;
    }

    it("every file loaded with the anchor's query string is reported", async () => {
      plant(BUILD, ["main.js", "chunk.js"]);
      const page = served(["/app/main.js?dpl=x", "/app/chunk.js?dpl=x"]);
      expect(await report()).toEqual({
        build: BUILD,
        files: [
          { i: 0, h: hashOf(bytes("/app/main.js?dpl=x")) },
          { i: 1, h: hashOf(plain("/app/chunk.js?dpl=x")) },
        ],
        skipped: 0,
      });
      expect(page.urls()).toEqual([`${ORIGIN}/app/main.js?dpl=x`, `${ORIGIN}/app/chunk.js?dpl=x`]);
    });

    it("a chunk loaded only with another query string (an older deployment) is skipped, unfetched", async () => {
      plant(BUILD, ["main.js", "chunk.js"]);
      const page = served(["/app/main.js?dpl=new", "/app/chunk.js?dpl=older"]);
      expect(await report()).toMatchObject({ files: [{ i: 0 }], skipped: 1 });
      expect(page.urls()).toEqual([`${ORIGIN}/app/main.js?dpl=new`]);
    });

    it("a chunk loaded with two query strings is skipped, also when one is the anchor's", async () => {
      plant(BUILD, ["main.js", "chunk.js"]);
      const page = served(["/app/main.js?dpl=new", "/app/chunk.js?dpl=new", "/app/chunk.js?dpl=older"]);
      expect(await report()).toMatchObject({ files: [{ i: 0 }], skipped: 1 });
      expect(page.urls()).toEqual([`${ORIGIN}/app/main.js?dpl=new`]);
    });

    it("no query string on both sides counts as the same", async () => {
      plant(BUILD, ["main.js", "chunk.js"]);
      served(["/app/main.js", "/app/chunk.js"]);
      expect(await report()).toMatchObject({ files: [{ i: 0 }, { i: 1 }], skipped: 0 });
    });

    it("the anchor without a query string and a chunk with one: skipped", async () => {
      plant(BUILD, ["main.js", "chunk.js"]);
      served(["/app/main.js", "/app/chunk.js?v=2"]);
      expect(await report()).toMatchObject({ files: [{ i: 0 }], skipped: 1 });
    });
  });

  it("a URL of this Build that ends like a listed path of another Build on the page is used by neither", async () => {
    plant(BUILD, ["a/main.js", "shared.js"]);
    plant(OTHER, ["b/main.js", "shared.js"]);
    for (const path of ["/app/a/main.js", "/app/b/main.js", "/app/shared.js"]) script(path);
    const a = bytes("a");
    const b = bytes("b");
    const page = pageFetch({
      [`${ORIGIN}/app/a/main.js`]: a,
      [`${ORIGIN}/app/b/main.js`]: b,
      [`${ORIGIN}/app/shared.js`]: plain("shared"),
    });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    await advance(240_000);
    expect(page.urls()).toEqual([`${ORIGIN}/app/a/main.js`, `${ORIGIN}/app/b/main.js`]);
    expect(reports(service)).toEqual([
      { build: BUILD, files: [{ i: 0, h: hashOf(a) }], skipped: 1 },
      { build: OTHER, files: [{ i: 0, h: hashOf(b) }], skipped: 1 },
    ]);
    guard.stop();
  });

  it("…also when the other Build was already reported today", () => {
    plant(BUILD, ["a/main.js", "shared.js"]);
    plant(OTHER, ["b/main.js", "shared.js"]);
    for (const path of ["/app/a/main.js", "/app/b/main.js", "/app/shared.js"]) script(path);
    expect(mapped(undefined, (build) => build === OTHER)).toEqual([
      { i: 0, url: `${ORIGIN}/app/a/main.js`, size: 0 },
      { i: 1, url: `${ORIGIN}/app/shared.js`, size: Number.POSITIVE_INFINITY },
    ]);
  });

  it("a path listed twice names one file: no URL is mapped to two indexes", () => {
    registry[KEY] = [{ b: BUILD, f: ["main.js", "main.js", "lib.js", "lib.js"] }];
    script("/main.js");
    script("/lib.js");
    expect(mapped().map((file) => file.i)).toEqual([0, 2]);
  });

  it("/x%2Fmain.js is not the Build's main.js; an encoded character inside a segment still matches", () => {
    plant(BUILD, ["main.js", "my file.js"]);
    script("/x%2Fmain.js");
    expect(plan(() => false)).toEqual([]);
    script("/app/main.js");
    script("/app/my%20file.js");
    expect(mapped()).toEqual([
      { i: 0, url: `${ORIGIN}/app/main.js`, size: 0 },
      { i: 1, url: `${ORIGIN}/app/my%20file.js`, size: 0 },
    ]);
  });
});

describe("the Build's own files are not visible (third review F1, F2, F3)", () => {
  const LEGACY = plain("/* the site's own, unhardened main.js */");
  /** Nothing is sent, and the foreign file's hash appears nowhere on the wire. */
  async function expectNothingSent(served: Record<string, Uint8Array>) {
    pageFetch(served);
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    await advance(240_000);
    guard.stop();
    expect(reports(service)).toEqual([]);
    const wire = JSON.stringify(service.requests.map((request) => request.body));
    for (const body of Object.values(served)) expect(wire).not.toContain(hashOf(body));
  }

  it("F1a: the Build is served from a CDN origin; the site has its own same-origin /js/main.js", async () => {
    plant(BUILD, ["main.js", "vendor.js"]);
    script("https://cdn.example/app/main.js");
    script("https://cdn.example/app/vendor.js");
    script("/js/main.js");
    await expectNothingSent({ [`${ORIGIN}/js/main.js`]: LEGACY });
  });

  it("F1b: the Build was imported (initiator 'other', no element); a foreign /legacy/main.js has a tag", async () => {
    plant(BUILD, ["main.js"]);
    timing([{ name: `${ORIGIN}/app/main.js`, initiatorType: "other" }]);
    script("/legacy/main.js");
    await expectNothingSent({ [`${ORIGIN}/legacy/main.js`]: LEGACY });
  });

  it("F1c: the Build was lazy-loaded after the 250-entry buffer filled (no entry, no element)", async () => {
    plant(BUILD, ["main.js"]);
    script("/legacy/main.js");
    timing(Array.from({ length: 249 }, (_, k) => ({ name: `${ORIGIN}/img/${k}.png`, initiatorType: "img" })));
    await expectNothingSent({ [`${ORIGIN}/legacy/main.js`]: LEGACY });
  });

  it("F1d: the Build is inlined in the HTML; the page also loads /static/main.js", async () => {
    plant(BUILD, ["main.js"]);
    script("/static/main.js");
    await expectNothingSent({ [`${ORIGIN}/static/main.js`]: LEGACY });
  });

  it("F2: the Build is under /cdn/utils/ (each of its files ends like two listed paths); a foreign /legacy/index.js", async () => {
    plant(BUILD, ["index.js", "utils/index.js"]);
    script("/cdn/utils/index.js"); // the Build's index.js, base /cdn/utils/
    script("/legacy/index.js"); // foreign
    const real = bytes("the Build's index.js");
    const foreign = plain("legacy index");
    pageFetch({ [`${ORIGIN}/cdn/utils/index.js`]: real, [`${ORIGIN}/legacy/index.js`]: foreign });
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    guard.stop();
    // The Build's own file is found by its content; the foreign one is never reported.
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(real) }], skipped: 0 }]);
    expect(JSON.stringify(reports(service))).not.toContain(hashOf(foreign));
  });

  it("F3: 500 padded script elements hide the Build's own tag: the foreign file is not reported", async () => {
    plant(BUILD, ["main.js"]);
    script("/legacy/main.js");
    for (let k = 0; k < 499; k += 1) script(`/legacy/main.js?pad=${k}`, { loaded: k < 249 });
    script("/app/main.js", { loaded: false }); // the Build's tag, 501st; the buffer was full
    expect(entries.length).toBe(250);
    await expectNothingSent({ [`${ORIGIN}/legacy/main.js`]: LEGACY });
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
            const chunk = new Uint8Array(MB).fill(sent);
            if (sent === 1) chunk.set(plain(needle(BUILD)));
            controller.enqueue(chunk);
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
    expected.set(plain(needle(BUILD)));
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
    expect(mapped().map((file) => file.i)).toEqual([0]);
  });

  it("an element whose URL was loaded by a preload (initiator 'link') counts", () => {
    plant(BUILD, ["main.js"]);
    script("/main.js", { loaded: false });
    timing([{ name: `${ORIGIN}/main.js`, initiatorType: "link", decodedBodySize: 10 }]);
    expect(mapped()).toEqual([{ i: 0, url: `${ORIGIN}/main.js`, size: 10 }]);
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
            status: 200,
            arrayBuffer: async () => bytes("q").buffer,
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
    expect(reports(service)).toEqual([{ build: BUILD, files: [{ i: 0, h: hashOf(bytes("q")) }], skipped: 1 }]);
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
    expect(mapped()).toEqual([{ i: 0, url: `${ORIGIN}/main.js`, size: 0 }]);
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
    expect(mapped().map((file) => file.i)).toEqual([0, 1]);
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

// The lows of the third review.

describe("the memo across tabs (third review F4, F5)", () => {
  it("F4: stop() during a collection does not erase what another tab reported meanwhile", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: { hang: true } });
    const { guard, storage } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs); // the collection started
    await advance(2_000);
    remember(storage, memoKey(OTHER), Date.now(), Date.now()); // another tab reports another Build
    guard.stop();
    await settle();
    const memo = JSON.parse(storage.data.get("ar.integrity") ?? "{}");
    expect(Object.keys(memo)).toEqual([memoKey(OTHER)]); // and this tab's own claim is given back
  });

  it("F5: a report that waits longer than the collection's claim is still sent by one tab only", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const storage = memoryStorage();
    const serviceA = fakeService({ nowMs: () => Date.now() });
    let failed = 0;
    const a = setup(
      {
        storage,
        fetch: vi.fn<GuardFetch>(async (url, init) => {
          if (url === ATTEST_URL && init.body.includes('"integrity"') && failed++ === 0) throw new Error("offline");
          return serviceA.fetch(url, init);
        }),
      },
      serviceA,
    ).guard;
    await a.attest();
    await advance(INTEGRITY.delayMs); // A hashed; its early attest failed; the report waits
    expect(failed).toBe(1);
    await advance(31_000);
    delete registry[CLAIMS]; // tab B is another page: it shares localStorage only
    const b = setup({ storage });
    await b.guard.attest();
    await advance(INTEGRITY.delayMs);
    await advance(240_000);
    a.stop();
    b.guard.stop();
    expect(reports(serviceA).length + reports(b.service).length).toBe(1);
  });

  it("F5: a waiting report is dropped when another tab reported that App and Build meanwhile", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const service = fakeService({ nowMs: () => Date.now() });
    let down = false;
    const { guard, storage } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => (down ? response(503, {}) : service.fetch(url, init))),
    });
    await guard.attest();
    down = true;
    await advance(INTEGRITY.delayMs); // hashed; the early attest failed; the report waits
    down = false;
    remember(storage, memoKey(BUILD), Date.now(), Date.now()); // another tab's report
    await advance(240_000 - INTEGRITY.delayMs); // the regular re-attest
    expect(service.challenges()).toBe(2);
    expect(reports(service)).toEqual([]);
    guard.stop();
  });
});

describe("answers and bodies (third review F6, F7)", () => {
  it("F6: a 206 Partial Content answer is not hashed", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: { status: 206, body: bytes("first half") } });
    vi.useRealTimers();
    const report = await collect(APP_ID, webcrypto as unknown as GuardCrypto, cleanNavigator(), null, Date.now, {
      aborted: false,
    });
    expect(report).toBeNull();
  });

  /** A fetch that answers when told, whatever the signal says, with a body that never ends. */
  function lateAnswer(cancel: () => unknown = async () => {}) {
    const state = { cancelled: 0, readers: 0 };
    let answer: ((value: unknown) => void) | undefined;
    vi.stubGlobal(
      "fetch",
      () =>
        new Promise((resolve) => {
          answer = resolve;
        }),
    );
    const give = () =>
      answer?.({
        ok: true,
        status: 200,
        type: "basic",
        redirected: false,
        headers: jsHeaders,
        body: {
          getReader: () => {
            state.readers += 1;
            return {
              read: () => new Promise(() => {}),
              cancel: () => {
                state.cancelled += 1;
                return cancel();
              },
            };
          },
        },
      });
    return { state, give };
  }

  it("F7: an answer that arrives after stop() has its body cancelled", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const late = lateAnswer();
    const { guard } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    guard.stop();
    await settle();
    late.give();
    await settle();
    expect(late.state.cancelled).toBeGreaterThanOrEqual(1);
  });

  it.each([
    ["answers with no promise", () => undefined],
    [
      "throws",
      () => {
        throw new Error("locked");
      },
    ],
  ])("a reader whose cancel() %s does not throw out of the budget timer or of stop()", async (_name, cancel) => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    const late = lateAnswer(cancel);
    const { guard, service } = setup();
    await guard.attest();
    await advance(INTEGRITY.delayMs);
    late.give();
    await settle();
    expect(late.state.readers).toBe(1);
    await advance(INTEGRITY.budgetMs); // the budget ends the read
    expect(late.state.cancelled).toBeGreaterThanOrEqual(1);
    expect(() => guard.stop()).not.toThrow();
    expect(unhandled).toEqual([]);
    expect(reports(service)).toEqual([]);
  });
});

describe("stop() and a handshake in flight", () => {
  it("a handshake in flight when stop() is called does not attach a report that became ready before stop()", async () => {
    plant(BUILD, ["main.js"]);
    script("/main.js");
    pageFetch({ [`${ORIGIN}/main.js`]: bytes("x") });
    const service = fakeService({ nowMs: () => Date.now() });
    let release: (() => void) | undefined;
    let hold = false;
    const { guard } = setup({
      fetch: vi.fn<GuardFetch>(async (url, init) => {
        if (hold && url === CHALLENGE_URL) await new Promise<void>((resolve) => (release = resolve));
        return service.fetch(url, init);
      }),
    });
    await guard.attest();
    await advance(INTEGRITY.delayMs - 1);
    hold = true;
    const explicit = guard.attest(); // waits on its challenge
    await advance(1); // the report is ready and waits for this handshake to end
    guard.stop();
    hold = false;
    release?.();
    await explicit;
    await settle();
    expect(reports(service)).toEqual([]);
    // It is not lost: the next handshake of this Guard carries it.
    await guard.attest();
    expect(reports(service)).toHaveLength(1);
    guard.stop();
  });
});

// A randomized differential test: plan() and locate() against a plain reference of the rule, as the third review ran
// against the earlier rule. The generator is the reviewer's.

interface RefScript {
  url: string;
  /** The query string of the URL, "" for none. */
  search: string;
  path: string;
  size: number;
  listed: boolean;
  loaded: boolean;
}

const JS_TYPES = new Set(["", "module"]);
for (const a of ["text", "application"]) {
  for (const x of ["", "x-"]) for (const l of ["java", "ecma"]) JS_TYPES.add(`${a}/${x}${l}script`);
}

function refDecode(pathname: string): string {
  try {
    return pathname
      .split("/")
      .map((segment) => (segment.toLowerCase().includes("%2f") ? segment : decodeURIComponent(segment)))
      .join("/");
  } catch {
    return pathname;
  }
}

interface RefElement {
  kind: "script" | "link";
  attr: string;
  type?: string;
}

/** The qualified scripts of a page, in the order they are first seen (Resource Timing, scripts, links). */
function refScripts(timingList: Entry[] | null, elements: RefElement[]): RefScript[] {
  const seen: RefScript[] = [];
  const get = (value: string): RefScript | undefined => {
    if (value === "" || value.length > 2048) return undefined;
    let url: URL;
    try {
      url = new URL(value, location.href);
    } catch {
      return undefined;
    }
    if (url.origin !== location.origin || (url.protocol !== "http:" && url.protocol !== "https:")) return undefined;
    url.hash = "";
    if (url.href.length > 2048) return undefined;
    let record = seen.find((item) => item.url === url.href);
    if (!record) {
      record = {
        url: url.href,
        search: url.search,
        path: refDecode(url.pathname),
        size: 0,
        listed: false,
        loaded: false,
      };
      seen.push(record);
    }
    return record;
  };
  if (timingList) {
    for (const entry of timingList) {
      const record = get(entry.name);
      if (!record) continue;
      record.loaded = true;
      record.size = Math.max(record.size, entry.decodedBodySize ?? 0);
      if (entry.initiatorType === "script") record.listed = true;
    }
  }
  for (const kind of ["script", "link"] as const) {
    for (const element of elements) {
      if (element.kind !== kind) continue;
      if (kind === "script" && !JS_TYPES.has((element.type ?? "").trim().toLowerCase())) continue;
      const record = get(element.attr);
      if (record) record.listed = true;
    }
  }
  const timed = timingList !== null;
  const full = timed && timingList.length >= 250;
  const out: RefScript[] = [];
  for (const record of seen) {
    if (!record.listed) continue;
    if (timed && !record.loaded) {
      if (!full) continue;
      record.size = Number.POSITIVE_INFINITY;
    }
    out.push(record);
  }
  return out;
}

/**
 * The rule, plainly: per Build the candidates for its first file, and for every candidate the files the Build maps
 * to if that candidate is the one that holds the marker.
 */
function refPlan(markers: { b: unknown; f: unknown }[], scripts: RefScript[], skip: (b: string) => boolean) {
  const builds: { build: string; first: unknown; listed: Map<string, number> }[] = [];
  // (d) The first 64 entries are scanned; the first 8 distinct Builds among them are read.
  for (const marker of markers.slice(0, 64)) {
    if (builds.length >= 8) break;
    if (typeof marker.b !== "string" || !/^bld_[0-9a-f]{24}$/.test(marker.b) || !Array.isArray(marker.f)) continue;
    if (builds.some((build) => build.build === marker.b)) continue;
    const listed = new Map<string, number>(); // path -> first index
    (marker.f as unknown[]).slice(0, 32).forEach((path, i) => {
      if (typeof path === "string" && path.length >= 1 && path.length <= 256 && !listed.has(path)) listed.set(path, i);
    });
    builds.push({ build: marker.b, first: (marker.f as unknown[])[0], listed });
  }
  const out: { build: string; candidates: string[]; mapped: { i: number; url: string; size: number }[][] }[] = [];
  for (const build of builds) {
    if (out.length >= 4 || skip(build.build)) continue;
    const first = build.first;
    if (typeof first !== "string" || !build.listed.has(first)) continue;
    const candidates: RefScript[] = [];
    for (const script of scripts) {
      if (script.path.endsWith(`/${first}`) && !candidates.some((taken) => taken.path === script.path)) {
        candidates.push(script);
      }
    }
    if (candidates.length === 0 || candidates.length > 4) continue;
    // (a) A candidate that cannot be fetched (not vouched for, or over 2 MB) cannot be examined: fail closed.
    if (candidates.some((candidate) => candidate.size > 2 * MB)) continue;
    const others = builds.filter((other) => other.build !== build.build).flatMap((other) => [...other.listed.keys()]);
    const mapped = candidates.map((candidate) => {
      const base = candidate.path.slice(0, candidate.path.length - first.length);
      const files: { i: number; url: string; size: number }[] = [];
      for (const [path, i] of [...build.listed].sort((x, y) => x[1] - y[1])) {
        const at = scripts.filter((item) => item.path === base + path);
        // The first file is the candidate itself; (c) another file is used only when exactly one loaded URL has its
        // path, with the candidate's query string.
        const script = path === first ? candidate : at[0];
        if (!script) continue;
        const usable = path === first || (at.length === 1 && script.search === candidate.search);
        const shared = others.some((path2) => script.path.endsWith(`/${path2}`));
        files.push({ i, url: script.url, size: shared || !usable ? Number.POSITIVE_INFINITY : script.size });
      }
      return files;
    });
    out.push({ build: build.build, candidates: candidates.map((candidate) => candidate.url), mapped });
  }
  return out;
}

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SUBDIRS = ["", "", "utils/", "a/", "a/utils/", "b/", "utils/utils/", "a b/"];
const NAMES = ["index.js", "main.js", "a.js", "m.mjs", "Main.js", "é.js"];
const BASES = ["/", "/a/", "/b/", "/a/b/", "/utils/", "/app/utils/", "/A/", "/app/", "/legacy/"];
const BUILDS = [
  BUILD,
  OTHER,
  "bld_aaaaaaaaaaaaaaaaaaaaaaaa",
  "bld_bbbbbbbbbbbbbbbbbbbbbbbb",
  "bld_cccccccccccccccccccccccc",
];

function generate(random: () => number) {
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)] as T;
  const chance = (p: number) => random() < p;
  const markers: { b: unknown; f: unknown }[] = [];
  const allPaths: string[] = [];
  const buildCount = 1 + Math.floor(random() * (chance(0.1) ? 5 : 3));
  for (let n = 0; n < buildCount; n += 1) {
    const f: unknown[] = [];
    const count = 1 + Math.floor(random() * 6);
    for (let k = 0; k < count; k += 1) {
      if (chance(0.05)) f.push(pick([null, "", 7, "x".repeat(300), "/main.js", "utils/"]));
      else {
        const path = pick(SUBDIRS) + pick(NAMES);
        f.push(path);
        allPaths.push(path);
      }
    }
    if (chance(0.1) && f.length > 0) f.push(f[0]);
    markers.push({ b: chance(0.1) ? pick([BUILD, "bld_bad", 3]) : BUILDS[n], f: chance(0.03) ? "nope" : f });
  }
  const mode = pick(["timed", "timed", "timed", "timed", "none", "full"] as const);
  const timingList: Entry[] = [];
  const elements: RefElement[] = [];
  const count = Math.floor(random() * 9);
  for (let k = 0; k < count; k += 1) {
    let path = pick(BASES) + (chance(0.85) && allPaths.length > 0 ? pick(allPaths) : pick(SUBDIRS) + pick(NAMES));
    if (chance(0.08)) {
      const at = Math.floor(random() * path.length);
      const c = path[at] as string;
      if (/[a-z.]/i.test(c)) path = `${path.slice(0, at)}%${c.charCodeAt(0).toString(16)}${path.slice(at + 1)}`;
    }
    if (chance(0.06)) {
      const at = path.indexOf("/", 1 + Math.floor(random() * path.length));
      if (at > 0) path = `${path.slice(0, at)}${pick(["%2F", "%2f"])}${path.slice(at + 1)}`;
    }
    if (chance(0.04)) path = path.replace("/", pick(["/%ZZ", "/%E0%A4/", "//", "/./", "/x/../"]));
    path = path.replace(/ /g, chance(0.5) ? "%20" : " ");
    let url = (chance(0.08) ? "https://cdn.example" : chance(0.5) ? ORIGIN : "") + path;
    if (chance(0.2)) url += pick(["?v=1", "?v=2", "?", `?${"q".repeat(2100)}`]);
    if (chance(0.1)) url += "#frag";
    const loaded = chance(0.85);
    const size = chance(0.1) ? 3 * MB : chance(0.5) ? 1234 : undefined;
    const source = pick(["script", "script", "script", "link", "timing-script", "timing-other", "both"] as const);
    const name = (() => {
      try {
        return new URL(url, location.href).href.replace(/#.*$/, "");
      } catch {
        return url;
      }
    })();
    const entry = (initiatorType: string): Entry => ({
      name,
      initiatorType,
      ...(size === undefined ? {} : { decodedBodySize: size }),
    });
    if (source === "timing-script") timingList.push(entry("script"));
    else if (source === "timing-other") timingList.push(entry(pick(["other", "fetch", "link"])));
    else {
      const kind = source === "link" ? "link" : "script";
      const type =
        kind === "script" && chance(0.3)
          ? pick([
              "module",
              "text/javascript",
              " Application/X-EcmaScript ",
              "application/json",
              "text/plain",
              "importmap",
            ])
          : undefined;
      elements.push({ kind, attr: url, ...(type === undefined ? {} : { type }) });
      if (loaded) timingList.push(entry(kind));
      if (source === "both" && chance(0.5)) timingList.push(entry("script"));
    }
  }
  if (mode === "full") {
    for (let k = 0; k < 250; k += 1) timingList.push({ name: `${ORIGIN}/img/${k}.png`, initiatorType: "img" });
  }
  if (chance(0.3)) timingList.sort(() => random() - 0.5);
  const skipped = new Set(BUILDS.filter(() => chance(0.15)));
  return { markers, mode, timingList, elements, skipped };
}

describe("plan() and locate() against a reference of the rule", () => {
  const plainJson = (value: unknown) =>
    JSON.stringify(value, (_key, item) => (item === Number.POSITIVE_INFINITY ? "Infinity" : item));

  for (const seed of [1, 2, 3, 20261114, 0xdecafbad]) {
    it(`seed ${seed}: 4,000 generated pages`, () => {
      const random = rng(seed);
      const disagreements: string[] = [];
      const stats = { builds: 0, candidates: 0, files: 0, unfetchable: 0, severalCandidates: 0 };
      for (let n = 0; n < 4_000; n += 1) {
        const page = generate(random);
        document.head.innerHTML = "";
        entries.length = 0;
        for (const element of page.elements) {
          const node = document.createElement(element.kind);
          if (element.kind === "script") {
            if (element.type !== undefined) node.setAttribute("type", element.type);
            node.setAttribute("src", element.attr);
          } else {
            node.setAttribute("rel", "modulepreload");
            node.setAttribute("href", element.attr);
          }
          document.head.appendChild(node);
        }
        entries.push(...page.timingList);
        const spy = vi.spyOn(performance, "getEntriesByType");
        if (page.mode === "none") spy.mockImplementation(() => ({ length: 0 }) as unknown as PerformanceEntryList);
        else {
          spy.mockImplementation((type) =>
            type === "resource" ? ([...entries] as unknown as PerformanceEntryList) : [],
          );
        }
        registry[KEY] = page.markers;
        const skip = (build: string) => page.skipped.has(build);
        const actual = plan(skip).map((planned) => {
          return {
            build: planned.build,
            candidates: planned.candidates.map((script) => script.url),
            mapped: planned.candidates.map((script) => locate(planned, script)),
          };
        });
        const expected = refPlan(
          page.markers,
          refScripts(page.mode === "none" ? null : page.timingList, page.elements),
          skip,
        );
        for (const build of actual) {
          stats.builds += 1;
          stats.candidates += build.candidates.length;
          if (build.candidates.length > 1) stats.severalCandidates += 1;
          for (const file of build.mapped.flat()) {
            stats.files += 1;
            if (file.size === Number.POSITIVE_INFINITY) stats.unfetchable += 1;
          }
        }
        if (plainJson(actual) !== plainJson(expected)) {
          disagreements.push(
            plainJson({ n, page: { ...page, skipped: [...page.skipped] }, actual, expected }).slice(0, 3000),
          );
          if (disagreements.length >= 3) break;
        }
      }
      console.info(`differential seed ${seed}: ${JSON.stringify(stats)}`);
      expect(stats.builds).toBeGreaterThan(500);
      expect(stats.severalCandidates).toBeGreaterThan(50);
      expect(disagreements).toEqual([]);
    }, 120_000);
  }
});

describe("worst-case time of plan() (third review F8, PB-06)", () => {
  it("64 Builds of 32 nested same-name paths, 1,500 long scripts that end like all of them", () => {
    const nested = Array.from({ length: 32 }, (_, i) => `${"dddddd/".repeat(i)}x.js`);
    const long = "dddddd/".repeat(280); // ~1.96 KB
    const names = Array.from({ length: 3 * INTEGRITY.scanMax }, (_, i) => `${ORIGIN}/${long}x.js?${i}`);
    const third = INTEGRITY.scanMax;
    vi.spyOn(Document.prototype, "querySelectorAll").mockImplementation(((selector: string) =>
      (selector.startsWith("script") ? names.slice(third, 2 * third) : names.slice(2 * third)).map((src) => ({
        src,
        href: src,
        getAttribute: () => null,
      }))) as unknown as typeof document.querySelectorAll);
    timing(names.map((name) => ({ name, initiatorType: "script" })));
    const best = (markers: unknown) => {
      registry[KEY] = markers;
      let elapsed = Number.POSITIVE_INFINITY;
      for (let run = 0; run < 5; run += 1) {
        const started = performance.now();
        const planned = plan(() => false);
        for (const build of planned) for (const script of build.candidates) locate(build, script);
        elapsed = Math.min(elapsed, performance.now() - started);
      }
      return elapsed;
    };
    const build = (n: number) => `bld_${String(n).padStart(24, "0")}`;
    const a = best(Array.from({ length: 64 }, (_, n) => ({ b: build(n), f: nested })));
    const b = best(
      Array.from({ length: 64 }, (_, n) => ({
        b: build(n),
        f: ["x.js", ...Array.from({ length: 31 }, (_, i) => `q${i}/x.js`)],
      })),
    );
    console.info(`guard integrity plan(), third review shapes: A ${a.toFixed(2)} ms, B ${b.toFixed(2)} ms`);
    expect(Math.max(a, b)).toBeLessThan(25);
  });

  it("at most 8 distinct Builds are read", () => {
    registry[KEY] = Array.from({ length: 12 }, (_, n) => ({
      b: `bld_${String(n).padStart(24, "0")}`,
      f: [`f${n}.js`],
    }));
    for (let n = 0; n < 12; n += 1) script(`/f${n}.js`);
    const reported = new Set<string>();
    const seen: string[] = [];
    for (let round = 0; round < 12; round += 1) {
      const [next] = plan((build) => reported.has(build));
      if (!next) break;
      reported.add(next.build);
      seen.push(next.build);
    }
    expect(seen).toHaveLength(8);
    expect(INTEGRITY.markersMax).toBe(8);
  });

  it("a Build registered after 8 repeats of another is still read, and the cross-Build rule still applies", () => {
    const a = { b: BUILD, f: ["a/main.js", "shared.js"] };
    registry[KEY] = [...Array.from({ length: 8 }, () => a), { b: OTHER, f: ["b/main.js", "shared.js"] }];
    for (const path of ["/app/a/main.js", "/app/b/main.js", "/app/shared.js"]) script(path);
    expect(plan(() => false).map((planned) => planned.build)).toEqual([BUILD, OTHER]);
    expect(mapped()).toEqual([
      { i: 0, url: `${ORIGIN}/app/a/main.js`, size: 0 },
      { i: 1, url: `${ORIGIN}/app/shared.js`, size: Number.POSITIVE_INFINITY },
    ]);
  });

  it("at most 64 registry entries are scanned", () => {
    const filler = { b: BUILD, f: ["a/main.js"] };
    registry[KEY] = [...Array.from({ length: 64 }, () => filler), { b: OTHER, f: ["b/main.js"] }];
    script("/app/b/main.js");
    expect(plan(() => false)).toEqual([]);
    expect(INTEGRITY.entriesMax).toBe(64);
  });
});
