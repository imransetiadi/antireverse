// Request signing (slice 04): sign() and fetch(). Every signature is checked with the protocol's reference verifier
// against the public key Guard sent at attest and the jti of the token it received; every content hash against
// node:crypto.
import { createHash, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ATTESTATION_PATTERNS,
  CONTENT_HASH_HEADER,
  EMPTY_CONTENT_SHA256,
  parseSignatureHeader,
  SIGNATURE_HEADER,
} from "../../protocol/src/index.ts";
import { verifyAttestationToken, verifyRequestSignature } from "../../protocol/src/server.ts";
import { createGuard, type Guard, type GuardFetch, type GuardOptions } from "../src/index.js";
import {
  APP_ID,
  ATTEST_URL,
  cleanNavigator,
  ENDPOINT,
  fakeService,
  KEYS,
  memoryStorage,
  response,
  spyCrypto,
  throwingStorage,
} from "./helpers.ts";

const API = "https://api.example.test";

function setup(overrides: Partial<GuardOptions> = {}) {
  const service = fakeService();
  const spy = spyCrypto();
  const guard = createGuard({
    appId: APP_ID,
    endpoint: ENDPOINT,
    fetch: service.fetch,
    crypto: spy.crypto,
    storage: memoryStorage(),
    navigator: cleanNavigator(),
    ...overrides,
  });
  return { guard, service, spy };
}

/** The public JWK Guard sent at attest and the jti of the token it received (read from the verified token). */
function binding(service: ReturnType<typeof fakeService>, token: string) {
  const attest = [...service.requests].reverse().find((request) => request.url === ATTEST_URL);
  const jwk = (attest?.body as { cnf: { jwk: unknown } } | undefined)?.cnf.jwk;
  const verified = verifyAttestationToken(token, KEYS, { appId: APP_ID, nowS: Math.floor(Date.now() / 1000) });
  if (verified.status !== "valid") throw new Error("token did not verify");
  return { jwk, jti: verified.claims.jti };
}

const sha256 = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("base64url");
/** What fetch sends as the content type of a string body, and Guard signs (review F1). */
const TEXT_TYPE = "text/plain;charset=UTF-8";
/** What fetch sends as the content type of a URLSearchParams body. */
const FORM_TYPE = "application/x-www-form-urlencoded;charset=UTF-8";
const nowS = () => Math.floor(Date.now() / 1000);

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("sign()", () => {
  it("attests first when there is no token, and returns the three headers; the signature verifies", async () => {
    const { guard, service } = setup();
    const headers = await guard.sign({ method: "GET", url: `${API}/v1/items?x=1&y=2` });
    guard.stop();

    expect(Object.keys(headers).sort()).toEqual(["ar-attestation", "ar-content-sha256", "ar-signature"]);
    const token = guard.token();
    expect(token).toEqual(expect.any(String));
    expect(headers["ar-attestation"]).toBe(token);
    expect(headers[CONTENT_HASH_HEADER]).toBe(EMPTY_CONTENT_SHA256);
    const parsed = parseSignatureHeader(headers[SIGNATURE_HEADER]);
    expect(parsed).not.toBeNull();
    expect(parsed?.n).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(parsed?.s).toMatch(/^[A-Za-z0-9_-]{86}$/);

    const { jwk, jti } = binding(service, token ?? "");
    expect(jti).toMatch(ATTESTATION_PATTERNS.jti);
    expect(
      verifyRequestSignature({
        method: "GET",
        target: "/v1/items?x=1&y=2",
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      }),
    ).toBe("valid");
  });

  it("concurrent calls without a token share one attest; later calls reuse the token", async () => {
    const { guard, service } = setup();
    const all = await Promise.all([
      guard.sign({ method: "GET", url: `${API}/a` }),
      guard.sign({ method: "GET", url: `${API}/b` }),
      guard.sign({ method: "GET", url: `${API}/c` }),
    ]);
    await guard.sign({ method: "GET", url: `${API}/d` });
    guard.stop();
    expect(service.challenges()).toBe(1);
    for (const headers of all) expect(headers[SIGNATURE_HEADER]).toEqual(expect.any(String));
  });

  it("signs with the non-extractable session key whose public half was sent at attest", async () => {
    const { guard, spy } = setup();
    const signSpy = vi.spyOn(spy.crypto.subtle as { sign: (...args: unknown[]) => unknown }, "sign");
    await guard.sign({ method: "GET", url: `${API}/a` });
    guard.stop();
    expect(spy.generateKey).toHaveBeenCalledTimes(1);
    expect(signSpy).toHaveBeenCalledTimes(1);
    expect(signSpy.mock.calls[0]?.[0]).toEqual({ name: "ECDSA", hash: "SHA-256" });
    expect(signSpy.mock.calls[0]?.[1]).toBe(spy.pairs[0]?.privateKey);
    expect(spy.pairs[0]?.privateKey.extractable).toBe(false);
  });

  it("signs the target as the browser sends it: resolved against location.href, path and query only", async () => {
    vi.stubGlobal("location", { href: "https://app.example.test/shop/page.html?old=1#top" });
    const { guard, service } = setup();
    const headers = await guard.sign({ method: "POST", url: "../api/x y?q=a b&é=1#frag", body: "" });
    guard.stop();
    const { jwk, jti } = binding(service, guard.token() ?? "");
    const check = (target: string) =>
      verifyRequestSignature({
        method: "POST",
        target,
        contentType: TEXT_TYPE,
        contentSha256: EMPTY_CONTENT_SHA256,
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      });
    const expected = new URL("../api/x y?q=a b&é=1#frag", "https://app.example.test/shop/page.html").href;
    const url = new URL(expected);
    expect(check(url.pathname + url.search)).toBe("valid");
    expect(url.pathname + url.search).toBe("/api/x%20y?q=a%20b&%C3%A9=1");
    expect(check("/api/x y?q=a b&é=1")).toBe("invalid");
  });

  it("upper-cases the method in the canonical string", async () => {
    const { guard, service } = setup();
    const headers = await guard.sign({ method: "post", url: `${API}/p`, body: "x" });
    guard.stop();
    const { jwk, jti } = binding(service, guard.token() ?? "");
    expect(
      verifyRequestSignature({
        method: "POST",
        target: "/p",
        contentType: TEXT_TYPE,
        contentSha256: sha256("x"),
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      }),
    ).toBe("valid");
  });

  it("defaults the method to GET", async () => {
    const { guard, service } = setup();
    const headers = await guard.sign({ url: `${API}/g` });
    guard.stop();
    const { jwk, jti } = binding(service, guard.token() ?? "");
    const verify = (method: string) =>
      verifyRequestSignature({
        method,
        target: "/g",
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      });
    expect(verify("GET")).toBe("valid");
  });

  const text = "héllo ✓ — 𝄞";
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255, 10, 13]);
  const backing = new Uint8Array([9, 9, 9, ...bytes, 9, 9]);
  // The content type is the one fetch itself sends for the body; Guard returns it as a header when it chose it.
  it.each<[string, () => unknown, Uint8Array | string, string]>([
    ["no body (undefined)", () => undefined, "", ""],
    ["no body (null)", () => null, "", ""],
    ["an empty string", () => "", "", TEXT_TYPE],
    ["a string (UTF-8)", () => text, text, TEXT_TYPE],
    ["an ArrayBuffer", () => bytes.slice().buffer, bytes, ""],
    ["a Uint8Array view at an offset", () => backing.subarray(3, 3 + bytes.length), bytes, ""],
    ["a DataView at an offset", () => new DataView(backing.buffer, 3, bytes.length), bytes, ""],
    ["a Uint16Array", () => new Uint16Array([1, 0xffff]), new Uint8Array(new Uint16Array([1, 0xffff]).buffer), ""],
    ["a Blob without a type", () => new Blob([text]), text, ""],
    ["a Blob with a type", () => new Blob([text], { type: "application/json" }), text, "application/json"],
    [
      "URLSearchParams",
      () => new URLSearchParams({ q: "a b", é: "✓" }),
      new URLSearchParams({ q: "a b", é: "✓" }).toString(),
      FORM_TYPE,
    ],
  ])("hashes %s exactly and signs that hash and its content type", async (_name, body, expectedBytes, contentType) => {
    const { guard, service } = setup();
    const headers = await guard.sign({ method: "POST", url: `${API}/b`, body: body() });
    guard.stop();
    const hash = sha256(expectedBytes);
    expect(headers[CONTENT_HASH_HEADER]).toBe(hash);
    if (contentType === "") expect(headers).not.toHaveProperty("content-type");
    else expect(headers["content-type"]).toBe(contentType);
    const { jwk, jti } = binding(service, guard.token() ?? "");
    expect(
      verifyRequestSignature({
        method: "POST",
        target: "/b",
        contentType: contentType,
        contentSha256: hash,
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      }),
    ).toBe("valid");
  });

  it.each<[string, () => unknown]>([
    ["FormData", () => new FormData()],
    ["a ReadableStream", () => new ReadableStream()],
    ["a plain object", () => ({ a: 1 })],
    ["a number", () => 42],
    ["a SharedArrayBuffer", () => new SharedArrayBuffer(4)],
  ])("does not sign %s: attestation header only", async (_name, body) => {
    const { guard } = setup();
    const headers = await guard.sign({ method: "POST", url: `${API}/u`, body: body() });
    guard.stop();
    expect(headers).toEqual({ "ar-attestation": guard.token() });
  });

  it("review F1: signs the caller's content type as given (any spelling), and then sets none itself", async () => {
    const { guard, service } = setup();
    const type = "Application/JSON; charset=utf-8";
    const headers = await guard.sign({
      method: "POST",
      url: `${API}/j`,
      body: '{"a":1}',
      headers: { "Content-Type": type },
    });
    const bare = await guard.sign({
      method: "GET",
      url: `${API}/g`,
      headers: new Headers({ "content-type": "text/csv" }),
    });
    guard.stop();
    expect(headers).not.toHaveProperty("content-type");
    const { jwk, jti } = binding(service, guard.token() ?? "");
    const verify = (header: string | undefined, contentType: string, method = "POST", target = "/j") =>
      verifyRequestSignature({
        method,
        target,
        contentType,
        contentSha256: method === "GET" ? EMPTY_CONTENT_SHA256 : sha256('{"a":1}'),
        header,
        jti,
        jwk,
        nowS: nowS(),
      });
    expect(verify(headers[SIGNATURE_HEADER], type)).toBe("valid");
    expect(verify(headers[SIGNATURE_HEADER], TEXT_TYPE)).toBe("invalid");
    expect(verify(headers[SIGNATURE_HEADER], "")).toBe("invalid");
    // A content type without a body is signed too: it is sent.
    expect(verify(bare[SIGNATURE_HEADER], "text/csv", "GET", "/g")).toBe("valid");
  });

  it("review F1: unreadable caller headers leave the request unsigned (attestation only)", async () => {
    const { guard } = setup();
    await guard.attest();
    // As a browser's Headers does for a value it cannot read (happy-dom's is lenient).
    vi.stubGlobal(
      "Headers",
      class {
        constructor() {
          throw new TypeError("Failed to construct 'Headers'");
        }
      },
    );
    const headers = await guard.sign({ method: "POST", url: `${API}/j`, body: "x", headers: { "content-type": "x" } });
    // Without caller headers no Headers is needed: still signed.
    const plain = await guard.sign({ method: "POST", url: `${API}/j`, body: "x" });
    guard.stop();
    expect(headers).toEqual({ "ar-attestation": guard.token() });
    expect(plain[SIGNATURE_HEADER]).toEqual(expect.any(String));
  });

  it("review F4: signs the exact serialised target: an empty query stays, a fragment goes", async () => {
    const { guard, service } = setup();
    const empty = await guard.sign({ method: "GET", url: `${API}/v1/items?` });
    const fragment = await guard.sign({ method: "GET", url: `${API}/v1/items?x=1#frag` });
    const both = await guard.sign({ method: "GET", url: `${API}/v1/items?#frag` });
    guard.stop();
    const { jwk, jti } = binding(service, guard.token() ?? "");
    const verify = (header: string | undefined, target: string) =>
      verifyRequestSignature({
        method: "GET",
        target,
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        header,
        jti,
        jwk,
        nowS: nowS(),
      });
    expect(verify(empty[SIGNATURE_HEADER], "/v1/items?")).toBe("valid");
    expect(verify(empty[SIGNATURE_HEADER], "/v1/items")).toBe("invalid");
    expect(verify(fragment[SIGNATURE_HEADER], "/v1/items?x=1")).toBe("valid");
    expect(verify(both[SIGNATURE_HEADER], "/v1/items?")).toBe("valid");
  });

  it("binds every field: another method, target, body, t, n or jti fails", async () => {
    const { guard, service } = setup();
    const headers = await guard.sign({ method: "PUT", url: `${API}/r?id=1`, body: "payload" });
    guard.stop();
    const { jwk, jti } = binding(service, guard.token() ?? "");
    const header = headers[SIGNATURE_HEADER] ?? "";
    const parsed = parseSignatureHeader(header);
    if (!parsed) throw new Error("no signature");
    const base = {
      method: "PUT",
      target: "/r?id=1",
      contentType: TEXT_TYPE,
      contentSha256: sha256("payload"),
      header,
      jti,
      jwk,
      nowS: parsed.t,
    };
    expect(verifyRequestSignature(base)).toBe("valid");
    const otherNonce = `${parsed.n[0] === "A" ? "B" : "A"}${parsed.n.slice(1)}`;
    expect(verifyRequestSignature({ ...base, method: "POST" })).toBe("invalid");
    expect(verifyRequestSignature({ ...base, target: "/r?id=2" })).toBe("invalid");
    expect(verifyRequestSignature({ ...base, contentSha256: sha256("payloaD") })).toBe("invalid");
    expect(verifyRequestSignature({ ...base, header: `v1,t=${parsed.t + 1},n=${parsed.n},s=${parsed.s}` })).toBe(
      "invalid",
    );
    expect(verifyRequestSignature({ ...base, header: `v1,t=${parsed.t},n=${otherNonce},s=${parsed.s}` })).toBe(
      "invalid",
    );
    expect(verifyRequestSignature({ ...base, jti: "0".repeat(32) })).toBe("invalid");
  });

  it("uses a fresh 128-bit nonce on every call", async () => {
    const { guard } = setup();
    const nonces = new Set<string>();
    for (let i = 0; i < 25; i += 1) {
      const headers = await guard.sign({ method: "GET", url: `${API}/n` });
      const parsed = parseSignatureHeader(headers[SIGNATURE_HEADER]);
      if (!parsed) throw new Error("no signature");
      nonces.add(parsed.n);
    }
    guard.stop();
    expect(nonces.size).toBe(25);
  });

  it("takes t from the injected clock, in whole seconds", async () => {
    const at = 1_800_000_000_987;
    const service = fakeService({ nowMs: () => at });
    const { guard } = setup({ now: () => at, fetch: service.fetch });
    const headers = await guard.sign({ method: "GET", url: `${API}/t` });
    guard.stop();
    const parsed = parseSignatureHeader(headers[SIGNATURE_HEADER]);
    expect(parsed?.t).toBe(1_800_000_000);
  });
});

describe("sign() never throws", () => {
  async function expectResolves(guard: Guard, input: unknown, expected: "none" | "attestation") {
    const headers = await guard.sign(input as Parameters<Guard["sign"]>[0]);
    guard.stop();
    if (expected === "none") expect(headers).toEqual({});
    else expect(headers).toEqual({ "ar-attestation": guard.token() });
  }

  it("when attestation fails: no header", async () => {
    const { guard } = setup({ fetch: vi.fn<GuardFetch>(async () => Promise.reject(new TypeError("down"))) });
    await expectResolves(guard, { method: "GET", url: `${API}/x` }, "none");
  });

  it("when crypto.subtle.sign rejects: attestation only", async () => {
    const spy = spyCrypto();
    const crypto = {
      ...spy.crypto,
      subtle: { ...spy.crypto.subtle, sign: async () => Promise.reject(new Error("OperationError")) },
    } as GuardOptions["crypto"];
    const { guard } = setup({ crypto });
    await expectResolves(guard, { method: "GET", url: `${API}/x` }, "attestation");
  });

  it("when crypto.subtle.sign is missing (an older injected crypto): attestation only", async () => {
    const spy = spyCrypto();
    const { sign: _sign, ...subtle } = spy.crypto.subtle as unknown as Record<string, unknown>;
    const { guard } = setup({ crypto: { ...spy.crypto, subtle } as unknown as GuardOptions["crypto"] });
    await expectResolves(guard, { method: "GET", url: `${API}/x` }, "attestation");
  });

  it("when crypto.subtle.sign throws synchronously: attestation only", async () => {
    const spy = spyCrypto();
    const sign = () => {
      throw new Error("sync");
    };
    const crypto = { ...spy.crypto, subtle: { ...spy.crypto.subtle, sign } } as GuardOptions["crypto"];
    const { guard } = setup({ crypto });
    await expectResolves(guard, { method: "GET", url: `${API}/x` }, "attestation");
  });

  it("when storage throws: still signs", async () => {
    const { guard } = setup({ storage: throwingStorage });
    const headers = await guard.sign({ method: "GET", url: `${API}/x` });
    guard.stop();
    expect(headers[SIGNATURE_HEADER]).toEqual(expect.any(String));
  });

  it.each([
    ["an invalid URL", { method: "GET", url: "http://[bad" }],
    ["a relative URL without a base", { method: "GET", url: "/rel" }],
    ["a URL that is not a string", { method: "GET", url: 42 }],
    ["a method that is not a string", { method: 7, url: `${API}/x` }],
    ["a method with a line feed", { method: "GET\nX", url: `${API}/x` }],
  ])("for %s: attestation only", async (_name, input) => {
    vi.stubGlobal("location", undefined);
    const { guard } = setup();
    await expectResolves(guard, input, "attestation");
  });

  it.each([
    ["undefined", undefined],
    ["null", null],
    ["a string", "https://x.test/"],
  ])("when the argument is %s: attestation only", async (_name, input) => {
    const { guard } = setup();
    await expectResolves(guard, input, "attestation");
  });

  it("when a getter of the argument throws: attestation only", async () => {
    const { guard } = setup();
    const input = {
      method: "GET",
      get url(): string {
        throw new Error("boom");
      },
    };
    await expectResolves(guard, input, "attestation");
  });

  it("when a Blob's arrayBuffer() rejects: attestation only", async () => {
    const { guard } = setup();
    const blob = new Blob(["x"]);
    blob.arrayBuffer = () => Promise.reject(new Error("NotReadableError"));
    await expectResolves(guard, { method: "POST", url: `${API}/x`, body: blob }, "attestation");
  });

  it.each([
    ["a payload that is not base64url JSON", "aaa.bbb.ccc"],
    ["a payload without jti", `aaa.${Buffer.from(JSON.stringify({ sub: "x" })).toString("base64url")}.ccc`],
    ["a jti of the wrong shape", `aaa.${Buffer.from(JSON.stringify({ jti: "xyz\nq" })).toString("base64url")}.ccc`],
  ])("when the token has %s: attestation only", async (_name, token) => {
    const service = fakeService();
    const fetch = vi.fn<GuardFetch>(async (url, init) => {
      const answer = await service.fetch(url, init);
      if (url !== ATTEST_URL) return answer;
      return response(200, { token, expires_at: new Date(Date.now() + 300_000).toISOString() });
    });
    const { guard } = setup({ fetch });
    await expectResolves(guard, { method: "GET", url: `${API}/x` }, "attestation");
    expect(guard.token()).toBe(token);
  });

  it("an inert Guard (unreadable options) resolves {}", async () => {
    const guard = createGuard(null as unknown as GuardOptions);
    await expect(guard.sign({ method: "GET", url: `${API}/x` })).resolves.toEqual({});
  });

  it("logs nothing", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((level) => vi.spyOn(console, level));
    const { guard } = setup();
    await guard.sign({ method: "GET", url: `${API}/x` });
    await guard.sign({ method: "GET", url: "http://[bad" });
    guard.stop();
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    for (const spy of spies) spy.mockRestore();
  });
});

describe("fetch()", () => {
  /** The headers a recorded page call carried (Guard always sends them as a plain record). */
  const sentHeaders = (call: { init: RequestInit | undefined } | undefined) =>
    (call?.init?.headers ?? {}) as Record<string, string>;

  /** The page's fetch: records each call and answers 200. */
  function pageFetch() {
    const calls: { input: unknown; init: RequestInit | undefined; receiver: unknown }[] = [];
    const fn = vi.fn(function (this: unknown, input: unknown, init?: RequestInit) {
      calls.push({ input, init, receiver: this });
      return Promise.resolve(new Response("ok"));
    });
    vi.stubGlobal("fetch", fn);
    return { fn, calls };
  }

  it("sends to the signed URL with the Guard headers merged into the caller's, through the global fetch", async () => {
    const page = pageFetch();
    const { guard, service } = setup();
    const res = await guard.fetch(`${API}/v1/orders?id=7`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Trace": "abc" },
      body: '{"qty":2}',
    });
    guard.stop();
    expect(await res.text()).toBe("ok");
    expect(page.calls.length).toBe(1);
    const call = page.calls[0];
    expect(call?.receiver).toBe(globalThis);
    expect(call?.input).toBe(`${API}/v1/orders?id=7`);
    expect(call?.init?.method).toBe("POST");
    expect(call?.init?.body).toBe('{"qty":2}');
    const headers = call?.init?.headers as Record<string, string>;
    expect(headers["content-type"]).toBe("application/json");
    expect(headers["x-trace"]).toBe("abc");
    expect(headers["ar-attestation"]).toBe(guard.token());
    expect(headers[CONTENT_HASH_HEADER]).toBe(sha256('{"qty":2}'));

    const sent = new URL(call?.input as string);
    const { jwk, jti } = binding(service, guard.token() ?? "");
    expect(
      verifyRequestSignature({
        method: "POST",
        target: sent.pathname + sent.search,
        contentType: "application/json",
        contentSha256: headers[CONTENT_HASH_HEADER] ?? "",
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      }),
    ).toBe("valid");
  });

  it("sends the normalised href it signed (relative input resolved against location.href)", async () => {
    vi.stubGlobal("location", { href: "https://app.example.test/shop/" });
    const page = pageFetch();
    const { guard, service } = setup();
    await guard.fetch("api/a b?x=ü");
    guard.stop();
    const sent = page.calls[0]?.input as string;
    expect(sent).toBe("https://app.example.test/shop/api/a%20b?x=%C3%BC");
    const headers = page.calls[0]?.init?.headers as Record<string, string>;
    const { jwk, jti } = binding(service, guard.token() ?? "");
    expect(
      verifyRequestSignature({
        method: "GET",
        target: "/shop/api/a%20b?x=%C3%BC",
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      }),
    ).toBe("valid");
  });

  it("review F4: fetches the exact href it signed: '?' kept, fragment dropped", async () => {
    const page = pageFetch();
    const { guard, service } = setup();
    await guard.fetch(`${API}/v1/items?`);
    await guard.fetch(`${API}/v1/items?x=1#frag`);
    guard.stop();
    expect(page.calls[0]?.input).toBe(`${API}/v1/items?`);
    expect(page.calls[1]?.input).toBe(`${API}/v1/items?x=1`);
    const { jwk, jti } = binding(service, guard.token() ?? "");
    const verify = (i: number, target: string) =>
      verifyRequestSignature({
        method: "GET",
        target,
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        header: sentHeaders(page.calls[i])[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      });
    expect(verify(0, "/v1/items?")).toBe("valid");
    expect(verify(1, "/v1/items?x=1")).toBe("valid");
  });

  it.each<[string, () => BodyInit, string]>([
    ["a string", () => '{"qty":2}', TEXT_TYPE],
    ["URLSearchParams", () => new URLSearchParams({ q: "a b" }), FORM_TYPE],
    ["a typed Blob", () => new Blob(["x"], { type: "image/png" }), "image/png"],
  ])(
    "review F1: with %s and no caller content type, sends and signs the type fetch would send",
    async (_n, body, type) => {
      const page = pageFetch();
      const { guard, service } = setup();
      const given = body();
      await guard.fetch(`${API}/t`, { method: "POST", body: given });
      guard.stop();
      const headers = sentHeaders(page.calls[0]);
      expect(headers["content-type"]).toBe(type);
      const { jwk, jti } = binding(service, guard.token() ?? "");
      expect(
        verifyRequestSignature({
          method: "POST",
          target: "/t",
          contentType: type,
          contentSha256: headers[CONTENT_HASH_HEADER] ?? "",
          header: headers[SIGNATURE_HEADER],
          jti,
          jwk,
          nowS: nowS(),
        }),
      ).toBe("valid");
    },
  );

  it("review F1: bytes without a caller content type go out without one, signed with an empty type", async () => {
    const page = pageFetch();
    const { guard, service } = setup();
    await guard.fetch(`${API}/t`, { method: "POST", body: new Uint8Array([1, 2, 3]) });
    guard.stop();
    const headers = sentHeaders(page.calls[0]);
    expect(headers).not.toHaveProperty("content-type");
    const { jwk, jti } = binding(service, guard.token() ?? "");
    const verify = (contentType: string) =>
      verifyRequestSignature({
        method: "POST",
        target: "/t",
        contentType,
        contentSha256: headers[CONTENT_HASH_HEADER] ?? "",
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      });
    expect(verify("")).toBe("valid");
  });

  it("review F1: a Request's own content type is signed as given", async () => {
    const page = pageFetch();
    const { guard, service } = setup();
    const request = new Request(`${API}/rq`, { method: "GET", headers: { "Content-Type": "application/x-custom" } });
    await guard.fetch(request);
    guard.stop();
    const headers = sentHeaders(page.calls[0]);
    expect(headers["content-type"]).toBe("application/x-custom");
    const { jwk, jti } = binding(service, guard.token() ?? "");
    expect(
      verifyRequestSignature({
        method: "GET",
        target: "/rq",
        contentType: "application/x-custom",
        contentSha256: EMPTY_CONTENT_SHA256,
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      }),
    ).toBe("valid");
  });

  it("accepts a URL object", async () => {
    const page = pageFetch();
    const { guard } = setup();
    await guard.fetch(new URL(`${API}/u?z=1`));
    guard.stop();
    expect(page.calls[0]?.input).toBe(`${API}/u?z=1`);
    expect(sentHeaders(page.calls[0])[SIGNATURE_HEADER]).toEqual(expect.any(String));
  });

  it.each<[string, () => HeadersInit]>([
    ["a Headers object", () => new Headers({ "X-A": "1", Accept: "text/plain" })],
    [
      "an array of pairs",
      () => [
        ["X-A", "1"],
        ["Accept", "text/plain"],
      ],
    ],
    ["a record", () => ({ "X-A": "1", Accept: "text/plain" })],
  ])("keeps caller headers given as %s", async (_name, headersInit) => {
    const page = pageFetch();
    const { guard } = setup();
    await guard.fetch(`${API}/h`, { headers: headersInit() });
    guard.stop();
    const headers = page.calls[0]?.init?.headers as Record<string, string>;
    expect(headers["x-a"]).toBe("1");
    expect(headers.accept).toBe("text/plain");
    expect(headers[SIGNATURE_HEADER]).toEqual(expect.any(String));
  });

  it("replaces caller values of the Guard headers only", async () => {
    const page = pageFetch();
    const { guard } = setup();
    await guard.fetch(`${API}/h`, {
      headers: { "ar-signature": "forged", "ar-content-sha256": "forged", "ar-attestation": "forged", "x-b": "2" },
    });
    guard.stop();
    const headers = page.calls[0]?.init?.headers as Record<string, string>;
    expect(headers["x-b"]).toBe("2");
    expect(headers["ar-attestation"]).toBe(guard.token());
    expect(headers[SIGNATURE_HEADER]).not.toBe("forged");
    expect(headers[CONTENT_HASH_HEADER]).toBe(EMPTY_CONTENT_SHA256);
  });

  it("never adds credentials, and keeps the caller's setting and other options", async () => {
    const page = pageFetch();
    const { guard } = setup();
    await guard.fetch(`${API}/c`);
    await guard.fetch(`${API}/c`, { method: "DELETE" });
    const controller = new AbortController();
    await guard.fetch(`${API}/c`, { credentials: "include", mode: "cors", signal: controller.signal });
    guard.stop();
    expect(page.calls[0]?.init).not.toHaveProperty("credentials");
    expect(page.calls[1]?.init).not.toHaveProperty("credentials");
    expect(page.calls[1]?.init?.method).toBe("DELETE");
    expect(page.calls[2]?.init?.credentials).toBe("include");
    expect(page.calls[2]?.init?.mode).toBe("cors");
    expect(page.calls[2]?.init?.signal).toBe(controller.signal);
  });

  it("with a Request input: signs its method and URL, keeps its headers, and sends the Request", async () => {
    const page = pageFetch();
    const { guard, service } = setup();
    const request = new Request(`${API}/req?a=1`, { method: "DELETE", headers: { "X-R": "r" } });
    await guard.fetch(request);
    guard.stop();
    expect(page.calls[0]?.input).toBe(request);
    const headers = page.calls[0]?.init?.headers as Record<string, string>;
    expect(headers["x-r"]).toBe("r");
    const { jwk, jti } = binding(service, guard.token() ?? "");
    expect(
      verifyRequestSignature({
        method: "DELETE",
        target: "/req?a=1",
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        header: headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: nowS(),
      }),
    ).toBe("valid");
  });

  it("with a Request that carries its own body: attestation only (the stream is not read)", async () => {
    const page = pageFetch();
    const { guard } = setup();
    const request = new Request(`${API}/req`, { method: "POST", body: "streamed" });
    await guard.fetch(request);
    guard.stop();
    const headers = page.calls[0]?.init?.headers as Record<string, string>;
    expect(headers).toEqual({ "content-type": "text/plain;charset=UTF-8", "ar-attestation": guard.token() });
    expect(request.bodyUsed).toBe(false);
  });

  it("an unsupported body is sent unchanged with the attestation only", async () => {
    const page = pageFetch();
    const { guard } = setup();
    const form = new FormData();
    form.append("a", "1");
    await guard.fetch(`${API}/f`, { method: "POST", body: form });
    guard.stop();
    expect(page.calls[0]?.init?.body).toBe(form);
    expect(page.calls[0]?.init?.headers).toEqual({ "ar-attestation": guard.token() });
  });

  it("still sends the request when attestation fails", async () => {
    const page = pageFetch();
    const { guard } = setup({ fetch: vi.fn<GuardFetch>(async () => Promise.reject(new TypeError("down"))) });
    await guard.fetch(`${API}/s`, { headers: { "x-c": "3" } });
    guard.stop();
    expect(page.calls.length).toBe(1);
    expect(page.calls[0]?.input).toBe(`${API}/s`);
    expect(page.calls[0]?.init?.headers).toEqual({ "x-c": "3" });
  });

  it("still sends the request when signing fails", async () => {
    const page = pageFetch();
    const spy = spyCrypto();
    const crypto = {
      ...spy.crypto,
      subtle: { ...spy.crypto.subtle, sign: async () => Promise.reject(new Error("OperationError")) },
    } as GuardOptions["crypto"];
    const { guard } = setup({ crypto });
    await guard.fetch(`${API}/s`);
    guard.stop();
    expect(page.calls[0]?.init?.headers).toEqual({ "ar-attestation": guard.token() });
  });

  it("passes an input it cannot resolve through unchanged, so fetch rejects as it would", async () => {
    vi.stubGlobal("location", undefined);
    const page = pageFetch();
    const { guard } = setup();
    await guard.fetch("/relative-without-base");
    guard.stop();
    expect(page.calls[0]?.input).toBe("/relative-without-base");
  });

  it("rejects exactly as fetch does on a network error", async () => {
    const failure = new TypeError("Failed to fetch");
    vi.stubGlobal("fetch", () => Promise.reject(failure));
    const { guard } = setup();
    await expect(guard.fetch(`${API}/n`)).rejects.toBe(failure);
    guard.stop();
  });

  it("rejects with a TypeError when there is no fetch at all", async () => {
    vi.stubGlobal("fetch", undefined);
    const { guard } = setup();
    await expect(guard.fetch(`${API}/n`)).rejects.toBeInstanceOf(TypeError);
    guard.stop();
  });

  it("an inert Guard passes the request through to the global fetch unchanged", async () => {
    const page = pageFetch();
    const guard = createGuard(null as unknown as GuardOptions);
    const init = { headers: { "x-d": "4" } };
    await guard.fetch(`${API}/i`, init);
    expect(page.calls[0]?.input).toBe(`${API}/i`);
    expect(page.calls[0]?.init).toBe(init);
  });

  it("works with the real Node WebCrypto object injected as is", async () => {
    const page = pageFetch();
    const { guard } = setup({ crypto: webcrypto as unknown as GuardOptions["crypto"] });
    await guard.fetch(`${API}/w`);
    guard.stop();
    expect(sentHeaders(page.calls[0])[SIGNATURE_HEADER]).toEqual(expect.any(String));
  });
});
