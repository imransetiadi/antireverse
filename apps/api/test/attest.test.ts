import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ATTESTATION_LIMITS,
  AttestationClaimsSchema,
  AttestResponseSchema,
  ChallengeResponseSchema,
  type Problem,
} from "@antireverse/protocol";
import { deviceSubject, jwkThumbprint, newId, verifyAttestationToken } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type AttestationKeys, createAttestationKeys } from "../src/attestation/keys.ts";
import { createWindowLimiter } from "../src/attestation/limiter.ts";
import { createNonceStore } from "../src/attestation/nonces.ts";
import { createBundleIssuer } from "../src/bundle.ts";
import {
  ATTEST_BODY_BYTES_MAX,
  ATTEST_PER_APP_PER_MINUTE,
  ATTEST_PER_PREFIX_PER_MINUTE,
  attestRoutes,
  NONCES_MAX,
} from "../src/routes/attest.ts";
import { createSigner } from "../src/signer.ts";
import { createAppFor, createOrganization, expectProblem, fetchBundle, makeTestApi, type TestApi } from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const DEVICE = "AAECAwQFBgcICQoLDA0ODw";

/** A session public key as Guard sends it (slice 04): EC P-256, the four public members only. */
function sessionJwk(): { kty: "EC"; crv: "P-256"; x: string; y: string } {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = publicKey.export({ format: "jwk" });
  if (typeof x !== "string" || typeof y !== "string") throw new Error("No coordinates.");
  return { kty: "EC", crv: "P-256", x, y };
}
const JWK = sessionJwk();
const JKT = jwkThumbprint(JWK);
const OTHER_JWK = sessionJwk();

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "600",
};

function expectCors(res: Response): void {
  for (const [name, value] of Object.entries(CORS)) expect(res.headers.get(name)).toBe(value);
  expect(res.headers.get("access-control-allow-credentials")).toBeNull();
}

describe("nonce store", () => {
  it("issues 32-hex nonces that are taken once, for their App, before they expire", () => {
    const nonces = createNonceStore({ max: 10, ttlMs: MINUTE });
    const a = nonces.issue("app_a", T0);
    expect(a.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(a.expiresAt).toBe(T0 + MINUTE);
    expect(nonces.take(a.nonce, "app_a", T0 + 1)).toBe(true);
    expect(nonces.take(a.nonce, "app_a", T0 + 2)).toBe(false);

    const b = nonces.issue("app_a", T0);
    expect(nonces.take(b.nonce, "app_a", T0 + MINUTE)).toBe(false);
    const c = nonces.issue("app_a", T0);
    expect(nonces.take(c.nonce, "app_a", T0 + MINUTE - 1)).toBe(true);
    // Taken by the wrong App: refused, and spent.
    const d = nonces.issue("app_a", T0);
    expect(nonces.take(d.nonce, "app_b", T0)).toBe(false);
    expect(nonces.take(d.nonce, "app_a", T0)).toBe(false);
    expect(nonces.take("0".repeat(32), "app_a", T0)).toBe(false);
  });

  it("holds at most its bound: the oldest nonce goes first, and expired ones are swept", () => {
    const nonces = createNonceStore({ max: 3, ttlMs: MINUTE });
    const issued = [0, 1, 2, 3].map((i) => nonces.issue("app_a", T0 + i));
    expect(nonces.size()).toBe(3);
    expect(nonces.take(issued[0]?.nonce ?? "", "app_a", T0 + 10)).toBe(false);
    expect(nonces.take(issued[1]?.nonce ?? "", "app_a", T0 + 10)).toBe(true);
    nonces.issue("app_a", T0 + 2 * MINUTE);
    expect(nonces.size()).toBe(1);
    expect(NONCES_MAX).toBe(100_000);
  });
});

describe("window limiter", () => {
  it("allows `limit` takes per key and window, keeps keys apart and says when to retry", () => {
    const limiter = createWindowLimiter({ limit: 2, windowMs: MINUTE, maxKeys: 10 });
    expect(limiter.take("a", T0).allowed).toBe(true);
    expect(limiter.take("a", T0 + 1).allowed).toBe(true);
    expect(limiter.take("a", T0 + 15_000)).toEqual({ allowed: false, retryAfterS: 45 });
    expect(limiter.take("b", T0 + 15_000).allowed).toBe(true);
    expect(limiter.take("a", T0 + MINUTE).allowed).toBe(true);
  });

  it("tracks at most `maxKeys` keys and never forgets a running window: a new key is refused while all run", () => {
    const limiter = createWindowLimiter({ limit: 1, windowMs: MINUTE, maxKeys: 2 });
    expect(limiter.take("a", T0).allowed).toBe(true);
    expect(limiter.take("b", T0 + 10_000).allowed).toBe(true);
    // Full of running windows: "c" is refused until the oldest window ends; "a" stays limited.
    expect(limiter.take("c", T0 + 20_000)).toEqual({ allowed: false, retryAfterS: 40 });
    expect(limiter.size()).toBe(2);
    expect(limiter.take("a", T0 + 30_000).allowed).toBe(false);
    // Once a's window ended, it makes room.
    expect(limiter.take("c", T0 + MINUTE).allowed).toBe(true);
    expect(limiter.size()).toBe(2);
    expect(limiter.take("b", T0 + MINUTE).allowed).toBe(false);
  });
});

describe("attestation endpoints", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-attest-"));
  const keyFile = join(root, "attestation-keys.json");
  const clock = { now: new Date(T0) };
  let api: TestApi;
  let keys: AttestationKeys;
  let appId: string;
  let otherAppId: string;
  let shieldKey: string;
  let signingPublicKey: string;
  /** Every response body this file received, and every token. */
  const seen: string[] = [];
  let addressCounter = 0;
  /** A fresh caller address in its own /24, so that a test does not spend another's prefix budget. */
  const freshAddress = (): string => `198.${51 + Math.floor(++addressCounter / 250)}.${addressCounter % 250}.7`;

  beforeAll(async () => {
    keys = createAttestationKeys({ file: keyFile, now: () => clock.now });
    const signer = createSigner();
    signingPublicKey = signer.publicKey;
    api = await makeTestApi({
      signer,
      now: () => clock.now,
      attestation: keys,
      clientAddress: (c) => c.req.header("x-test-address"),
    });
    const organization = await createOrganization(api);
    const created = await createAppFor(api, organization.admin_key.key);
    appId = created.app.id;
    shieldKey = created.shield_key.key;
    otherAppId = (await createAppFor(api, organization.admin_key.key, { name: "Back office" })).app.id;
  });
  afterAll(async () => {
    await api.close();
    rmSync(root, { recursive: true, force: true });
  });

  async function post(path: string, body: unknown, address = freshAddress()): Promise<Response> {
    const res = await api.app.request(path, {
      method: "POST",
      headers: { "content-type": "application/json", "x-test-address": address },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    seen.push(await res.clone().text());
    return res;
  }

  async function challenge(app = appId, address?: string): Promise<{ nonce: string; expires_at: string }> {
    const res = await post("/v1/attest/challenge", { app_id: app }, address);
    expect(res.status).toBe(200);
    return ChallengeResponseSchema.parse(await res.json());
  }

  function attestBody(nonce: string, signals: string[] = [], app = appId) {
    return { app_id: app, nonce, device: DEVICE, signals, cnf: { jkt: JKT, jwk: JWK } };
  }

  async function attest(signals: string[] = [], app = appId): Promise<{ token: string; expires_at: string }> {
    const address = freshAddress();
    const { nonce } = await challenge(app, address);
    const res = await post("/v1/attest", attestBody(nonce, signals, app), address);
    expect(res.status).toBe(200);
    const body = AttestResponseSchema.parse(await res.json());
    seen.push(body.token);
    return body;
  }

  function claimsOf(token: string) {
    return AttestationClaimsSchema.parse(JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString()));
  }

  describe("POST /v1/attest/challenge", () => {
    it("answers a 32-hex nonce valid for 60 seconds, with CORS and without caching", async () => {
      clock.now = new Date(T0 + 1_234);
      const res = await post("/v1/attest/challenge", { app_id: appId });
      expect(res.status).toBe(200);
      expectCors(res);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const body = (await res.json()) as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(["expires_at", "nonce"]);
      expect(body.nonce).toMatch(/^[0-9a-f]{32}$/);
      expect(body.expires_at).toBe(new Date(T0 + 1_234 + ATTESTATION_LIMITS.nonceS * 1_000).toISOString());
    });

    it("answers a fixed 400 for an App that does not exist, with CORS", async () => {
      const res = await post("/v1/attest/challenge", { app_id: newId("app") });
      expectCors(res);
      const problem = await expectProblem(res, 400);
      expect(problem).toEqual({
        type: "https://antireverse.dev/problems/attestation-refused",
        title: "Attestation refused",
        status: 400,
        detail: "The App is unknown, or the nonce is unknown, used or expired. Request a new challenge.",
      });
    });

    it("answers a validation problem for a body that is not a challenge request", async () => {
      for (const body of [{}, { app_id: "app_1" }, { app_id: 7 }]) {
        const res = await post("/v1/attest/challenge", body);
        expectCors(res);
        const problem = await expectProblem(res, 400);
        expect(problem.type).toBe("https://antireverse.dev/problems/validation");
      }
      const malformed = await post("/v1/attest/challenge", "{not json");
      expectCors(malformed);
      expect((await expectProblem(malformed, 400)).type).toBe("https://antireverse.dev/problems/malformed-json");
    });

    it("refuses a body larger than 4 KB with 413", async () => {
      expect(ATTEST_BODY_BYTES_MAX).toBe(4_096);
      const res = await post("/v1/attest/challenge", { app_id: appId, pad: "x".repeat(ATTEST_BODY_BYTES_MAX) });
      expectCors(res);
      const problem = await expectProblem(res, 413);
      expect(problem.type).toBe("https://antireverse.dev/problems/payload-too-large");
      expect(problem.detail).toBe("The request body is larger than 4096 bytes.");
      const fits = await post("/v1/attest/challenge", { app_id: appId, pad: "x".repeat(4_000) });
      expect(fits.status).toBe(200);
    });
  });

  describe("CORS preflight", () => {
    it.each(["/v1/attest/challenge", "/v1/attest"])(
      "answers OPTIONS %s with 204 and the CORS headers",
      async (path) => {
        const res = await api.app.request(path, {
          method: "OPTIONS",
          headers: {
            origin: "https://shop.example",
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type",
          },
        });
        expect(res.status).toBe(204);
        expectCors(res);
        expect(await res.text()).toBe("");
      },
    );

    it("needs no key: the other endpoints still answer 401 without one", async () => {
      const res = await api.app.request("/v1/policy-bundle");
      expect(res.status).toBe(401);
      expect(res.headers.get("access-control-allow-origin")).toBeNull();
    });
  });

  describe("POST /v1/attest", () => {
    it("answers a token whose claims are exactly those of the plan, verifiable with the bundle's keys", async () => {
      clock.now = new Date(T0 + 10_500);
      const address = freshAddress();
      const { nonce } = await challenge(appId, address);
      const res = await post("/v1/attest", attestBody(nonce, ["automation.webdriver"]), address);
      expect(res.status).toBe(200);
      expectCors(res);
      const body = (await res.json()) as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(["expires_at", "token"]);
      const { token, expires_at } = AttestResponseSchema.parse(body);
      seen.push(token);

      const iat = Math.floor((T0 + 10_500) / 1_000);
      const claims = claimsOf(token);
      expect(claims).toEqual({
        iss: "antireverse",
        aud: appId,
        sub: deviceSubject(appId, DEVICE),
        iat,
        exp: iat + 300,
        jti: claims.jti,
        cnf: { jkt: JKT, jwk: JWK },
        verdict: "suspect",
        risk: 70,
        sig: ["automation.webdriver"],
        pv: 1,
      });
      expect(claims.jti).toMatch(/^[0-9a-f]{32}$/);
      expect(claims.sub).toMatch(/^dev_[0-9a-f]{24}$/);
      expect(expires_at).toBe(new Date((iat + 300) * 1_000).toISOString());
      const header = JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString());
      expect(header).toEqual({ alg: "EdDSA", typ: "JWT", kid: keys.currentKid() });

      const bundle = await fetchBundle(api, shieldKey, signingPublicKey);
      const keySet = bundle.payload.attestation_keys ?? [];
      expect(verifyAttestationToken(token, keySet, { appId, nowS: iat })).toEqual({ status: "valid", claims });
      // For another App the same token is not valid.
      expect(verifyAttestationToken(token, keySet, { appId: otherAppId, nowS: iat }).status).toBe("invalid");
    });

    it.each([
      [[], "trusted", 5, []],
      [["automation.webdriver"], "suspect", 70, ["automation.webdriver"]],
      [["automation.headless"], "suspect", 60, ["automation.headless"]],
      [["env.inconsistent"], "suspect", 40, ["env.inconsistent"]],
      [["env.inconsistent", "automation.headless"], "hostile", 100, ["automation.headless", "env.inconsistent"]],
      [["automation.webdriver", "env.inconsistent"], "hostile", 100, ["automation.webdriver", "env.inconsistent"]],
      [["future.signal", "env.inconsistent", "env.inconsistent"], "suspect", 40, ["env.inconsistent"]],
      [["future.signal"], "trusted", 5, []],
    ])("signals %j give %s with risk %i", async (signals, verdict, risk, sig) => {
      const { token } = await attest(signals as string[]);
      const claims = claimsOf(token);
      expect([claims.verdict, claims.risk, claims.sig]).toEqual([verdict, risk, sig]);
    });

    it("gives the same device the same subject per App, and every token its own jti", async () => {
      const a = claimsOf((await attest()).token);
      const b = claimsOf((await attest()).token);
      const c = claimsOf((await attest([], otherAppId)).token);
      expect(a.sub).toBe(b.sub);
      expect(c.sub).toBe(deviceSubject(otherAppId, DEVICE));
      expect(c.sub).not.toBe(a.sub);
      expect(new Set([a.jti, b.jti, c.jti]).size).toBe(3);
    });

    it("accepts a nonce once", async () => {
      const address = freshAddress();
      const { nonce } = await challenge(appId, address);
      expect((await post("/v1/attest", attestBody(nonce), address)).status).toBe(200);
      const again = await post("/v1/attest", attestBody(nonce), address);
      expectCors(again);
      expect((await expectProblem(again, 400)).type).toBe("https://antireverse.dev/problems/attestation-refused");
    });

    it("accepts a nonce for 60 seconds only", async () => {
      clock.now = new Date(T0 + HOUR);
      const address = freshAddress();
      const late = await challenge(appId, address);
      const inTime = await challenge(appId, address);
      clock.now = new Date(T0 + HOUR + MINUTE - 1);
      expect((await post("/v1/attest", attestBody(inTime.nonce), address)).status).toBe(200);
      clock.now = new Date(T0 + HOUR + MINUTE);
      await expectProblem(await post("/v1/attest", attestBody(late.nonce), address), 400);
    });

    it("refuses a nonce issued for another App, an unknown nonce and an unknown App, with one fixed text", async () => {
      const address = freshAddress();
      const { nonce } = await challenge(appId, address);
      const wrongApp = await expectProblem(await post("/v1/attest", attestBody(nonce, [], otherAppId), address), 400);
      // Spent by the failed attempt.
      const spent = await expectProblem(await post("/v1/attest", attestBody(nonce), address), 400);
      const unknown = await expectProblem(await post("/v1/attest", attestBody("0".repeat(32)), address), 400);
      const unknownApp = await expectProblem(
        await post("/v1/attest", attestBody("1".repeat(32), [], newId("app")), address),
        400,
      );
      const noApp = await expectProblem(await post("/v1/attest/challenge", { app_id: newId("app") }, address), 400);
      for (const problem of [spent, unknown, unknownApp, noApp] as Problem[]) expect(problem).toEqual(wrongApp);
    });

    describe("session key (slice 04)", () => {
      async function refusedWith(cnf: unknown): Promise<Problem> {
        const address = freshAddress();
        const { nonce } = await challenge(appId, address);
        const res = await post("/v1/attest", { ...attestBody(nonce), cnf }, address);
        expectCors(res);
        const problem = await expectProblem(res, 400);
        // Spent by the refused attempt, like any other refusal after the nonce was taken.
        expect((await post("/v1/attest", attestBody(nonce), address)).status).toBe(400);
        return problem;
      }

      async function fixedRefusal(): Promise<Problem> {
        return expectProblem(await post("/v1/attest", attestBody("0".repeat(32))), 400);
      }

      it("refuses a request without cnf.jwk with the fixed attestation-refused text", async () => {
        expect(await refusedWith({ jkt: JKT })).toEqual(await fixedRefusal());
      });

      it("refuses a jwk whose thumbprint is not cnf.jkt with the fixed text", async () => {
        expect(await refusedWith({ jkt: JKT, jwk: OTHER_JWK })).toEqual(await fixedRefusal());
        expect(await refusedWith({ jkt: jwkThumbprint(OTHER_JWK), jwk: JWK })).toEqual(await fixedRefusal());
      });

      it("refuses a non-canonical coordinate with 400", async () => {
        // The last character of a canonical 32-byte coordinate has its two low bits zero: flip one of them.
        const last = JWK.x.slice(-1);
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        const nonCanonical = `${JWK.x.slice(0, -1)}${alphabet[alphabet.indexOf(last) + 1]}`;
        expect(Buffer.from(nonCanonical, "base64url")).toEqual(Buffer.from(JWK.x, "base64url"));
        const address = freshAddress();
        const { nonce } = await challenge(appId, address);
        const res = await post(
          "/v1/attest",
          { ...attestBody(nonce), cnf: { jkt: JKT, jwk: { ...JWK, x: nonCanonical } } },
          address,
        );
        expectCors(res);
        await expectProblem(res, 400);
      });

      it("refuses a key that is not EC P-256 with 400", async () => {
        const address = freshAddress();
        const { nonce } = await challenge(appId, address);
        for (const jwk of [
          { ...JWK, crv: "P-384" },
          { ...JWK, kty: "OKP" },
          { ...JWK, x: undefined },
        ]) {
          const res = await post("/v1/attest", { ...attestBody(nonce), cnf: { jkt: JKT, jwk } }, address);
          await expectProblem(res, 400);
        }
      });

      it("puts the key it was sent in the token: cnf.jwk equals it, with its thumbprint as cnf.jkt", async () => {
        const address = freshAddress();
        const { nonce } = await challenge(appId, address);
        const res = await post(
          "/v1/attest",
          { ...attestBody(nonce), cnf: { jkt: JKT, jwk: { ...JWK, d: "private-member-must-not-travel", kid: "x" } } },
          address,
        );
        expect(res.status).toBe(200);
        const { token } = AttestResponseSchema.parse(await res.json());
        seen.push(token);
        const raw = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString()) as {
          cnf: Record<string, unknown>;
        };
        expect(raw.cnf).toEqual({ jkt: JKT, jwk: JWK });
        expect(Object.keys(raw.cnf.jwk as object)).toEqual(["kty", "crv", "x", "y"]);
      });
    });

    it("answers a validation problem for a malformed request, and keeps the nonce for a correct retry", async () => {
      const address = freshAddress();
      const { nonce } = await challenge(appId, address);
      for (const body of [
        { ...attestBody(nonce), device: "short" },
        { ...attestBody(nonce), cnf: {} },
        { ...attestBody(nonce), signals: "automation.webdriver" },
        { ...attestBody(nonce), signals: Array.from({ length: 17 }, () => "env.inconsistent") },
        { ...attestBody(nonce), nonce: "XYZ" },
      ]) {
        const res = await post("/v1/attest", body, address);
        expect((await expectProblem(res, 400)).type).toBe("https://antireverse.dev/problems/validation");
      }
      expect((await post("/v1/attest", attestBody(nonce), address)).status).toBe(200);
    });

    it("answers other methods with the API's 404", async () => {
      for (const method of ["GET", "PUT", "DELETE"]) {
        expect((await api.app.request("/v1/attest", { method })).status).toBe(404);
        expect((await api.app.request("/v1/attest/challenge", { method })).status).toBe(404);
      }
    });
  });

  describe("rate limits", () => {
    it("allows 60 requests per minute per caller prefix, both endpoints together, then 429", async () => {
      expect(ATTEST_PER_PREFIX_PER_MINUTE).toBe(60);
      clock.now = new Date(T0 + 2 * HOUR);
      // Three addresses of one /24 share its budget.
      const addresses = ["192.0.2.1", "192.0.2.77", "192.0.2.254"];
      for (let i = 0; i < 30; i++) {
        const address = addresses[i % 3] ?? "";
        const { nonce } = await challenge(appId, address);
        expect((await post("/v1/attest", attestBody(nonce), address)).status).toBe(200);
      }
      clock.now = new Date(T0 + 2 * HOUR + 30_000);
      const refused = await post("/v1/attest/challenge", { app_id: appId }, "192.0.2.9");
      expectCors(refused);
      expect(refused.headers.get("retry-after")).toBe("30");
      expect(await expectProblem(refused, 429)).toEqual({
        type: "https://antireverse.dev/problems/too-many-attestations",
        title: "Too many requests",
        status: 429,
        detail: "Too many attestation requests. Try again in a minute.",
      });
      // Another prefix is not affected; IPv6 callers count per /48.
      expect((await post("/v1/attest/challenge", { app_id: appId }, "192.0.3.1")).status).toBe(200);
      for (let i = 0; i < 60; i++) {
        const res = await post("/v1/attest/challenge", { app_id: appId }, `2001:db8:1:${i.toString(16)}::1`);
        expect(res.status).toBe(200);
      }
      expect((await post("/v1/attest/challenge", { app_id: appId }, "2001:db8:1:ffff::2")).status).toBe(429);
      // A new minute, a new budget.
      clock.now = new Date(T0 + 2 * HOUR + MINUTE);
      expect((await post("/v1/attest/challenge", { app_id: appId }, "192.0.2.9")).status).toBe(200);
    });

    it("allows 600 requests per minute per App, then 429, whatever the prefixes; other Apps are unaffected", async () => {
      expect(ATTEST_PER_APP_PER_MINUTE).toBe(600);
      clock.now = new Date(T0 + 3 * HOUR);
      // The first of the 600: a nonce kept for an attest after the App's minute is full.
      const held = await challenge(otherAppId, "10.203.0.1");
      for (let i = 1; i < 600; i++) {
        const res = await post("/v1/attest/challenge", { app_id: otherAppId }, `10.${Math.floor(i / 50)}.${i % 50}.1`);
        expect(res.status).toBe(200);
      }
      const refused = await post("/v1/attest/challenge", { app_id: otherAppId }, "10.200.0.1");
      expectCors(refused);
      expect((await expectProblem(refused, 429)).type).toBe("https://antireverse.dev/problems/too-many-attestations");
      // Attest counts against the App as well, once its nonce is valid; a made-up nonce is refused as such.
      expect((await post("/v1/attest", attestBody(held.nonce, [], otherAppId), "10.201.0.1")).status).toBe(429);
      expect((await post("/v1/attest", attestBody("2".repeat(32), [], otherAppId), "10.201.0.1")).status).toBe(400);
      expect((await post("/v1/attest/challenge", { app_id: appId }, "10.202.0.1")).status).toBe(200);
      clock.now = new Date(T0 + 3 * HOUR + MINUTE);
      expect((await post("/v1/attest/challenge", { app_id: otherAppId }, "10.200.0.1")).status).toBe(200);
    });
  });

  it("counts the App limit only for Apps that exist: made-up App ids cannot reset a victim's window", async () => {
    // The route with a small bound of tracked Apps, so that a flood larger than the bound is quick to send.
    const keysMax = 100;
    const ms = { now: T0 + 5 * HOUR };
    const routes = attestRoutes({
      db: api.db,
      attestation: keys,
      clientAddress: (c) => c.req.header("x-test-address"),
      now: () => new Date(ms.now),
      limitKeysMax: keysMax,
    });
    let n = 0;
    const send = (app: string) =>
      routes.request("/v1/attest/challenge", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-test-address": `2001:db8:${Math.floor(++n / 60).toString(16)}::1`,
        },
        body: JSON.stringify({ app_id: app }),
      });
    const third = (await createAppFor(api, (await createOrganization(api, "Victim")).admin_key.key)).app.id;
    const fourth = (await createAppFor(api, (await createOrganization(api, "Bystander")).admin_key.key)).app.id;

    for (let i = 0; i < ATTEST_PER_APP_PER_MINUTE; i++) expect((await send(third)).status).toBe(200);
    expect((await send(third)).status).toBe(429);
    // More made-up App ids than the limiter tracks, from many prefixes: each is refused as unknown.
    for (let i = 0; i < keysMax + 10; i++) expect((await send(newId("app"))).status).toBe(400);
    // The victim's window still runs: refused until the minute ends.
    expect((await send(third)).status).toBe(429);
    // The made-up ids took no place in the limiter: another real App is still counted and served.
    expect((await send(fourth)).status).toBe(200);
    ms.now += MINUTE;
    expect((await send(third)).status).toBe(200);
  });

  describe("keys in the Policy Bundle", () => {
    it("carries the public attestation keys, re-issuing the same version with a later issued_at on rotation", async () => {
      // The bundle is first issued 12 hours after the keys were made, so a rotation is not a daily re-issue.
      clock.now = new Date(T0 + 12 * HOUR);
      const first = await fetchBundle(api, shieldKey, signingPublicKey);
      expect(first.payload.attestation_keys).toEqual(keys.attestationKeys());
      expect(first.payload.attestation_keys).toHaveLength(2);
      clock.now = new Date(T0 + DAY - 1_000);
      const same = await fetchBundle(api, shieldKey, signingPublicKey);
      expect(same.etag).toBe(first.etag);

      // A token signed one second before the rotation.
      const before = await attest(["env.inconsistent"]);
      const beforeKid = JSON.parse(Buffer.from(before.token.split(".")[0] ?? "", "base64url").toString()).kid;
      expect(beforeKid).toBe(first.payload.attestation_keys?.[0]?.kid);

      clock.now = new Date(T0 + DAY);
      const rotated = await fetchBundle(api, shieldKey, signingPublicKey);
      expect(rotated.etag).not.toBe(first.etag);
      expect(rotated.payload.version).toBe(first.payload.version);
      expect(Date.parse(rotated.payload.issued_at)).toBeGreaterThan(Date.parse(first.payload.issued_at));
      const set = rotated.payload.attestation_keys ?? [];
      expect(set).toHaveLength(3);
      expect(set.slice(0, 2)).toEqual(first.payload.attestation_keys);
      // The new current key was already in the bundle a Shield held (as next) for a day.
      expect(keys.currentKid()).toBe(first.payload.attestation_keys?.[1]?.kid);

      const nowS = Math.floor((T0 + DAY) / 1_000);
      expect(verifyAttestationToken(before.token, set, { appId, nowS }).status).toBe("valid");
      const after = await attest();
      expect(verifyAttestationToken(after.token, set, { appId, nowS }).status).toBe("valid");
      // And a Shield still holding the bundle from before the rotation verifies it too.
      expect(verifyAttestationToken(after.token, first.payload.attestation_keys ?? [], { appId, nowS }).status).toBe(
        "valid",
      );
    });

    it("issues a new bundle with a new ETag when only the attestation keys change", () => {
      const at = { ms: T0 };
      const issuer = createBundleIssuer({ signer: createSigner(), now: () => new Date(at.ms) });
      const subject = {
        audience: "aud_0123456789abcdef",
        epoch: "0".repeat(32),
        appId,
        environment: "production" as const,
        version: 3,
        rules: [],
        attestationKeys: [{ kid: "0123456789abcdef", public_key: "A".repeat(43) }],
      };
      const a = issuer.issue(subject);
      expect(issuer.issue({ ...subject, attestationKeys: [...subject.attestationKeys] }).etag).toBe(a.etag);
      const b = issuer.issue({
        ...subject,
        attestationKeys: [...subject.attestationKeys, { kid: "fedcba9876543210", public_key: "B".repeat(43) }],
      });
      expect(b.etag).not.toBe(a.etag);
      const pa = JSON.parse(a.signed.bundle);
      const pb = JSON.parse(b.signed.bundle);
      expect(pb.version).toBe(pa.version);
      expect(Date.parse(pb.issued_at)).toBeGreaterThan(Date.parse(pa.issued_at));
      expect(pb.attestation_keys).toHaveLength(2);
      // Without keys the member is absent, as in bundles before slice 03.
      expect("attestation_keys" in JSON.parse(issuer.issue({ ...subject, attestationKeys: [] }).signed.bundle)).toBe(
        false,
      );
    });
  });

  it("never lets a private key, an address, a nonce, a device id or a token into a response or a log line", () => {
    const stored = JSON.parse(readFileSync(keyFile, "utf8")) as Record<string, { private_key?: string }>;
    const secrets = ["previous", "current", "next"]
      .map((role) => stored[role]?.private_key)
      .filter((value): value is string => typeof value === "string");
    expect(secrets.length).toBeGreaterThanOrEqual(2);
    const bodies = seen.join("\n");
    for (const secret of secrets) expect(bodies).not.toContain(secret);

    const log = api.logger.lines.join("\n");
    expect(api.logger.lines.some((line) => line.includes("route=/v1/attest"))).toBe(true);
    for (const secret of secrets) expect(log).not.toContain(secret);
    expect(log).not.toMatch(/198\.5|192\.0\.2|2001:db8|10\.200/);
    expect(log).not.toContain(DEVICE);
    expect(log).not.toContain(JKT);
    expect(log).not.toContain(JWK.x);
    expect(log).not.toContain(JWK.y);
    expect(log).not.toMatch(/[0-9a-f]{32}/);
    expect(log).not.toMatch(/eyJ/);
  });
});
