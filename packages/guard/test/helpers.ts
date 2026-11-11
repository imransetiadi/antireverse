// Test doubles for Guard: an Attestation service behind a fake fetch (validating with the protocol's schemas and
// minting real tokens), a Map-backed storage, a spying WebCrypto wrapper and navigator objects.
import { generateKeyPairSync, webcrypto } from "node:crypto";
import { vi } from "vitest";
import {
  type AttestationClaims,
  AttestRequestSchema,
  ChallengeRequestSchema,
  verdictFor,
} from "../../protocol/src/index.ts";
import { attestationKid, deviceSubject, signAttestationToken } from "../../protocol/src/server.ts";
import type {
  GuardCrypto,
  GuardFetch,
  GuardNavigator,
  GuardRequestInit,
  GuardResponse,
  GuardStorage,
} from "../src/index.js";

export const APP_ID = "app_89abcdef0123456789abcdef";
export const ENDPOINT = "https://attest.example.test";
export const CHALLENGE_URL = `${ENDPOINT}/v1/attest/challenge`;
export const ATTEST_URL = `${ENDPOINT}/v1/attest`;

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const rawPublicKey = Buffer.from(publicKey.export({ format: "jwk" }).x ?? "", "base64url");
export const KEYS = [{ kid: attestationKid(rawPublicKey), public_key: rawPublicKey.toString("base64url") }];
const KID = KEYS[0]?.kid ?? "";

export interface RecordedRequest {
  url: string;
  init: GuardRequestInit;
  body: unknown;
}

export function response(status: number, body: unknown): GuardResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

/**
 * A fake Attestation service. Each challenge issues a fresh nonce; each attest checks the body against the
 * protocol's schema and the nonce, then signs a real token whose lifetime is `ttlS` from `nowMs()`.
 */
export function fakeService(opts: { nowMs?: () => number; ttlS?: number } = {}) {
  const nowMs = opts.nowMs ?? (() => Date.now());
  const ttlS = opts.ttlS ?? 300;
  const requests: RecordedRequest[] = [];
  const nonces = new Set<string>();
  let counter = 0;
  const fetch = vi.fn<GuardFetch>(async (url, init) => {
    const body: unknown = JSON.parse(init.body);
    requests.push({ url, init, body });
    if (url === CHALLENGE_URL) {
      const parsed = ChallengeRequestSchema.safeParse(body);
      if (!parsed.success) return response(400, { title: "Bad request" });
      counter += 1;
      const nonce = counter.toString(16).padStart(32, "0");
      nonces.add(nonce);
      return response(200, { nonce, expires_at: new Date(nowMs() + 60_000).toISOString() });
    }
    if (url === ATTEST_URL) {
      const parsed = AttestRequestSchema.safeParse(body);
      if (!parsed.success || !nonces.delete(parsed.data.nonce)) return response(400, { title: "Bad request" });
      const iat = Math.floor(nowMs() / 1000);
      const { verdict, risk } = verdictFor(parsed.data.signals);
      const claims: AttestationClaims = {
        iss: "antireverse",
        aud: parsed.data.app_id,
        sub: deviceSubject(parsed.data.app_id, parsed.data.device),
        iat,
        exp: iat + ttlS,
        jti: counter.toString(16).padStart(32, "f"),
        cnf: parsed.data.cnf,
        verdict,
        risk,
        sig: parsed.data.signals,
        pv: 1,
      };
      const token = signAttestationToken(privateKey, KID, claims);
      return response(200, { token, expires_at: new Date((iat + ttlS) * 1000).toISOString() });
    }
    return response(404, {});
  });
  const challenges = () => requests.filter((request) => request.url === CHALLENGE_URL).length;
  return { fetch, requests, challenges };
}

export function memoryStorage(initial: Record<string, string> = {}): GuardStorage & { data: Map<string, string> } {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => void data.set(key, value),
  };
}

export const throwingStorage: GuardStorage = {
  getItem: () => {
    throw new Error("SecurityError: storage is disabled");
  },
  setItem: () => {
    throw new Error("SecurityError: storage is disabled");
  },
};

/** Node's WebCrypto behind spies, so a test sees every call and every key pair generated. */
export function spyCrypto() {
  const pairs: CryptoKeyPair[] = [];
  const getRandomValues = vi.fn((array: Uint8Array) => webcrypto.getRandomValues(array));
  const generateKey = vi.fn(async (algorithm: unknown, extractable: boolean, usages: string[]) => {
    const pair = (await webcrypto.subtle.generateKey(
      algorithm as EcKeyGenParams,
      extractable,
      usages as KeyUsage[],
    )) as CryptoKeyPair;
    pairs.push(pair);
    return pair;
  });
  const crypto: GuardCrypto = {
    getRandomValues: <T extends Uint8Array>(array: T): T => {
      getRandomValues(array);
      return array;
    },
    subtle: {
      generateKey,
      exportKey: (format, key) => webcrypto.subtle.exportKey(format, key as CryptoKey),
      digest: (algorithm, data) => webcrypto.subtle.digest(algorithm, data as Uint8Array<ArrayBuffer>),
      sign: (algorithm, key, data) =>
        webcrypto.subtle.sign(algorithm, key as CryptoKey, data as Uint8Array<ArrayBuffer>),
    },
  };
  return { crypto, pairs, getRandomValues, generateKey };
}

export const UA = {
  chromeWindows:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
  chromeMac:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
  headlessLinux:
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36",
  chromeAndroid:
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
  firefoxLinux: "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
  safariIphone:
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
} as const;

/** A clean desktop Chrome on Windows: no signal. */
export function cleanNavigator(overrides: Partial<GuardNavigator> = {}): GuardNavigator {
  return {
    webdriver: false,
    userAgent: UA.chromeWindows,
    platform: "Win32",
    plugins: { length: 5 },
    userAgentData: { platform: "Windows" },
    ...overrides,
  };
}
