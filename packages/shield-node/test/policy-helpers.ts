// Shared by the Policy tests. Not a test file: Vitest collects only *.test.ts.
// Bundles are signed here with node:crypto, exactly as the API signs them: Ed25519 over the UTF-8 bytes of the
// bundle string, base64url.
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import type { BundlePayload, BundleRule, SignedBundle } from "@antireverse/protocol";
import { bundleAudience } from "@antireverse/protocol/server";
import type { Transport } from "../src/index.ts";

/** The instant the tests' clocks start at. */
export const NOW = Date.parse("2026-11-10T08:00:00.000Z");
export const DAY_MS = 86_400_000;
/** The epoch of the API's database the test bundles are issued from, unless a test names another. */
export const EPOCH = "0123456789abcdef0123456789abcdef";
/** The epoch of the same API after its database was reset. */
export const NEW_EPOCH = "fedcba9876543210fedcba9876543210";

export interface Signer {
  /** The raw public key as 43 base64url characters: what `policyPublicKey` takes. */
  publicKey: string;
  keyId: string;
  /** The signature of the bundle string as 86 base64url characters. */
  sign(bundle: string): string;
}

export function createSigner(): Signer {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "jwk" }).x as string;
  return {
    publicKey: raw,
    keyId: createHash("sha256").update(Buffer.from(raw, "base64url")).digest("hex").slice(0, 16),
    sign: (bundle) => sign(null, Buffer.from(bundle, "utf8"), privateKey).toString("base64url"),
  };
}

/** A Rule of a bundle. `n` gives it a distinct identifier. */
export function rule(n: number, overrides: Partial<BundleRule> = {}): BundleRule {
  return {
    id: `rul_${n.toString(16).padStart(24, "0")}`,
    path: "/api/admin/**",
    methods: [],
    action: "block",
    mode: "enforce",
    ...overrides,
  };
}

/** The payload of a bundle issued at `NOW` for the Shield key `key`. */
export function payload(key: string, overrides: Partial<BundlePayload> = {}): BundlePayload {
  const issuedAt = overrides.issued_at === undefined ? NOW : Date.parse(overrides.issued_at);
  return {
    format: 1,
    audience: bundleAudience(key),
    epoch: EPOCH,
    app_id: "app_89abcdef0123456789abcdef",
    environment: "development",
    version: 1,
    issued_at: new Date(issuedAt).toISOString(),
    not_after: new Date(issuedAt + 7 * DAY_MS).toISOString(),
    rules: [rule(1)],
    ...overrides,
  };
}

/** What `GET /v1/policy-bundle` answers: the bundle string, its signature and the identifier of the key. */
export function signed(signer: Signer, bundle: unknown): SignedBundle {
  const text = typeof bundle === "string" ? bundle : JSON.stringify(bundle);
  return { bundle: text, signature: signer.sign(text), key_id: signer.keyId };
}

/** Replaces one character in the middle of `text` by a different one of the same alphabet. */
export function flip(text: string, at = Math.floor(text.length / 2)): string {
  const replacement = text[at] === "A" ? "B" : "A";
  return text.slice(0, at) + replacement + text.slice(at + 1);
}

type Sent = Parameters<Transport>[0];
type Answer = Awaited<ReturnType<Transport>>;

export interface FakeApi {
  transport: Transport;
  /** Every `GET /v1/policy-bundle` received. */
  gets: Sent[];
  /** Every `POST /v1/events` received. */
  posts: Sent[];
  /** Every `POST /v1/inventory` received (slice 19): kept apart, so that `posts` holds Event batches only. */
  inventories: Sent[];
  /** Publishes a bundle: from now on it is served with a new ETag, and `If-None-Match` of that ETag gives 304. */
  publish(bundle: SignedBundle | string): void;
  /** Overrides what the next policy requests get: an answer, an Error to reject with, or a function. Null: as published. */
  policyAnswer(answer: Answer | Error | (() => Promise<Answer>) | null): void;
}

/** A fake Anti Reverse API: it serves the published bundle with ETag handling and accepts every batch and inventory. */
export function fakeApi(): FakeApi {
  const gets: Sent[] = [];
  const posts: Sent[] = [];
  const inventories: Sent[] = [];
  let body = "";
  let etagCounter = 0;
  let override: Answer | Error | (() => Promise<Answer>) | null = null;
  const transport: Transport = async (request) => {
    if (request.method !== "GET") {
      (request.url.endsWith("/v1/inventory") ? inventories : posts).push(request);
      return { status: 202 };
    }
    gets.push(request);
    if (override instanceof Error) throw override;
    if (typeof override === "function") return override();
    if (override !== null) return override;
    if (etagCounter === 0) return { status: 404, body: "" };
    const etag = `"bundle-${etagCounter}"`;
    if (request.headers["if-none-match"] === etag) return { status: 304, body: "", etag };
    return { status: 200, body, etag };
  };
  return {
    transport,
    gets,
    posts,
    inventories,
    publish(bundle) {
      body = typeof bundle === "string" ? bundle : JSON.stringify(bundle);
      etagCounter += 1;
      override = null;
    },
    policyAnswer(answer) {
      override = answer;
    },
  };
}
