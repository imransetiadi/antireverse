import { createPublicKey, randomBytes, verify } from "node:crypto";
import {
  type BundlePayload,
  BundlePayloadSchema,
  type CreateAppRequestInput,
  type CreateAppResponse,
  CreateAppResponseSchema,
  type CreateOrganizationResponse,
  CreateOrganizationResponseSchema,
  type Environment,
  EXAMPLE_SHIELD_EVENT,
  type Policy,
  PolicyResponseSchema,
  type Problem,
  ProblemSchema,
  type ShieldEvent,
  type SignedBundle,
  SignedBundleSchema,
} from "@antireverse/protocol";
import { expect, vi } from "vitest";
import { type AppDeps, createApp } from "../src/app.ts";
import { createEventBus, type EventBus } from "../src/bus.ts";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { createIncidentQueue, type IncidentQueue } from "../src/exposure/match.ts";
import { createNotifier } from "../src/notify/notifier.ts";
import { createSigner, type Signer } from "../src/signer.ts";

// Applies to every test file that imports these helpers. PGlite compiles PostgreSQL on start-up: about
// a second on an idle machine, several when other suites run beside this one.
vi.setConfig({ testTimeout: 30_000, hookTimeout: 30_000 });

export interface CapturedLogger {
  lines: string[];
  info(line: string): void;
  warn(line: string): void;
}

export function captureLogger(): CapturedLogger {
  const lines: string[] = [];
  return { lines, info: (line) => lines.push(line), warn: (line) => lines.push(line) };
}

export interface TestApi {
  app: ReturnType<typeof createApp>;
  /** The test database; a test that overrides `db` with a fake gets it back here unchanged. */
  db: OwnedDb;
  bus: EventBus;
  /** The key that signs Policy Bundles: in memory, a new one per test file, unless the test passes its own. */
  signer: Signer;
  logger: CapturedLogger;
  /** Every key issued through the helpers below; `expectNoKeyLogged` checks the logger against it. */
  issuedKeys: string[];
  /** Resolves when every `vulnerable-component` Incident queued so far has been written (they follow the response). */
  flushIncidents(): Promise<void>;
  close(): Promise<void>;
}

/** One in-memory database and one app: build it once per test file. */
export async function makeTestApi(overrides: Partial<AppDeps> = {}): Promise<TestApi> {
  const db = (overrides.db as OwnedDb | undefined) ?? (await openDb());
  const bus = overrides.bus ?? createEventBus();
  const signer = overrides.signer ?? createSigner();
  const logger = captureLogger();
  // The queue the app opens Incidents on, made here so that a test can flush it: with the notifier the test gave,
  // else one like the app's default (on db; no channel, no delivery).
  const exposureIncidents: IncidentQueue =
    overrides.exposureIncidents ??
    createIncidentQueue({
      db,
      notifier: overrides.notifier ?? createNotifier({ db, now: overrides.now, logger }),
      logger,
    });
  const app = createApp({ db, bus, signer, logger, ...overrides, exposureIncidents });
  return {
    app,
    db,
    bus,
    signer,
    logger,
    issuedKeys: [],
    flushIncidents: () => exposureIncidents.flush(),
    close: async () => {
      await exposureIncidents.flush();
      await db.close();
    },
  };
}

export function bearer(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}` };
}

export function json(body: unknown, headers: Record<string, string> = {}): RequestInit {
  return { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) };
}

/** Like `json`, for `PUT`. */
export function put(body: unknown, headers: Record<string, string> = {}): RequestInit {
  return { ...json(body, headers), method: "PUT" };
}

/** `/v1/apps/:appId/policies/:environment`, optionally followed by `/versions` or `/rollback`. */
export function policyPath(appId: string, environment: string, rest = ""): string {
  return `/v1/apps/${appId}/policies/${environment}${rest}`;
}

/** Publishes `rules` as the next version of the Policy and returns it. */
export async function publishPolicy(
  api: TestApi,
  adminKey: string,
  appId: string,
  environment: Environment,
  rules: unknown[],
): Promise<Policy> {
  const res = await api.app.request(policyPath(appId, environment), put({ rules }, bearer(adminKey)));
  expect(res.status).toBe(201);
  return PolicyResponseSchema.parse(await res.json()).policy;
}

/** True when `signature` is the Ed25519 signature of exactly the bytes of `text` under the raw public key. */
export function verifySignature(publicKey: string, text: string, signature: string): boolean {
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKey }, format: "jwk" });
  return verify(null, Buffer.from(text, "utf8"), key, Buffer.from(signature, "base64url"));
}

export interface FetchedBundle {
  etag: string;
  signed: SignedBundle;
  payload: BundlePayload;
}

/** Fetches the Policy Bundle of a Shield key, checks its signature against `publicKey` and parses it. */
export async function fetchBundle(api: TestApi, shieldKey: string, publicKey: string): Promise<FetchedBundle> {
  const res = await api.app.request("/v1/policy-bundle", { headers: bearer(shieldKey) });
  expect(res.status).toBe(200);
  const signed = SignedBundleSchema.parse(await res.json());
  expect(verifySignature(publicKey, signed.bundle, signed.signature)).toBe(true);
  const etag = res.headers.get("etag");
  if (etag === null) throw new Error("The bundle response has no ETag.");
  return { etag, signed, payload: BundlePayloadSchema.parse(JSON.parse(signed.bundle)) };
}

export async function createOrganization(api: TestApi, name = "Acme"): Promise<CreateOrganizationResponse> {
  const res = await api.app.request("/v1/organizations", json({ name }));
  expect(res.status).toBe(201);
  const body = CreateOrganizationResponseSchema.parse(await res.json());
  api.issuedKeys.push(body.admin_key.key);
  return body;
}

export async function createAppFor(
  api: TestApi,
  adminKey: string,
  body: CreateAppRequestInput = { name: "Storefront" },
): Promise<CreateAppResponse> {
  const res = await api.app.request("/v1/apps", json(body, bearer(adminKey)));
  expect(res.status).toBe(201);
  const created = CreateAppResponseSchema.parse(await res.json());
  api.issuedKeys.push(created.shield_key.key);
  return created;
}

/** Asserts a problem document with the given status and returns it. */
export async function expectProblem(res: Response, status: number): Promise<Problem> {
  expect(res.status).toBe(status);
  expect(res.headers.get("content-type")).toBe("application/problem+json");
  const problem = ProblemSchema.parse(await res.json());
  expect(problem.status).toBe(status);
  return problem;
}

/** The logger saw requests, and no line it received contains a key (whole, or its secret part). */
export function expectNoKeyLogged(api: TestApi): void {
  expect(api.issuedKeys.length).toBeGreaterThan(0);
  expect(api.logger.lines.length).toBeGreaterThan(0);
  for (const key of api.issuedKeys) {
    const secret = key.slice(-43);
    for (const line of api.logger.lines) {
      expect(line).not.toContain(key);
      expect(line).not.toContain(secret);
    }
  }
}

/** A version-7 UUID for the given millisecond; later milliseconds sort later. */
export function uuidv7(ms: number = Date.now()): string {
  const bytes = randomBytes(16);
  bytes.writeUIntBE(ms, 0, 6);
  bytes[6] = 0x70 | ((bytes[6] ?? 0) & 0x0f);
  bytes[8] = 0x80 | ((bytes[8] ?? 0) & 0x3f);
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** A valid Event with a fresh identifier; `overrides` replaces top-level members. */
export function shieldEvent(ms: number, overrides: Partial<ShieldEvent> = {}): ShieldEvent {
  return { ...EXAMPLE_SHIELD_EVENT, event_id: uuidv7(ms), ts: new Date(ms).toISOString(), ...overrides };
}

export function batchOf(events: unknown[]): { protocol: 1; sdk: { name: string; version: string }; events: unknown[] } {
  return { protocol: 1, sdk: { name: "shield-node", version: "0.0.0" }, events };
}

export const tick = (ms = 0): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export interface SseFrame {
  id?: string;
  event?: string;
  data?: string;
}

/** A minimal reader of server-sent events over a response body. */
export function sseReader(body: ReadableStream<Uint8Array>) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  return {
    /** The next frame as raw text, comment frames included. */
    async next(): Promise<string> {
      for (;;) {
        const end = buffer.indexOf("\n\n");
        if (end >= 0) {
          const frame = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          return frame;
        }
        const { done, value } = await reader.read();
        if (done) throw new Error("The stream ended.");
        buffer += decoder.decode(value, { stream: true });
      }
    },
    /** The next frame that is not a comment, parsed into its fields. */
    async nextEvent(): Promise<SseFrame> {
      for (;;) {
        const frame = await this.next();
        const lines = frame.split("\n");
        if (lines.every((line) => line.startsWith(":"))) continue;
        const fields: Record<string, string> = {};
        for (const line of lines) {
          const colon = line.indexOf(":");
          const name = line.slice(0, colon);
          const value = line.slice(colon + 1).replace(/^ /, "");
          fields[name] = name in fields ? `${fields[name]}\n${value}` : value;
        }
        return fields;
      }
    },
    cancel: () => reader.cancel(),
  };
}

/** Rejects when `promise` has not settled after `ms`. */
export function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Timed out after ${ms} ms waiting for ${what}.`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
