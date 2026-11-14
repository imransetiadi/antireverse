import { randomBytes } from "node:crypto";
import {
  ATTESTATION_LIMITS,
  type AttestationClaims,
  AttestRequestSchema,
  type AttestResponse,
  ChallengeRequestSchema,
  type ChallengeResponse,
  USAGE_COUNTED_VERDICTS,
  USAGE_DEVICE_DAILY_CAP,
  usageMonthOf,
  verdictFor,
} from "@antireverse/protocol";
import { deviceSubject, jwkThumbprint } from "@antireverse/protocol/server";
import { type Context, Hono, type MiddlewareHandler } from "hono";
import type { AttestationKeys } from "../attestation/keys.ts";
import { createWindowLimiter } from "../attestation/limiter.ts";
import { createNonceStore } from "../attestation/nonces.ts";
import type { AppEnv } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import { addressPrefix } from "../prefix.ts";
import { ATTEST_BODY_BYTES_MAX, problem } from "../problem.ts";
import { deviceRef, recordDevice } from "../stores/usage.ts";
import { createUsageSalts, type UsageSalts } from "../usage/salts.ts";
import { validateJson } from "../validate.ts";
import type { ClientAddress } from "./beacon.ts";

export { ATTEST_BODY_BYTES_MAX };

/** Requests per caller prefix (/24 or /48; unknown addresses share one) per minute, both endpoints together. */
export const ATTEST_PER_PREFIX_PER_MINUTE = 60;
/** Requests per App per minute, both endpoints together, whatever the callers. */
export const ATTEST_PER_APP_PER_MINUTE = 600;
/** Challenge nonces held at once; the oldest goes first. */
export const NONCES_MAX = 100_000;
/** Prefixes and Apps whose minute is counted at once (each); the oldest goes first. */
export const LIMIT_KEYS_MAX = 10_000;

const MINUTE_MS = 60_000;
const ISSUER = "antireverse";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Max-Age": "600",
} as const;

/** True when `jkt` is the RFC 7638 thumbprint of `jwk`; false also for a key `jwkThumbprint` refuses. */
function thumbprintIs(jwk: Parameters<typeof jwkThumbprint>[0], jkt: string): boolean {
  try {
    return jwkThumbprint(jwk) === jkt;
  } catch (error) {
    if (error instanceof TypeError) return false;
    throw error;
  }
}

export interface AttestDeps {
  db: Db;
  attestation: AttestationKeys;
  clientAddress: ClientAddress;
  now?: (() => Date) | undefined;
  /** Prefixes and Apps whose minute is counted at once (each). Default `LIMIT_KEYS_MAX`. */
  limitKeysMax?: number | undefined;
  /** Receives the kind of a failure to meter a Guard device; never an identifier. */
  logger?: Logger | undefined;
  /** The month salts of the device references (slice 17a). Default: salts in memory. */
  usageSalts?: UsageSalts | undefined;
  /** New device references per App and UTC day at most. Default `USAGE_DEVICE_DAILY_CAP`. */
  usageDeviceDailyCap?: number | undefined;
}

/**
 * The public Attestation service (slice 03): `POST /v1/attest/challenge` and `POST /v1/attest`, plus their CORS
 * preflights. No key: any page may call them, without credentials. Every answer carries the CORS headers. Order of
 * checks: caller prefix limit, body bound (4 KB), schema, the App (challenge) or the nonce (attest), then the App
 * limit. Neither limiter ever forgets a running window: when full, a new prefix or App is answered 429.
 * Unknown App, bad nonce, and a missing `cnf.jwk` or one whose thumbprint is not `cnf.jkt` share one fixed 400. Nothing of the request (address, App id, nonce, device, token) is
 * logged; the caller's address is reduced to its prefix at once and used only for the limit.
 */
export function attestRoutes(deps: AttestDeps): Hono<AppEnv> {
  const { db, attestation, clientAddress } = deps;
  const now = deps.now ?? (() => new Date());
  const limitKeysMax = deps.limitKeysMax ?? LIMIT_KEYS_MAX;
  const logger = redacting(deps.logger ?? consoleLogger);
  const usageSalts = deps.usageSalts ?? createUsageSalts();
  const deviceCap = deps.usageDeviceDailyCap ?? USAGE_DEVICE_DAILY_CAP;
  const counted: readonly string[] = USAGE_COUNTED_VERDICTS;
  const nonces = createNonceStore({ max: NONCES_MAX, ttlMs: ATTESTATION_LIMITS.nonceS * 1_000 });
  const byPrefix = createWindowLimiter({
    limit: ATTEST_PER_PREFIX_PER_MINUTE,
    windowMs: MINUTE_MS,
    maxKeys: limitKeysMax,
  });
  const byApp = createWindowLimiter({ limit: ATTEST_PER_APP_PER_MINUTE, windowMs: MINUTE_MS, maxKeys: limitKeysMax });
  const routes = new Hono<AppEnv>();

  const cors: MiddlewareHandler = async (c, next) => {
    await next();
    // After the handler, so that every answer carries them: errors, 413 and 429 included.
    for (const [name, value] of Object.entries(CORS_HEADERS)) c.header(name, value);
  };

  const tooMany = (c: Context, retryAfterS: number) => {
    c.header("Retry-After", String(retryAfterS));
    return problem(c, "too-many-attestations");
  };

  const prefixLimit: MiddlewareHandler = async (c, next) => {
    const prefix = addressPrefix(clientAddress(c)) ?? "unknown";
    const { allowed, retryAfterS } = byPrefix.take(prefix, now().getTime());
    if (!allowed) return tooMany(c, retryAfterS);
    await next();
  };

  /** Counts the request against its App; a 429 response when the App's minute is full. */
  function appLimit(c: Context, appId: string): Response | null {
    const { allowed, retryAfterS } = byApp.take(appId, now().getTime());
    return allowed ? null : tooMany(c, retryAfterS);
  }

  for (const path of ["/v1/attest/challenge", "/v1/attest"]) {
    routes.options(path, cors, (c) => c.body(null, 204));
  }

  const guard = [cors, prefixLimit, limitBody(ATTEST_BODY_BYTES_MAX, "attestation-payload-too-large")] as const;

  routes.post("/v1/attest/challenge", ...guard, validateJson(ChallengeRequestSchema), async (c) => {
    const { app_id: appId } = c.req.valid("json");
    const exists = await db.tx("none", async (q) => {
      const { rows } = await q.query<{ exists: boolean }>("SELECT attest_app_exists($1::text) AS exists", [appId]);
      return rows[0]?.exists === true;
    });
    if (!exists) return problem(c, "attestation-refused");
    // Counted only for an App that exists: a made-up id never takes a place in the App limiter (review F1).
    const limited = appLimit(c, appId);
    if (limited !== null) return limited;
    const { nonce, expiresAt } = nonces.issue(appId, now().getTime());
    return c.json({ nonce, expires_at: new Date(expiresAt).toISOString() } satisfies ChallengeResponse, 200);
  });

  routes.post("/v1/attest", ...guard, validateJson(AttestRequestSchema), async (c) => {
    const request = c.req.valid("json");
    const appId = request.app_id;
    const ms = now().getTime();
    // The nonce was bound to an App that existed at the challenge: no lookup here. Counted against the App only
    // once the nonce proved it (review F1); a refused request spends the nonce.
    if (!nonces.take(request.nonce, appId, ms)) return problem(c, "attestation-refused");
    // From slice 04 the session key itself is required (amendment A2), and it must be the key `jkt` names: the
    // token carries it, and Shield verifies request signatures with it. Refused with the same fixed text.
    const jwk = request.cnf.jwk;
    if (jwk === undefined || !thumbprintIs(jwk, request.cnf.jkt)) return problem(c, "attestation-refused");
    const limited = appLimit(c, appId);
    if (limited !== null) return limited;

    const iat = Math.floor(ms / 1_000);
    const exp = iat + ATTESTATION_LIMITS.ttlS;
    const { verdict, risk } = verdictFor(request.signals);
    const sub = deviceSubject(appId, request.device);
    // Slice 17a: a device with a counted verdict (trusted or suspect) is metered as a monthly active Guard device: its
    // reference is HMAC-SHA-256 under the UTC month's salt (kept by this process, never in the database) of `sub`,
    // recorded once per App and month, at most `deviceCap` new ones per App and UTC day (then the day is flagged).
    // One short transaction; a failure to record never fails the attestation, and only its kind is logged.
    if (counted.includes(verdict)) {
      try {
        const at = new Date(ms);
        const ref = deviceRef(usageSalts.saltFor(usageMonthOf(at)), sub);
        await db.tx("none", (q) => recordDevice(q, appId, ref, at, deviceCap));
      } catch (error) {
        const code = (error as { code?: unknown }).code;
        const sqlState = typeof code === "string" && /^[0-9A-Z]{5}$/.test(code) ? ` sqlstate=${code}` : "";
        logger.warn(`usage device record error ${(error as Error)?.name ?? "Error"}${sqlState}`);
      }
    }
    const claims: AttestationClaims = {
      iss: ISSUER,
      aud: appId,
      sub,
      iat,
      exp,
      jti: randomBytes(16).toString("hex"),
      cnf: { jkt: request.cnf.jkt, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } },
      verdict,
      risk,
      sig: [...request.signals],
      pv: 1,
    };
    const token = attestation.sign(claims);
    return c.json({ token, expires_at: new Date(exp * 1_000).toISOString() } satisfies AttestResponse, 200);
  });

  return routes;
}
