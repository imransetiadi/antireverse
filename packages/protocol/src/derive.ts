import { createHash, createHmac } from "node:crypto";
import { CANARY_KINDS, CANARY_PLAN, CANARY_ROUTE_WORDS, type Canary, LEAK_RULES, type LeakRuleId } from "./canaries.ts";
import { ID_PATTERNS } from "./constants.ts";

// Canary values and the Clone Beacon token derived from the build seed, and leak-finding fingerprints. Both are pure functions of their
// input: the same seed reproduces the same Canaries byte for byte, with no network call.
//
// Derivation, per Canary of kind <kind> and index <i> (0-based within its kind):
//   key  = "antireverse/canary/v1/" + the seed as a decimal integer
//   id    = "cny_" + the first 24 hex characters of HMAC-SHA256(key, "id/<kind>/<i>")
//   value = HMAC-SHA256(key, "<kind>/<i>") = d (32 bytes), encoded by kind:
//     key:   "ak_live_" + (d as a big-endian integer mod 62^32) in 32 base62 digits over 0-9A-Za-z, most
//            significant first, zero-padded. 2^256 / 62^32 is about 2^65, so every digit string is equally
//            likely to within about 2^-65.
//     route: "/api/internal/" + (d[0..15] as a big-endian integer mod 36^8) in 8 base36 digits over 0-9a-z,
//            zero-padded, + "/" + CANARY_ROUTE_WORDS[d[31] mod 5]. 2^128 / 36^8 is about 2^87 (uniform to
//            within 2^-87); the word is very slightly biased (256 mod 5 = 1), which only affects a label.
// Output order: every key Canary, then every route Canary (the order of CANARY_KINDS).
//
// Scoped derivation (v2), used when the Build is registered for an App and version: the Canary ids are unique
// per Organization, so two Builds with the same pinned seed must not share Canaries. With a scope
// { appId, version }:
//   key     = "antireverse/canary/v2/" + the seed as a decimal integer
//   message = appId + "\n" + version + "\n" + the v1 message ("id/<kind>/<i>" or "<kind>/<i>")
// and the encodings are unchanged. Without a scope the v1 derivation (and its known answers) is unchanged.
//
// Clone Beacon token (always scoped: a beacon is only planted in a registered Build):
//   key     = "antireverse/beacon/v1/" + the seed as a decimal integer
//   token   = "bcn_" + the first 24 hex characters of HMAC-SHA256(key, appId + "\n" + version + "\nbeacon")

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz";
const KEY_DIGITS = 32;
const ROUTE_DIGITS = 8;

function digits(value: bigint, alphabet: string, count: number): string {
  const base = BigInt(alphabet.length);
  let rest = value;
  let out = "";
  for (let i = 0; i < count; i++) {
    out = alphabet[Number(rest % base)] + out;
    rest /= base;
  }
  return out;
}

const bigEndian = (bytes: Buffer): bigint => BigInt(`0x${bytes.toString("hex")}`);

/** The App and version a registered Build's Canaries are scoped to (derivation v2). */
export interface CanaryScope {
  appId: string;
  version: string;
}

function checkSeed(seed: unknown, what: string): asserts seed is number {
  if (typeof seed !== "number" || !Number.isSafeInteger(seed) || seed < 0) {
    throw new TypeError(`A ${what} seed is a safe integer of at least 0.`);
  }
}

function checkScope(scope: unknown, what: string): asserts scope is CanaryScope {
  const { appId, version } = (scope ?? {}) as Partial<CanaryScope>;
  if (typeof appId !== "string" || !ID_PATTERNS.app.test(appId)) {
    throw new TypeError(`A ${what} scope's appId is an App id.`);
  }
  if (typeof version !== "string" || version.length === 0 || /[\r\n]/.test(version)) {
    throw new TypeError(`A ${what} scope's version is a non-empty string without a line break.`);
  }
}

/**
 * The Canaries of a Build: `CANARY_PLAN` of each kind (one key, two routes), keys first. `seed` is the
 * harden seed, a safe integer of at least 0. `scope` (optional) scopes them to an App and version (v2); its
 * `appId` must be an App id and its `version` a non-empty string without a line break. Anything else is a
 * TypeError.
 */
export function deriveCanaries(seed: number, scope?: CanaryScope): Canary[] {
  checkSeed(seed, "Canary");
  if (scope !== undefined) checkScope(scope, "Canary");
  const key = scope === undefined ? `antireverse/canary/v1/${seed}` : `antireverse/canary/v2/${seed}`;
  const prefix = scope === undefined ? "" : `${scope.appId}\n${scope.version}\n`;
  const hmac = (message: string): Buffer =>
    createHmac("sha256", key)
      .update(prefix + message, "utf8")
      .digest();
  const canaries: Canary[] = [];
  for (const kind of CANARY_KINDS) {
    for (let index = 0; index < CANARY_PLAN[kind]; index++) {
      const id = `cny_${hmac(`id/${kind}/${index}`).toString("hex").slice(0, 24)}`;
      const d = hmac(`${kind}/${index}`);
      if (kind === "key") {
        canaries.push({ id, kind, value: `ak_live_${digits(bigEndian(d), BASE62, KEY_DIGITS)}` });
      } else {
        const segment = digits(bigEndian(d.subarray(0, 16)), BASE36, ROUTE_DIGITS);
        const word = CANARY_ROUTE_WORDS[(d[31] as number) % CANARY_ROUTE_WORDS.length];
        canaries.push({ id, kind, value: `/api/internal/${segment}/${word}` });
      }
    }
  }
  return canaries;
}

/**
 * The Clone Beacon token of a registered Build: `bcn_` + the first 24 hex characters of
 * HMAC-SHA256("antireverse/beacon/v1/<seed>", "<appId>\n<version>\nbeacon"). `seed` and `scope` are checked as
 * for `deriveCanaries`, but the scope is required. Anything else is a TypeError.
 */
export function deriveBeaconToken(seed: number, scope: CanaryScope): string {
  checkSeed(seed, "beacon");
  checkScope(scope, "beacon");
  const digest = createHmac("sha256", `antireverse/beacon/v1/${seed}`)
    .update(`${scope.appId}\n${scope.version}\nbeacon`, "utf8")
    .digest("hex");
  return `bcn_${digest.slice(0, 24)}`;
}

const RULE_IDS: ReadonlySet<string> = new Set(LEAK_RULES.map((rule) => rule.id));

/**
 * The fingerprint of a leak finding: the first 32 hex characters of SHA-256(rule + NUL + path + NUL + value),
 * over UTF-8. It names a finding (for an allowlist) without revealing its value.
 */
export function leakFingerprint(rule: LeakRuleId, path: string, value: string): string {
  if (!RULE_IDS.has(rule)) throw new TypeError("Unknown leak rule.");
  if (typeof path !== "string" || typeof value !== "string") throw new TypeError("A path and a value are strings.");
  return createHash("sha256").update(`${rule}\u0000${path}\u0000${value}`, "utf8").digest("hex").slice(0, 32);
}
