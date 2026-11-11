// Decides whether a Policy Bundle from the API is applied: signature, audience, epoch and version, expiry and bounds.
//
// Shield has no runtime dependency, so the bundle is validated by hand, without the schemas of the protocol
// package. The bounds are the protocol's (`POLICY_LIMITS`, `PATH_PATTERN`, `BundlePayloadSchema`); a bound that
// changes there must change here, and test/verify.test.ts pins the agreement.
//
// Order matters: the size of the input is bounded before anything is parsed, and the signature is verified over
// the bundle text exactly as it arrived before that text is read. Unknown members are ignored. A refusal names
// its cause and never repeats a value from the bundle.
import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";
import type { BundlePayload, BundleRule, SignedBundle } from "@antireverse/protocol";
import { type ParsedCidr, parseCidr } from "../address.ts";
import { APP_ID_PATTERN, KEYS_MAX, KID_PATTERN, PUBLIC_KEY_PATTERN } from "../attestation.ts";
import { type PatchInput, readPatches } from "../patches.ts";
import { compilePattern } from "./match.ts";
import { type AppliedPolicy, type AttestationKey, type BlockInput, buildPolicy } from "./store.ts";

/** Bytes of a bundle string at most. Equal to `POLICY_LIMITS.bundleBytesMax` of the protocol. */
export const BUNDLE_BYTES_MAX = 65_536;
/** Bytes of the response that carries a bundle at most. */
export const RESPONSE_BYTES_MAX = 131_072;
/** Rules of a Policy at most. Equal to `POLICY_LIMITS.rulesMax` of the protocol. */
const RULES_MAX = 50;
/** Methods of a Rule at most. Equal to `POLICY_LIMITS.methodsMax` of the protocol. */
const METHODS_MAX = 8;

const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/; // 32 bytes
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/; // 64 bytes
const RULE_ID = /^rul_[0-9a-f]{24}$/;
/** `epoch` of a bundle: 32 lower-case hex characters, random per database of the API. */
const EPOCH = /^[0-9a-f]{32}$/;
const METHOD = /^[A-Z-]{1,16}$/;
/** Canaries of a bundle at most. Equal to `CANARY_LIMITS.perBundle` of the protocol. */
export const CANARIES_MAX = 100;
/** A Canary identifier. Equal to `ID_PATTERNS.cny` of the protocol. */
export const CANARY_ID = /^cny_[0-9a-f]{24}$/;
/** The value of a `key` Canary. Equal to `CANARY_VALUE_PATTERNS.key` of the protocol. */
export const CANARY_KEY_VALUE = /^ak_live_[0-9A-Za-z]{32}$/;
/** The value of a `route` Canary. Equal to `CANARY_VALUE_PATTERNS.route` of the protocol. */
export const CANARY_ROUTE_VALUE = /^\/api\/internal\/[0-9a-z]{8}\/(export|debug|config|backup|sync)$/;
/** Blocks of a bundle at most. Equal to `CONTAINMENT_LIMITS.activePerAppEnv` of the protocol. */
export const BLOCKS_MAX = 150;
/** Allowlist CIDRs of a bundle at most. Equal to `CONTAINMENT_LIMITS.allowlistMax` of the protocol. */
export const ALLOWLIST_MAX = 100;
/** A Containment identifier. Equal to `ID_PATTERNS.cnt` of the protocol. */
export const CONTAINMENT_ID = /^cnt_[0-9a-f]{24}$/;
/** An actor hash. Equal to `ACTOR_HASH_PATTERN` of the protocol. */
export const ACTOR_HASH = /^iph_[0-9a-f]{32}$/;
/** A network prefix as an Event carries it. Equal to `IP_PREFIX_PATTERN` of the protocol. */
export const IP_PREFIX =
  /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.0\/24|(?:0|[1-9a-f][0-9a-f]{0,3}):(?:0|[1-9a-f][0-9a-f]{0,3}):(?:0|[1-9a-f][0-9a-f]{0,3})::\/48)$/;
/** An ISO-8601 time in UTC, the form `Date#toISOString` produces. */
const ISO_TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/;

/**
 * Why a bundle was not applied.
 * - `signature`: the signature does not verify with the configured public key (or is not a signature at all).
 * - `format`: the bundle is of a format this Shield does not know.
 * - `audience`: the bundle was issued for another Shield key.
 * - `version`: the bundle is older than the Policy that is applied, within the same epoch.
 * - `expired`: `not_after` of the bundle has passed.
 * - `invalid`: the response or the bundle is too large, is not JSON, or breaks a bound.
 */
export type RefusalReason = "signature" | "format" | "audience" | "version" | "expired" | "invalid";

export type Verified =
  | { ok: true; policy: AppliedPolicy }
  /** `detail` is a short description for people. It never contains a value from the bundle, or a key. */
  | { ok: false; reason: RefusalReason; detail: string };

export interface VerifyContext {
  /** The configured public key (`importPublicKey`). */
  publicKey: KeyObject;
  /** The audience of this Shield (`audienceOf` its key). */
  audience: string;
  /** The version of the applied Policy: an older bundle of the same epoch is refused. */
  appliedVersion: number;
  /**
   * The epoch of the applied Policy; null for the built-in Policy. A bundle of another epoch was issued after the
   * API's database was reset, when versions restarted: it is accepted whatever its version.
   */
  appliedEpoch: string | null;
  /**
   * `issued_at` of the applied Policy in milliseconds; 0 for the built-in Policy. A bundle of another epoch must be
   * issued later, so that a bundle of a previous history cannot be replayed across a reset (decided with Jev).
   */
  appliedIssuedAt: number;
  /** Milliseconds since the epoch. */
  now: number;
}

function refuse(reason: RefusalReason, detail: string): Verified {
  return { ok: false, reason, detail };
}

/**
 * The public key of the API's signing key from its transmitted form: the raw 32 bytes of an Ed25519 key as
 * 43 base64url characters. Null for anything else. Never throws.
 */
export function importPublicKey(text: unknown): KeyObject | null {
  if (typeof text !== "string" || !PUBLIC_KEY.test(text)) return null;
  try {
    return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: text }, format: "jwk" });
  } catch {
    return null;
  }
}

/**
 * The audience of the bundles issued for a Shield key: the first 32 hex characters of its SHA-256.
 * Equal to `bundleAudience` of the protocol's server entry, computed here because Shield imports no protocol code.
 */
export function audienceOf(shieldKey: string): string {
  return createHash("sha256").update(shieldKey, "utf8").digest("hex").slice(0, 32);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Milliseconds of an ISO-8601 UTC time, or null. */
function timeOf(value: unknown): number | null {
  if (typeof value !== "string" || !ISO_TIME.test(value)) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

/** The member of the Rule that breaks a bound, or the Rule ready to compile. */
function readRule(value: unknown): Parameters<typeof buildPolicy>[0]["rules"][number] | string {
  if (!isObject(value)) return "is not an object";
  const rule = value as { [K in keyof BundleRule]?: unknown };
  if (typeof rule.id !== "string" || !RULE_ID.test(rule.id)) return "id is not a Rule identifier";
  const pattern = compilePattern(rule.path);
  if (pattern === null) return "path is not a path pattern";
  const methods = rule.methods;
  if (!Array.isArray(methods) || methods.length > METHODS_MAX) return `methods is not a list of at most ${METHODS_MAX}`;
  for (let i = 0; i < methods.length; i++) {
    const method: unknown = methods[i];
    if (typeof method !== "string" || !METHOD.test(method)) return "methods holds something that is not a method";
    if (methods.indexOf(method) !== i) return "methods lists a method twice";
  }
  if (rule.action !== "block") return "action is not known";
  if (rule.mode !== "monitor" && rule.mode !== "enforce") return "mode is not known";
  return { id: rule.id, path: rule.path as string, methods: methods as string[], mode: rule.mode, pattern };
}

type CanaryInput = NonNullable<Parameters<typeof buildPolicy>[0]["canaries"]>[number];

/** What breaks a bound in the Canary, or the Canary. The message never repeats a value. */
function readCanary(value: unknown): CanaryInput | string {
  if (!isObject(value)) return "is not an object";
  const canary = value as { id?: unknown; kind?: unknown; value?: unknown };
  if (typeof canary.id !== "string" || !CANARY_ID.test(canary.id)) return "id is not a Canary identifier";
  if (canary.kind !== "key" && canary.kind !== "route") return "kind is not known";
  const pattern = canary.kind === "key" ? CANARY_KEY_VALUE : CANARY_ROUTE_VALUE;
  if (typeof canary.value !== "string" || !pattern.test(canary.value)) {
    return `value is not a decoy ${canary.kind === "key" ? "key" : "route"}`;
  }
  return { id: canary.id, kind: canary.kind, value: canary.value };
}

/** What breaks a bound in the block, or the block. The message never repeats a value. */
function readBlock(value: unknown): BlockInput | string {
  if (!isObject(value)) return "is not an object";
  const block = value as { id?: unknown; kind?: unknown; ip_hash?: unknown; ip_prefix?: unknown; expires_at?: unknown };
  if (typeof block.id !== "string" || !CONTAINMENT_ID.test(block.id)) return "id is not a Containment identifier";
  const expiresMs = timeOf(block.expires_at);
  if (block.kind === "actor") {
    if (typeof block.ip_hash !== "string" || !ACTOR_HASH.test(block.ip_hash)) return "ip_hash is not an actor hash";
    if (expiresMs === null) return "expires_at is not a time";
    return { id: block.id, kind: "actor", ipHash: block.ip_hash, expiresMs };
  }
  if (block.kind === "prefix") {
    if (typeof block.ip_prefix !== "string" || !IP_PREFIX.test(block.ip_prefix)) {
      return "ip_prefix is not a /24 or /48 network prefix";
    }
    if (expiresMs === null) return "expires_at is not a time";
    return { id: block.id, kind: "prefix", ipPrefix: block.ip_prefix, expiresMs };
  }
  return "kind is not known";
}

/**
 * What breaks a bound in the attestation key, or the key imported. The kid must be the first 16 hex characters of the
 * SHA-256 of the decoded key, as `attestationKid` of the protocol derives it: a bundle that names a key by another
 * key's kid is refused (decided with Jev: accept_but_recheck_kid, 0.55). The message never repeats a value.
 */
function readAttestationKey(value: unknown): AttestationKey | string {
  if (!isObject(value)) return "is not an object";
  const entry = value as { kid?: unknown; public_key?: unknown };
  if (typeof entry.kid !== "string" || !KID_PATTERN.test(entry.kid)) return "kid is not 16 hex characters";
  if (typeof entry.public_key !== "string" || !PUBLIC_KEY_PATTERN.test(entry.public_key)) {
    return "public_key is not a raw Ed25519 public key in base64url";
  }
  const raw = Buffer.from(entry.public_key, "base64url");
  if (createHash("sha256").update(raw).digest("hex").slice(0, 16) !== entry.kid) {
    return "kid is not the key id of its public_key";
  }
  const key = importPublicKey(entry.public_key);
  if (key === null) return "public_key is not an Ed25519 public key";
  return { kid: entry.kid, publicKey: entry.public_key, key };
}

/**
 * Verifies what `GET /v1/policy-bundle` answered — `{ bundle, signature, key_id }` — and compiles the Policy.
 * `key_id` is not read: which key signed is settled by the signature alone.
 */
export function verifyBundle(envelope: unknown, context: VerifyContext): Verified {
  if (!isObject(envelope)) return refuse("invalid", "the response is not a signed bundle");
  const { bundle, signature } = envelope as { [K in keyof SignedBundle]?: unknown };
  if (typeof bundle !== "string") return refuse("invalid", "the response is not a signed bundle");
  // A string has at least as many bytes as characters: the cheap test first.
  if (bundle.length > BUNDLE_BYTES_MAX || Buffer.byteLength(bundle, "utf8") > BUNDLE_BYTES_MAX) {
    return refuse("invalid", `the bundle is larger than ${BUNDLE_BYTES_MAX} bytes`);
  }

  // The signature covers the bytes of the bundle text as transmitted. Nothing of the text is read before.
  let genuine = false;
  if (typeof signature === "string" && SIGNATURE.test(signature)) {
    try {
      genuine = verify(null, Buffer.from(bundle, "utf8"), context.publicKey, Buffer.from(signature, "base64url"));
    } catch {
      genuine = false;
    }
  }
  if (!genuine) return refuse("signature", "the signature does not verify with policyPublicKey");

  let parsed: unknown;
  try {
    parsed = JSON.parse(bundle);
  } catch {
    return refuse("invalid", "the bundle is not JSON");
  }
  if (!isObject(parsed)) return refuse("invalid", "the bundle is not a JSON object");
  const payload = parsed as { [K in keyof BundlePayload]?: unknown };

  if (payload.format !== 1) return refuse("format", "the bundle has a format this Shield does not know");
  if (payload.audience !== context.audience) return refuse("audience", "the bundle was issued for another Shield key");
  // The audience an Attestation Token must name. A bundle without it is still applied (it was never needed before
  // slice 03), and then no token is valid; a malformed one refuses the bundle.
  const appId = payload.app_id;
  if (appId !== undefined && (typeof appId !== "string" || !APP_ID_PATTERN.test(appId))) {
    return refuse("invalid", "app_id is not an App identifier");
  }

  const epoch = payload.epoch;
  if (typeof epoch !== "string" || !EPOCH.test(epoch)) return refuse("invalid", "epoch is not 32 hex characters");
  const version = payload.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 0) {
    return refuse("invalid", "version is not a whole number");
  }
  // Versions are compared within one epoch only. A new epoch is a reset history: its versions start again, and
  // signature, audience, expiry and bounds are all that apply. A replay of an older bundle of the applied epoch is
  // refused here.
  if (epoch === context.appliedEpoch && version < context.appliedVersion) {
    return refuse("version", `version ${version} is older than the applied version ${context.appliedVersion}`);
  }

  const issuedAt = timeOf(payload.issued_at);
  if (issuedAt === null) return refuse("invalid", "issued_at is not a time");
  if (epoch !== context.appliedEpoch && context.appliedEpoch !== null && !(issuedAt > context.appliedIssuedAt)) {
    return refuse("version", "a bundle of another history was issued before the applied one");
  }
  // The same version can be issued again with another Canary set (the Policy did not change, a Build did). A bundle
  // of the applied version issued before the applied one is an older issue: replaying it must not roll the Canaries
  // back. The same issue fetched again is accepted.
  if (epoch === context.appliedEpoch && version === context.appliedVersion && issuedAt < context.appliedIssuedAt) {
    return refuse("version", `a bundle of version ${version} was issued before the applied one`);
  }
  const notAfter = timeOf(payload.not_after);
  if (notAfter === null) return refuse("invalid", "not_after is not a time");
  // A clock that returns nonsense must not make an expired bundle look fresh.
  if (!(context.now < notAfter)) return refuse("expired", "not_after of the bundle has passed");

  const listed = payload.rules;
  if (!Array.isArray(listed)) return refuse("invalid", "rules is not a list");
  if (listed.length > RULES_MAX) return refuse("invalid", `the bundle holds more than ${RULES_MAX} Rules`);
  const rules: Parameters<typeof buildPolicy>[0]["rules"][number][] = [];
  for (let i = 0; i < listed.length; i++) {
    const rule = readRule(listed[i]);
    if (typeof rule === "string") return refuse("invalid", `Rule ${i + 1}: ${rule}`);
    rules.push(rule);
  }
  // Optional (slice 04, amendment A1): the Rules that require a signed request travel apart from `rules`, so that a
  // Shield from before slice 04 ignores them instead of applying them as plain blocks. Same shape and checks as
  // `rules`; both lists hold at most 50 Rules together. A malformed one refuses the whole bundle.
  const signatureRules: Parameters<typeof buildPolicy>[0]["rules"][number][] = [];
  const required = payload.signature_rules;
  if (required !== undefined) {
    if (!Array.isArray(required)) return refuse("invalid", "signature_rules is not a list");
    if (listed.length + required.length > RULES_MAX) {
      return refuse("invalid", `rules and signature_rules hold more than ${RULES_MAX} Rules together`);
    }
    for (let i = 0; i < required.length; i++) {
      const rule = readRule(required[i]);
      if (typeof rule === "string") return refuse("invalid", `signature Rule ${i + 1}: ${rule}`);
      signatureRules.push(rule);
    }
  }

  // Optional: a bundle from before slice 07 has no Canaries. A malformed Canary refuses the bundle as a malformed
  // Rule does: the applied Policy, with its Canaries, stays.
  const canaries: CanaryInput[] = [];
  const planted = payload.canaries;
  if (planted !== undefined) {
    if (!Array.isArray(planted)) return refuse("invalid", "canaries is not a list");
    if (planted.length > CANARIES_MAX) return refuse("invalid", `the bundle holds more than ${CANARIES_MAX} Canaries`);
    for (let i = 0; i < planted.length; i++) {
      const canary = readCanary(planted[i]);
      if (typeof canary === "string") return refuse("invalid", `Canary ${i + 1}: ${canary}`);
      canaries.push(canary);
    }
  }
  // Optional: a bundle from before slice 09 has no blocks and no allowlist. A malformed entry refuses the bundle as a
  // malformed Rule does: the applied Policy, with its blocks and allowlist, stays. A block already past its expiry
  // is valid content; it is simply never enforced.
  const blocks: BlockInput[] = [];
  const listedBlocks = payload.blocks;
  if (listedBlocks !== undefined) {
    if (!Array.isArray(listedBlocks)) return refuse("invalid", "blocks is not a list");
    if (listedBlocks.length > BLOCKS_MAX) return refuse("invalid", `the bundle holds more than ${BLOCKS_MAX} blocks`);
    for (let i = 0; i < listedBlocks.length; i++) {
      const block = readBlock(listedBlocks[i]);
      if (typeof block === "string") return refuse("invalid", `block ${i + 1}: ${block}`);
      blocks.push(block);
    }
  }
  const allowlist: ParsedCidr[] = [];
  const ranges = payload.allowlist;
  if (ranges !== undefined) {
    if (!Array.isArray(ranges)) return refuse("invalid", "allowlist is not a list");
    if (ranges.length > ALLOWLIST_MAX) return refuse("invalid", `the allowlist holds more than ${ALLOWLIST_MAX} CIDRs`);
    for (let i = 0; i < ranges.length; i++) {
      const range = parseCidr(ranges[i]);
      // Only the canonical text is accepted: nothing is rewritten, as the protocol's `CidrSchema`.
      if (range === null || range.cidr !== ranges[i]) {
        return refuse("invalid", `allowlist entry ${i + 1} is not a normalised CIDR`);
      }
      allowlist.push(range);
    }
  }
  // Optional: a bundle from before slice 03 has no attestation keys, and then no token verifies. A malformed entry
  // refuses the bundle as a malformed Rule does: the applied Policy, with its keys, stays.
  const attestationKeys: AttestationKey[] = [];
  const listedKeys = payload.attestation_keys;
  if (listedKeys !== undefined) {
    if (!Array.isArray(listedKeys)) return refuse("invalid", "attestation_keys is not a list");
    if (listedKeys.length > KEYS_MAX) {
      return refuse("invalid", `the bundle holds more than ${KEYS_MAX} attestation keys`);
    }
    for (let i = 0; i < listedKeys.length; i++) {
      const key = readAttestationKey(listedKeys[i]);
      if (typeof key === "string") return refuse("invalid", `attestation key ${i + 1}: ${key}`);
      if (attestationKeys.some((known) => known.kid === key.kid)) {
        return refuse("invalid", `attestation key ${i + 1}: kid is listed twice`);
      }
      attestationKeys.push(key);
    }
  }
  // Optional (slice 20): a bundle from before slice 20 has no Virtual patches. Unlike the other members it never
  // refuses the bundle (forward compatibility, decided with Jev: fix_2_3_5): a patch this Shield cannot read is
  // skipped and counted, and a member that is not a list or is over its byte budget is ignored as a member.
  let patches: PatchInput[] = [];
  let patchesSkipped = 0;
  if (payload.patches !== undefined) {
    const read = readPatches(payload.patches);
    patches = read.patches;
    patchesSkipped = read.skipped + (read.ignored === null ? 0 : 1);
  }
  return {
    ok: true,
    policy: buildPolicy({
      version,
      epoch,
      issuedAt,
      notAfter,
      rules,
      signatureRules,
      canaries,
      blocks,
      allowlist,
      appId: appId ?? null,
      attestationKeys,
      patches,
      patchesSkipped,
    }),
  };
}

/** Verifies the body of the response of `GET /v1/policy-bundle`. The body is bounded before it is parsed. */
export function verifyBody(body: unknown, context: VerifyContext): Verified {
  if (typeof body !== "string") return refuse("invalid", "the response has no body");
  if (body.length > RESPONSE_BYTES_MAX || Buffer.byteLength(body, "utf8") > RESPONSE_BYTES_MAX) {
    return refuse("invalid", `the response is larger than ${RESPONSE_BYTES_MAX} bytes`);
  }
  let envelope: unknown;
  try {
    envelope = JSON.parse(body);
  } catch {
    return refuse("invalid", "the response is not JSON");
  }
  return verifyBundle(envelope, context);
}
