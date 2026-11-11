import { createHash } from "node:crypto";
import {
  type BundleAttestationKey,
  type BundleBlock,
  type BundleLimitRule,
  type BundlePatch,
  type BundlePayload,
  type BundleRule,
  type Canary,
  type Environment,
  POLICY_LIMITS,
  type PolicyRule,
  type SignedBundle,
} from "@antireverse/protocol";
import { storedLimit } from "./policy.ts";
import type { Signer } from "./signer.ts";

/** What a bundle is issued for. Every member comes from the Shield key and the stored Policy. */
export interface BundleSubject {
  /** `bundleAudience` of the Shield key. */
  audience: string;
  /** The epoch of the database the Policy comes from: versions are comparable only within one epoch. */
  epoch: string;
  appId: string;
  environment: Environment;
  /** The current version of the Policy; 0 when nothing was published. */
  version: number;
  rules: readonly PolicyRule[];
  /**
   * The active Canaries of the App and Environment, in the order the bundle carries them. None or empty: the
   * bundle has no `canaries` member, as before slice 07.
   */
  canaries?: readonly Canary[] | undefined;
  /**
   * The active Containments of the App and Environment, in the order the bundle carries them. A block whose
   * `expires_at` is not after the issuer's clock is left out. None or empty: no `blocks` member.
   */
  blocks?: readonly BundleBlock[] | undefined;
  /** The Organization's allowlist CIDRs, in order. None or empty: no `allowlist` member. */
  allowlist?: readonly string[] | undefined;
  /**
   * The public halves of the attestation keys (previous, current, next), in order. None or empty: no
   * `attestation_keys` member, as before slice 03.
   */
  attestationKeys?: readonly BundleAttestationKey[] | undefined;
  /**
   * The active Virtual patches of the App and Environment, in the order and modes the bundle carries them, already
   * within `PATCH_LIMITS` (`selectShipped`). None or empty: no `patches` member, as before slice 20.
   */
  patches?: readonly BundlePatch[] | undefined;
}

export interface IssuedBundle {
  signed: SignedBundle;
  /**
   * Changes whenever the bundle does: with the epoch, the version, the Canary set or the attestation keys, and when
   * the bundle is issued again.
   * It is a hash of the signed bytes, so it covers every member of the payload.
   */
  etag: string;
}

export interface BundleIssuer {
  /** The signed bundle of the subject: the one issued before while it is current, a new one otherwise. */
  issue(subject: BundleSubject): IssuedBundle;
}

/** A bundle is valid for 7 days from its issue. */
export const BUNDLE_LIFETIME_MS = 7 * 24 * 60 * 60 * 1_000;
/** A bundle older than this is issued again, so that a Shield in contact always has days of validity left. */
export const BUNDLE_REISSUE_AFTER_MS = 24 * 60 * 60 * 1_000;
/** Bundles kept. One Shield key has one bundle; beyond this number the one unused for longest is dropped. */
export const BUNDLE_CACHE_ENTRIES = 1_024;
/** A re-issue less than this before the bundle it replaces (by the clock) is dated just after it instead. */
const SAME_MOMENT_MS = 1_000;

interface Kept {
  epoch: string;
  version: number;
  /** `canaryDigest` of the Canaries the kept bundle carries. */
  canaries: string;
  /** `containmentDigest` of the blocks and the allowlist the kept bundle carries. */
  containment: string;
  /** `attestationDigest` of the attestation keys the kept bundle carries. */
  attestation: string;
  /** `patchDigest` of the Virtual patches the kept bundle carries. */
  patches: string;
  issuedAt: number;
  /** The issuer's clock when it signed the bundle: the age counts from here (`issuedAt` may be 1 ms ahead). */
  signedAt: number;
  issued: IssuedBundle;
}

/**
 * A Rule as Shield needs it: no name, no `requires` (the member it sits in says that), the documented order. Block
 * only: a Rule that is not a plain block Rule never comes out of here as one.
 */
function bundleRule(rule: PolicyRule): BundleRule {
  if (rule.action !== "block" || rule.limit !== undefined) {
    // Cannot happen with a stored Policy: a Rule has a limit exactly when its action is throttle, and such a Rule
    // goes in `limit_rules`. Better no bundle than a limit enforced as a plain block.
    throw new TypeError("A Rule in rules or signature_rules must be a block Rule without a limit.");
  }
  return { id: rule.id, path: rule.path, methods: [...rule.methods], action: "block", mode: rule.mode };
}

/** A limit Rule as Shield needs it (slice 08): a bundle Rule with the action throttle, then its limit, complete. */
function bundleLimitRule(rule: PolicyRule): BundleLimitRule {
  if (rule.action !== "throttle" || rule.limit === undefined) {
    throw new TypeError("A Rule in limit_rules must be a throttle Rule with a limit.");
  }
  return {
    id: rule.id,
    path: rule.path,
    methods: [...rule.methods],
    action: "throttle",
    mode: rule.mode,
    limit: storedLimit(rule.limit),
  };
}

/** Whether the Rule travels in `limit_rules`: it has a limit, or says throttle (then `bundleLimitRule` judges it). */
const isLimitRule = (rule: PolicyRule): boolean => rule.limit !== undefined || rule.action === "throttle";

/** Names a Canary set, order included: equal for the same Canaries in the same order, whatever the objects. */
function canaryDigest(canaries: readonly Canary[]): string {
  const hash = createHash("sha256");
  for (const canary of canaries) hash.update(JSON.stringify([canary.id, canary.kind, canary.value]));
  return hash.digest("hex");
}

/** Names the blocks and the allowlist, order included, like `canaryDigest`. */
function containmentDigest(blocks: readonly BundleBlock[], allowlist: readonly string[]): string {
  const hash = createHash("sha256");
  for (const block of blocks) {
    hash.update(
      JSON.stringify([
        "block",
        block.id,
        block.kind,
        block.kind === "actor" ? block.ip_hash : block.ip_prefix,
        block.expires_at,
      ]),
    );
  }
  for (const cidr of allowlist) hash.update(JSON.stringify(["allow", cidr]));
  return hash.digest("hex");
}

/** Names an attestation key set, order included, like `canaryDigest`: a rotation changes it. */
function attestationDigest(keys: readonly BundleAttestationKey[]): string {
  const hash = createHash("sha256");
  for (const key of keys) hash.update(JSON.stringify([key.kid, key.public_key]));
  return hash.digest("hex");
}

/** Names the Virtual patches, order and modes included, like `canaryDigest`: activation or a mode change changes it. */
function patchDigest(patches: readonly BundlePatch[]): string {
  return createHash("sha256").update(JSON.stringify(patches)).digest("hex");
}

/** A block as the bundle carries it: the members in the documented order, nothing else. */
function bundleBlock(block: BundleBlock): BundleBlock {
  return block.kind === "actor"
    ? { id: block.id, kind: "actor", ip_hash: block.ip_hash, expires_at: block.expires_at }
    : { id: block.id, kind: "prefix", ip_prefix: block.ip_prefix, expires_at: block.expires_at };
}

/**
 * Issues signed Policy Bundles and keeps each one while it is current: the same epoch, version and Canary set, issued less
 * than 24 hours ago. A kept bundle is handed out as it is, so its `ETag` stays the same and a polling
 * Shield is answered "not modified".
 */
export function createBundleIssuer(options: { signer: Signer; now?: () => Date; maxEntries?: number }): BundleIssuer {
  const { signer } = options;
  const now = options.now ?? (() => new Date());
  const maxEntries = Math.max(1, options.maxEntries ?? BUNDLE_CACHE_ENTRIES);
  // In order of use, oldest first: a Map iterates in insertion order and a used entry is inserted again.
  const kept = new Map<string, Kept>();

  function sign(subject: BundleSubject, blocks: readonly BundleBlock[], issuedAt: number): IssuedBundle {
    const payload: BundlePayload = {
      format: 1,
      audience: subject.audience,
      epoch: subject.epoch,
      app_id: subject.appId,
      environment: subject.environment,
      version: subject.version,
      issued_at: new Date(issuedAt).toISOString(),
      not_after: new Date(issuedAt + BUNDLE_LIFETIME_MS).toISOString(),
      // A Rule with a requirement never goes in `rules`: a Shield before slice 04 would enforce it as a plain block
      // (plan 04 amendment A1). It goes in `signature_rules`, which such a Shield strips. Nor does a Rule with a
      // limit (slice 08): it goes in `limit_rules`, which a Shield before slice 08 strips. Policy order in each;
      // the three together are the Policy's Rules, so at most `POLICY_LIMITS.rulesMax`.
      rules: subject.rules.filter((rule) => !isLimitRule(rule) && rule.requires === undefined).map(bundleRule),
    };
    const signatureRules = subject.rules.filter((rule) => !isLimitRule(rule) && rule.requires === "signature");
    if (signatureRules.length > 0) payload.signature_rules = signatureRules.map(bundleRule);
    // Only when there is one: a Policy without limit Rules gives the bundle it gave before slice 08, byte for byte.
    const limitRules = subject.rules.filter(isLimitRule);
    if (limitRules.length > 0) payload.limit_rules = limitRules.map(bundleLimitRule);
    const canaries = subject.canaries ?? [];
    if (canaries.length > 0) {
      payload.canaries = canaries.map(
        (canary) => ({ id: canary.id, kind: canary.kind, value: canary.value }) as Canary,
      );
    }
    if (blocks.length > 0) payload.blocks = blocks.map(bundleBlock);
    const allowlist = subject.allowlist ?? [];
    if (allowlist.length > 0) payload.allowlist = [...allowlist];
    const attestationKeys = subject.attestationKeys ?? [];
    if (attestationKeys.length > 0) {
      payload.attestation_keys = attestationKeys.map((key) => ({ kid: key.kid, public_key: key.public_key }));
    }
    const patches = subject.patches ?? [];
    if (patches.length > 0) payload.patches = patches.map((patch) => ({ ...patch }));
    // Serialised exactly once: the signature covers these bytes, and these bytes are what is transmitted.
    const bundle = JSON.stringify(payload);
    const bytes = Buffer.from(bundle, "utf8");
    if (bytes.byteLength > POLICY_LIMITS.bundleBytesMax) {
      // Cannot happen within the limits of a Policy. Shield would refuse such a bundle: better not to send it.
      throw new RangeError("The Policy Bundle is larger than a bundle may be.");
    }
    const signature = signer.sign(bytes);
    const etag = `"${createHash("sha256").update(bundle).update(signature).digest("hex").slice(0, 32)}"`;
    return { signed: { bundle, signature, key_id: signer.keyId }, etag };
  }

  return {
    issue(subject) {
      // The audience names one Shield key, and a Shield key belongs to one App and Environment.
      const slot = `${subject.appId} ${subject.environment} ${subject.audience}`;
      const at = now().getTime();
      const current = kept.get(slot);
      kept.delete(slot);

      const canaries = canaryDigest(subject.canaries ?? []);
      // Expiry is checked here, on the issuer's clock, whatever the caller read: a block past its expiry never
      // goes out, and its passing changes the digest, so the kept bundle is replaced.
      const blocks = (subject.blocks ?? []).filter((block) => Date.parse(block.expires_at) > at);
      const containment = containmentDigest(blocks, subject.allowlist ?? []);
      const attestation = attestationDigest(subject.attestationKeys ?? []);
      const patches = patchDigest(subject.patches ?? []);
      const age = current === undefined ? Number.NaN : at - current.signedAt;
      let entry: Kept;
      if (
        current !== undefined &&
        current.epoch === subject.epoch &&
        current.version === subject.version &&
        current.canaries === canaries &&
        current.containment === containment &&
        current.attestation === attestation &&
        current.patches === patches &&
        age >= 0 &&
        age < BUNDLE_REISSUE_AFTER_MS
      ) {
        entry = current;
      } else {
        // A re-issue of the same epoch is strictly later than the bundle it replaces, also when the change
        // comes within the same millisecond: Shield refuses an older bundle of the same version, so a replayed
        // bundle can neither bring back a lifted block nor drop a new one. A clock that went back further than
        // `SAME_MOMENT_MS` is believed instead, so a bundle is never dated more than that ahead of the clock.
        const gap = current === undefined ? Number.NaN : current.issuedAt - at;
        const issuedAt =
          current !== undefined && current.epoch === subject.epoch && gap >= 0 && gap < SAME_MOMENT_MS
            ? current.issuedAt + 1
            : at;
        entry = {
          epoch: subject.epoch,
          version: subject.version,
          canaries,
          containment,
          attestation,
          patches,
          issuedAt,
          signedAt: at,
          issued: sign(subject, blocks, issuedAt),
        };
      }

      kept.set(slot, entry);
      if (kept.size > maxEntries) {
        const oldest = kept.keys().next();
        if (!oldest.done) kept.delete(oldest.value);
      }
      return entry.issued;
    },
  };
}
