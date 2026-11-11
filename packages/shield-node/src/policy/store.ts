// The applied Policy: what `decide` reads. Replaced as a whole when a verified bundle arrives, never edited.
import type { KeyObject } from "node:crypto";
import type { ParsedCidr } from "../address.ts";
import { type AppliedLimitRule, type LimitRuleInput, prepareLimitRule } from "../limits.ts";
import { type MatchablePatch, type PatchInput, preparePatch } from "../patches.ts";
import type { Decision } from "../types.ts";
import type { PathPattern } from "./match.ts";

/** One Rule of the applied Policy, ready to match. */
export interface AppliedRule {
  readonly id: string;
  /** The path pattern as published. It is the `request.route` of the Event of a blocked request. */
  readonly path: string;
  /** Upper-case methods the Rule applies to; an empty list is every method. */
  readonly methods: readonly string[];
  readonly mode: "monitor" | "enforce";
  readonly pattern: PathPattern;
  /** The Decision of a request this Rule decides. One frozen object per Rule: `decide` allocates nothing. */
  readonly decision: Decision;
}

export interface AppliedPolicy {
  readonly version: number;
  /**
   * The `epoch` of the bundle: random per database of the API. Versions are comparable only within one epoch.
   * Null for the built-in Policy, which was never issued.
   */
  readonly epoch: string | null;
  /** `issued_at` of the bundle, in milliseconds since the epoch. */
  readonly issuedAt: number;
  /** `not_after` of the bundle, in milliseconds since the epoch. Afterwards the Policy is stale and still applied. */
  readonly notAfter: number;
  readonly rules: readonly AppliedRule[];
  /**
   * The Rules that require a signed request (the bundle's `signature_rules`, slice 04). One matches a request (path
   * and methods, as a plain Rule) only when the requirement is not met. Checked after `rules`.
   */
  readonly signatureRules: readonly AppliedRule[];
  /**
   * The Rules with a limit (the bundle's `limit_rules`, slice 08), in bundle order. Never read by `decide`: the
   * limiter counts them, after Containments and Rules and before the Virtual patches.
   */
  readonly limitRules: readonly AppliedLimitRule[];
  /**
   * Entries of the bundle's `limit_rules` this Shield could not read and skipped (forward compatibility), plus 1 when
   * the member was ignored as a whole. Internal: `ShieldStats` (contract C3) is unchanged.
   */
  readonly limitRulesSkipped: number;
  /** The Decision of a request no Rule matches. */
  readonly allow: Decision;
  /** Decoy key → Canary id: a request that carries the key adds the signal of the Canary. Built once per bundle. */
  readonly canaryKeys: ReadonlyMap<string, string>;
  /** Decoy route → Canary id: a request whose path, raw or canonical, is the route adds the signal. */
  readonly canaryRoutes: ReadonlyMap<string, string>;
  /** Actor hash → the actor block that names it. Built once per bundle. */
  readonly blocksByHash: ReadonlyMap<string, BlockEntry>;
  /** Network prefix (`a.b.c.0/24`, `x:y:z::/48`) → the prefix block that names it. Built once per bundle. */
  readonly blocksByPrefix: ReadonlyMap<string, BlockEntry>;
  /** The never-block ranges, parsed once per bundle. */
  readonly allowlist: readonly ParsedCidr[];
  /** The Decision of a request a Containment blocks: block, enforce, no Rule. One frozen object per Policy. */
  readonly containedDecision: Decision;
  /** `app_id` of the bundle: the audience an Attestation Token must name. Null for the built-in Policy. */
  readonly appId: string | null;
  /** The attestation public keys of the bundle by kid, each imported once per bundle. Empty: no token verifies. */
  readonly attestationKeys: ReadonlyMap<string, AttestationKey>;
  /** The Virtual patches of the bundle in order (slice 20). Evaluated after the Rules. */
  readonly patches: readonly AppliedPatch[];
  /**
   * Entries of the bundle's `patches` this Shield could not read and skipped (forward compatibility), plus 1 when the
   * member was ignored as a whole. Internal: `ShieldStats` (contract C3) is unchanged.
   */
  readonly patchesSkipped: number;
}

/** One Virtual patch of the applied Policy (slice 20), prepared once per bundle. */
export interface AppliedPatch extends MatchablePatch {
  readonly id: string;
  readonly mode: "monitor" | "enforce";
  /** The advisory of the Finding that activated the patch. */
  readonly advisory: string;
  /** The Decision of a request this patch decides: block, its mode, no Rule. One frozen object per patch. */
  readonly decision: Decision;
  /**
   * The Decision recorded when the patch's body was never checked (A6, F2), or could not be read under a monitor
   * patch (A11, M2): allow in monitor — it did not block and
   * never counts as an exploit attempt or a hit; the Event still names the patch with `patch_body` "unchecked".
   */
  readonly uncheckedDecision: Decision;
}

/** One attestation public key of the applied bundle. */
export interface AttestationKey {
  readonly kid: string;
  /** The raw key as the bundle carries it (43 base64url characters): a cached token is kept only while it stays. */
  readonly publicKey: string;
  readonly key: KeyObject;
}

/** One block of the applied Policy: the Containment's id and the end of the block in milliseconds. */
export interface BlockEntry {
  readonly id: string;
  readonly expiresMs: number;
}

/** One block of a bundle, already checked. */
export type BlockInput =
  | { readonly id: string; readonly kind: "actor"; readonly ipHash: string; readonly expiresMs: number }
  | { readonly id: string; readonly kind: "prefix"; readonly ipPrefix: string; readonly expiresMs: number };

/** One Canary of a bundle, already checked. */
export interface CanaryEntry {
  readonly id: string;
  readonly kind: "key" | "route";
  readonly value: string;
}

/** The path pattern behind each block Decision Shield has handed out. */
const routes = new WeakMap<Decision, string>();

export function buildPolicy(input: {
  version: number;
  /** Null, or left out, for a Policy that no bundle carried. */
  epoch?: string | null;
  issuedAt: number;
  notAfter: number;
  rules: readonly Pick<AppliedRule, "id" | "path" | "methods" | "mode" | "pattern">[];
  /** Left out: none. */
  signatureRules?: readonly Pick<AppliedRule, "id" | "path" | "methods" | "mode" | "pattern">[];
  /** Left out: none. */
  canaries?: readonly CanaryEntry[];
  /** Left out: none. */
  blocks?: readonly BlockInput[];
  /** Left out: none. */
  allowlist?: readonly ParsedCidr[];
  /** Left out: null. */
  appId?: string | null;
  /** Left out: none. */
  attestationKeys?: readonly AttestationKey[];
  /** Left out: none. */
  patches?: readonly PatchInput[];
  /** Left out: 0. */
  patchesSkipped?: number;
  /** Left out: none. */
  limitRules?: readonly LimitRuleInput[];
  /** Left out: 0. */
  limitRulesSkipped?: number;
}): AppliedPolicy {
  const { version } = input;
  const compile = (rule: Pick<AppliedRule, "id" | "path" | "methods" | "mode" | "pattern">): AppliedRule => {
    const decision: Decision = Object.freeze({
      action: "block",
      mode: rule.mode,
      ruleId: rule.id,
      policyVersion: version,
    });
    routes.set(decision, rule.path);
    return Object.freeze({
      id: rule.id,
      path: rule.path,
      methods: Object.freeze([...rule.methods]),
      mode: rule.mode,
      pattern: rule.pattern,
      decision,
    });
  };
  const rules = input.rules.map(compile);
  const signatureRules = (input.signatureRules ?? []).map(compile);
  const canaryKeys = new Map<string, string>();
  const canaryRoutes = new Map<string, string>();
  for (const canary of input.canaries ?? []) {
    const lookup = canary.kind === "key" ? canaryKeys : canaryRoutes;
    if (!lookup.has(canary.value)) lookup.set(canary.value, canary.id); // the first of two equal values names it
  }
  const blocksByHash = new Map<string, BlockEntry>();
  const blocksByPrefix = new Map<string, BlockEntry>();
  for (const block of input.blocks ?? []) {
    const lookup = block.kind === "actor" ? blocksByHash : blocksByPrefix;
    const target = block.kind === "actor" ? block.ipHash : block.ipPrefix;
    const known = lookup.get(target);
    // Two blocks of one target (the API keeps one active): the one that lasts longer stands.
    if (known === undefined || block.expiresMs > known.expiresMs) {
      lookup.set(target, Object.freeze({ id: block.id, expiresMs: block.expiresMs }));
    }
  }
  const attestationKeys = new Map<string, AttestationKey>();
  for (const key of input.attestationKeys ?? []) attestationKeys.set(key.kid, Object.freeze({ ...key }));
  return Object.freeze({
    version,
    epoch: input.epoch ?? null,
    issuedAt: input.issuedAt,
    notAfter: input.notAfter,
    rules: Object.freeze(rules),
    signatureRules: Object.freeze(signatureRules),
    limitRules: Object.freeze((input.limitRules ?? []).map((rule) => prepareLimitRule(rule, version))),
    limitRulesSkipped: input.limitRulesSkipped ?? 0,
    // Only the built-in Policy is Monitor mode as a whole: nothing was published, so nothing could be enforced.
    allow: Object.freeze({
      action: "allow",
      mode: version === 0 ? "monitor" : "enforce",
      ruleId: null,
      policyVersion: version,
    }),
    canaryKeys,
    canaryRoutes,
    blocksByHash,
    blocksByPrefix,
    allowlist: Object.freeze([...(input.allowlist ?? [])]),
    containedDecision: Object.freeze({ action: "block", mode: "enforce", ruleId: null, policyVersion: version }),
    appId: input.appId ?? null,
    attestationKeys,
    patches: Object.freeze(
      (input.patches ?? []).map(
        (patch): AppliedPatch =>
          Object.freeze({
            ...preparePatch(patch),
            id: patch.id,
            mode: patch.mode,
            advisory: patch.advisory,
            decision: Object.freeze({ action: "block", mode: patch.mode, ruleId: null, policyVersion: version }),
            uncheckedDecision: Object.freeze({
              action: "allow",
              mode: "monitor",
              ruleId: null,
              policyVersion: version,
            }),
          }),
      ),
    ),
    patchesSkipped: input.patchesSkipped ?? 0,
  });
}

/** Version 0, no Rules: what Shield applies until a bundle arrives. It was never issued, so it is never stale. */
export const BUILT_IN_POLICY: AppliedPolicy = buildPolicy({
  version: 0,
  issuedAt: 0,
  notAfter: Number.POSITIVE_INFINITY,
  rules: [],
});

/**
 * The path pattern of the Rule behind a block Decision that `decide` returned; undefined for any other object.
 * The middleware records it as the route of a blocked request, so that the concrete path never leaves the process.
 */
export function routeOfDecision(decision: Decision): string | undefined {
  return routes.get(decision);
}

export interface PolicyStore {
  current(): AppliedPolicy;
  apply(policy: AppliedPolicy): void;
  /** `now` is past `not_after` of the applied Policy. A stale Policy stays applied. */
  isStale(now: number): boolean;
}

export function createPolicyStore(): PolicyStore {
  let applied = BUILT_IN_POLICY;
  return {
    current: () => applied,
    apply(policy) {
      applied = policy;
    },
    isStale: (now) => now > applied.notAfter,
  };
}
