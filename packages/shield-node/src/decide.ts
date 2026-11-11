import { matchForms, matchMethod, normalisePath, pathForms } from "./policy/match.ts";
import type { AppliedPolicy } from "./policy/store.ts";
import type { DecideInput, Decision } from "./types.ts";

/**
 * The Decision for one request under `policy`. Synchronous and free of I/O by contract: it runs inside the host's
 * request, so it reads the applied Policy and nothing else. It never throws: input that cannot be read matches
 * no path, and a method that cannot be read meets only the Rules for every method.
 *
 * A Rule matches when its methods include the method and its pattern matches the path as text or any canonical
 * form of it (`pathForms`): decoded, with dot segments resolved — what a middleware after Shield may read. The
 * forms are split once per call and shared by every Rule.
 *
 * The requirement Rules (`signature_rules`, slice 04) follow the plain Rules in that one order, and are skipped when
 * `input.signed` is true: a requirement Rule matches only a request that does not meet its requirement. An input
 * without `signed` does not meet it. A CORS preflight (`OPTIONS` with `preflight`) skips them too (review F3).
 *
 * A Rule whose methods list `GET` also matches `HEAD`, which Express answers with the GET handler (review F2).
 *
 * The first Rule in order that matches in Enforce mode decides. Otherwise the first matching Rule in Monitor
 * mode marks the request, which proceeds. Otherwise the request is allowed.
 *
 * The returned objects are frozen and shared: one per Rule and one per Policy.
 */
export function decide(policy: AppliedPolicy, input: DecideInput): Decision {
  const plain = policy.rules;
  const given = input as { method?: unknown; path?: unknown; signed?: unknown; preflight?: unknown } | null | undefined;
  const method = typeof given?.method === "string" ? given.method.toUpperCase() : "";
  // Met, or a CORS preflight (which a browser never signs): no requirement Rule applies.
  const exempt = given?.signed === true || (given?.preflight === true && method === "OPTIONS");
  const required = exempt ? NONE : policy.signatureRules;
  if (plain.length === 0 && required.length === 0) return policy.allow;
  const target = given?.path;
  if (typeof target !== "string") return policy.allow;
  const forms = pathForms(normalisePath(target));
  if (forms.length === 0) return policy.allow; // not a path: no Rule matches
  let marked: Decision | undefined;
  for (const rules of [plain, required]) {
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i] as (typeof rules)[number];
      if (marked !== undefined && rule.mode === "monitor") continue; // only an Enforce Rule can still change the outcome
      if (!matchMethod(rule.methods, method) || !matchForms(rule.pattern, forms)) continue;
      if (rule.mode === "enforce") return rule.decision;
      marked = rule.decision;
    }
  }
  return marked ?? policy.allow;
}

const NONE: AppliedPolicy["signatureRules"] = Object.freeze([]);
