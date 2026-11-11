---
title: "Plan — Slice 04 Signed requests"
aliases: [Plan 04]
project: anti-reverse
doc: PLAN
slice: 4
version: 0.1.0
status: done
updated: 2026-11-11
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# Slice 04 — Signed Requests Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** A replayed or tampered request on a route that requires signing is rejected; every request records its signature status.

**Architecture:** Guard signs a canonical string with its non-extractable P-256 key; the token carries the public key. Shield verifies offline (token first, then signature, timestamp, nonce), keeps a bounded per-instance nonce window, and exposes `verifyBody` for the body parser's `verify` hook. Rules gain an optional requirement. The Console adds the rule option and a signature status chip. No new dependency.

**Spec:** [tickets/04-signed-requests.md](../tickets/04-signed-requests.md). Background: SDD §5.2, §7 (request signature row), §10 (policy); PERFORMANCE PB-01 (signature 0.30 ms, replay check 0.02 ms); SECURITY TA-06, TP-04; MEMORY D-005, D-027, D-030, D-053, D-054, D-055. Earlier plans and amendments still bind (slice 03 token verification and cache; slice 02 rule matching, raw and canonical paths, broad-rule confirmation; privacy allowlist; fail open; never log tokens, signatures or bodies).

## Global Constraints (additions)

- **Headers (lower-case):** `ar-signature: v1,t=<unix seconds>,n=<nonce>,s=<signature>` — nonce 22 base64url (128 bit random), signature 86 base64url (64-byte IEEE P1363 r‖s, ECDSA P-256 SHA-256); `ar-content-sha256: <43 base64url>` — SHA-256 of the exact body bytes (the empty string's hash for no body). Order of `t,n,s` fixed; exactly one of each.
- **Canonical string (UTF-8):** `"ar-sig-v1\n" + METHOD (upper case) + "\n" + request target (path and query exactly as sent on the wire, i.e. Express `req.originalUrl`) + "\n" + content-sha256 + "\n" + t + "\n" + n + "\n" + token jti`.
- **Token:** claims `cnf` gains `jwk: { kty: "EC", crv: "P-256", x, y }` (43-char base64url coordinates); `/v1/attest` takes `cnf: { jkt, jwk }` and refuses (400, fixed text) when `jwkThumbprint(jwk) !== jkt`. Tokens without `cnf.jwk` still verify (status valid) but cannot back a signature (signature status `invalid`).
- **Shield signature status:** `missing` (no `ar-signature`), `invalid` (malformed headers, no valid token, no key, bad signature, content hash header malformed), `stale` (|t − now| > 60 s), `replayed` (the pair (token jti, n) seen within 120 s on this instance), `valid`. Order: parse → token valid with jwk → signature → timestamp → nonce (a nonce is remembered only after a valid signature). Nonce store: ≤ 100,000 entries, 120 s, oldest evicted only when expired; when full of live entries new signed requests are `invalid`? — no: record `replayed` cannot be decided, so treat as `invalid` and count it (fail closed only under an enforced requirement). Imported keys cached by jkt (≤ 10,000).
- **Body:** `body: "checked" | "unchecked" | "mismatch" | "none"` — `none` when the request has no body (no `content-length` > 0 and no `transfer-encoding`); `checked` when `shield.verifyBody` saw bytes whose hash equals `ar-content-sha256`; `mismatch` → `verifyBody` throws an error with `status = 403` and `expose = false` (body-parser answers 403 before the handler) and the signature status becomes `invalid`; `unchecked` when a body exists but no hook ran. For `none`, `ar-content-sha256` must equal the empty-string hash, else `invalid`.
- **Event:** `signature: { status, body } | null` (optional-nullable, default null for older Shields).
- **Rules:** `PolicyRule` gains optional `requires: "signature"`. A rule with a requirement matches a request (path + methods) only when the requirement is NOT met: signature `valid` and body `checked` or `none`. Then its action (block) applies in its mode (monitor records, enforce answers the standard block response). Because the body check happens in the parser hook after Shield's decision, an enforced requirement on a route with a body needs the hook; without it the body is `unchecked` and the request is blocked under enforce — the Console warns about this.
- **Guard:** `sign({ method, url, body }) → Promise<Record<string,string>>` (always resolves; on any failure returns the attestation header only, or `{}`), `fetch(input, init)` → signs then calls the global fetch with merged headers (never adds credentials), re-attesting first if no token. URL: resolved against `location.href`; the signed target is `pathname + search` of that URL. Body hashing: string (UTF-8), ArrayBuffer, ArrayBufferView, Blob (`arrayBuffer()`), URLSearchParams (`toString()` UTF-8, content type set as fetch would); FormData / ReadableStream / unknown → unsigned (attestation only).
- **Console:** rule form checkbox "Require a signed request" (with help: "Requests on this route must come from Guard with a valid signature. Add shield.verifyBody to your body parser for routes that take a body."); rule list shows "Signed requests required"; signature chip states: Signed (checked or no body), Signed · body not checked, Unsigned, Invalid, Stale, Replayed, Not reported. Restyled design (D-053).
- **Budgets:** PB-01 p99 ≤ 1.5 ms for a signed request (token cached, signature verify, nonce check); bench cold and warm.

## Review Focus

1. **Signature correctness:** canonical string identical in Guard and Shield; P1363 vs DER handled; every field bound; no acceptance with a token lacking jwk; method/target case and encoding pitfalls. *(guard, shield)*
2. **Replay:** a nonce is consumed only after a valid signature; replay within 120 s caught; stale beyond 60 s; memory bounded; full store behaviour. *(shield)*
3. **Body binding:** `verifyBody` mismatch refused before the handler; no body-parser behaviour change otherwise; `unchecked` never counted as satisfied. *(shield)*
4. **Rules:** requirement semantics in monitor and enforce; broad-rule confirmation still applies; old Shields ignore the field safely (they would treat such a rule as a plain block — check and prevent: the API must not ship `requires` rules to Shields that cannot understand them, or the rule must be expressed so old Shields ignore it). *(protocol, API, shield)*
5. **Guard:** never throws; no private key exposure; unsupported bodies degrade to unsigned. *(guard)*

## Contracts

- **P1 Protocol:** signature constants and parsers (`SIGNATURE_HEADER`, `CONTENT_HASH_HEADER`, `SIGNATURE_LIMITS { windowS: 60, nonceTtlS: 120 }`, `parseSignatureHeader`, `canonicalSigningString`), `SignatureStatus`, `EventSignatureSchema`; claims `cnf.jwk` optional; `AttestRequest` `cnf.jwk`; `PolicyRule.requires` optional; server helpers `verifyRequestSignature(...)` reference for tests.
- **P2 Guard:** `sign`, `fetch`, body hashing, P1363 output (WebCrypto ECDSA already returns P1363).
- **P3 API:** attest checks jwk ↔ jkt and puts `cnf.jwk` in tokens; policy publish accepts `requires`; Review Focus 4 safety for older Shields.
- **P4 Shield:** verification, nonce store, `verifyBody`, rule requirement, Event field, bench.
- **P5 Console:** rule option, rule list, signature chip, copy.

## Tasks

Order: Task 1 (protocol) → Tasks 2–5 in parallel → Task 6 (e2e) → Task 7 (review, docs).

## Residual risks known up front

- Per-instance replay window (no shared store).
- Proxies that rewrite the request target or body break signatures (documented).
- Signing does not stop a scripted real browser running Guard.

## Deliberately not in this slice

Shared nonce store · expressions on verdicts · challenge response · non-Express adapters.

## Amendments

- **A1 — Requirement rules travel separately; a full nonce store refuses (Jev: separate_member_invalid_when_full, 0.51 — flagged to the owner).** In the Policy (API and Console) a rule may carry `requires: "signature"`. In the signed bundle, rules with a requirement are NOT put in `rules`; they go in a new optional member `signature_rules` (same rule shape, no `requires` field) that Shields before slice 04 ignore, so an older Shield never turns a requirement into a plain block. When the nonce store holds 100,000 live entries, a new signed request is recorded `invalid` (replay cannot be ruled out) and is only blocked where an enforced requirement applies; no live entry is ever evicted.
- **A2 — Protocol as built (Jev: tighten_body_require_jwk, 0.74).** Signature header regex and canonical string pinned (example SHA-256 `f227c025…6b78`, checked with printf); P1363 only (a DER signature is invalid); `EMPTY_CONTENT_SHA256 = 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU`; bundle rule shape omits `name` and `requires`; `rules + signature_rules ≤ 50`. Tightened: status `missing` ⇔ body null, otherwise a body state is required; `jwkThumbprint` refuses non-canonical coordinates; `/v1/attest` requires `cnf.jwk` from this slice (the schema keeps it optional so older claims parse).
- **A3 — Guard as built.** `sign()` and `fetch()` (global fetch; attestation calls keep the injectable transport); a Request with its own stream body is sent unsigned rather than read; headers merged as fetch does and lower-cased; a token whose jti cannot be read still attests but requests go out unsigned; the method is upper-cased only in the signed string (Shield's canonical string upper-cases too); Guard replaces only the `ar-*` headers it sets. 11 KB gzip.
- **A4 — Console as built.** Rule form checkbox "Require a signed request" (help: "Requests on this route must come from Guard with a valid signature. For routes that take a body, add shield.verifyBody to your body parser."); a "Signed requests required" tag under the rule's path; an unknown requirement value is refused as a stale form. "Signature" column after "Client": Signed, Signed · body not checked, Unsigned, Invalid, Invalid · body changed, Stale, Replayed, Not reported — each with its own Phosphor glyph, word and colour.
- **A5 — Shield as built, with the owner's error stance (owner 2026-11-11; Jev split 0.48/0.41).** Decision order: containment, then plain rules and signature rules in bundle order (first enforced match wins). `bodyVerified: true` (option) defers an enforced requirement on a request with a body to `verifyBody`; without it such requests are blocked at decision time. `verifyBody` answers 403 only where an enforced requirement applies; elsewhere a body mismatch is recorded (invalid, mismatch) and the request continues, so monitor never changes a response. Owner: where an enforced requirement applies, an internal error during the signature check counts as not met and blocks (fail closed); everywhere else Shield still fails open (D-004). Bench: signed warm p99 102 µs, cold 179 µs, replayed 133 µs (PB-01 1.5 ms).
- **A6 — Review fixes.** F1 (MEDIUM, owner's decision 2026-11-11 after Jev split 0.57/0.39): the `content-type` header value (exact, empty when absent) joins the canonical string, and `bodyVerified` becomes `{ types: [...] }` — media types whose parser carries `shield.verifyBody`; under an enforced requirement a request with a body whose media type is not listed is blocked at decision time; a deferred check that never ran is recorded as the requirement's block decision when the response closes. Jev (0.91): F2 HEAD matches any Rule listing GET (all rules); F3 a CORS preflight (OPTIONS with `access-control-request-method`) is exempt from requirement Rules only; F4 Guard signs the exact serialised target it fetches; F5 a nonce is kept until t + 61 s; F6 `shield.errorHandler()` writes the standard block response for Shield's body refusal, and the error carries that JSON body.
- **A7 — End to end.** HTTP 12 tests (own Express app with `express.json({ verify: shield.verifyBody })`); browser: rule with the requirement set and promoted in the Console, `guard.fetch` passes (Signed), the captured request replayed from Node gets 403 and shows Replayed.
