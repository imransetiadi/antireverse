---
title: "Plan — Slice 03 Attestation path"
aliases: [Plan 03]
project: anti-reverse
doc: PLAN
slice: 3
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

# Slice 03 — Attestation Path Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** Guard obtains an Attestation Token; Shield verifies it offline and records a verdict on every request; the Console shows it.

**Architecture:** A new browser package `@antireverse/guard` (plain ES modules with JSDoc types and a hand-written `.d.ts`, type-checked with `checkJs`) collects signals, keeps a random device id, creates a non-extractable P-256 session key, and runs challenge → attest against two public API endpoints. The API mints Ed25519 JWTs with a dedicated, daily-rotated attestation key set whose public keys travel in the signed Policy Bundle. Shield verifies tokens offline from the `ar-attestation` header and records the result on the Event. The Console renders a verdict chip. No new dependency anywhere.

**Spec:** [tickets/03-attestation-path.md](../tickets/03-attestation-path.md). Background: [SDD.md](../SDD.md) §5.2, §7 (token claims), §9; [SECURITY.md](../SECURITY.md) TP-04, SC-KEY-02; [PERFORMANCE.md](../PERFORMANCE.md) PB-01, PB-05..PB-08; [UIUX.md](../UIUX.md) (restyled, D-053); MEMORY D-005, D-017, D-020, D-025, D-029. Earlier plans and amendments still bind (signed bundle verification, epoch, replay refusal, ETag digest re-issue; privacy allowlist; per-Organization bounds; never log keys or tokens).

## Global Constraints (additions)

- **Identifiers:** token `jti` = 32 hex; attestation key id `kid` = 16 hex (first 16 hex of SHA-256 of the raw public key); device `sub` = `dev_` + 24 hex.
- **Guard API:** `createGuard({ appId, endpoint, storage?, now? })` → `{ attest(): Promise<string|null>, token(): string|null, headers(): Record<string,string>, signals(): string[], stop(): void }`. Lazy: nothing runs until `attest()` (or `start()` scheduling it in idle time). Re-attests 60 s before expiry. Never throws to the caller (returns null and keeps no token on failure). `headers()` → `{ "ar-attestation": token }` or `{}`.
- **Signals v1:** `automation.webdriver` (`navigator.webdriver === true`), `automation.headless` (UA contains `HeadlessChrome`, or `navigator.plugins` absent where the UA claims Chrome desktop), `env.inconsistent` (UA platform contradicts `navigator.platform`/`userAgentData.platform`). Signal ids only; no values.
- **Device id:** 128-bit random (WebCrypto), base64url, stored in `localStorage["ar.device"]`; a new one when storage is unavailable. Never sent raw beyond the attest call; the token's `sub` is `dev_` + 24 hex of SHA-256(`app_id` + ":" + device id) computed by the API.
- **Session key:** `crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])` (non-extractable private key); public JWK thumbprint per RFC 7638 → `cnf.jkt` (base64url SHA-256).
- **Endpoints (public, no key):** `POST /v1/attest/challenge` `{ app_id }` → `{ nonce, expires_at }` (nonce 32 hex, single use, 60 s, in memory, bounded); `POST /v1/attest` `{ app_id, nonce, device, signals, cnf: { jkt } }` → `{ token, expires_at }`. CORS: `Access-Control-Allow-Origin: *`, methods POST/OPTIONS, header `content-type`, no credentials. Unknown App or bad nonce → 400 problem with a fixed text. Rate limits: 60 requests per minute per caller prefix, 600 per minute per App; over → 429. Only the caller's /24 or /48 is kept (for limits), never logged with the address.
- **Token:** JWS compact, header `{ "alg": "EdDSA", "typ": "JWT", "kid" }`; claims `iss: "antireverse"`, `aud: <app_id>`, `sub`, `iat`, `exp = iat + 300`, `jti`, `cnf: { jkt }`, `verdict`, `risk`, `sig: [signal ids]`, `pv: 1`.
- **Verdict v1:** no signal → `trusted`, risk 5; `automation.webdriver` → `suspect` 70; `automation.headless` → `suspect` 60; `env.inconsistent` → `suspect` 40; two or more signals → `hostile`, risk = min(100, sum). Unknown signal ids are ignored.
- **Keys:** `attestation-keys.json` beside the data directory (like `signing-key.json`), separate purpose. Set = {previous?, current, next}. Tokens are signed with current. Every 24 h (injectable clock) next → current only if next has been published ≥ 1 h; a fresh next is generated; previous is kept 24 h. The bundle carries `attestation_keys: [{ kid, public_key }]` (≤ 3, base64url raw Ed25519); the ETag digest includes them.
- **Shield:** header `ar-attestation` (lower-case; one value; ≤ 2,048 chars). Verification: three base64url parts; header alg `EdDSA`, typ `JWT`, kid in the applied bundle's set; Ed25519 signature over `header.payload`; `iss`, `aud` = bundle `app_id`, `exp > now − 30 s`, `iat ≤ now + 30 s`, `exp − iat ≤ 300`; claims well-formed. Verified results cached by `jti` (≤ 10,000, until `exp`). Result → Event `attestation: { status: "valid"|"missing"|"invalid"|"expired", verdict: …|null, risk: number|null }`. Fail open; never log the token. Bench: valid cached token and invalid token paths within PB-01 (p99 ≤ 1.5 ms) — measure cold and warm.
- **Event:** `attestation` optional-nullable (default null for older Shields), within the privacy allowlist.
- **Console:** `AttestationChip` (word + Phosphor icon + colour): Trusted (ShieldCheck, primary), Suspect (ShieldWarning, medium), Hostile (ShieldSlash or Skull — pick a distinct silhouette, critical), No token (Minus/CircleDashed, subtle), Invalid (Prohibit, high), Expired (ClockCountdown, subtle). Column "Client" in the live feed and evidence tables. Follows UIUX.md as restyled (D-053).

## Review Focus

1. **Cryptography:** only EdDSA accepted (`alg: none`, HS*, ES*, missing kid rejected), audience and expiry enforced, signature over exactly the received bytes, no token accepted with a key not in the bundle. *(shield, API)*
2. **Key rollover:** no moment where a valid token's key is missing from a Shield's bundle; old keys retire; keys never leave the API except public halves. *(API)*
3. **Public endpoints:** nonce single use and expiry; rate limits; no address logged; CORS without credentials. *(API)*
4. **Guard:** never blocks or throws into the page; non-extractable key; no personal data; storage unavailable handled. *(guard)*
5. **Honesty:** UI and docs never claim a Trusted verdict proves a genuine client. *(console, docs)*

## Contracts

- **P1 Protocol:** `attestation.ts` (isomorphic): `ATTESTATION_SIGNALS`, `VERDICTS`, `ATTESTATION_STATUSES`, `ATTESTATION_LIMITS` (ttl 300, nonce 60, skew 30, header max 2048, keys max 3), `verdictFor(signals)` (the table), schemas `ChallengeRequest/Response`, `AttestRequest/Response`, `AttestationClaims`, `EventAttestation`, `BundleAttestationKey`; Event gains `attestation`; Bundle gains `attestation_keys`. Server entry: `signAttestationToken(privateKey, kid, claims)`, `verifyAttestationToken(token, keys, { appId, now })` → `{ status, claims? }` (used by Shield tests as the reference, and by the API), `jwkThumbprint(jwk)`, `attestationKid(publicKeyRaw)`.
- **P2 Guard:** `packages/guard` (new workspace: package.json with `type: module`, `exports` → `src/index.js` and `types` → `src/index.d.ts`; vitest project `guard` with jsdom or happy-dom only if already installed — otherwise a minimal fake browser global set in tests; tsconfig with `checkJs`).
- **P3 API:** key store with rotation; endpoints; nonce store; limits; bundle field.
- **P4 Shield:** header read, verify, cache, Event field, bench.
- **P5 Console:** chip, column, copy.

## Tasks

Order: Task 1 (protocol) → Tasks 2–5 in parallel (Guard ‖ API ‖ Shield ‖ Console) → Task 6 (e2e) → Task 7 (review, docs).

1. **Protocol** — failing tests first: schemas, verdict table, sign/verify round trip, tampered payload/signature, wrong alg (`none`, `HS256`), unknown kid, wrong audience, expired, future iat, lifetime > 300, thumbprint known answer (RFC 7638 example), kid derivation.
2. **Guard** — failing tests first: attest flow against a fake fetch (challenge → attest → token), re-attest timing (injected clock), never throws (fetch failing, storage throwing, crypto missing), signals from faked navigator values, device id persistence, non-extractable key (extractable false), size under budget (gzip the sources).
3. **API** — failing tests first per Review Focus 2–3: nonce single use and expiry, unknown App, limits, CORS preflight, token claims and signature (verify with the protocol), sub derivation, rotation schedule (next published ≥ 1 h before use; previous retained), bundle keys and ETag change on rotation, no key material in responses or logs.
4. **Shield** — failing tests first per Review Focus 1: every rejection case, cache by jti, expiry by Shield clock, Event field, no token in logs/events, bench.
5. **Console** — failing tests first: chip states, column in live feed and evidence, copy pins (no claim that Trusted proves genuineness), build.
6. **End to end** — HTTP: challenge/attest with signal sets → tokens verify with the bundle keys; requests through Shield on the reference app with valid, missing, forged, expired, other-App tokens → Events carry the right status and verdict. Browser: a static page (served by the reference app or a fixture server on the same origin as the API calls it makes) loads Guard, attests, calls the reference app with `headers()`; Playwright's Chromium reports `navigator.webdriver`, so the expected verdict is Suspect — assert it in the Console live feed.
7. **Review and docs.**

## Residual risks known up front

- Scriptable handshake: clean signals can be sent by any client; verdicts are evidence only.
- Nonces and limits live in one API process's memory.
- Bearer token: until slice 04, a stolen token is usable for up to 5 minutes.

## Deliberately not in this slice

Request signing · enforcement on verdicts · challenge programs · Guard hardening · remote config · integrity/hooking/debugger signals · grace period.

## Amendments

- **A1 — Protocol as built (Jev: accept_but_recheck_kid, 0.55 — leaned, flagged to the owner).** Unknown signal ids are dropped from attest requests and tolerated in token `sig` (forward compatibility); verdict and risk are taken as signed; `0 < exp − iat ≤ 300` lives in the claims schema; `expires_at` values are ISO-8601; derived patterns are grouped in `ATTESTATION_PATTERNS`; extra exports `ATTESTATION_HEADER`, `EXAMPLE_ATTESTATION_CLAIMS`. Added: when Shield applies a bundle it checks each key id equals the first 16 hex of SHA-256 of its public key, and refuses the bundle otherwise. Known answers: kid of the RFC 8032 test key `21fe31dfa154a261`; jkt of the RFC 7517 A.1 key `cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s`; worst-case bundle 60,886 bytes.
- **A2 — Console as built (Jev: accept_all, 0.74).** A "Client" column right after Decision in the live feed and Incident evidence; chips: Trusted (shield check, accent), Suspect (shield warning, medium), Hostile (shield slash, critical), No token (minus), Invalid (prohibit, high), Expired (clock countdown), Not reported (dashed circle, for older Shields); verdict chips tinted with "risk N" beside them, other chips hollow; a visible note above each Event table: "Client shows the Guard attestation Shield verified for each request. It is evidence, not proof."; a valid status without a verdict is never shown as Trusted.
- **A3 — Guard as built (Jev: lock_and_timeout, 0.56).** Plain ES modules with JSDoc and a hand-written `.d.ts`, 6.5 KB gzip, tests in happy-dom (already installed). Local token lifetime clamped to 90–300 s against client clock skew, re-attest 60 s before; `token()` returns null after it; a failed re-attest drops the token without automatic retry (the page calls `attest()` again); `automation.headless` = no plugins where the UA claims desktop Chrome; `env.inconsistent` compares OS families. Added: a 10 s timeout on both Guard requests; the workspace is registered in `package-lock.json` (npm install, no new package) so `npm ci` keeps working.
- **A4 — API as built.** One fixed 400 text for an unknown App and any bad nonce (no oracle); a key counts as published when it enters the set (every bundle response carries it at once); the first start signs with a new key; both endpoints share the limits (60/min per caller prefix, 600/min per App — 30 attestations per minute per prefix); a SECURITY DEFINER function checks App existence for the keyless endpoints (migration 0012); rotation is lazy, on first use after it falls due; keys file mode 0600, written by temp file and rename. Open for the owner (Jev 0.37, leaning to count only successful attestations toward the per-App limit): a distributed caller can use up one App's 600 per minute and deny its genuine clients a token.
- **A5 — Shield as built (Jev: accept_cache_by_hash, 0.96).** A bundle without `app_id` makes every token invalid (older bundles stay valid); a malformed `app_id` refuses the bundle; a header sent twice is invalid; the attested bench cases are gated against PB-01 (1.5 ms) — measured p99 65–67 µs on an idle machine (one run failed under a load average of 8–11 from parallel workers). Changed: the verified-token cache is keyed by the SHA-256 of the exact token string, so nothing unverified is read before the signature check. Each forged token costs one Ed25519 verify (~50 µs); there is no negative cache.
- **A6 — Review fixes (Jev: fix_all_as_proposed, 0.73).** F1 (MEDIUM) made-up App ids could evict and reset a real App's limit window: the App limit counts only after the App exists (challenge) or the nonce validates (attest), and a full limiter refuses new keys instead of evicting running windows — this also answers the open per-App limit point. F2 (LOW) two API processes on one key file split the key set: rotation re-reads the file and adopts a newer set. F3 (LOW) after downtime a never-served key could sign at once: on load, publication counts from process start. F4 (LOW) a failed rotation write retried on every use: back off once a minute, one warning. F5 (LOW) `createGuard` could throw on hostile options: option reads are guarded and fall back to an inert Guard. The review found the token verifiers agree on 1,332 crafted cases and no issue in signature, header, encoding, claim or cache handling.
- **A7 — End to end.** Playwright's Chromium earns Hostile (risk 100): `navigator.webdriver`, no plugins under a desktop Chrome user agent, and a Windows user agent on a macOS platform. The test derives the expected verdict from the signals the browser shows. Expired tokens are produced with the running API's own key set and past times.
