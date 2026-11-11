# Anti Reverse

A SaaS platform that protects digital products against reverse engineering, tampering, cloning and automated abuse — and proves the protection by attacking the product with authorization.

**State of this repository:** slices 01 (walking skeleton), 02 (Policy path) and 05 (Harden path). Shield can observe and block, and a web bundle can be hardened in CI; everything else in the specification is not built yet.

## What works today

1. Create an Organization and an App in the Console.
2. Add Shield to an Express server with the key the Console shows.
3. Every request to that server appears in the Console's live feed within seconds.

Then, to block: open the App's **Policy** page, add a Rule (for example `/api/admin/**`), promote it to Enforce and confirm. Shields with the policy public key apply it within 15 seconds; matching requests get `403 {"error":"request_blocked"}` and appear as *Blocked* in the feed. Roll back from the history in one action.

## Quickstart

Requirements: Node.js 22.12 or newer and npm. No Docker, no database to install.

```bash
npm install
```

```bash
npm run dev
```

`npm run dev` starts the API on `http://127.0.0.1:8787` and the Console on `http://127.0.0.1:3000`. Then:

1. Open the Console, create an Organization, and save the admin key it shows once.
2. Create an App and copy the Shield key it shows once.
3. In a second terminal, start the reference target with that key:

```bash
AR_SHIELD_KEY="<the Shield key>" AR_POLICY_PUBLIC_KEY="<the policy public key>" npm run dev:range
```

4. Open the App's live feed in the Console and request the reference target:

```bash
curl http://127.0.0.1:4010/api/products/7
```

The request appears in the feed as `GET /api/products/:id`, Decision *Allowed*, mode *Monitor*.

To protect your own Express server instead of the reference target:

```ts
import { createShield } from "@antireverse/shield-node";

const shield = createShield({
  key: process.env.AR_SHIELD_KEY,
  endpoint: "http://127.0.0.1:8787",
  policyPublicKey: process.env.AR_POLICY_PUBLIC_KEY, // without it Shield observes only
});
app.use(shield.express());
```

`@antireverse/shield-node` is not published to npm yet; inside this repository it is a workspace package.

## Layout

| Path | What it is |
|---|---|
| `packages/protocol` | The wire contract: Event schema, key and identifier formats, API bodies |
| `packages/shield-node` | Shield for Node: Express middleware with no runtime dependencies |
| `apps/api` | The API: key authentication, Organizations, Apps, ingest, Event list, live stream |
| `apps/console` | The Console (Next.js) |
| `apps/range` | `ar-range`, the reference target that Shield observes |
| `tests/e2e` | The journey over HTTP and in a real browser |
| `*.md` at the root | The specification: PRD, SDD, SECURITY, PERFORMANCE, OPERATION, QASUITE, UIUX, MEMORY |
| `tickets/`, `plans/` | The ticket and implementation plan of each slice, with spike findings |

## Detection and alerts

Two managed rules run on every App over the Events Shield sends: **Blocked burst** (at least 20 enforced blocks from one network prefix within 5 minutes → High) and **Failed sign-in burst** (at least 30 application responses with status 401 or 403 from one prefix within 5 minutes → Medium; Shield's own blocks do not count). A Detection joins the open Incident for the same rule, App, Environment and prefix; a resolved Incident is never reopened. Open **Incidents** in the Console to read the timeline and evidence, then acknowledge or resolve.

Add alert channels under **Alerts**: a **webhook** (its signing secret is shown once) or a **Slack** incoming webhook. A new Incident sends one alert to every channel, with up to 3 attempts. Webhook requests carry `AR-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">`; verify it with `verifyWebhookSignature` from `@antireverse/protocol/server`, and accept the header when any `v1` matches.

- **Destinations are checked on every attempt:** `https` only, and an address that is loopback, private, link-local, cloud metadata or otherwise special-purpose is refused; the connection is pinned to the checked address. `AR_ALLOW_PRIVATE_ALERT_URLS=1` allows `http` and local addresses — for local development and tests only.
- **Limits (honest):** the detector and the alert queue live in the API process, so a restart forgets partial bursts and queued alerts. Channel URLs and signing secrets are stored in the database as plain text. Email alerts are not offered until a provider is chosen.

## Guard and attestation

`@antireverse/guard` is a small browser library (plain ES modules, no dependency, about 7 KB gzip). It gets a short-lived Attestation Token and lets your frontend send it with API calls:

```js
import { createGuard } from "@antireverse/guard";
const guard = createGuard({ appId: "app_…", endpoint: "https://<anti-reverse-api>" });
await guard.attest();                      // or guard.start() to run in idle time
await fetch("/api/orders", { headers: { ...guard.headers() } });
```

Shield verifies the token offline with keys from the signed Policy Bundle and records, for every request, whether a valid token came with it and the verdict Guard's signals earned: **Trusted**, **Suspect** or **Hostile** (with a risk score), or **No token**, **Invalid**, **Expired**. The Console shows it in the live feed and in Incident evidence. Nothing is blocked on it yet.

- **Honest limits:** a token shows that a Guard-like client completed the handshake recently — not that the client is genuine; anyone can script the handshake with clean signals. Guard reports; Shield decides. Signals today: automation (webdriver, headless) and environment inconsistency. Until request signing (slice 04), a stolen token can be reused for up to 5 minutes. The attestation endpoints rate-limit by caller address; behind a reverse proxy the API sees one address for everyone.
- Attestation keys live in `attestation-keys.json` beside the data directory (separate from the policy key), rotate daily, and are published an hour before they sign. Back the file up with the database. Run one API process per key file.

## Signed requests

Guard can sign each API call so a captured request cannot be replayed or altered:

```js
const res = await guard.fetch("/api/orders", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(order) });
```

On your server, let Shield check bodies through your parser and render its refusals:

```js
const shield = createShield({ /* … */, bodyVerified: { types: ["application/json"] } });
app.use(shield.express());
app.use(express.json({ verify: shield.verifyBody }));
// … routes …
app.use(shield.errorHandler());
```

In the Console, tick **Require a signed request** on a Rule; run it in monitor first, then promote it. On an enforced route, a request that is unsigned, older than 60 s, replayed, or whose body or content type changed after signing gets the standard 403; a request with a body whose type is not in `bodyVerified.types` is refused there too. Every request shows its signature status in the live feed. Browser preflights (`OPTIONS`) are not subject to the requirement.

- **Honest limits:** replay protection is per Shield instance; a script driving a real browser with Guard signs genuine requests (signing stops replay and tampering, not automation); anyone can obtain a token with their own key, so the requirement proves a Guard-like client, not a genuine one; proxies that rewrite the path, content type or body break signatures.

## Known vulnerabilities (Exposure)

Anti Reverse lists the open-source packages each App ships and runs, and matches them against a local copy of the OSV npm advisories. Your package list never goes to a third party.

```bash
npm run vulns:sync -w @antireverse/api                 # download and import npm advisories (stop the API first)
antireverse harden dist --register --lockfile package-lock.json --fail-on high
```

- **Build:** Harden sends package names and versions from the lockfile with the Build; the registration answer lists open Findings, and `--fail-on <low|medium|high|critical>` exits 4 when any are at or above that level.
- **Runtime:** Shield reads its installed packages at start and re-sends the list every 6 hours (`inventory: false` or `AR_SHIELD_INVENTORY=0` turns it off).
- **Findings:** advisory and CVE ids, severity (GHSA rating, else CVSS v3.1, else unknown), affected ranges and the version that fixes it. A Finding is Open, Fixed (the version is gone), Ignored (reason, up to 90 days; carried to later Builds) or Withdrawn (the advisory no longer applies). A new Critical or High Finding opens a "Vulnerable component" Incident and alerts.
- **Console:** Findings for the Organization and per App, a Finding page with Ignore and Reopen, and a Findings section on each Build.
- **Honest limits:** npm only; no lockfile means no build Findings; severity is the advisory's, not whether your code reaches the vulnerable function; fixing means upgrading.

## Clone Beacon

Tell Harden where your frontend is served, and it plants a small Clone Beacon beside the Canaries:

```bash
npx tsx packages/harden/src/cli.ts harden <bundle-dir> --out <out-dir> \
  --origin https://shop.example.com --origin https://www.shop.example.com \
  --register --endpoint <api-url> --key-env AR_ADMIN_KEY --app <appId> --environment production --build-version <v>
```

On an allowed origin, or on a local development host (localhost, `.test`, private addresses …), the beacon does nothing, so your visitors never contact Anti Reverse. When a copy of the bundle runs anywhere else — a phishing clone or a mirror — it sends one small report, and a High **Clone detected** Incident opens naming the origin and the Build, with an alert to your channels. The Console shows the origin as plain text, never as a link.

- `--origin` needs `--register`; up to 20 origins, written exactly as browsers show them (`https://host[:port]`). To allow a new domain, harden and register a new Build.
- Your Content-Security-Policy `connect-src` must allow the Anti Reverse API, or browsers drop the report.
- **Limits (honest):** a cloner who edits the bundle can remove the beacon; it catches wholesale copies. Anyone holding a bundle can forge reports, so each App counts at most 20 new origins per hour and the public endpoint is rate-limited. There is no origin lock — the beacon never stops your app.

## Containment

From an Incident, **Block actor** stops one attacking client for 15 minutes, 1 hour or 24 hours; **Block network** stops a whole /24 (or IPv6 /48) after you type the prefix. A block applies to the Incident's App and Environment only, reaches every Shield within about 5 seconds (its poll), expires on its own — Shield enforces the expiry even offline — and can be lifted early; every block and lift records who and when, and a lift is final. Blocked requests get the standard `403 {"error":"request_blocked"}` and do not open new Incidents. At most 150 blocks are active per App and Environment.

Actor identity is a keyed hash of the client address that **only you can compute**: set `AR_ACTOR_KEY` (or Shield's `actorKey` option) on every server running Shield for that App — 32 or more characters, not the Shield key — and keep it secret; Anti Reverse never receives it. Generate one with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Without it Shield sends no hash: Incidents show no Actors and only network blocks are possible (`shield.stats().actorHashing` tells you which). **Never block** under Settings lists address ranges (CIDR) that containment can never block; it does not exempt them from your Rules.

- **Limits (honest):** rotating the actor key, or running Shields with different keys, makes existing actor blocks stop matching (network blocks are unaffected). An IPv4 attacker who keeps changing addresses escapes an actor block — block the network. IPv6 Actors are hashed per /64. Blocks wait for Shield's next poll; there is no push channel yet. The never-block list is checked by Shield for actor blocks, since Anti Reverse cannot see the address behind a hash.

## Leak scan and Canaries

`antireverse harden` scans the bundle before it changes anything and fails with exit code 3 when something is about to leak: a source map, a private key, a known secret-key format (AWS, GitHub, Stripe, Slack, Google), a random-looking value assigned to a secret-like name (also unquoted in `.env`/YAML files), or an internal URL. It prints the rule, `path:line`, a masked value and a fingerprint — never the value — and writes and registers nothing. To accept a reviewed false positive, commit its fingerprint with a reason in `.antireverse/leak-allow.json` (or pass `--leak-allow <file>`):

```json
{ "version": 1, "allow": [{ "fingerprint": "<32 hex>", "reason": "Public demo key, revoked" }] }
```

Each Build also gets **Canaries**: one decoy API key and two decoy internal routes, planted as plain text in one protected file. They look like your own key (`ak_live_…`), never a third-party provider's. With `--register` they are registered with the Build and sent to Shield in the signed bundle; when anyone uses one against your API — a bearer token, `x-api-key`, `?api_key=` or the decoy route — Shield adds a signal to that request's Event (never the key) without changing the response, and a High **Canary used** Incident opens within about a second, naming the Build that leaked, and alerts your channels.

- **Limits (honest):** the scan matches patterns; multi-line or computed secrets and symlinked files are not caught. Canaries are only seen where Shield runs. Their values derive from the build seed (and App and version when registering) so output stays reproducible — an attacker who brute-forces the seed could recognise them. A bundle too small to hold the Canaries within the size budget fails the harden.

## Hardening a bundle

`antireverse harden` is a build-time step a developer runs in their own CI over a web bundle they own, to make reverse engineering costlier. It never changes behaviour — it runs the bundle's own test command against the protected output and fails if anything differs — and the source never leaves the machine; only a signed-free Build Manifest (hashes, paths, costs) is uploaded when you pass `--register`.

```bash
npx tsx packages/harden/src/cli.ts harden <bundle-dir> --profile balanced --out <out-dir> --test "npm test"
```

- **Profiles:** `light` = identifier mangling only; `balanced` = mangling + string encryption bound at the use site; `maximum` = `balanced` for now. A per-build `--seed` makes output deterministic.
- **Budget is a gate:** a module is never shipped more than 35 % larger (gzip); if a transform would exceed it, the file falls back to mangle-only or is emitted unchanged, with the reason in the report.
- **Report-only by default:** without `--out` it writes nothing. `--register --endpoint <url> --key-env AR_ADMIN_KEY --app <appId> --environment development --build-version <v>` uploads the Manifest (the key is read only from the named environment variable).
- **Limits (honest):** mangling and string encryption are obfuscation, not secrecy — the decoder ships in the bundle, so never put real secrets in client code. The opt-in `--integrity` check is a tamper *signal* for already-bundled (non-ESM) code, not tamper-proofing. A file that calls `eval` is left unmangled (eval can read a local by name). Public export names, imports and property keys are preserved by design.

## Commands

| Command | Does |
|---|---|
| `npm run verify` | Lint and format check, type-check, all unit and integration tests, the HTTP journey |
| `npm test` | Tests only |
| `npm run e2e` | The browser journey (Playwright). One-time set-up: `npx playwright install --only-shell --no-remove chromium` (about 100 MB) |
| `npm run bench` | Shield overhead benchmark; fails when p99 exceeds 0.5 ms per request |
| `npm run dev` | API and Console |
| `npm run dev:range` | The reference target (needs `AR_SHIELD_KEY`) |
| `npm run fix` | Apply formatting and safe lint fixes |

## Configuration

| Variable | Used by | Default |
|---|---|---|
| `HOST`, `PORT` | API, reference target | `127.0.0.1`; `8787` (API), `4010` (reference target) |
| `PORT` | Console | `3000` |
| `AR_DATA_DIR` | API | `apps/api/.data/pg` |
| `AR_API_URL` | Console, reference target | `http://127.0.0.1:8787` |
| `AR_SHIELD_KEY` | reference target | none — without it Shield is disabled and the server still runs |
| `AR_POLICY_PUBLIC_KEY` | reference target | none — without it Shield observes only and never blocks |
| `AR_SHIELD_DISABLED=1` | any server using Shield | switches Shield off |
| `AR_ALLOW_PRIVATE_ALERT_URLS=1` | API | off — alert channels must be public `https` |
| `AR_ACTOR_KEY` | any server using Shield | none — without it no Actor identities are sent and only network blocks are possible |
| `AR_CONSOLE_URL` | API (links in alerts) | `http://127.0.0.1:3000` |
| `AR_NEXT_DIST_DIR` | Console | `.next` — the browser e2e sets `.next/e2e` so it can run beside a dev server |

## What is deliberately missing

> The Harden package (Babel 8) asks for Node ≥ 22.18; it installs and runs on 22.12 with a warning. Use Node ≥ 22.18 in CI to clear it.


This is a local walking skeleton, not a deployable service.

- **No user accounts.** The Console signs in with the Organization's admin key, kept in an httpOnly cookie. Anyone who can reach the API can create an Organization. Keep it on localhost.
- **Development storage.** The API uses PostgreSQL embedded in its process (PGlite) with real row-level security. Exactly one process may open the data directory, and it is not durable against power loss. Production will use a PostgreSQL server with the same SQL.
- **Policies are basic.** Rules match a path pattern and methods and can only block. No conditions, rollout, push channel, simulation or audit log yet. Shield polls for the signed Policy every 5 seconds.
- **Signing key.** The API signs Policies with an Ed25519 key in `signing-key.json` beside the data directory. Back it up with the database: losing it means re-configuring every Shield's `AR_POLICY_PUBLIC_KEY`.
- **Broad Rules.** Enforcing a Rule whose pattern starts with a wildcard needs a stronger confirmation; `/**` cannot be enforced.
- **Matching is deliberately wide.** Shield also matches decoded and dot-resolved forms of the path, so a request whose path *resolves* into a blocked area is blocked too. A known limit: HEAD against a Rule limited to GET is not blocked.
- **No rate limiting, key rotation, sampling, CI or deployment.**
- **Route templates have limits.** Shield records the route template, never the concrete URL. Install it on the application rather than on a mounted router where you can: the path above Shield is recorded as `(mount)`. A regular-expression mount is recorded as `(unmatched)`; one without capture groups that matches non-numeric text is not detectable and is unsupported.

The order in which these arrive is in [PRD.md](PRD.md) §18. The vocabulary used everywhere is in [MEMORY.md](MEMORY.md) §3.
