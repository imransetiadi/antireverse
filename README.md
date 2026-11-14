# Airverse

> Formerly Anti Reverse. Package names (`@antireverse/*`), the `antireverse` command, `AR_*` settings and wire names (`ar-*` headers) keep the old name so deployed clients keep working (D-065).

A SaaS platform that protects digital products against reverse engineering, tampering, cloning and automated abuse — and proves the protection by attacking the product with authorization.

**State of this repository:** slices 01–14, 16, 19 and 20 of [PRD.md](PRD.md) §18 are built: the walking skeleton, Policies, Guard attestation and signed requests, Harden, detection and alerts (Slack, webhook, email), the leak scan and Canaries, rate limits and login protection, containment, the Clone Beacon, policy simulation, the Reverse Assessment (with a scripted stand-in agent) and its CI gate, Verified Targets and Rules of Engagement, known-vulnerability Findings with virtual patches, the onboarding Set up page with the docs in `docs/`, the audit log (18a), data controls (18b: export and deletion), retention (18c) and usage metering (17a). Not built yet: Pentest Campaigns (15), plans and billing (17b), and the rest of GA hardening (18).

## What works today

1. Create an Organization and an App in the Console.
2. Add Shield to an Express or plain Node `http` server with the key the Console shows.
3. Every request to that server appears in the Console's live feed within seconds.

After you create an App, the Console shows its three set-up steps (**Add Shield**, **Add Guard**, **Harden your build**) with the App's real values, and a link, **Open the Set up page**, to the App's **Set up** page. That page shows the same steps and marks each one **Done** live, as Airverse sees it work ("First protected request received" for Shield); the Apps list shows **Set up: n of 3** until all three are done. [docs/getting-started.md](docs/getting-started.md) walks through it.

Then, to block: open the App's **Policy** page, add a Rule (for example `/api/admin/**`), promote it to Enforce and confirm. Shields with the policy public key apply it within 15 seconds; matching requests get `403 {"error":"request_blocked"}` and appear as *Blocked* in the feed. Roll back from the history in one action.

## Quickstart

Requirements: Node.js 22.12 or newer and npm. No Docker, no database to install.

**Packages are not published to npm.** `@antireverse/shield-node`, `@antireverse/guard` and `@antireverse/harden` exist only as workspace packages of this repository. `npm install` at the root links them, so code inside the repository (such as `apps/range`) imports them by name. To use Shield in a server outside the repository, depend on the folder: `npm install /path/to/this/repo/packages/shield-node` (it has no runtime dependencies). Its entry point is TypeScript, so the server must run on a Node that strips types (tested on 22.23.4) or through tsx; plain Node 22.12 cannot load it. For Guard, serve the files of `packages/guard/src` (see [docs/guard.md](docs/guard.md)).

**Running Harden.** Its entry point, `packages/harden/src/cli.ts`, is a TypeScript file, run by the `antireverse` bin. On Node 22.23 or newer (tested on 22.23.4), `npx antireverse harden …` works. On Node 22.12 the bin fails at once with `ERR_UNKNOWN_FILE_EXTENSION`; there, run `npx tsx packages/harden/src/cli.ts harden …` (the form every command in this README uses) or `node --experimental-strip-types node_modules/.bin/antireverse harden …` (Node prints an ExperimentalWarning).

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

`@antireverse/shield-node` is not published to npm yet; inside this repository it is a workspace package (see Requirements above for using it elsewhere).

## Docs

Step-by-step guides for developers, in [docs/](docs/):

- [Getting started](docs/getting-started.md): from creating an Organization to the first protected request, then Guard and Harden.
- [Shield](docs/shield.md): Express set-up, environment variables, monitor and enforce, the policy key.
- [Guard](docs/guard.md): the script tag and its options, signed requests.
- [Harden](docs/harden.md): the commands, `--register`, `--routes`, `--logic`, `--assess` and the CI gate.
- [Reverse Assessment](docs/reverse-assessment.md): what the score means, its Objectives and its honest limits.

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

**Email alerts:** set `AR_SMTP_HOST`, `AR_SMTP_PORT` (587), `AR_SMTP_TLS` (`starttls` or `implicit`), `AR_SMTP_USER`, `AR_SMTP_PASSWORD` (or `AR_SMTP_PASSWORD_FILE`) and `AR_SMTP_FROM` (optionally `AR_SMTP_FROM_NAME`, `AR_SMTP_CONFIRMATIONS_PER_DAY`), and publish SPF and DKIM for the sender domain. Then add an Email channel in the Console; each recipient gets a confirmation link and receives alerts only after pressing Confirm.

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

Airverse lists the open-source packages each App ships and runs, and matches them against a local copy of the OSV npm advisories. Your package list never goes to a third party.

```bash
npm run vulns:sync -w @antireverse/api                 # download and import npm advisories (stop the API first)
antireverse harden dist --register --lockfile package-lock.json --fail-on high
```

- **Build:** Harden sends package names and versions from the lockfile with the Build; the registration answer lists open Findings, and `--fail-on <low|medium|high|critical>` exits 4 when any are at or above that level.
- **Runtime:** Shield reads its installed packages at start and re-sends the list every 6 hours (`inventory: false` or `AR_SHIELD_INVENTORY=0` turns it off).
- **Findings:** advisory and CVE ids, severity (GHSA rating, else CVSS v3.1, else unknown), affected ranges and the version that fixes it. A Finding is Open, Fixed (the version is gone), Ignored (reason, up to 90 days; carried to later Builds) or Withdrawn (the advisory no longer applies). A new Critical or High Finding opens a "Vulnerable component" Incident and alerts.
- **Console:** Findings for the Organization and per App, a Finding page with Ignore and Reopen, and a Findings section on each Build.
- **Honest limits:** npm only; no lockfile means no build Findings; severity is the advisory's, not whether your code reaches the vulnerable function; fixing means upgrading.

### Virtual patches

For some advisories Airverse ships a virtual patch: Shield recognises the known exploit request for the vulnerable package. A patch is added automatically, in monitor, wherever a Finding for its advisory is open or ignored, and removed when the Finding is fixed. Promote it to Enforce on the Finding page (type the patch id to confirm); return to monitor in one action. A match opens a High "Exploit attempt" Incident.

- Catalog today: qs (CVE-2022-24999), lodash (CVE-2019-10744, CVE-2020-8203), xml2js (CVE-2023-0842).
- Body checks need `shield.verifyBody` on your body parsers; a body Shield never saw is recorded as "body not checked" and is never blocked. Under an enforced patch, a body in a character set Shield cannot read is refused.
- **Honest limits:** a patch stops the known shape of an exploit, not every variant; some patterns can match ordinary text, so read the hits in monitor before enforcing. Upgrading is the fix.

## Rate limits and login protection

A Rule can throttle: a limit of requests (or of failed responses, 401 and 403) per window, counted per address or per attested device. Over the limit an enforced Rule answers `429` with `Retry-After`; in monitor nothing changes. The Console's **Login protection** preset limits a login route to 10 failed responses per 5 minutes per address. A wave of failed logins from one network opens a High "Credential stuffing" Incident.

- **Honest limits:** counters are per Shield instance (several instances multiply the limit until a shared store exists); people behind one address share a counter; an attacker spread over many addresses stays under per-address limits.

## Policy simulation

On the Policy page, **Simulate** replays the last 24 hours of recorded requests against your Rules (or **Simulate with this Rule** for one you are typing) and shows, per Rule, how many requests it would refuse and from how many clients. The promote confirmation shows what promoting that Rule alone would refuse. Nothing is stored or published.

- **Honest limits:** an estimate from recorded traffic only. It never claims a refusal it cannot be sure of and reports the rest as "could not be judged". Virtual patches, blocks on individual clients, device limits and Shield's body checks are not simulated. Give Shield an actor key so clients can be told apart.

## Verified Targets and Rules of Engagement

Before Airverse may test a host, prove you own it under **Prove → Targets**: add the host, then publish the shown TXT record at `_airverse-challenge.<host>` or serve the token at `https://<host>/.well-known/airverse-verification.txt`, and press Verify. Ownership is re-checked daily. Under **Rules of Engagement**, sign what may be tested (hosts, excluded paths, intensity, UTC window, contacts) by typing the shown phrase; signed versions cannot be changed. **Check a test** shows whether a given test would be allowed.

- **Honest limits:** without user accounts, "signed" means signed with the Organization's admin key; DNS and the file prove control of the name at check time only.

## Reverse Assessment

Register a Build with its route inventory and protected functions, and queue an Assessment of the protected output:

```bash
npx tsx packages/harden/src/cli.ts harden <bundle-dir> --out <out-dir> --integrity \
  --register --endpoint <api-url> --key-env AR_ADMIN_KEY --app <appId> --environment production --build-version <v> \
  --routes routes.json --logic logic.json --assess T1
```

The Build page then shows **Reverse resistance**: the score or why there is none, each of the five Objectives — **W1 Map** (15 %), **W2 Secrets** (20 %), **W3 Logic** (25 %), **W4 Tamper** (20 %), **W5 Replay** (20 %) — with its evidence and a fix suggestion, and **Assess again** once a run has finished. The artifact is kept for 30 days after the last run. See [docs/reverse-assessment.md](docs/reverse-assessment.md) for what each Objective tests and how the score is computed.

Add `--logic logic.json` to designate up to 5 protected functions with hidden test vectors (Objective Logic); without it Logic is not assessed and the run is inconclusive. Tamper is judged on the bundle's JavaScript files: a Build without `--integrity` has no tamper check, so it counts as tampered.

- **Honest limits:** the agent is a scripted stand-in until a real model is configured, so results measure the pipeline, not real resistance. Untrusted code runs in a child process under Node's permission model, not a separate hosted account; a further adversarial review is pending before a real model agent is enabled. Harden's integrity check is a tamper signal, not tamper-proofing.

### CI gate

Add `--min-rrs <0–100>` to `harden --register --assess <tier>` to wait for the score and fail the step when it is lower: exit 5 below the threshold, exit 6 when there is no score (inconclusive, failed, or `--wait` ran out) unless you pass `--on-no-score pass`. For a separate pipeline step use `antireverse gate --assessment <asm_id> --min-rrs <n> --endpoint <url> --key-env <VAR>`. `--out` is written before the wait; progress goes to stderr every minute.

## Audit log

Every administrative change writes an entry in the same transaction: who (the admin key), when, what, and why. Sensitive actions — promoting to enforce, containment, signing Rules of Engagement, deleting a target — require a reason, sent as the percent-encoded `X-Airverse-Reason` header (the Console asks for it). Entries are append-only and hash-chained per Organization; **Settings → Audit log** shows them, checks the chain, and exports NDJSON that starts with a head signed by the audit key (`GET /v1/audit/public-key`), so an auditor can verify the export and detect truncation. The key lives in `audit-key.json` beside the data directory: back it up with the database.

## Usage

**Settings → Usage** (and `GET /v1/usage?month=YYYY-MM`) shows a month's usage per App, for the current month and the 13 before it:

- **Protected requests:** Events stored by the API, counted when they are stored. A resent batch adds nothing, and the count stays exact after retention removes the Events. Requests Shield drops before they reach Airverse, and batches the API refuses, are not counted.
- **Monthly active Guard devices:** distinct devices whose Attestation Token had a trusted or suspect verdict. At most 50,000 new devices are counted per App per day; past that the count is shown as a lower bound. Devices are counted by a keyed reference under a random salt per month. The salt is kept only in `usage-salts.json` beside the data directory, never in the database, and is deleted when the month is rolled up, so devices cannot be linked across months.
- **Prove sandbox minutes:** the run time of each Assessment, recorded once when it ends. An interrupted run counts at most its tier's budget plus grace.
- **Also shown:** the Apps count and the Event retention. Seats are not applicable until member accounts exist.

There are no prices, plans or limits yet (slice 17b, after the pricing decision).

## Data controls

**Settings → Data controls** (and the API under `/v1/organization/export`, `/v1/organization/deletion`, `/v1/subjects/*`):

- **Export** streams everything the Organization has as NDJSON: a manifest, one line per row, and an end line with per-table counts and a SHA-256 over the file, signed with the audit key. The audit chain comes first, up to the signed head named in the manifest; other tables are read page by page (`consistency: "per-page"`). Credentials leave as hashes.
- **Delete Organization** needs the typed name and a reason. Every key stops working at once (403 `organization-deletion-pending`, except deletion status, cancel and export); the data is erased at the first daily purge after seven days unless the deletion is cancelled. The purge removes every row in every table, the audit chain included, and leaves a tombstone with a signed report readable at `GET /v1/deletions/<deletion id>/report`. The Clone Beacon and attestation have no key and stay open meanwhile; what they record is purged too.
- **End-user requests** take the actor hash (`iph_…`, computed with the Shield key by `actorHash`; Airverse never receives the address): export that actor's Events and blocks, or erase them (reason required). Active blocks stay until they end and are listed in the report. Audit entries name the actor by a derived `subj_` reference, never the hash.
- **Retention** sets how long Events are kept: 7, 30, 90, 180 or 395 days (new Organizations 30; Organizations that existed before 18c start at 395). Shortening needs a reason. A daily job removes, per Organization: Events older than that (Events carrying a Guard report after at most 30 days), blocks that ended longer ago than that, Incidents last seen more than 395 days ago with their Detections and alert deliveries (an Incident waits while a block still names it), alert deliveries and finished Assessments older than 395 days, and expired protected artifacts. Each run's counts show on the page. Builds and the audit log are kept for the Organization's lifetime.

Backups are outside this: their 35-day expiry bounds how long erased data can survive in them.

## Clone Beacon

Tell Harden where your frontend is served, and it plants a small Clone Beacon beside the Canaries:

```bash
npx tsx packages/harden/src/cli.ts harden <bundle-dir> --out <out-dir> \
  --origin https://shop.example.com --origin https://www.shop.example.com \
  --register --endpoint <api-url> --key-env AR_ADMIN_KEY --app <appId> --environment production --build-version <v>
```

On an allowed origin, or on a local development host (localhost, `.test`, private addresses …), the beacon does nothing, so your visitors never contact Airverse. When a copy of the bundle runs anywhere else — a phishing clone or a mirror — it sends one small report, and a High **Clone detected** Incident opens naming the origin and the Build, with an alert to your channels. The Console shows the origin as plain text, never as a link.

- `--origin` needs `--register`; up to 20 origins, written exactly as browsers show them (`https://host[:port]`). To allow a new domain, harden and register a new Build.
- Your Content-Security-Policy `connect-src` must allow the Airverse API, or browsers drop the report.
- **Limits (honest):** a cloner who edits the bundle can remove the beacon; it catches wholesale copies. Anyone holding a bundle can forge reports, so each App counts at most 20 new origins per hour and the public endpoint is rate-limited. There is no origin lock — the beacon never stops your app.

## Containment

From an Incident, **Block actor** stops one attacking client for 15 minutes, 1 hour or 24 hours; **Block network** stops a whole /24 (or IPv6 /48) after you type the prefix. A block applies to the Incident's App and Environment only, reaches every Shield within about 5 seconds (its poll), expires on its own — Shield enforces the expiry even offline — and can be lifted early; every block and lift records who and when, and a lift is final. Blocked requests get the standard `403 {"error":"request_blocked"}` and do not open new Incidents. At most 150 blocks are active per App and Environment.

Actor identity is a keyed hash of the client address that **only you can compute**: set `AR_ACTOR_KEY` (or Shield's `actorKey` option) on every server running Shield for that App — 32 or more characters, not the Shield key — and keep it secret; Airverse never receives it. Generate one with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Without it Shield sends no hash: Incidents show no Actors and only network blocks are possible (`shield.stats().actorHashing` tells you which). **Never block** under Settings lists address ranges (CIDR) that containment can never block; it does not exempt them from your Rules.

- **Limits (honest):** rotating the actor key, or running Shields with different keys, makes existing actor blocks stop matching (network blocks are unaffected). An IPv4 attacker who keeps changing addresses escapes an actor block — block the network. IPv6 Actors are hashed per /64. Blocks wait for Shield's next poll; there is no push channel yet. The never-block list is checked by Shield for actor blocks, since Airverse cannot see the address behind a hash.

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
- **Policies are simple.** Rules match a path pattern and methods, and block, throttle, or require a signed request. No conditions, rollout, push channel or audit log yet; simulation is an estimate from recorded traffic (see Policy simulation). Shield polls for the signed Policy every 5 seconds.
- **Signing key.** The API signs Policies with an Ed25519 key in `signing-key.json` beside the data directory. Back it up with the database: losing it means re-configuring every Shield's `AR_POLICY_PUBLIC_KEY`.
- **Broad Rules.** Enforcing a Rule whose pattern starts with a wildcard needs a stronger confirmation; `/**` cannot be enforced.
- **Matching is deliberately wide.** Shield also matches decoded and dot-resolved forms of the path, so a request whose path *resolves* into a blocked area is blocked too. A known limit: HEAD against a Rule limited to GET is not blocked.
- **No rotation of Shield or admin keys, no event sampling, no deployment.** Rate limits exist, but their counters are per Shield instance (see Rate limits). The CI gates are Harden's exit codes (`--fail-on`, `--min-rrs`, `antireverse gate`); there is no hosted CI integration.
- **Route templates have limits.** Shield records the route template, never the concrete URL. Install it on the application rather than on a mounted router where you can: the path above Shield is recorded as `(mount)`. A regular-expression mount is recorded as `(unmatched)`; one without capture groups that matches non-numeric text is not detectable and is unsupported.

The order in which these arrive is in [PRD.md](PRD.md) §18. The vocabulary used everywhere is in [MEMORY.md](MEMORY.md) §3.
