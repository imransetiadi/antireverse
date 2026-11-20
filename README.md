# Airverse

> Formerly Anti Reverse. Package names (`@antireverse/*`), the `antireverse` command, `AR_*` settings and wire names (`ar-*` headers) keep the old name so deployed clients keep working (D-065).

A SaaS platform that protects digital products against reverse engineering, tampering, cloning and automated abuse — and proves the protection by attacking the product with authorization.

**State of this repository:** slices 01–14, 16, 19 and 20 of [PRD.md](PRD.md) §18 are built: the walking skeleton, Policies, Guard attestation and signed requests, Harden, detection and alerts (Slack, webhook, email), the leak scan and Canaries, rate limits and login protection, containment, the Clone Beacon, policy simulation, the Reverse Assessment (with a scripted stand-in agent) and its CI gate, Verified Targets and Rules of Engagement, known-vulnerability Findings with virtual patches, the onboarding Set up page with the docs in `docs/`, the audit log (18a), data controls (18b: export and deletion), retention (18c), usage metering (17a), SLO measurement with the operator dashboard (18d), the release-gate runner (18e), synthetic probes for enforcement propagation and event freshness (18g), tamper detection (21) and the Pentest Campaign pipeline with a scripted stand-in engine (15a). Not built yet: a real Campaign engine (15b), plans and billing (17b), browser measurement of the Console (SLO-08), and the rest of GA hardening (18).

## How to use Airverse

The product is used in this order. Each step links to the section that explains it.

| Step | What you do | Where |
|---|---|---|
| 1 | Install and start the API and the Console | [Quickstart](#quickstart) |
| 2 | Create an Organization and an App; keep the admin key and the Shield key | [Quickstart](#quickstart) |
| 3 | Add Shield to your server, so every request shows in the live feed | [docs/shield.md](docs/shield.md) |
| 4 | Add Guard to your pages, so browsers attest and sign requests | [Guard and attestation](#guard-and-attestation), [docs/guard.md](docs/guard.md) |
| 5 | Harden your bundle and register the Build | [Hardening a bundle](#hardening-a-bundle), [docs/harden.md](docs/harden.md) |
| 6 | Write a Policy, simulate it, then promote it to Enforce | [What works today](#what-works-today), [Policy simulation](#policy-simulation) |
| 7 | Add alert channels and handle Incidents; block an attacker | [Detection and alerts](#detection-and-alerts), [Containment](#containment) |
| 8 | Measure resistance with a Reverse Assessment, and gate CI on the score | [Reverse Assessment](#reverse-assessment) |
| 9 | Verify a host you own, sign Rules of Engagement, and run a Campaign against it | [Verified Targets and Rules of Engagement](#verified-targets-and-rules-of-engagement), [Pentest Campaigns](#pentest-campaigns) |
| 10 | Govern: audit log, usage, data export and deletion, retention | [Audit log](#audit-log), [Usage](#usage), [Data controls](#data-controls) |
| 11 | Operate: SLO dashboard, Campaign kill switch, release gate | [Operator SLO dashboard](#operator-slo-dashboard), [Release gate](#release-gate) |

Two kinds of people use it:

- **A customer** signs in to the Console with the Organization's admin key and does steps 2 to 10.
- **An operator** runs the API, sets its variables ([Configuration](#configuration)), and uses `/ops` in the Console with the operator token.

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

## Pentest Campaigns

A Campaign is a scoped test that Airverse runs against a host **you own**, under the Rules of Engagement you signed. In this version the engine is a scripted stand-in. The product says so on every result: "Scripted checks. They measure the pipeline and its safety controls. This is not a penetration test."

**Switch it on (operator).** Campaigns are off unless the API is started with `AR_PROVE_CAMPAIGNS=1`. Without it, creating a Campaign answers 403.

**Before you can launch one:**

1. Under **Prove → Targets**, verify the host. Whichever method verified it, a Campaign also needs the token served at `https://<host>/.well-known/airverse-verification.txt`: at the start of every Campaign that file must be answered by the very address the Campaign will test.
2. Under **Prove → Rules of Engagement**, sign Rules that put the host in scope. They must be at most 90 days old and must not exclude the verification path.

**Launch (Prove → Campaigns → New Campaign):**

1. Choose the Target and an intensity: `passive` or `safe-active`, never above the signed one.
2. Type the phrase `I authorise a test of <host>`.
3. Tick "This target is a staging or test system".
4. Give a reason. It is written to the audit log.

**What a Campaign sends.** These limits are fixed in code:

| Limit | Value |
|---|---|
| Methods | GET and HEAD only; never a body, a cookie or a credential |
| Requests | At most 60, the ownership check included |
| Rate | One request per second, one at a time |
| Time | At most 300 seconds |
| Response data | 64 KB of body read per response, about 2 MB in all. One response may make its connection read at most 64 KB of body, 16 KB of headers and 80 KB of TLS and framing overhead; beyond that the connection is cut, at most one network read (64 KB) late |
| What is asked | Only the probes the engine declares in its catalog: exact method and path, and fixed query values. Any other request the engine asks for is refused and ends the Campaign |
| Where | HTTPS on port 443, to the one address resolved at the start; redirects are never followed |
| Running at once | One per Organization and one per server |
| Created | 5 per Organization and 3 per Target in 24 hours |

Every request carries `User-Agent: Airverse-Campaign/1` and `X-Airverse-Campaign: <id>`, so you can recognise it in your logs.

**Watch and stop.** The Campaign page refreshes while it runs and shows the request log, refusals included. **Stop** is there for as long as the Campaign is queued or running. A stop is final, and no request follows it: the stop, the operator's switch and a suspension are read from the database before every request — the ownership check at the start included — and once more at the moment it is sent, and a Campaign is not started past one that is already recorded. A Campaign that was stopped never ends as completed, even when the stop arrived as its last check finished; what it did until then is still reported. Requesting the Organization's deletion stops its running Campaign the same way, and ends one that is still queued (a Campaign is never left queued under a pending deletion); after cancelling the deletion, launch a new Campaign.

**Read the result.**

- **Findings** have a severity and redacted evidence. A Finding is *Unverified* until one repeat confirms it.
- **Evidence is small on purpose.** Of a response, a Finding keeps the status, a short list of headers (of a Content-Security-Policy only that it was sent) and at most 200 characters of the body around what the check matched. Nothing else of a response body is stored: no longer excerpt, no hash, nothing in the request log or the audit log. A Finding's title and severity are the check's own, never text taken from a response.
- **The report** says how many checks ran, reported a finding, were inconclusive or were skipped. It never says "no vulnerabilities found".
- **Inconclusive** means the check got an answer it could not read: a body cut at 64 KB, one that is not plain UTF-8 text, or one in which something was redacted and the check found nothing (what it looks for may be what was redacted). A body sent with a `Content-Encoding` (gzip, br), with a declared charset other than UTF-8 or US-ASCII, or with bytes that are not valid UTF-8 is not decoded or guessed at; the check is counted as inconclusive, never as "ran, nothing reported".
- **The request log shows what each connection really read**, in bytes, failed requests included. The number is never rounded down to a limit. A request marked *Read limit passed* means the target sent more than one request may read; that Campaign ends as failed, on its byte budget.
- **A Campaign ends** as completed, stopped, refused (a start check failed, with the reason), failed or interrupted (the API restarted; it is never resumed). If a Finding was reported and not stored, for any reason, the Campaign ends as failed and the report says how many.

**Operator controls** (`/ops` in the Console, or the API with `Authorization: Bearer $AR_OPS_TOKEN`):

| Action | Route |
|---|---|
| See the switch, suspensions and active Campaigns | `GET /v1/ops/prove` |
| Stop everything and refuse new Campaigns | `POST /v1/ops/prove/kill` |
| Allow Campaigns again | `POST /v1/ops/prove/enable` |
| Suspend or resume one Organization | `POST /v1/ops/prove/organizations/<id>/suspend`, `…/resume` |

Each takes a JSON body `{ "reason": "…" }`. A kill or a suspension may be sent again: it ends anything still open and writes the operator's audit entry for any Campaign it ended that has none yet (for example after an earlier attempt failed half-way). `stopped` in the answer counts the Campaigns this call wrote that entry for. A kill or suspension completes entries only for Campaigns that ended since it was turned on; a Campaign that an earlier stop, since lifted, ended without its entry stays without one.

**Honest limits:**

- **The stand-in is not a penetration test.** It runs six fixed checks written against the reference target's seeded weaknesses. Its results say nothing about your real exposure.
- **There is no VM or egress proxy yet.** The request gate is code inside the API, and requests leave from the API host's own address.
- **A GET can change state on a careless application.** Exclude such paths in the Rules.
- **"Staging" and "signed by an Owner" are declarations made with an admin key.** Nothing verifies them.
- **Text is put into one form before anything reads it.** Zero-width characters are deleted, control characters become a space or a line break, and the text is NFKC-normalised (a fullwidth digit is a digit, a ligature its letters). The engine's checks, the redaction patterns and the stored evidence all read that form, so evidence may differ from the raw response in exactly these ways.
- **Evidence is redacted by patterns, over a window of at most 200 characters.** Keys, tokens, passwords, emails, card numbers and cookies are removed where they are recognised. The patterns miss many shapes of secret; what protects you is that so little is kept. A secret that stands within those 200 characters of a match, in a shape the patterns do not know, is stored. Treat evidence as sensitive.
- **A refused request shows no text.** If the engine asks for something that is not one of its declared probes, the request log shows the reason, the method as GET, HEAD or "Another method", and roughly how much was asked for (nothing, at most 256 characters, at most 1,024, or more — never the exact count). What was asked for is not stored: it is text the engine chose, possibly out of a response.
- **The engine runs in a worker thread, not a sandbox.** It is started without the API's environment variables, and it can only ask the gate for requests; a real engine needs a real isolation boundary.
- **The query string is not part of what the Rules authorise;** only the path is.

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

## Tamper detection

Harden plants an integrity marker with `--register` (turn it off with `--no-integrity-marker`): the Build id and up to 32 protected file paths, never hashes. An attestation may then report the SHA-256 a browser observed for those files, and the API compares it with the registered Build after it has answered.

- **Incident:** a mismatch opens one High **Tampered Build** Incident per Build, naming the file, the registered and the observed hash and the page origin. The attestation verdict and Shield do not change.
- **Arming:** a Build opens Incidents only after one report matched it fully, so a pipeline that changes files after Harden does not raise a false alarm. The Build page shows "watched since" or "not yet seen unmodified".
- **Stale, not tampered:** a hash that is the registered one for the same path in a recent Build (one of the newest 20, or registered in the last 30 days) is ignored.
- **Limits per Build:** 20 new file-and-hash pairs an hour, 50 in any 24 hours, 600 mismatching reports an hour. When a limit hid a distinct hash, the Incident says so.
- **Guard's collector:** about 30 s after the first token, Guard hashes the Build's files that the page loaded from its own origin (at most 2 MB each, about 5 s in all) and sends the report with one early re-attest, once per Build per device per day. Turn it off with `createGuard({ integrity: false })`. Details and limits are in `docs/guard.md`.
- **Honest limits:** it catches non-adaptive tampering only: a modified bundle can strip the marker, strip Guard or report the registered hashes. Anyone with the public App id can forge mismatches for an armed Build, and can also spend its limits, within the numbers above. The RRS does not change.

## Release gate

`npm run gate:release` checks a release candidate against every line of QASUITE §16 and SECURITY §12 and writes a signed report to `reports/gate/` (gitignored).

- **States:** each criterion is `pass`, `fail` or `not-checkable`. The verdict is `releasable` only when every criterion passes; otherwise it is `blocked`.
- **Exit codes:** 0 releasable, 1 blocked by a failure, 2 blocked only by lines that cannot be checked yet, 3 runner error.
- **What runs today:** `npm run verify`, the Playwright suite, the audit, tenant, authorization and privacy matrices, the stand-in RRS regression against a recorded baseline, the Shield bench against PB-01 and PB-02, and a local load smoke against PB-21, SLO-01 and SLO-02. A skipped or todo test fails its check.
- **Options:** `--only <ids>`, `--skip-slow` (reported as not checked) and `--online` (allows `npm audit`, which contacts the registry).
- **Signature:** the report is signed with an Ed25519 key kept outside the repository (`AR_GATE_KEY_FILE`, default `~/.config/airverse/gate-key.json`). `npm run gate:verify-report -- <dir>` accepts only the local key or `--expect <fingerprint>`.

Today every check that can run passes, and the verdict is `blocked` with exit code 2: 15 lines cannot be fully checked yet (real-agent RRS, Pentest Campaigns, the browser corpus, SDK signing, staging rehearsals and others).

## Operator SLO dashboard

Set `AR_OPS_TOKEN` (32–512 printable characters) to turn on operator access; without it the operator routes answer 404. The API then measures, for this instance:

| SLO | What it measures |
|---|---|
| SLO-01 | Attestation |
| SLO-02 | Ingest |
| SLO-03 | Policy distribution |
| SLO-04 | Event freshness |
| SLO-05 | Detection latency |
| SLO-06 | Enforcement propagation — only with the synthetic probes on (see below) |
| SLO-07 | Control API |
| SLO-09 | Alert delivery |
| SLO-10 | Prove |

What it keeps and reports:

- **Per minute**, it keeps good and total counts and latency histograms in `slo_minutes`, for 35 days. There are no tenant identifiers.
- **Per SLO**, it reports 30-day attainment, the error budget left and burn rates over 5 m, 30 m, 1 h, 6 h and 3 d.
- **What counts:** only Airverse's own failures. Client-caused 4xx, slow or aborted uploads, and failures of a tenant's own alert destination are left out.

Where to read it:

- `GET /v1/ops/slo` (JSON) and `GET /metrics` (Prometheus) take `Authorization: Bearer $AR_OPS_TOKEN`.
- The Console's `/ops` page signs in with the same token, in its own cookie. It shows one panel per SLO and is not linked from the tenant navigation.

Burn alerts:

| Severity | Burn rate | Window (confirmation) |
|---|---|---|
| Page | 14.4× | 1 h (5 m) |
| Page | 6× | 6 h (30 m) |
| Ticket | 1× | 3 d |

- An alert needs at least 3 events. Its state survives restarts.
- Each alert is logged and, if `AR_OPS_WEBHOOK_URL` is set, posted there. The post is signed with `AR_OPS_WEBHOOK_SECRET` when that is set, and names the SLO's runbook.
- SLO-06 is measured only while the synthetic probes run (below). SLO-08 (Console page loads against Core Web Vitals) is not measured: it needs a browser.

### Synthetic probes

Start the API with `AR_PROBES=1` to run the two probes of OPERATION.md §7 once a minute. They are off by default.

| Probe | What one cycle does | Feeds | Good | Bad |
|---|---|---|---|---|
| Enforcement | Publishes a block Rule on `/airverse-probe/<fresh nonce>` through the Control API, then waits until the probe's Shield answers 403 on that path | SLO-06 | within 30 s | later, given up at 60 s, or the publish failed |
| Event freshness | Waits until the Event of that refused request is readable through `GET /v1/apps/:appId/events` | SLO-04 (one extra sample a minute) | within 5 s | later, or given up at 30 s |

How it works:

- **The real path.** The prober talks to the API over HTTP on its own listening address, with real keys. It runs a real Shield (`@antireverse/shield-node`) that polls and verifies the signed bundle and sends its Events on the SDK's own timers.
- **Its own Organization.** Probe traffic lives in a system Organization the API creates for itself (registered in `system_organizations`). No tenant's Events, usage, Policies or bundles ever hold it, and the marked Rule exists only in the probe App's bundle, so it cannot block anyone's traffic. Its keys are made anew at every start and exist in memory only; the rows of the keys before them are removed.
- **Not counted elsewhere.** The probe's own requests and Events feed no other SLI (SLO-02, -03, -05, -07, and the count of SLO-04 from receipt to live bus): only its two measurements are recorded. Nothing is detected on its Events, so no Incident or alert is ever made for the probe's Organization.
- **One cycle at a time.** The next cycle is scheduled when the one before has ended. On shutdown the cycle in flight is cut and records nothing.
- **Failures.** Each failed leg is a warning in the log (`probe failed leg=… outcome=…`) and a bad SLO sample; burn alerts fire through the rules above (SLO-06 names runbook RB-04). When the block was not enforced, the Event leg is skipped and not counted. A cycle cut by shutdown records nothing.
- **A probe that cannot run counts as failing.** If the probe cannot be set up (its Organization, its Shield or its loopback server), up to three cycles in a row record nothing; from the fourth, each cycle is a failed SLO-06 sample, and the log and the status name the cause (`reason=setup`, `setup_failures`).
- **Where to see it.** `GET /v1/ops/slo` carries a `probes` status (`null` when off): interval, cycles run and failed since the start, and the last cycle's two legs. `/ops` shows it above the SLO panels.

What the numbers are not:

- They are measured **inside one API instance, against one Shield in the same process, over the loopback interface**. They are not per-region measurements and say nothing about customers' Shields or the network between them and the API.
- When the API is down, the prober is down too and records nothing.
- Shield learns of a new block at its next poll (every 5 s plus jitter), so the enforcement time is mostly that wait.
- While on, the probe Organization gains about 1,440 Policy versions, audit entries and Events a day: about 3 MB a day, or 1.1 GB a year (about 1.5 KB per audit entry and 0.6 KB per Policy version). Events go after 7 days; Policy versions and audit entries are not pruned. Rotating the probe Organization is a follow-up.
- An SLO-06 alert that is firing when probes are switched off is resolved at the next start without them.

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
| `npm run gate:release` | The release gate: every check that can run, and a signed report (see Release gate) |
| `npm run gate:verify-report -- <dir>` | Checks a gate report's signature |

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
| `AR_SMTP_*` | API (email alerts) | none — email alerts are off; see Detection and alerts |
| `AR_OPS_TOKEN` | API (operator routes, `/ops`) | none — operator routes answer 404 |
| `AR_OPS_WEBHOOK_URL`, `AR_OPS_WEBHOOK_SECRET` | API (SLO burn alerts) | none — alerts are logged only |
| `AR_PROVE_CAMPAIGNS=1` | API | off — Campaigns cannot be created |
| `AR_PROBES=1` | API (synthetic probes) | off — SLO-06 is not measured; any value but unset, empty, `0` or `1` stops the start |
| `AR_GATE_KEY_FILE` | release gate | `~/.config/airverse/gate-key.json` |
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

## License

Airverse is licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for the copyright notice.
