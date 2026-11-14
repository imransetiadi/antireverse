# Guard

Guard is a small browser library: plain ES modules, no dependency, no build step, about 17 KB gzip. It gets a short-lived Attestation Token from Airverse and lets your frontend send it with API calls. Shield, on your server, verifies the token offline and records the result for every request. Guard reports; Shield decides.

`@antireverse/guard` is not published to npm yet. Its files are in `packages/guard/src` of this repository.

## Script tag

Serve the files of `packages/guard/src` from your site, for example at `/guard/`. With Express:

```ts
app.use("/guard", express.static("packages/guard/src"));
```

Then load Guard as a module:

```html
<script type="module">
  import { createGuard } from "/guard/index.js";

  const guard = createGuard({
    appId: "app_…",                       // the App ID from the Console's Apps page
    endpoint: "http://127.0.0.1:8787",   // the Airverse API
  });
  await guard.attest();                   // get a token before the first call

  const res = await fetch("/api/orders", { headers: { ...guard.headers() } });
</script>
```

`guard.headers()` is `{}` until a token exists, so wait for `attest()` before the first call. Two alternatives:

- `guard.fetch(url, init)` attests first when there is no token yet, then signs and sends the request.
- `guard.start()` only schedules attestation in the background, in idle time, and returns at once. Use it when the first calls may go out without a token; later calls carry one once it has arrived.

With a bundler, import it the same way: `import { createGuard } from "@antireverse/guard";`.

The attestation endpoints answer any origin (CORS `*`) without credentials, so your page can call them cross-origin.

## Options

`createGuard(options)` never throws and does nothing until `attest()` or `start()`.

| Option | Default | What it is |
|---|---|---|
| `appId` | required | The App ID: `app_` and 24 hex characters. |
| `endpoint` | required | Base URL of the Airverse API. A trailing slash is ignored. |
| `storage` | `localStorage` | Where the device id is kept. `null` keeps it in memory only. |
| `now` | `Date.now` | The clock, in milliseconds. |
| `fetch` | the global `fetch` | Used for the attestation requests. |
| `crypto` | `globalThis.crypto` | Random values and Web Crypto. |
| `navigator` | the global `navigator` | What the signals read. |
| `integrity` | `true` | `false` turns [tamper detection](#tamper-detection) off. |

`now`, `fetch`, `crypto` and `navigator` are there for tests; a page needs only `appId` and `endpoint`.

## Methods

| Method | What it does |
|---|---|
| `attest()` | Runs the handshake and keeps the token; re-attests 60 s before it expires. Never rejects: resolves the token, or `null`. |
| `start()` | Schedules the first `attest()` in idle time. |
| `stop()` | Cancels pending timers. |
| `token()` | The current token, or `null`. |
| `headers()` | `{ "ar-attestation": token }`, or `{}` without a token. Spread it into a request's headers. |
| `sign(request)` | The headers for one signed request: `ar-attestation`, `ar-signature`, `ar-content-sha256`. |
| `fetch(input, init)` | Signs the request, then sends it with the global `fetch`. |
| `signals()` | The signal ids the environment shows now. |

## Signed requests

Guard can sign each API call so a captured request cannot be replayed or altered:

```js
const res = await guard.fetch("/api/orders", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(order),
});
```

On the server, Shield checks the signature; for bodies, add `shield.verifyBody` to your parser (see [Shield](shield.md#signed-request-bodies)). In the Console, tick **Require a signed request** on a Rule, run it in monitor first, then promote it. On an enforced route a request that is unsigned, older than 60 s, replayed, or whose body or content type changed after signing gets the standard 403.

## Tamper detection

When you harden a bundle with `--register`, Harden plants an [integrity marker](harden.md#integrity-marker) in it: the Build ID and the paths of up to 32 protected files. Guard uses it to tell Airverse which bytes a browser actually received. Nothing needs to be configured: if the page runs a hardened bundle and Guard, it works. Load order does not matter.

**What Guard does.** About 30 seconds after the first token, while the tab is visible and the browser is idle, Guard:

1. reads the marker;
2. looks for the listed files among the scripts the browser loaded from the page's own origin;
3. fetches each of them again, one at a time, with `fetch(url, { cache: "force-cache", credentials: "same-origin" })` (normally answered from the HTTP cache) and computes the SHA-256 of the bytes. What is hashed is what this second request receives; if the server answers it differently from the first (a file replaced between the two, a cache that varies), the hash is of the second answer;
4. sends the result with one extra attestation, made right then if the tab is still visible.

**Which URLs count.** A URL counts as a loaded script when the browser's Resource Timing lists it as loaded by a script, or when a `<script src>` or `<link rel="modulepreload">` names it and Resource Timing has an entry for it. A `<script>` whose `type` is not JavaScript or `module` (a JSON data block, a template) never counts. Guard therefore never requests a URL the browser did not request itself, and never a file the marker does not list. In a browser without Resource Timing the elements alone count.

If Resource Timing is there but its list is empty, nothing counts and **nothing is reported**. That is the case in Firefox with `privacy.resistFingerprinting`, in Tor Browser, and on a page that calls `performance.clearResourceTimings()` before the check.

**How a file is matched.** Guard finds the one base of the Build: the URL path under which its files are served, so that a file is at exactly *base + its path*. With the marker listing `main.js` and `chunks/a.js`, and the page loading `/app/main.js` and `/app/chunks/a.js`, the base is `/app/`. The query string is ignored; when the page loaded one path with several query strings, the first one seen is used.

A Build is hashed only when the page points to **exactly one base**. Guard takes the base only from loaded scripts that end like exactly one of the listed paths. A script that ends like two of them tells nothing: `/assets/utils/index.js` could be `utils/index.js` under `/assets/` or `index.js` under `/assets/utils/`, so it is used only once another file has settled the base. If those scripts point to two bases, or to none, the Build is ambiguous and **nothing is sent for it** on this page: a missing report is better than the hash of the wrong file, which would open a false Incident. This happens when:

- another script with the same name lives elsewhere on the origin (`/app/main.js` and `/legacy/main.js`), however many other files either directory explains;
- the only files of the Build the page loaded are ones whose path ends like another listed path (a Build listing `index.js` and `utils/index.js`, on a page that loaded nothing but `/assets/utils/index.js`).

When two registered Builds on one page would both name the same URL, that file is hashed for neither and counts as skipped in both.

**What leaves the browser.** One object in the body of `POST /v1/attest`:

```json
{ "build": "bld_…", "files": [{ "i": 0, "h": "<SHA-256, base64url>" }], "skipped": 0 }
```

`i` is the file's position in the marker's list, `h` its hash, and `skipped` the number of files Guard found on the page but could not hash. No URL, no path and no file content is sent. A listed file the page did not load is not mentioned at all. If no file could be hashed, nothing is sent. The report does not change the token, the verdict or what Shield does; the API compares it with the registered Build and opens a High **Tampered Build** Incident when a file differs (see [Harden](harden.md#integrity-marker) for when a Build is watched).

The list of positions does show which of the Build's files this visit loaded, for example which lazy chunks. It travels in the same request as the device identifier of the attestation. If that is more than you want to share, turn tamper detection off.

**Content Security Policy.** Guard fetches the files from your own origin, so `connect-src` must allow `'self'`, next to the Airverse API you already allow for attestation. A file that CSP blocks counts as skipped; nothing breaks.

**Scripts on another origin** (a CDN host, for example) are skipped: Guard hashes same-origin files only. A Build whose files are all served from another origin sends no report and is never watched.

**Turning it off.**

```js
const guard = createGuard({ appId: "app_…", endpoint: "…", integrity: false });
```

With `integrity: false` Guard reads no marker and fetches no file.

**Limits.**

| Limit | Value |
|---|---|
| When | Once per page view, about 30 s after the first token. A hidden tab waits until it is visible. A visit that ends earlier reports nothing. |
| Per device | One report per App and Build in 24 hours, remembered in `localStorage` under `ar.integrity` (the App ID, the Build ID and a time; at most 64 entries). The memo is per Build, not per file: if the first report covered only some files, the others are not reported by this device that day. |
| Without `localStorage` | Nothing can be remembered: every page view that lasts 30 s hashes and reports again (once per page, however many Guards it creates). |
| Several tabs | A tab that starts hashing a Build keeps the others from doing the same for a minute. |
| File size | A file over 2 MB is skipped; Guard stops downloading once it has read that much. |
| Time | 5 s for all files together; what is not hashed by then is skipped. |
| Files | At most 32 per Build, as the marker lists them. |
| Save-Data | When the browser asks for reduced data use, Guard does nothing. |
| Extra traffic | One attestation, at most 4 KB, plus the file requests (from the cache when the files are cacheable). |
| Several bundles on one page | One Build per attestation: the first registered Build not reported in the last 24 hours goes with the extra attestation, the next with the regular re-attestation about four minutes later, and so on. This keeps every request small. |
| `stop()` | Ends a running check at once, including its request in flight. A later `start()` or `attest()` runs it again. |

A failed fetch, an opaque response, a redirected one (a login page), an answer whose `Content-Type` is not JavaScript (the HTML page a single-page app serves for unknown paths) and an oversized file all count as skipped. Serve the files with a JavaScript content type, as browsers already require for modules. So does a script element the browser's Resource Timing buffer had no room to record (the buffer holds 250 entries by default). If the extra attestation fails, or the tab is hidden when the files have been hashed, the current token stays valid, the regular schedule goes on, and the report goes with the next attestation.

Browsers differ in what Resource Timing records. Chromium lists the modules a script imports; a browser that does not will report only the files named by `<script>` and `<link rel="modulepreload">` elements, so it may report fewer files.

## What the Console shows

The live feed's **Client** column shows, for each request, the verdict Shield verified: **Trusted**, **Suspect** or **Hostile** (with a risk score), or **No token**, **Invalid**, **Expired**. The **Signature** column shows whether the request was signed. Nothing is blocked on the attestation verdict yet.

## Honest limits

- A token shows that a Guard-like client completed the handshake recently, not that the client is genuine. Anyone can script the handshake with clean signals.
- Signals today: automation (webdriver, headless) and environment inconsistency.
- Signing stops replay and tampering, not automation: a script driving a real browser with Guard signs genuine requests.
- Proxies that rewrite the path, content type or body break signatures.
- Tamper detection catches changes that do not adapt to it. Whoever changes your files can also remove the marker, remove Guard or report the registered hashes. It tells you about accidents and crude tampering: a CDN that rewrites scripts, a compromised deploy, an injected snippet.
- Tamper detection finds a Build's files by their URL paths. A page on which a second directory holds a script that ends like exactly one of the Build's listed paths is ambiguous and reports nothing. Files that are inlined into HTML, run in a worker or load after the check are not hashed.
- The attestation endpoints rate-limit by caller address; behind a reverse proxy the API sees one address for everyone.

See also: [Getting started](getting-started.md), [Shield](shield.md).
