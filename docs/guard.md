# Guard

Guard is a small browser library: plain ES modules, no dependency, no build step, about 19 KB gzip. It gets a short-lived Attestation Token from Airverse and lets your frontend send it with API calls. Shield, on your server, verifies the token offline and records the result for every request. Guard reports; Shield decides.

`@antireverse/guard` is on npm: `npm install --save-exact @antireverse/guard@0.1.0`. Its files are then in `node_modules/@antireverse/guard/dist`. In a clone of the Airverse repository the same modules are in `packages/guard/src`, and `npm run sdk:pack` there writes a tarball (`npm install --ignore-scripts <path>/antireverse-guard-<version>.tgz`) with the same `dist` folder.

## Script tag

Serve the files of `node_modules/@antireverse/guard/dist` from your site, for example at `/guard/`. With Express:

```ts
app.use("/guard", express.static("node_modules/@antireverse/guard/dist"));
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
2. finds the Build's first file among the scripts the browser loaded from the page's own origin, by its content (see below), and from it the other listed files;
3. fetches each of them again, one at a time, with `fetch(url, { cache: "force-cache", credentials: "same-origin" })` (normally answered from the HTTP cache) and computes the SHA-256 of the bytes. What is hashed is what this second request receives; if the server answers it differently from the first (a file replaced between the two, a cache that varies), the hash is of the second answer;
4. sends the result with one extra attestation, made right then if the tab is still visible.

**Which URLs count.** A URL counts as a loaded script when the browser's Resource Timing lists it as loaded by a script, or when a `<script src>` or `<link rel="modulepreload">` names it and Resource Timing has an entry for it. A `<script>` whose `type` is not JavaScript or `module` (a JSON data block, a template) never counts. Guard therefore never requests a URL the browser did not request itself, and never a file the marker does not list. In a browser without Resource Timing the elements alone count.

If Resource Timing is there but its list is empty, nothing counts and **nothing is reported**. That is the case in Firefox with `privacy.resistFingerprinting`, in Tor Browser, and on a page that calls `performance.clearResourceTimings()` before the check.

**How the Build's files are found.** Guard never guesses from file names where a Build lives. Harden plants the marker in the first file the marker lists, and the marker's own text (`b:"<Build ID>",f:[`) is in that file. So Guard:

1. takes the loaded scripts whose URL path ends with `/` and the path of that first file. These are the candidates. Every URL is a candidate in its own right: `/app/main.js` and `/app/main.js?fmt=dev` are two;
2. fetches every candidate and looks for the marker's text in its bytes. The one that holds it is the Build's first file. The bare Build ID is not enough;
3. takes the rest of that URL's path as the base. Every other listed file is the loaded script at exactly *base + its path*. With the marker listing `main.js` and `chunks/a.js` and the first file found at `/app/main.js`, the base is `/app/` and the other file is `/app/chunks/a.js`, nothing else.

**Query strings.** Another listed file is hashed only when the page loaded exactly one URL with its path, and that URL has the same query string as the first file's (none on both counts as the same). `/app/main.js?dpl=7` goes with `/app/chunks/a.js?dpl=7`. If the chunk was loaded as `?dpl=6`, or as both, it counts as skipped: a different query string may be a different deployment's bytes.

A script that merely has the same name (`/legacy/main.js`) does not hold the marker and is never reported. A changed copy of the first file that still holds the marker is reported, with the hash of what it is now: that is the point.

**Nothing is sent for a Build** on a page where its first file cannot be settled this way. Guard fails closed:

- **The Build is served from another origin** (a CDN host). Guard reads same-origin files only.
- **The bundle is inlined in the HTML**, or its first file was not loaded as a script on this page, was loaded after the check, or is not in Resource Timing.
- **The marker was removed** from the first file. The other files are then not looked at either.
- **The Build was hardened with `--integrity`.** The self-check wrapper holds the planted file as a string, in which the marker's text is escaped, so it is not in the bytes Guard reads. Such a Build is never watched (see [Harden](harden.md#integrity-marker)).
- **More than 4 same-origin scripts** end like the first file's path. Guard fetches none of them.
- **A candidate could not be examined**: it answered with an error or a redirect, is over 2 MB, is not served as JavaScript, or the browser's Resource Timing buffer was full and has no entry for it. One such candidate is enough, even when another one holds the marker, and even when it is only another query string of the true file's own path.
- **A candidate's URL contains the Build ID** (also percent-encoded, also in the query string). An endpoint that echoes its URL would echo the marker too, so such a URL proves nothing and is not fetched.
- **Two candidates hold the marker**: the Build deployed twice on the origin and both copies loaded, or the first file loaded under two query strings.
- **The time ran out** before every candidate was read.

**A minifier may keep the marker.** esbuild's minifier keeps the marker's text as it is (this is tested); other tools were not tried. A formatter, or a tool set to write single quotes or to add spaces, rewrites the text (`b: 'bld_…'`), and then Guard does not find the Build at all: nothing is reported for it. Where the text survives, the rewritten first file is found and reported with its own hash, which is not the registered one. Such a Build never matches, so it is never watched and opens no Incident (see [Harden](harden.md#integrity-marker)). But if a watched Build is served raw to some visitors and minified to others (a CDN's "auto-minify" switched on later, or only at some edges), the minified copies are reported as a mismatch and open an Incident.

**What this rests on.** A wrong file can still be reported if the origin itself serves the marker's text somewhere else. The remaining case is an endpoint that serves or echoes the marker's text at a URL ending like the first file's path, where the echo does not come from the URL itself. Two things are assumed about your origin:

1. No other same-origin URL whose path ends like the first file's path answers with that file's content or with the marker's text. A combining endpoint (`/min/f=js/jquery.js,app/main.js`) that returns the whole planted file inside a bundle is such a URL; so is an endpoint that prints a stored value (a comment, a profile field) holding the marker's text as JavaScript.
2. If there is one, the true file is also a counted script on the page. Then both are candidates, Guard sees two that hold the marker, and sends nothing. This holds for another directory and for another query string of the same path alike. When the true file is not counted (on another origin, inlined, loaded another way) and only the other URL is, that URL's answer is taken for the Build's first file and its hash is reported.

When a file of this Build also ends like a path that another registered Build on the same page lists, it could belong to either, so it is hashed for neither and counts as skipped.

**What leaves the browser.** One object in the body of `POST /v1/attest`:

```json
{ "build": "bld_…", "files": [{ "i": 0, "h": "<SHA-256, base64url>" }], "skipped": 0 }
```

`i` is the file's position in the marker's list, `h` its hash, and `skipped` the number of files Guard found on the page but could not hash. No URL, no path and no file content is sent. A listed file the page did not load is not mentioned at all. If no file could be hashed, nothing is sent. The report does not change the token, the verdict or what Shield does; the API compares it with the registered Build and opens a High **Tampered Build** Incident when a file differs (see [Harden](harden.md#integrity-marker) for when a Build is watched).

The list of positions does show which of the Build's files this visit loaded, for example which lazy chunks. It travels in the same request as the device identifier of the attestation. If that is more than you want to share, turn tamper detection off.

**Content Security Policy.** Guard fetches the files from your own origin, so `connect-src` must allow `'self'`, next to the Airverse API you already allow for attestation. A file that CSP blocks counts as skipped; nothing breaks.

**Scripts on another origin** (a CDN host, for example) are skipped: Guard hashes same-origin files only. A Build whose first file is served from another origin sends no report and is never watched, even if the site has scripts of the same name on its own origin.

**Turning it off.**

```js
const guard = createGuard({ appId: "app_…", endpoint: "…", integrity: false });
```

With `integrity: false` Guard reads no marker and fetches no file.

**Limits.**

| Limit | Value |
|---|---|
| When | Once per page view, about 30 s after the first token. A hidden tab waits until it is visible. A visit that ends earlier reports nothing. |
| Per device | Normally one report per App and Build in 24 hours, remembered in `localStorage` under `ar.integrity` (the App ID, the Build ID and a time; at most 64 entries). The memo is per Build, not per file: if the first report covered only some files, the others are not reported by this device that day. It can be more than one: without usable `localStorage`, in private windows, after the user clears site data, when two tabs finish at the same moment, or when a device reported more than 64 Builds in a day. It can be none: see "Nothing is sent" above. |
| Without `localStorage` | Nothing can be remembered: every page view that lasts 30 s hashes and reports again (once per page, however many Guards it creates). |
| Several tabs | A tab that starts hashing a Build keeps the others from doing the same for a minute, and for up to five minutes while its report waits to be sent. A report that waited is dropped if another tab reported the Build meanwhile. |
| File size | A file over 2 MB is skipped; Guard stops downloading once it has read that much. |
| Time | 5 s for everything Guard fetches; what is not hashed by then is skipped. |
| Page size | At most 8 Builds are read (from the first 64 marker entries), and at most 500 distinct URLs of the page are looked at. |
| Files | At most 32 per Build, as the marker lists them. |
| Save-Data | When the browser asks for reduced data use, Guard does nothing. |
| Extra traffic | One attestation, at most 4 KB, plus the file requests (from the cache when the files are cacheable). |
| Several bundles on one page | One Build per attestation: the first registered Build of which a file could be hashed (and that was not reported in the last 24 hours) goes with the extra attestation, the next such Build with the regular re-attestation about four minutes later, and so on. This keeps every request small. |
| `stop()` | Ends a running check at once, including its request in flight. A later `start()` or `attest()` runs it again. |

For the files other than the first: a failed fetch, an answer with a status other than 200 (a 206 partial answer too), an opaque response, a redirected one (a login page), an answer whose `Content-Type` is not JavaScript (the HTML page a single-page app serves for unknown paths) and an oversized file all count as skipped. **Classic scripts served with another content type are not hashed**: a browser runs `<script src>` whatever the type says (`text/plain`, `application/octet-stream`), but Guard does not hash it. Serve the files with a JavaScript content type, as browsers already require for modules. So does a script element the browser's Resource Timing buffer had no room to record (the buffer holds 250 entries by default). If the extra attestation fails, or the tab is hidden when the files have been hashed, the current token stays valid, the regular schedule goes on, and the report goes with the next attestation.

Browsers differ in what Resource Timing records. Chromium lists the modules a script imports; a browser that does not will report only the files named by `<script>` and `<link rel="modulepreload">` elements, so it may report fewer files.

## What the Console shows

The live feed's **Client** column shows, for each request, the verdict Shield verified: **Trusted**, **Suspect** or **Hostile** (with a risk score), or **No token**, **Invalid**, **Expired**. The **Signature** column shows whether the request was signed. Nothing is blocked on the attestation verdict yet.

## Honest limits

- A token shows that a Guard-like client completed the handshake recently, not that the client is genuine. Anyone can script the handshake with clean signals.
- Signals today: automation (webdriver, headless) and environment inconsistency.
- Signing stops replay and tampering, not automation: a script driving a real browser with Guard signs genuine requests.
- Proxies that rewrite the path, content type or body break signatures.
- Tamper detection catches changes that do not adapt to it. Whoever changes your files can also remove the marker, remove Guard or report the registered hashes. It tells you about accidents and crude tampering: a CDN that rewrites scripts, a compromised deploy, an injected snippet.
- Tamper detection finds a Build by the marker in its first file. A page where that file is on another origin, inlined, stripped of its marker or not loaded reports nothing for the Build. Files that are inlined into HTML, run in a worker or load after the check are not hashed.
- The attestation endpoints rate-limit by caller address; behind a reverse proxy the API sees one address for everyone.

See also: [Getting started](getting-started.md), [Shield](shield.md).
