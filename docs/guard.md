# Guard

Guard is a small browser library: plain ES modules, no dependency, no build step, about 7 KB gzip. It gets a short-lived Attestation Token from Airverse and lets your frontend send it with API calls. Shield, on your server, verifies the token offline and records the result for every request. Guard reports; Shield decides.

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

The last four are there for tests; a page needs only `appId` and `endpoint`.

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

## What the Console shows

The live feed's **Client** column shows, for each request, the verdict Shield verified: **Trusted**, **Suspect** or **Hostile** (with a risk score), or **No token**, **Invalid**, **Expired**. The **Signature** column shows whether the request was signed. Nothing is blocked on the attestation verdict yet.

## Honest limits

- A token shows that a Guard-like client completed the handshake recently, not that the client is genuine. Anyone can script the handshake with clean signals.
- Signals today: automation (webdriver, headless) and environment inconsistency.
- Signing stops replay and tampering, not automation: a script driving a real browser with Guard signs genuine requests.
- Proxies that rewrite the path, content type or body break signatures.
- The attestation endpoints rate-limit by caller address; behind a reverse proxy the API sees one address for everyone.

See also: [Getting started](getting-started.md), [Shield](shield.md).
