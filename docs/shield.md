# Shield

Shield is a middleware for your Node server. It records every request as an Event in the Console and applies your App's Policy. It has no runtime dependencies and never sends the concrete URL: only the method, the route template, the status, the latency and the network prefix of the client.

Supported today: **Express** and a plain **Node `http`** server. Next.js, Fastify, Koa and other frameworks are not supported yet.

`@antireverse/shield-node` is on npm: `npm install --save-exact @antireverse/shield-node@0.1.0`. It is plain JavaScript with no dependency and runs on plain Node 22.12. Two alternatives: `npm run sdk:pack` in the Airverse repository writes a tarball (`npm install --ignore-scripts <path>/antireverse-shield-node-<version>.tgz`), or depend on the clone's `packages/shield-node` folder, whose entry point is TypeScript: the server then needs a Node that strips types, or `tsx`. Shield reports to an Airverse API, which is not on a registry: you run it from the repository ([Getting started](getting-started.md)).

## Set up with Express

Shield goes first, before your routes, so it sees every request:

```ts
import express from "express";
import { createShield } from "@antireverse/shield-node";

const app = express();

const shield = createShield({
  key: process.env.AR_SHIELD_KEY,
  endpoint: "http://127.0.0.1:8787",
  policyPublicKey: process.env.AR_POLICY_PUBLIC_KEY, // without it Shield observes only
});
app.use(shield.express());

// … your routes …
```

Install it on the application rather than on a mounted router where you can: the path above Shield is recorded as `(mount)`.

Give the server its keys through the environment:

```bash
export AR_SHIELD_KEY="<the Shield key>"
export AR_POLICY_PUBLIC_KEY="<the policy public key>"
```

When the server stops, call `await shield.close()` to send what is still buffered.

### When Shield does nothing

A missing or bad key does not stop your server: Shield disables itself, logs one line, and requests are served as usual. (An invalid `bodyVerified` option is the exception: `createShield` throws a TypeError at startup.) `shield.stats().disabledReason` says why:

- no Shield key was given, or it is malformed (a Shield key is `ark_<prod|stg|dev>_` followed by 43 characters);
- no endpoint, or the endpoint is not an `http` or `https` URL;
- `AR_SHIELD_DISABLED=1` is set, or `disabled: true` was passed.

## Set up with plain Node `http`

Without Express, call Shield's middleware first in your request handler and pass your own handler as its `next`:

```ts
import http from "node:http";
import { createShield } from "@antireverse/shield-node";

const shield = createShield({
  key: process.env.AR_SHIELD_KEY,
  endpoint: "http://127.0.0.1:8787",
  policyPublicKey: process.env.AR_POLICY_PUBLIC_KEY,
});
const protect = shield.express();

// handle(req, res) is your request handler.
http
  .createServer((req, res) => {
    protect(req, res, () => handle(req, res));
  })
  .listen(3000);
```

When Shield blocks a request, it answers 403 itself and does not call `next`, so your handler does not run.

Without a router Shield cannot name routes: the live feed shows `(unmatched)` as the route of every request. Rules still match the request path.

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `AR_SHIELD_KEY` | your code (as in the example) and the reference target | The App's Shield key. Without it Shield is disabled and the server still runs. |
| `AR_POLICY_PUBLIC_KEY` | your code (as in the example) and the reference target | The policy public key. Without it Shield observes only and never blocks. |
| `AR_API_URL` | the reference target | Base URL of the API. Default `http://127.0.0.1:8787`. |
| `AR_SHIELD_DISABLED=1` | Shield | Switches Shield off (unless the `disabled` option says otherwise). |
| `AR_ACTOR_KEY` | Shield (when `actorKey` is not given) | The secret for actor identities. See below. |
| `AR_SHIELD_INVENTORY=0` | Shield (when `inventory` is not given) | Stops sending the list of installed packages. |

## Options

| Option | Default | What it does |
|---|---|---|
| `key` | required | The App's Shield key. |
| `endpoint` | required | Base URL of the Airverse API. |
| `policyPublicKey` | none | Shield applies only Policies signed with this key. Without it Shield fetches no Policy and blocks nothing. |
| `policyPollIntervalMs` | 5,000 | How often Shield asks for the Policy. Never less than 100. |
| `actorKey` | `AR_ACTOR_KEY` | The key of the actor hash: at least 32 characters, no whitespace, not the Shield key. Never sent to Airverse. |
| `bodyVerified` | none | `{ types: ["application/json"] }`: the body types whose parser carries `shield.verifyBody`, for signed requests. |
| `inventory` | true | Sends the installed packages (names, versions, dev flag) at start and every 6 hours, for known-vulnerability Findings. |
| `projectRoot` | the working directory | The folder whose lockfile the inventory reads. |
| `clientAddress` | the socket's remote address | A function returning the client address, for example behind a proxy you trust. Only its network prefix is recorded. |
| `disabled` | `AR_SHIELD_DISABLED === "1"` | Turns Shield off. |
| `logger` | `console` | Receives at most one line per distinct condition. |
| `counterStore` | in memory, per instance | Where limit Rules count. |

`shield.stats()` reports what Shield is doing: Events sent and dropped, the applied Policy version, why the last Policy fetch changed nothing, whether actor hashing is on, and the inventory state. It never contains a key.

## Monitor and enforce

Every Rule on the App's **Policy** page has a mode:

- **Monitor:** matching requests go through. The Event says what enforce would have done.
- **Enforce:** matching requests are answered `403 {"error":"request_blocked"}` before your handler runs, and appear as *Blocked* in the live feed. A Throttle Rule answers `429` with `Retry-After` over its limit.

A new Rule starts in monitor. **Promote to enforce** publishes a new Policy version; Shields apply it within 15 seconds (they poll every 5 seconds). **Back to monitor** and **Roll back** undo it. A Rule that blocks every request (`/**`) cannot be enforced, and a pattern that starts with a wildcard needs a stronger confirmation.

Without a Policy, Shield runs the built-in Policy (version 0): no Rules, everything allowed, mode *Monitor*.

## Policy key

The API signs every Policy with its own Ed25519 key. Shield applies a Policy only when its signature checks out against `policyPublicKey`; any other Policy is refused.

- The Console shows the key as **Policy public key** right after you create an App and on the App's **Policy** page.
- The API also serves it at `GET /v1/signing-key`.

```bash
curl http://127.0.0.1:8787/v1/signing-key
```

Without the policy public key, Shield observes only: it records Events and never blocks. The API keeps the private key in `signing-key.json` beside its data directory; back it up with the database, because losing it means re-configuring every Shield's `AR_POLICY_PUBLIC_KEY`.

## Signed request bodies

When a Rule has **Require a signed request**, let Shield check bodies through your parser and render its refusals:

```ts
const shield = createShield({ /* … */ bodyVerified: { types: ["application/json"] } });
app.use(shield.express());
app.use(express.json({ verify: shield.verifyBody }));
// … routes …
app.use(shield.errorHandler());
```

On the browser side, Guard signs the requests: see [Guard](guard.md).

## Actor identities

Actor identity is a keyed hash of the client address that only you can compute. Set `AR_ACTOR_KEY` (or `actorKey`) on every server running Shield for the App, 32 or more characters, not the Shield key. Generate one with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Without it Shield sends no hash: Incidents show no Actors and only network blocks are possible.

## Honest limits

- Counters of limit Rules are per Shield instance; several instances multiply the limit.
- Replay protection of signed requests is per Shield instance.
- Shield records the route template, never the concrete URL. A regular-expression mount is recorded as `(unmatched)`.
- HEAD against a Rule limited to GET is not blocked.
- Policies and blocks arrive by polling; there is no push channel yet.

See also: [Getting started](getting-started.md), [Guard](guard.md).
