// The set-up code shown after an App is created. Code is not translated, so it does not live in the
// message catalog; the labels around it do.

/**
 * `@antireverse/shield-node` is not on npm yet, so `npm install @antireverse/shield-node` fails. It installs from a
 * copy of the Airverse repository (checked by hand on Node 22.12: a plain http server then records Events; that
 * version needs `--experimental-strip-types`, as the package ships TypeScript source).
 */
export const SHIELD_INSTALL = "npm install /path/to/airverse/packages/shield-node";

/** The line that hands the Shield key to the server through its environment. */
export function shieldEnvironmentLine(shieldKey: string): string {
  return `export AR_SHIELD_KEY="${shieldKey}"`;
}

export const POLICY_KEY_LINE_START = 'export AR_POLICY_PUBLIC_KEY="';
export const POLICY_KEY_LINE_END = '"';

/** The line that hands the policy public key to the server. Without it Shield observes and never blocks. */
export function policyKeyLine(publicKey: string): string {
  return `${POLICY_KEY_LINE_START}${publicKey}${POLICY_KEY_LINE_END}`;
}

/** The middleware set-up for Express (UIUX.md §16). `endpoint` is the base URL of the Airverse API. */
export function shieldExpressSnippet(endpoint: string): string {
  return [
    'import { createShield } from "@antireverse/shield-node";',
    "",
    "const shield = createShield({",
    "  key: process.env.AR_SHIELD_KEY,",
    `  endpoint: ${JSON.stringify(endpoint)},`,
    "  policyPublicKey: process.env.AR_POLICY_PUBLIC_KEY,",
    "});",
    "app.use(shield.express());",
  ].join("\n");
}

/**
 * The same middleware on a plain `node:http` server: Shield first, the application's handler as its `next`. A test runs
 * this wiring (shield-plain-http.test.ts). Without a router Shield cannot name routes: every Event's route is
 * `(unmatched)`; Rules still match the request path.
 */
export function shieldNodeHttpSnippet(endpoint: string): string {
  return [
    'import http from "node:http";',
    'import { createShield } from "@antireverse/shield-node";',
    "",
    "const shield = createShield({",
    "  key: process.env.AR_SHIELD_KEY,",
    `  endpoint: ${JSON.stringify(endpoint)},`,
    "  policyPublicKey: process.env.AR_POLICY_PUBLIC_KEY,",
    "});",
    "const protect = shield.express();",
    "",
    "// handle(req, res) is your request handler.",
    "http",
    "  .createServer((req, res) => {",
    "    protect(req, res, () => handle(req, res));",
    "  })",
    "  .listen(3000);",
  ].join("\n");
}

/**
 * Guard in a web page (README "Guard and attestation"): plain ES modules without a build step, so a module script can
 * import it from wherever the site serves the package's `src` files. It attests, then sends the token with each call.
 */
export function guardScriptSnippet(appId: string, endpoint: string): string {
  return [
    '<script type="module">',
    '  import { createGuard } from "/vendor/antireverse-guard/index.js";',
    "",
    "  const guard = createGuard({",
    `    appId: ${JSON.stringify(appId)},`,
    `    endpoint: ${JSON.stringify(endpoint)},`,
    "  });",
    "  await guard.attest();",
    "",
    "  // Send the token with each call to your server; Shield checks it.",
    '  await fetch("/api/orders", { headers: { ...guard.headers() } });',
    "</script>",
  ].join("\n");
}

/**
 * Harden and register a bundle (README "Clone Beacon", "Hardening a bundle"), run from a copy of the Airverse
 * repository: the CLI is not on npm yet, and its `antireverse` bin is TypeScript that `npx` cannot run on Node 22.12.
 * The admin key is read only from the variable named by `--key-env`. The Build version is the commit of the app's own
 * repository (`git -C`): the command runs in the Airverse checkout, whose commit would tag every Build (review F2).
 */
export function hardenCommand(options: { endpoint: string; appId: string; environment: string }): string {
  return [
    "npx tsx packages/harden/src/cli.ts harden /path/to/app/dist --out /path/to/app/protected \\",
    `  --register --endpoint ${JSON.stringify(options.endpoint)} --key-env AR_ADMIN_KEY \\`,
    `  --app ${options.appId} --environment ${options.environment} --build-version "$(git -C /path/to/app rev-parse --short HEAD)"`,
  ].join("\n");
}
