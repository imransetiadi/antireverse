// The set-up code shown after an App is created. Code is not translated, so it does not live in the
// message catalog; the labels around it do.
import { RELEASED_VERSION } from "@/lib/released-version.ts";

/**
 * The three packages are on npm. Every install line names the exact released version (`--save-exact` pins it in the
 * project's `package.json`), never `latest`: the reader gets what this Console was written for.
 */
export const SHIELD_INSTALL = `npm install --save-exact @antireverse/shield-node@${RELEASED_VERSION}`;
export const GUARD_INSTALL = `npm install --save-exact @antireverse/guard@${RELEASED_VERSION}`;
export const HARDEN_INSTALL = `npm install --save-dev --save-exact @antireverse/harden@${RELEASED_VERSION}`;

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

/** The lines both Guard snippets share: create it with the App's values, attest, send the token. */
function guardBody(appId: string, endpoint: string, indent: string): string[] {
  return [
    "",
    "const guard = createGuard({",
    `  appId: ${JSON.stringify(appId)},`,
    `  endpoint: ${JSON.stringify(endpoint)},`,
    "});",
    "await guard.attest();",
    "",
    "// Send the token with each call to your server; Shield checks it.",
    'await fetch("/api/orders", { headers: { ...guard.headers() } });',
  ].map((line) => (line === "" ? line : `${indent}${line}`));
}

/** Guard through a bundler: imported by name from the installed package. */
export function guardBundlerSnippet(appId: string, endpoint: string): string {
  return ['import { createGuard } from "@antireverse/guard";', ...guardBody(appId, endpoint, "")].join("\n");
}

/**
 * Guard without a bundler: plain ES modules, so a module script imports it from where the site serves the files of
 * `node_modules/@antireverse/guard/dist` (`/guard`, as the package's guide does).
 */
export function guardScriptSnippet(appId: string, endpoint: string): string {
  return [
    '<script type="module">',
    '  import { createGuard } from "/guard/index.js";',
    ...guardBody(appId, endpoint, "  "),
    "</script>",
  ].join("\n");
}

/**
 * Harden and register a bundle, run in the developer's own project where `@antireverse/harden` is installed.
 * `--no-install` makes npx run only that installed copy. The admin key is read only from the variable named by
 * `--key-env`. The Build version is the commit of the project the command runs in.
 */
export function hardenCommand(options: { endpoint: string; appId: string; environment: string }): string {
  return [
    "npx --no-install antireverse harden dist --out dist-protected \\",
    `  --register --endpoint ${JSON.stringify(options.endpoint)} --key-env AR_ADMIN_KEY \\`,
    `  --app ${options.appId} --environment ${options.environment} --build-version "$(git rev-parse --short HEAD)"`,
  ].join("\n");
}
