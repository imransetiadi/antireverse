// The set-up code shown after an App is created. Code is not translated, so it does not live in the
// message catalog; the labels around it do.

export const SHIELD_INSTALL = "npm install @antireverse/shield-node";

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

/** The middleware set-up for Express (UIUX.md §16). `endpoint` is the base URL of the Anti Reverse API. */
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
