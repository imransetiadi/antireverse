// Slice 18d: the operator settings, read from the environment at start-up. No error message quotes a value.
//
// - `AR_OPS_TOKEN`: the operator token of `GET /v1/ops/slo` and `GET /metrics`. Unset or empty: those routes answer
//   404. Set: 32 to 512 printable ASCII characters without spaces, else the start fails (Jev, refuse_start, 1.0).
// - `AR_OPS_WEBHOOK_URL`: optional; burn alerts are POSTed there (http or https, no user info). Being the operator's
//   own configuration, a private address is allowed (an internal alert manager).
// - `AR_OPS_WEBHOOK_SECRET`: optional, with the URL only; 32 to 512 printable characters. When set, every alert
//   carries `AR-Signature: t=<unix seconds>,v1=<hex HMAC-SHA-256 of "<t>.<body>">`, the signature of alert-channel
//   webhooks (`signWebhookBody`, checked with `verifyWebhookSignature`).

export interface OpsWebhook {
  url: string;
  secret: string | null;
}

export interface OpsSettings {
  token: string | null;
  webhook: OpsWebhook | null;
}

export const OPS_VARIABLES = ["AR_OPS_TOKEN", "AR_OPS_WEBHOOK_URL", "AR_OPS_WEBHOOK_SECRET"] as const;

const SECRET_TEXT = /^[\x21-\x7e]{32,512}$/;

export function readOpsSettings(env: Record<string, string | undefined>): OpsSettings {
  const token = env.AR_OPS_TOKEN || null;
  if (token !== null && !SECRET_TEXT.test(token)) {
    throw new Error("AR_OPS_TOKEN must be at least 32 (at most 512) printable ASCII characters without spaces.");
  }
  const url = env.AR_OPS_WEBHOOK_URL || null;
  const secret = env.AR_OPS_WEBHOOK_SECRET || null;
  if (url === null) {
    if (secret !== null) throw new Error("AR_OPS_WEBHOOK_SECRET is set without AR_OPS_WEBHOOK_URL.");
    return { token, webhook: null };
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("AR_OPS_WEBHOOK_URL must be an http or https URL.");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username !== "" || parsed.password !== "") {
    throw new Error("AR_OPS_WEBHOOK_URL must be an http or https URL without user information.");
  }
  if (secret !== null && !SECRET_TEXT.test(secret)) {
    throw new Error(
      "AR_OPS_WEBHOOK_SECRET must be at least 32 (at most 512) printable ASCII characters without spaces.",
    );
  }
  return { token, webhook: { url, secret } };
}
