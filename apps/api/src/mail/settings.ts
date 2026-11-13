import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { ALERT_EMAIL_LIMITS } from "@antireverse/protocol";
import { cleanHeaderText, isMailAddress, type Sender } from "./message.ts";

// The one SMTP account of the service (slice 06b, D-068): read from the environment at start-up. All or none: with
// none, email channels cannot be created and the Console says why; a partial set is a start-up error naming the
// missing variable. No error message ever quotes a value, and the password never leaves this object except into the
// AUTH command of the SMTP client.

export type SmtpTlsMode = "starttls" | "implicit";

export interface SmtpSettings {
  host: string;
  port: number;
  /** `starttls`: plain connection upgraded by STARTTLS, which is then required. `implicit`: TLS from the first byte. */
  tls: SmtpTlsMode;
  user: string;
  password: string;
  from: Sender;
  /**
   * Test only (`AR_SMTP_TEST_CA_FILE`): a PEM CA that replaces the system's trusted CAs, so that a local test server's
   * certificate validates. The host name is still checked against the certificate.
   */
  ca: string | undefined;
  /** Confirmation mails of the whole service per UTC day (`AR_SMTP_CONFIRMATIONS_PER_DAY`; when absent, 500). */
  confirmationsPerDay?: number;
}

export const SMTP_VARIABLES = [
  "AR_SMTP_HOST",
  "AR_SMTP_PORT",
  "AR_SMTP_TLS",
  "AR_SMTP_USER",
  "AR_SMTP_PASSWORD",
  "AR_SMTP_PASSWORD_FILE",
  "AR_SMTP_FROM",
  "AR_SMTP_FROM_NAME",
  "AR_SMTP_TEST_CA_FILE",
  "AR_SMTP_CONFIRMATIONS_PER_DAY",
] as const;

export const DEFAULT_SMTP_PORT = 587;
export const DEFAULT_FROM_NAME = "Airverse";

const HOST_NAME =
  /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point.
const CONTROL = /[\u0000-\u001f\u007f]/;

/**
 * Reads `AR_SMTP_*`; an empty variable counts as unset. Null when none is set. Throws an `Error` whose message names
 * the variable at fault, never a value, when the set is partial or a value is invalid.
 */
export function readSmtpSettings(
  env: Record<string, string | undefined>,
  options: { readFile?: (path: string) => string } = {},
): SmtpSettings | null {
  const readFile = options.readFile ?? ((path: string) => readFileSync(path, "utf8"));
  const get = (name: (typeof SMTP_VARIABLES)[number]): string | undefined => {
    const value = env[name];
    return value === undefined || value === "" ? undefined : value;
  };
  if (SMTP_VARIABLES.every((name) => get(name) === undefined)) return null;

  const required = (name: "AR_SMTP_HOST" | "AR_SMTP_USER" | "AR_SMTP_FROM"): string => {
    const value = get(name);
    if (value === undefined) throw new Error(`${name} is required when any AR_SMTP_* variable is set.`);
    return value;
  };
  const host = required("AR_SMTP_HOST");
  const user = required("AR_SMTP_USER");
  const passwordValue = get("AR_SMTP_PASSWORD");
  const passwordFile = get("AR_SMTP_PASSWORD_FILE");
  if (passwordValue === undefined && passwordFile === undefined) {
    throw new Error("AR_SMTP_PASSWORD or AR_SMTP_PASSWORD_FILE is required when any AR_SMTP_* variable is set.");
  }
  const fromAddress = required("AR_SMTP_FROM").toLowerCase();

  if (passwordValue !== undefined && passwordFile !== undefined) {
    throw new Error("Set only one of AR_SMTP_PASSWORD and AR_SMTP_PASSWORD_FILE.");
  }
  if (!(HOST_NAME.test(host) || isIP(host) !== 0))
    throw new Error("AR_SMTP_HOST must be a host name or an IP address.");

  const portText = get("AR_SMTP_PORT") ?? String(DEFAULT_SMTP_PORT);
  const port = /^[0-9]{1,5}$/.test(portText) ? Number(portText) : Number.NaN;
  if (!(port >= 1 && port <= 65_535)) throw new Error("AR_SMTP_PORT must be an integer from 1 to 65535.");

  const tls = get("AR_SMTP_TLS") ?? "starttls";
  if (tls !== "starttls" && tls !== "implicit") throw new Error("AR_SMTP_TLS must be starttls or implicit.");

  if (CONTROL.test(user)) throw new Error("AR_SMTP_USER must not contain control characters.");
  if (!isMailAddress(fromAddress)) throw new Error("AR_SMTP_FROM must be a valid email address.");
  const name = get("AR_SMTP_FROM_NAME") ?? DEFAULT_FROM_NAME;
  if (cleanHeaderText(name) !== name) {
    throw new Error("AR_SMTP_FROM_NAME must be one line of text without control characters.");
  }

  let password: string;
  if (passwordValue !== undefined) {
    password = passwordValue;
  } else {
    try {
      password = readFile(passwordFile as string).replace(/\r?\n$/, "");
    } catch {
      // The error of the file system names the path, and could quote more: it is not passed on.
      throw new Error("AR_SMTP_PASSWORD_FILE could not be read.");
    }
  }
  if (password === "") throw new Error("The SMTP password is empty.");
  if (CONTROL.test(password)) throw new Error("The SMTP password must not contain control characters.");

  const perDayText = get("AR_SMTP_CONFIRMATIONS_PER_DAY");
  const confirmationsPerDay =
    perDayText === undefined
      ? ALERT_EMAIL_LIMITS.confirmationMailsPerDay
      : /^[0-9]{1,7}$/.test(perDayText)
        ? Number(perDayText)
        : 0;
  if (!(confirmationsPerDay >= 1 && confirmationsPerDay <= 1_000_000)) {
    throw new Error("AR_SMTP_CONFIRMATIONS_PER_DAY must be a whole number from one to one million.");
  }

  const caFile = get("AR_SMTP_TEST_CA_FILE");
  let ca: string | undefined;
  if (caFile !== undefined) {
    try {
      ca = readFile(caFile);
    } catch {
      throw new Error("AR_SMTP_TEST_CA_FILE could not be read.");
    }
  }

  return { host, port, tls, user, password, from: { address: fromAddress, name }, ca, confirmationsPerDay };
}

/** One log line about the settings: host, port and TLS mode. Never the user, the password or the sender. */
export function smtpSummary(settings: SmtpSettings): string {
  return `smtp host=${settings.host} port=${settings.port} tls=${settings.tls}`;
}
