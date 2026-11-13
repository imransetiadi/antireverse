import { randomBytes } from "node:crypto";
import { ALERT_EMAIL_LIMITS, EMAIL_ADDRESS_PATTERN, type Incident, type Severity } from "@antireverse/protocol";

// The mails Airverse sends (slice 06b): plain text, UTF-8, quoted-printable. Every header line is built here and only
// here. Tenant text (an Incident title, an App name) reaches exactly one header, the Subject, and only after
// `cleanHeaderText` removed every control, format and line-separator character; it is then either plain printable
// ASCII folded at spaces or RFC 2047 encoded words. Addresses must match `EMAIL_ADDRESS_PATTERN`, which admits no
// character that could end a header line or an SMTP command. The body is quoted-printable: 7-bit lines of at most 76
// characters, whatever the text.

/** Code points of an Incident title in a Subject, at most. */
export const SUBJECT_TITLE_MAX = 100;
/** Characters of a header line we write, at most (RFC 5322 recommends 78). */
const HEADER_LINE_MAX = 78;
/** Bytes of UTF-8 in one encoded word: 39 bytes are 52 base64 characters, 64 with `=?UTF-8?B?` and `?=`. */
const WORD_BYTES_MAX = 39;
/** Characters of a quoted-printable line, at most (RFC 2045), soft-break `=` included. */
const QP_LINE_MAX = 76;

export const SEVERITY_WORDS: Readonly<Record<Severity, string>> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** The From of every mail: the service's sender address and display name (`AR_SMTP_FROM`, `AR_SMTP_FROM_NAME`). */
export interface Sender {
  address: string;
  name: string;
}

export interface MailText {
  subject: string;
  /** Lines separated by `\n`; `buildMessage` writes CRLF. */
  body: string;
}

// Control (Cc: C0, DEL, C1 with NEL), format (Cf: zero-width, bidi overrides, BOM), line and paragraph separators (Zl,
// Zp), and lone surrogates (Cs).
const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu;

/** Text fit for one line: tabs become spaces, every unsafe character is removed, whitespace runs collapse, trimmed. */
export function cleanHeaderText(value: string): string {
  return value.replaceAll("\t", " ").replace(UNSAFE, "").replace(/\s+/gu, " ").trim();
}

/** True for an address Airverse would send to or from: see `EMAIL_ADDRESS_PATTERN`. */
export function isMailAddress(value: string): boolean {
  return value.length <= ALERT_EMAIL_LIMITS.addressMax && EMAIL_ADDRESS_PATTERN.test(value);
}

function requireAddress(value: string, what: string): string {
  if (!isMailAddress(value)) throw new TypeError(`The ${what} address is not a valid address.`);
  return value;
}

/** `[Airverse] <Severity>: <title>`, the title cleaned and cut to `SUBJECT_TITLE_MAX` code points (`(no title)` if none is left). */
export function subjectFor(severity: Severity, title: string): string {
  const cleaned = [...cleanHeaderText(title)].slice(0, SUBJECT_TITLE_MAX).join("").trimEnd();
  return `[Airverse] ${SEVERITY_WORDS[severity]}: ${cleaned === "" ? "(no title)" : cleaned}`;
}

const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/** RFC 2047 B-encoded words of `text`, each at most `WORD_BYTES_MAX` bytes of UTF-8, never splitting a character. */
function encodedWords(text: string): string[] {
  const words: string[] = [];
  let chunk: Buffer[] = [];
  let size = 0;
  const flush = () => {
    if (chunk.length > 0) words.push(`=?UTF-8?B?${Buffer.concat(chunk).toString("base64")}?=`);
    chunk = [];
    size = 0;
  };
  for (const character of text) {
    const bytes = Buffer.from(character, "utf8");
    if (size + bytes.length > WORD_BYTES_MAX) flush();
    chunk.push(bytes);
    size += bytes.length;
  }
  flush();
  return words;
}

/** Folds tokens into lines of at most `HEADER_LINE_MAX` characters; continuation lines start with one space. */
function fold(name: string, tokens: string[]): string {
  const lines: string[] = [];
  let line = `${name}:`;
  for (const token of tokens) {
    if (line.length + 1 + token.length > HEADER_LINE_MAX && line !== `${name}:`) {
      lines.push(line);
      line = "";
    }
    line += ` ${token}`;
  }
  lines.push(line);
  return lines.join("\r\n");
}

/**
 * Plain printable ASCII when every word fits on a line and nothing looks like an encoded word; else encoded words.
 * Either way, every line is printable ASCII of at most 78 characters, and only the first one starts a field.
 */
function textTokens(value: string, room: number): string[] {
  const words = value.split(" ").filter((word) => word.length > 0);
  const plain = PRINTABLE_ASCII.test(value) && !value.includes("=?") && words.every((word) => word.length <= room - 1);
  return plain ? words : encodedWords(value);
}

function header(name: string, value: string): string {
  return fold(name, textTokens(cleanHeaderText(value), HEADER_LINE_MAX - name.length - 2));
}

/** `"Display Name" <address>`, the name quoted when plain ASCII and short, else encoded; just the address without a name. */
function mailbox(name: string, address: string): string {
  const cleaned = cleanHeaderText(name);
  if (cleaned === "") return fold("From", [`<${address}>`]);
  const quoted = `"${cleaned.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
  if (PRINTABLE_ASCII.test(cleaned) && !cleaned.includes("=?") && `From: ${quoted}`.length <= HEADER_LINE_MAX) {
    return fold("From", [quoted, `<${address}>`]);
  }
  return fold("From", [...encodedWords(cleaned), `<${address}>`]);
}

const hex = (byte: number) => `=${byte.toString(16).toUpperCase().padStart(2, "0")}`;

/**
 * One line of text as quoted-printable tokens: a literal character or an `=XX` escape, never split. Only printable
 * ASCII and inner spaces stay literal; a tab is escaped too, so every encoded line is printable ASCII.
 */
function qpTokens(line: string): string[] {
  const bytes = Buffer.from(line, "utf8");
  const tokens: string[] = [];
  bytes.forEach((byte, index) => {
    const last = index === bytes.length - 1;
    if ((byte >= 33 && byte <= 126 && byte !== 61) || (byte === 32 && !last)) {
      tokens.push(String.fromCharCode(byte));
    } else {
      tokens.push(hex(byte));
    }
  });
  return tokens;
}

/** Quoted-printable (RFC 2045) of UTF-8 text: every line break becomes CRLF, lines are at most 76 characters. */
export function encodeQuotedPrintable(text: string): string {
  const out: string[] = [];
  for (const line of text.split(/\r\n|\r|\n/)) {
    let current = "";
    for (const token of qpTokens(line)) {
      if (current.length + token.length > QP_LINE_MAX - 1) {
        out.push(`${current}=`);
        current = "";
      }
      current += token;
    }
    out.push(current);
  }
  return out.join("\r\n");
}

/** The inverse of `encodeQuotedPrintable`, for tests and the e2e mail reader. */
export function decodeQuotedPrintable(encoded: string): string {
  const joined = encoded.replace(/=\r\n/g, "");
  const bytes: number[] = [];
  for (let i = 0; i < joined.length; i++) {
    const character = joined[i] as string;
    if (character === "=" && /^[0-9A-F]{2}$/.test(joined.slice(i + 1, i + 3))) {
      bytes.push(Number.parseInt(joined.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(...Buffer.from(character, "utf8"));
    }
  }
  return Buffer.from(bytes).toString("utf8");
}

/** A new Message-ID on the sender's domain: `<32 hex characters@domain>`. */
export function newMessageId(senderAddress: string): string {
  const domain = senderAddress.slice(senderAddress.lastIndexOf("@") + 1);
  return `<${randomBytes(16).toString("hex")}@${domain}>`;
}

/** RFC 5322 date in UTC: `Tue, 10 Nov 2026 08:20:01 +0000`. */
function rfc5322Date(date: Date): string {
  return date.toUTCString().replace(/GMT$/, "+0000");
}

/**
 * The whole message, CRLF line endings, ready for DATA (the SMTP client dot-stuffs it). One recipient per message:
 * `To` names that recipient alone, so no recipient ever sees another's address.
 *
 * Accepted limit (review F5): the `To` address is the one the tenant typed, so its local part — `+tag` included, up to
 * 64 characters of `EMAIL_ADDRESS_PATTERN` — reaches the recipient, also in a confirmation mail to someone who never
 * agreed to anything. It cannot add a header or a recipient (the pattern admits no space, `<`, `>`, `,`, `;`, `:` or
 * control character), and the Subject and body of a confirmation mail carry no tenant text at all.
 */
export function buildMessage(input: {
  from: Sender;
  to: string;
  subject: string;
  body: string;
  date: Date;
  messageId: string;
}): string {
  const from = requireAddress(input.from.address, "sender");
  const to = requireAddress(input.to, "recipient");
  if (!/^<[\x21-\x3b\x3d\x3f-\x7e]{1,200}>$/.test(input.messageId)) throw new TypeError("Invalid Message-ID.");
  const headers = [
    mailbox(input.from.name, from),
    fold("To", [`<${to}>`]),
    header("Subject", input.subject),
    `Date: ${rfc5322Date(input.date)}`,
    `Message-ID: ${input.messageId}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: quoted-printable",
    "Auto-Submitted: auto-generated",
  ];
  return `${headers.join("\r\n")}\r\n\r\n${encodeQuotedPrintable(input.body)}`;
}

/** `2026-11-10 08:20:00 UTC`. */
function utc(iso: string): string {
  return `${iso.slice(0, 19).replace("T", " ")} UTC`;
}

/** The alert of a newly opened Incident. Tenant text is cleaned to one line each, so it cannot add a line. */
export function alertMail(input: { incident: Incident; appName: string; consoleUrl: string }): MailText {
  const { incident } = input;
  const base = input.consoleUrl.replace(/\/+$/, "");
  return {
    subject: subjectFor(incident.severity, incident.title),
    body: [
      `Incident: ${cleanHeaderText(incident.title)}`,
      `Severity: ${SEVERITY_WORDS[incident.severity]}`,
      `App: ${cleanHeaderText(input.appName)}`,
      `Environment: ${incident.environment}`,
      `Opened at: ${utc(incident.created_at)}`,
      `Open in the Console: ${base}/incidents/${incident.id}`,
      "",
      "You receive this mail because this address was confirmed for an alert channel of an Airverse Organization.",
      "",
    ].join("\n"),
  };
}

/** The test alert of `POST /v1/alert-channels/:id/test`. */
export function testAlertMail(): MailText {
  return {
    subject: "[Airverse] Test alert",
    body: "Test alert from Airverse: this channel is connected.\n",
  };
}

/**
 * The confirmation mail. It goes to an address nobody has confirmed yet, so it carries no tenant text at all (no
 * Organization, channel or App name): it cannot be used to send someone else's words to a stranger.
 */
export function confirmationMail(input: { token: string; consoleUrl: string }): MailText {
  const base = input.consoleUrl.replace(/\/+$/, "");
  const hours = ALERT_EMAIL_LIMITS.confirmationTtlS / 3600;
  return {
    subject: "[Airverse] Confirm alert emails",
    body: [
      "This address was added to an alert channel of an Airverse Organization.",
      "To receive its security alerts by email, confirm with this link:",
      "",
      `${base}/alerts/confirm?token=${input.token}`,
      "",
      `The link works once and expires in ${hours} hours.`,
      "If you did not expect this mail, ignore it: nothing will be sent to you without confirmation.",
      "",
    ].join("\n"),
  };
}
