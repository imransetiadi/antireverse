import { CAMPAIGN_LIMITS, type CampaignLocation } from "@antireverse/protocol";

// Redaction of a Campaign response (slice 15a). It runs in the gate, before the engine, a Finding or a log can hold
// what a target answered: keys, tokens and JWTs, email addresses, card-like numbers (Luhn-valid digit runs), cookie
// values and high-entropy strings are replaced by a fixed marker. It errs on the side of removing: a hash or a long
// random identifier goes too. Redaction is stable: redacting a redacted text changes nothing. Every pattern is bounded
// or anchored so that a hostile body (64 KB of one character, of `@`, of `eyJ`) costs linear time.

const KEY = "[redacted-key]";
const TOKEN = "[redacted-token]";
const SECRET = "[redacted-secret]";
const EMAIL = "[redacted-email]";
const NUMBER = "[redacted-number]";

/** What stands in for a body that is not text: it is never decoded, redacted in part or handed on. */
export const BODY_WITHHELD = "[binary or non-UTF-8 body withheld]";

// Private keys, PEM and PGP: the whole block, to its END line or the end of the text.
const PEM =
  /-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----|$)/g;
// Three base64url parts, the first starting `eyJ`; a line break may follow a dot. Short parts count too.
const JWT = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{2,2048}\.\s{0,4}[A-Za-z0-9_-]{2,4096}\.\s{0,4}[A-Za-z0-9_-]{2,1024}/g;
const KEY_SHAPES: readonly RegExp[] = [
  /(?<![A-Za-z0-9])(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g,
  // An AWS key id, also glued to what precedes it.
  /A[KS]IA[0-9A-Z]{16}/g,
  /(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,}/g,
  /(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}/g,
  /(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}/g,
  /(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{30,}/g,
  // The product's own keys, secrets, Canary keys and beacon tokens (the shapes the audit log refuses).
  /(?<![A-Za-z0-9])(?:aro|ark|whsec)_[A-Za-z0-9_-]{8,}/g,
  /(?<![A-Za-z0-9])ak_live_[0-9A-Za-z]{8,}/g,
  /(?<![A-Za-z0-9])bcn_[0-9a-f]{24}/g,
];
// `scheme://user:password@host`: the password.
const CONNECTION_STRING =
  /(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{1,20}:\/\/[^\s:/@"'<>]{0,64}:)[^\s@/"'<>]{1,128}(@)/g;
const AUTH_SCHEME = /(?<![A-Za-z0-9])(Bearer|Basic)\s{1,8}[A-Za-z0-9._~+/=-]{8,}/gi;
// An `Authorization:` or `Cookie:` line in a body. The value is read below, by hand.
const CREDENTIAL_LINE = /(?<![A-Za-z0-9_-])((?:proxy-)?authorization|(?:set-)?cookie)(["']?[ \t]{0,8}[:=][ \t]{0,8})/gi;
// `name="…token…" … value="…"` (an HTML input, a JSON name and value pair): the value.
const NAMED_VALUE =
  /((?<![A-Za-z0-9_-])name["']?\s{0,8}[:=]\s{0,8}["']([A-Za-z0-9_.-]{1,64})["'][^<>{}\n]{0,64}?value["']?\s{0,8}[:=]\s{0,8})(["'])((?:\\.|(?!\3)[^\\\n]){0,512})\3/gi;
// `<password>…</password>`, attributes and a namespace prefix allowed: the content.
const ELEMENT = /(<(?:[A-Za-z0-9_-]{1,32}:)?([A-Za-z0-9_.-]{1,64})(?:\s[^<>]{0,128})?>)([^<]{1,512})(?=<\/)/g;
// A name and a separator (`=`, `:`, `=>`), with any spacing around it and an optional quote after the name. The name
// starts where no name character precedes it, so a long run is tried once. The value is read below, by hand: a
// name that is not a secret's does not consume its value, so that a secret assignment inside it is still found.
const NAME_AND_SEPARATOR = /(?<![A-Za-z0-9_-])([A-Za-z0-9_.-]{1,64})(["']?\s{0,16}(?:=>|[:=])\s{0,16})/g;
// A name that holds one of these is a secret's: password, user_password, DB_PASS, passwd, pwd, refresh_token,
// csrf_token, XSRF-TOKEN, client-secret, aws_secret_access_key, encryption_key, private_key, apiKey, session,
// PHPSESSID, sid, connect.sid, auth, signature, credential.
const SECRET_NAME =
  /pass|pwd|secret|token|credential|signature|sess|csrf|xsrf|(?:^|[_.-])(?:sid|auth|oauth)(?:$|[_.-])|authorization|[_.-]key(?:$|[_.-])|[a-z]Key$|apikey/i;
const HANDLED_ELSEWHERE = /^(?:(?:proxy-)?authorization|(?:set-)?cookie)$/i;
const VALUE_MAX = 1024;
const LOCAL_PART = /[\p{L}\p{N}._%+-]/u;
const DOMAIN_PART = /[\p{L}\p{N}.-]/u;
const DOMAIN = /^[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+$/u;
// Digits with one or two separators between them (space, tab, no-break space, dot, dash, slash, underscore, comma),
// taken as one run.
const DIGIT_RUN = /[0-9](?:[ \t\u00a0./_,-]{0,2}[0-9])+/g;
const CANDIDATE = /[A-Za-z0-9+/_=-]{24,}/g;
const HEX = /^[0-9a-fA-F]+$/;
const CARD_MIN = 13;
const CARD_MAX = 19;

/** Whether `digits[from, from + length)` (values 0–9) passes the Luhn check. */
function luhn(digits: readonly number[], from: number, length: number): boolean {
  let sum = 0;
  let double = false;
  for (let index = from + length - 1; index >= from; index--) {
    let digit = digits[index] as number;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

/** The lengths a card number starting at `digits[from]` can have, by its network's prefix (IIN); none for others. */
function cardLengths(digits: readonly number[], from: number): readonly number[] {
  const prefix = (length: number): number => {
    let value = 0;
    for (let index = 0; index < length; index++) value = value * 10 + (digits[from + index] ?? 0);
    return value;
  };
  const two = prefix(2);
  const three = prefix(3);
  const four = prefix(4);
  if (digits[from] === 4) return [16, 19, 13]; // Visa
  if ((two >= 51 && two <= 55) || (four >= 2221 && four <= 2720)) return [16]; // Mastercard
  if (two === 34 || two === 37) return [15]; // American Express
  if (four === 6011 || two === 65 || (three >= 644 && three <= 649)) return [16, 19]; // Discover
  if (four >= 3528 && four <= 3589) return [16, 19]; // JCB
  if (two === 36 || two === 38 || (three >= 300 && three <= 305)) return [14, 16, 19]; // Diners Club
  if (two === 62) return [16, 19, 17, 18]; // UnionPay
  return [];
}

/**
 * Card-like numbers in one run of digits and separators. The rule, so that order numbers, timestamps, addresses and
 * sizes survive:
 *
 * - a run of 13 to 19 digits in all is a card number when the WHOLE run passes the Luhn check;
 * - any other run of 13 digits or more (digits stand before or after the number: an order number, a date) is searched
 *   for a window that starts and ends where a group of digits starts and ends, begins with a card network's prefix,
 *   has one of that network's lengths, and passes the Luhn check.
 *
 * A run of fewer than 13 digits is never touched.
 */
function redactCardNumbers(run: string): string {
  const digits: number[] = [];
  const positions: number[] = [];
  for (let index = 0; index < run.length; index++) {
    const code = run.charCodeAt(index) - 48;
    if (code >= 0 && code <= 9) {
      digits.push(code);
      positions.push(index);
    }
  }
  if (digits.length < CARD_MIN) return run;
  if (digits.length <= CARD_MAX && luhn(digits, 0, digits.length)) return NUMBER;
  const groupStart = (index: number): boolean =>
    index === 0 || positions[index] !== (positions[index - 1] as number) + 1;
  const groupEnd = (index: number): boolean =>
    index === digits.length - 1 || positions[index + 1] !== (positions[index] as number) + 1;
  let out = "";
  let copied = 0;
  let start = 0;
  while (start + CARD_MIN <= digits.length) {
    let taken = 0;
    if (groupStart(start)) {
      for (const length of cardLengths(digits, start)) {
        const last = start + length - 1;
        if (last < digits.length && groupEnd(last) && luhn(digits, start, length)) {
          taken = length;
          break;
        }
      }
    }
    if (taken === 0) {
      start++;
      continue;
    }
    out += run.slice(copied, positions[start]) + NUMBER;
    copied = (positions[start + taken - 1] as number) + 1;
    start += taken;
  }
  return out + run.slice(copied);
}

/** Shannon entropy of the characters, in bits per character. */
function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * A run of 24 or more key characters that looks random: long hex, or mixed letters and digits of high entropy. A run
 * with a `/` (base64, but also a path) counts only with upper case, lower case and digits together.
 */
function looksRandom(value: string): boolean {
  if (HEX.test(value)) return value.length >= 32 && /[0-9]/.test(value) && /[a-fA-F]/.test(value);
  const digits = value.replace(/[^0-9]/g, "").length;
  const letters = /[A-Za-z]/.test(value);
  if (digits === 0 || !letters) return false;
  const mixedCase = /[a-z]/.test(value) && /[A-Z]/.test(value);
  if (value.includes("/") && !mixedCase) return false;
  if (!mixedCase && digits / value.length < 0.2) return false;
  return entropy(value) >= 3.5;
}

/**
 * Email addresses replaced, found from each `@` (or `%40`, `&#64;`, `&#x40;`) outwards — at most 64 characters
 * before it and 255 after, letters of any script — so that a long run without one costs nothing.
 */
function redactEmails(text: string): string {
  let out = "";
  let copied = 0;
  const sign = /@|%40|&#0{0,4}64;|&#x0{0,4}40;/gi;
  for (let match = sign.exec(text); match !== null; match = sign.exec(text)) {
    const at = match.index;
    const after = at + match[0].length;
    if (at < copied) continue;
    let start = at;
    while (start > copied && at - start < 64 && LOCAL_PART.test(text[start - 1] as string)) start--;
    let end = after;
    while (end < text.length && end - after < 255 && DOMAIN_PART.test(text[end] as string)) end++;
    const domain = text.slice(after, end).replace(/[.-]+$/, "");
    if (start < at && DOMAIN.test(domain)) {
      out += text.slice(copied, start) + EMAIL;
      copied = after + domain.length;
      sign.lastIndex = copied;
    } else sign.lastIndex = Math.max(end, after);
  }
  return out + text.slice(copied);
}

/** The end of a quoted value that opens at `open` (the quote's index): the closing quote's index, or -1. */
function closingQuote(text: string, open: number): number {
  const quote = text[open];
  const limit = Math.min(text.length, open + 1 + VALUE_MAX);
  for (let index = open + 1; index < limit; index++) {
    const character = text[index];
    if (character === "\\") index++;
    else if (character === quote) return index;
    else if (character === "\n") return -1;
  }
  return -1;
}

/** The end (exclusive) of an unquoted value at `from`: the first character of `stop`, or `VALUE_MAX` characters. */
function unquotedEnd(text: string, from: number, stop: RegExp): number {
  const limit = Math.min(text.length, from + VALUE_MAX);
  let index = from;
  while (index < limit && !stop.test(text[index] as string)) index++;
  return index;
}

const LINE_END = /[\r\n]/;
const BARE_END = /[\s"'&,;<>]/;
const JSON_END = /[\s,}\]]/;

/** An `Authorization:` line keeps its scheme word; a `Cookie:` line keeps its cookies' names. */
function redactCredentialLines(text: string): string {
  let out = "";
  let copied = 0;
  CREDENTIAL_LINE.lastIndex = 0;
  for (let match = CREDENTIAL_LINE.exec(text); match !== null; match = CREDENTIAL_LINE.exec(text)) {
    const from = match.index + match[0].length;
    const quoted = text[from] === '"' || text[from] === "'";
    const close = quoted ? closingQuote(text, from) : -1;
    const start = quoted ? from + 1 : from;
    const end = close !== -1 ? close : unquotedEnd(text, start, LINE_END);
    const value = text.slice(start, end);
    let kept: string;
    if (/cookie/i.test(match[1] as string)) {
      kept = value
        .split(";")
        .map((part) => {
          const equals = part.indexOf("=");
          return equals === -1 ? part : `${part.slice(0, equals + 1)}${SECRET}`;
        })
        .join(";");
    } else {
      const scheme = /^([A-Za-z]{1,16})[ \t]+\S/.exec(value);
      kept = scheme === null ? SECRET : `${scheme[1]} ${TOKEN}`;
    }
    out += text.slice(copied, start) + kept;
    copied = end;
    CREDENTIAL_LINE.lastIndex = Math.max(end, from);
  }
  return out + text.slice(copied);
}

/**
 * `name = value` in its many spellings, for names that are a secret's. A quoted value is replaced up to its closing
 * quote (escapes inside it are skipped; a `b` before the quote is a Python bytes literal). An unquoted one ends at
 * the end of the line after `:` (YAML, a header), at a space or a delimiter after `=`, and at `,` or `}` after a
 * quoted name (JSON). A name that is not a secret's does not consume its value: scanning resumes right after the
 * separator, so `next=https://…?token=…` and `"config":"db_password=…"` are found too.
 */
function redactAssignments(text: string): string {
  let out = "";
  let copied = 0;
  NAME_AND_SEPARATOR.lastIndex = 0;
  for (let match = NAME_AND_SEPARATOR.exec(text); match !== null; match = NAME_AND_SEPARATOR.exec(text)) {
    const name = match[1] as string;
    const separator = match[2] as string;
    const from = match.index + match[0].length;
    if (!SECRET_NAME.test(name) || HANDLED_ELSEWHERE.test(name)) {
      NAME_AND_SEPARATOR.lastIndex = from;
      continue;
    }
    let open = from;
    if ((text[open] === "b" || text[open] === "B") && (text[open + 1] === '"' || text[open + 1] === "'")) open++;
    let start: number;
    let end: number;
    if (text[open] === '"' || text[open] === "'") {
      const close = closingQuote(text, open);
      start = open + 1;
      end = close !== -1 ? close : unquotedEnd(text, start, LINE_END);
    } else {
      start = from;
      const stop = /^["']/.test(separator) ? JSON_END : separator.includes(":") ? LINE_END : BARE_END;
      end = unquotedEnd(text, start, stop);
    }
    if (end > start) {
      out += text.slice(copied, start) + SECRET;
      copied = end;
    }
    NAME_AND_SEPARATOR.lastIndex = Math.max(end, from);
  }
  return out + text.slice(copied);
}

/**
 * `text` with everything that looks like a secret or personal data replaced. Text with a NUL in it is not text (a
 * binary body, or UTF-16 read as UTF-8, in which every pattern here would miss): it is withheld whole. Never throws.
 */
export function redactText(text: string): string {
  let out = String(text);
  if (out.includes("\u0000")) return BODY_WITHHELD;
  out = out.replace(PEM, KEY);
  out = out.replace(CONNECTION_STRING, (_match, before: string, at: string) => `${before}${SECRET}${at}`);
  out = out.replace(JWT, TOKEN);
  for (const shape of KEY_SHAPES) out = out.replace(shape, KEY);
  out = redactCredentialLines(out);
  out = out.replace(NAMED_VALUE, (match, before: string, name: string, quote: string) =>
    SECRET_NAME.test(name) ? `${before}${quote}${SECRET}${quote}` : match,
  );
  out = out.replace(ELEMENT, (match, open: string, name: string) =>
    SECRET_NAME.test(name) ? `${open}${SECRET}` : match,
  );
  out = redactAssignments(out);
  out = out.replace(AUTH_SCHEME, (_match, scheme: string) => `${scheme} ${TOKEN}`);
  out = redactEmails(out);
  out = out.replace(DIGIT_RUN, redactCardNumbers);
  out = out.replace(CANDIDATE, (run) => (looksRandom(run) ? SECRET : run));
  return out;
}

/**
 * The body of a response as the engine, a Finding and a hash may hold it: decoded as UTF-8 and redacted, or
 * `BODY_WITHHELD` when it is not text (a NUL byte anywhere, or a UTF-16 byte order mark).
 */
export function redactBody(body: Uint8Array): string {
  const bytes = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (bytes.length >= 2 && ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff))) {
    return BODY_WITHHELD;
  }
  if (bytes.includes(0)) return BODY_WITHHELD;
  return redactText(bytes.toString("utf8"));
}

/**
 * Where a Location header points, which is all that is kept of it: `same-host` only for the Campaign's own host over
 * HTTPS on port 443 without credentials (a relative reference included); anything else, or anything that does not
 * parse, is `other-host`. Null without the header. A redirect is never followed either way.
 */
export function locationOf(location: string | undefined, host: string): CampaignLocation | null {
  if (location === undefined) return null;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point.
  if (/[\\\u0000-\u001f]/.test(location)) return "other-host";
  try {
    const url = new URL(location, `https://${host}/`);
    const same =
      url.protocol === "https:" &&
      url.hostname === host &&
      url.port === "" &&
      url.username === "" &&
      url.password === "";
    return same ? "same-host" : "other-host";
  } catch {
    return "other-host";
  }
}

/** Response headers kept, each as redacted text of at most 256 characters. */
const KEPT_HEADERS = [
  "content-type",
  "content-length",
  "server",
  "x-powered-by",
  "retry-after",
  "cache-control",
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "access-control-allow-origin",
] as const;
const HEADER_VALUE_MAX = 256;
const COOKIE_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const COOKIE_FLAGS = /^(?:httponly|secure|samesite=(?:strict|lax|none))$/i;

/** One Set-Cookie header as its name, `[redacted]` for the value, and the HttpOnly, Secure and SameSite flags. */
function redactCookie(cookie: string): string {
  const [pair = "", ...attributes] = cookie.split(";").map((part) => part.trim());
  const name = pair.split("=")[0] ?? "";
  const flags = attributes.filter((attribute) => COOKIE_FLAGS.test(attribute));
  return [`${COOKIE_NAME.test(name) ? name : "cookie"}=[redacted]`, ...flags].join("; ");
}

/**
 * The response headers the engine and a Finding may hold: an allowlist (`KEPT_HEADERS`), `set-cookie` with every value
 * removed, `www-authenticate` as its scheme only, and `location` as `same-host` or `other-host`.
 */
export function redactHeaders(
  headers: Readonly<Record<string, string | string[] | undefined>>,
  host: string,
): Record<string, string> {
  const kept: Record<string, string> = {};
  const first = (name: string): string | undefined => {
    const value = headers[name];
    return Array.isArray(value) ? value[0] : value;
  };
  for (const name of KEPT_HEADERS) {
    const value = first(name);
    if (typeof value === "string") kept[name] = redactText(value).slice(0, HEADER_VALUE_MAX);
  }
  const cookies = headers["set-cookie"];
  if (cookies !== undefined) {
    const list = (Array.isArray(cookies) ? cookies : [cookies]).slice(0, 16);
    kept["set-cookie"] = list
      .map(redactCookie)
      .join(", ")
      .slice(0, HEADER_VALUE_MAX * 4);
  }
  const challenge = first("www-authenticate");
  if (typeof challenge === "string") kept["www-authenticate"] = /^[A-Za-z]{1,16}/.exec(challenge)?.[0] ?? "other";
  const location = locationOf(first("location"), host);
  if (location !== null) kept.location = location;
  return kept;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: replacing control characters is the point.
const EXCERPT_CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

/**
 * At most `excerptBytesMax` (2 KB) of UTF-8 from `body`, starting a little before `at`. Whole characters only, and no
 * control character but a line break or a tab: each other one becomes a space, so that an excerpt can always be
 * stored and shown.
 */
export function excerptAround(body: string, at: number): string {
  const position = Number.isInteger(at) ? Math.min(Math.max(at, 0), body.length) : 0;
  let start = Math.max(0, position - 256);
  // Never start inside a surrogate pair.
  const code = body.charCodeAt(start);
  if (code >= 0xdc00 && code <= 0xdfff) start += 1;
  let bytes = 0;
  let out = "";
  for (const character of body.slice(start, start + CAMPAIGN_LIMITS.excerptBytesMax)) {
    // A surrogate without its pair (the cut fell inside one, or the body held one) is left out.
    if (character.length === 1 && character >= "\ud800" && character <= "\udfff") continue;
    const size = Buffer.byteLength(character, "utf8");
    if (bytes + size > CAMPAIGN_LIMITS.excerptBytesMax) break;
    bytes += size;
    out += character;
  }
  return out.replace(EXCERPT_CONTROL, " ");
}
