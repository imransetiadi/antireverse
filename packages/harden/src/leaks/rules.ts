// The leak-scan rules (slice 07): one detector per protocol `LEAK_RULES` id. Each detector finds candidate
// values in a text and returns their offsets; the scanner turns them into findings (line, mask, fingerprint).
// Detectors are pure and deterministic. A value found here is never printed, logged or stored by Harden: only
// its mask and fingerprint leave the scanner.
import type { LeakRuleId } from "@antireverse/protocol";

/** One raw match: where it starts in the text and the value it found (kept inside the scanner only). */
export interface LeakMatch {
  index: number;
  value: string;
}

export interface LeakDetector {
  id: LeakRuleId;
  /** `path` (relative to the bundle) lets a rule depend on the file type. */
  find(text: string, path: string): LeakMatch[];
}

/** All matches of a global regex; `group` picks the value (0 = whole match). Offsets point at the match start. */
function matchesOf(text: string, pattern: RegExp, group = 0): LeakMatch[] {
  const out: LeakMatch[] = [];
  for (const m of text.matchAll(pattern)) {
    const value = m[group];
    if (value) out.push({ index: m.index, value });
  }
  return out;
}

/** True for a `*.map` file name (a source map shipped with the bundle). */
export function isSourceMapPath(path: string): boolean {
  return path.toLowerCase().endsWith(".map");
}

/** Shannon entropy of `s`, in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = [...s].length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

const SECRET_NAME = /secret|token|password|passwd|api[_-]?key|private[_-]?key|client[_-]?secret/i;
/** Minimum length and entropy of a value assigned to a secret-like name. */
const SECRET_MIN_LENGTH = 16;
const SECRET_MIN_ENTROPY = 3.5;

// name (bare, or the inside of a quoted key) · optional closing quote · the operator · a string literal in ',
// " or ` on one line. The operator is `:`, `=` (not `==`/`=>`), or a TypeScript annotation ending in `=`
// (`: <type> =`, the type bounded to 80 characters without quotes, colons, `;` or `=`, so an object's next key
// is never taken for a type and backtracking stays bounded). Group 1 = name, 2 = quote, 3 = content.
const ASSIGNMENT =
  /([A-Za-z_$][\w$-]*)["']?(?:\s*:\s*[^=;\n:'"`]{1,80}?\s*=(?![=>])|\s*(?::|=(?![=>])))\s*(["'`])((?:\\.|(?!\2)[^\\\n])*)\2/g;

// A config line with an unquoted value: `NAME=value` (.env, .properties, .ini; optional `export`) or
// `name: value` (YAML). The value runs to the next whitespace; a quoted value is left to ASSIGNMENT.
const UNQUOTED_ASSIGNMENT = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][\w.-]*)[ \t]*[:=][ \t]*([^\s"'`#][^\s]*)/gm;

const CONFIG_EXTENSIONS = new Set([".yml", ".yaml", ".ini", ".properties", ".toml", ".conf", ".cfg"]);

/** True for a config file whose values may be unquoted: .env*, YAML, INI-like, or a file without extension. */
export function isConfigPath(path: string): boolean {
  const base = (path.split("/").pop() ?? path).toLowerCase();
  if (base.startsWith(".env")) return true;
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return true;
  return CONFIG_EXTENSIONS.has(base.slice(dot));
}

function isSecretValue(name: string, value: string): boolean {
  return (
    SECRET_NAME.test(name) && [...value].length >= SECRET_MIN_LENGTH && shannonEntropy(value) >= SECRET_MIN_ENTROPY
  );
}

function secretAssignments(text: string, path: string): LeakMatch[] {
  const out: LeakMatch[] = [];
  for (const m of text.matchAll(ASSIGNMENT)) {
    const [, name = "", , value = ""] = m;
    if (isSecretValue(name, value)) out.push({ index: m.index, value });
  }
  if (isConfigPath(path)) {
    for (const m of text.matchAll(UNQUOTED_ASSIGNMENT)) {
      const [, name = "", value = ""] = m;
      if (isSecretValue(name, value)) out.push({ index: m.index, value });
    }
  }
  return out;
}

const PRIVATE_KEY_BEGIN = /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----/g;

/** A PEM private key: the whole block when its END line is present, else the BEGIN line. */
function privateKeys(text: string): LeakMatch[] {
  const out: LeakMatch[] = [];
  for (const m of text.matchAll(PRIVATE_KEY_BEGIN)) {
    const end = `-----END ${m[1] ?? ""}PRIVATE KEY-----`;
    const endAt = text.indexOf(end, m.index);
    const value = endAt === -1 ? m[0] : text.slice(m.index, endAt + end.length);
    out.push({ index: m.index, value });
  }
  return out;
}

const URL_PATTERN = /\bhttps?:\/\/[^\s"'`<>()\\]+/gi;

function ipv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p <= 255) ? parts : null;
}

/** True when `host` is localhost, a loopback, private or link-local address, or an internal-only name. */
export function isInternalHost(rawHost: string): boolean {
  const host = rawHost.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (/\.(internal|local|corp|lan)$/.test(host)) return true;
  if (host.startsWith("[")) {
    const v6 = host.slice(1, -1);
    return v6 === "::1" || /^fe[89ab][0-9a-f]?:/.test(v6) || /^f[cd][0-9a-f]{2}:/.test(v6);
  }
  const v4 = ipv4(host);
  if (!v4) return false;
  const [a = 0, b = 0] = v4;
  return (
    a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)
  );
}

function internalUrls(text: string): LeakMatch[] {
  const out: LeakMatch[] = [];
  for (const m of text.matchAll(URL_PATTERN)) {
    const authority = m[0].replace(/^https?:\/\//i, "").split(/[/?#]/)[0] ?? "";
    const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
    const host = hostPort.startsWith("[") ? hostPort.slice(0, hostPort.indexOf("]") + 1) : hostPort.split(":")[0];
    if (host && isInternalHost(host)) out.push({ index: m.index, value: m[0] });
  }
  return out;
}

/** The detectors, in the order of the protocol's `LEAK_RULES`. `source-map` also has a file-name check. */
export const LEAK_DETECTORS: readonly LeakDetector[] = [
  // A sourceMappingURL comment in JS (`//#`, legacy `//@`) or CSS (`/*#`); the value is the URL, incl. data: maps.
  { id: "source-map", find: (t) => matchesOf(t, /[#@]\s*sourceMappingURL=([^\s*'"`]+)/g, 1) },
  { id: "private-key", find: privateKeys },
  { id: "aws-access-key", find: (t) => matchesOf(t, /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g) },
  { id: "github-token", find: (t) => matchesOf(t, /\bgh[pousr]_[0-9A-Za-z]{36}/g) },
  { id: "stripe-secret", find: (t) => matchesOf(t, /\b[sr]k_live_[0-9A-Za-z]{24,}/g) },
  { id: "slack-token", find: (t) => matchesOf(t, /\bxox[abprs]-[0-9A-Za-z-]{10,}/g) },
  { id: "google-api-key", find: (t) => matchesOf(t, /\bAIza[0-9A-Za-z_-]{35}/g) },
  { id: "secret-assignment", find: secretAssignments },
  { id: "internal-url", find: internalUrls },
];
