// Virtual patches (slice 20, D-061): reading the bundle's optional `patches` member, and matching a request.
//
// Shield has no runtime dependency, so the protocol's patch contract (`patches.ts` of the protocol package: the
// bundle entry `BundlePatchSchema`, `PATCH_LIMITS` and the reference matcher `matchPatch`) is repeated here by
// hand. test/patches.test.ts pins every constant against the protocol and checks this matcher against the
// protocol's on many generated requests (encodings, duplicates, arrays, JSON escapes, sizes). A bound or a rule
// that changes there must change here.
//
// Matching, in short (the protocol documents each point): ASCII letters only are folded; every string is compared
// raw and once percent-decoded (`+` as a space in the query only), a form identical to the raw one not twice; query
// pairs split as qs splits them (`]=` first), the key before the first `=` a candidate too; the body decoded as
// UTF-8, UTF-16 or UTF-32 (charset or byte order mark; any other charset counts as a match, D-062) and also compared
// with JSON `\uXXXX` escapes decoded; path, query and each header value are scanned over their first 16,384
// characters. Each form is ASCII-lower-cased once per request and searched with the native `indexOf`, `startsWith`
// and `endsWith` (Jev native_indexof_latin1): a condition costs at most its input's length × the value's length
// (≤ 256). ASCII-compatible single-byte charsets (`LATIN1_CHARSETS`) are read as Latin-1, an empty charset as UTF-8. No regular expression ever runs on request data, and each condition costs time linear in its
// input. Nothing here logs, and no header value, query value or body leaves this module.
import type { IncomingMessage } from "node:http";
import { compilePattern } from "./policy/match.ts";
import type { AppliedPatch, AppliedPolicy } from "./policy/store.ts";

/** Equal to `PATCH_TARGETS` of the protocol. */
export const PATCH_TARGETS = Object.freeze([
  "method",
  "path",
  "query_key",
  "query_value",
  "header_name",
  "header",
  "body",
] as const);
export type PatchTarget = (typeof PATCH_TARGETS)[number];

/** Equal to `PATCH_OPS` of the protocol. */
export const PATCH_OPS = Object.freeze([
  "equals",
  "contains",
  "starts_with",
  "ends_with",
  "length_over",
  "present",
  "json_key",
] as const);
export type PatchOp = (typeof PATCH_OPS)[number];

/** The bounds of `PATCH_LIMITS` of the protocol that a Shield reads (pinned by a test). */
export const PATCH_LIMITS = Object.freeze({
  conditionsMax: 8,
  perBundle: 50,
  valueMin: 1,
  valueMax: 256,
  lengthOverMax: 1_000_000,
  methodsMax: 8,
  headerNameMax: 128,
  pathMax: 16_384,
  queryMax: 16_384,
  headerValueMax: 16_384,
  bundleBytesMax: 16_384,
});

/** Equal to `PATCH_ID_PATTERN` of the protocol. */
export const PATCH_ID = /^vp_[a-z0-9_]{3,48}$/;
/** An advisory id: equal to the pattern of `AdvisoryIdSchema` of the protocol (checked by a test). */
export const ADVISORY_ID = /^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;
/** Equal to the protocol's: printable ASCII, the alphabet of a condition value. */
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;
/** Equal to the protocol's: a lower-case HTTP header name (RFC 9110 token characters). */
const HEADER_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;
/** Equal to the protocol's: a decimal without a leading zero, at most 7 digits. */
const DECIMAL = /^[1-9][0-9]{0,6}$/;
/** Equal to `HttpMethodSchema` of the protocol. */
const METHOD = /^[A-Z-]{1,16}$/;

/** One condition of a bundle patch, as the protocol's `ConditionSchema` parses it (unknown keys dropped). */
export interface Condition {
  readonly target: PatchTarget;
  readonly name?: string;
  readonly op: PatchOp;
  readonly value?: string;
}

/** One entry of the bundle's `patches`, checked: the protocol's `BundlePatch`. */
export interface PatchInput {
  readonly id: string;
  readonly mode: "monitor" | "enforce";
  readonly methods?: readonly string[];
  readonly path?: string;
  readonly conditions: readonly Condition[];
  readonly advisory: string;
}

/** A condition ready to evaluate: its value in lower case (for `json_key`, as a JSON string literal). Per bundle. */
export interface PreparedCondition {
  readonly condition: Condition;
  readonly needle: string;
  readonly over: number;
  /** `name` in lower case (query_value), or null. */
  readonly foldedName: string | null;
}

/** A patch prepared once per bundle: what matching reads. */
export interface MatchablePatch {
  readonly methods?: readonly string[] | undefined;
  readonly path?: string | undefined;
  readonly conditions: readonly PreparedCondition[];
  /** Some condition reads the body: then the patch is "body-dependent". */
  readonly bodyDependent: boolean;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isValue = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length >= PATCH_LIMITS.valueMin &&
  value.length <= PATCH_LIMITS.valueMax &&
  PRINTABLE_ASCII.test(value);

/** The fields of a condition and of a bundle patch this Shield reads; any other field makes it unreadable. */
const CONDITION_FIELDS = new Set(["target", "name", "op", "value"]);
const PATCH_FIELDS = new Set(["id", "mode", "methods", "path", "conditions", "advisory"]);

/** What breaks a bound in the condition, or the condition. The message never repeats a value. */
function readCondition(value: unknown, ops: readonly string[]): Condition | string {
  if (!isObject(value)) return "is not an object";
  for (const key of Object.keys(value)) if (!CONDITION_FIELDS.has(key)) return "has an unknown field";
  const { target, name, op } = value;
  const given = value.value;
  if (typeof target !== "string" || !(PATCH_TARGETS as readonly string[]).includes(target)) {
    return "target is not known";
  }
  if (typeof op !== "string" || !ops.includes(op)) return "op is not known";
  if (name !== undefined && !isValue(name)) return "name is not 1 to 256 printable characters";
  if (given !== undefined && !isValue(given)) return "value is not 1 to 256 printable characters";
  if (target === "header") {
    if (name === undefined || name.length > PATCH_LIMITS.headerNameMax || !HEADER_NAME.test(name)) {
      return "a header condition does not name a lower-case header";
    }
  } else if (target !== "query_value" && name !== undefined) {
    return "only header and query_value take a name";
  }
  if (op === "json_key" && target !== "body") return "json_key applies to the body only";
  if (op === "present") {
    if (given !== undefined) return "present takes no value";
  } else if (given === undefined) {
    return "the operator needs a value";
  } else if (op === "length_over" && (!DECIMAL.test(given) || Number(given) > PATCH_LIMITS.lengthOverMax)) {
    return "length_over does not take a decimal from 1 to 1000000";
  }
  // The protocol's key order (target, name, op, value): the byte budget is measured on this form.
  const condition: Record<string, string> = { target };
  if (name !== undefined) condition.name = name;
  condition.op = op;
  if (given !== undefined) condition.value = given;
  return condition as unknown as Condition;
}

/** What breaks a bound in the bundle patch, or the patch. The message never repeats a value. */
export function readPatch(value: unknown, ops: readonly string[] = PATCH_OPS): PatchInput | string {
  if (!isObject(value)) return "is not an object";
  // A field this Shield does not know may change what the patch means: the patch is not read.
  for (const key of Object.keys(value)) if (!PATCH_FIELDS.has(key)) return "has an unknown field";
  const { id, mode, methods, path, conditions, advisory } = value;
  if (typeof id !== "string" || !PATCH_ID.test(id)) return "id is not a patch identifier";
  if (mode !== "monitor" && mode !== "enforce") return "mode is not known";
  if (methods !== undefined) {
    if (!Array.isArray(methods) || methods.length > PATCH_LIMITS.methodsMax) {
      return `methods is not a list of at most ${PATCH_LIMITS.methodsMax}`;
    }
    for (let i = 0; i < methods.length; i++) {
      const method: unknown = methods[i];
      if (typeof method !== "string" || !METHOD.test(method)) return "methods holds something that is not a method";
      if (methods.indexOf(method) !== i) return "methods lists a method twice";
    }
  }
  if (path !== undefined && compilePattern(path) === null) return "path is not a path pattern";
  if (!Array.isArray(conditions) || conditions.length < 1 || conditions.length > PATCH_LIMITS.conditionsMax) {
    return `conditions is not a list of 1 to ${PATCH_LIMITS.conditionsMax}`;
  }
  const read: Condition[] = [];
  for (let i = 0; i < conditions.length; i++) {
    const condition = readCondition(conditions[i], ops);
    if (typeof condition === "string") return `condition ${i + 1}: ${condition}`;
    read.push(condition);
  }
  if (typeof advisory !== "string" || !ADVISORY_ID.test(advisory)) return "advisory is not an advisory id";
  // The protocol's key order (id, mode, methods, path, conditions, advisory): the byte budget is measured on it.
  const patch: Record<string, unknown> = { id, mode };
  if (methods !== undefined) patch.methods = [...(methods as string[])];
  if (path !== undefined) patch.path = path;
  patch.conditions = read;
  patch.advisory = advisory;
  return patch as unknown as PatchInput;
}

/** What `readPatches` made of the bundle's `patches` member. */
export interface ReadPatches {
  /** The patches this Shield can read, in bundle order, at most `perBundle`. */
  readonly patches: PatchInput[];
  /** Entries skipped: unreadable (an unknown target, operator, field or shape), an id listed again, beyond 50. */
  readonly skipped: number;
  /** Why the member was ignored as a whole (not a list, or over the byte budget), or null. Never repeats a value. */
  readonly ignored: string | null;
}

/**
 * The bundle's `patches` member, read with the tolerance of an older Shield for a newer API (forward compatibility):
 * patch by patch, each entry this Shield cannot read — an unknown target, operator or field, a bad shape — is skipped
 * and counted, and the others are kept in order; so is an id listed again (the first stands), and every entry beyond
 * the 50th. Only a member that is not a list, or whose JSON is over `bundleBytesMax` bytes, is ignored, as a member:
 * it never refuses the bundle. (The protocol's schema stays strict on the API's side; this is Shield's tolerance.)
 */
export function readPatches(value: unknown, ops: readonly string[] = PATCH_OPS): ReadPatches {
  if (!Array.isArray(value)) return { patches: [], skipped: 0, ignored: "patches is not a list" };
  let bytes: number;
  try {
    bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  } catch {
    return { patches: [], skipped: 0, ignored: "patches is not JSON" };
  }
  if (bytes > PATCH_LIMITS.bundleBytesMax) {
    return {
      patches: [],
      skipped: 0,
      ignored: `patches hold more than ${PATCH_LIMITS.bundleBytesMax} bytes of JSON together`,
    };
  }
  const patches: PatchInput[] = [];
  const ids = new Set<string>();
  let skipped = 0;
  for (let i = 0; i < value.length; i++) {
    const patch = patches.length < PATCH_LIMITS.perBundle ? readPatch(value[i], ops) : "beyond the limit";
    if (typeof patch === "string" || ids.has(patch.id)) {
      skipped += 1;
      continue;
    }
    ids.add(patch.id);
    patches.push(patch);
  }
  return { patches, skipped, ignored: null };
}

// --- Matcher: the protocol's `matchPatch`, by hand ---------------------------------------------------------------

const PERCENT = 37;
const PLUS = 43;
const SPACE = 32;
const TAB = 9;
const SLASH = 47;
/** Characters handed to `String.fromCharCode` at once. */
const CHUNK = 8192;

const lower = (code: number): number => (code >= 65 && code <= 90 ? code + 32 : code);

function hexValue(code: number): number {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 65 && code <= 70) return code - 55;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}

function fromCodes(codes: Uint16Array, written: number): string {
  let out = "";
  for (let at = 0; at < written; at += CHUNK) {
    out += String.fromCharCode.apply(null, codes.subarray(at, Math.min(written, at + CHUNK)) as unknown as number[]);
  }
  return out;
}

/** One pass of percent-decoding, byte by byte; with `plus`, `+` becomes a space. Returns `text` when unchanged. */
export function decodeOnce(text: string, plus: boolean): string {
  if (text.indexOf("%") === -1 && (!plus || text.indexOf("+") === -1)) return text;
  const length = text.length;
  const codes = new Uint16Array(length);
  let written = 0;
  for (let i = 0; i < length; i++) {
    const code = text.charCodeAt(i);
    if (code === PERCENT && i + 2 < length) {
      const high = hexValue(text.charCodeAt(i + 1));
      const low = high === -1 ? -1 : hexValue(text.charCodeAt(i + 2));
      if (low !== -1) {
        codes[written++] = high * 16 + low;
        i += 2;
        continue;
      }
    }
    codes[written++] = plus && code === PLUS ? SPACE : code;
  }
  return fromCodes(codes, written);
}

/** JSON `\uXXXX` escapes decoded, each to its UTF-16 code unit; a malformed escape stays. */
function decodeJsonEscapes(text: string): string {
  let at = text.indexOf("\\u");
  if (at === -1) return text;
  // From one `\u` to the next with the native `indexOf`; the text between is copied as a slice.
  const length = text.length;
  const parts: string[] = [];
  let copied = 0;
  while (at !== -1) {
    let value = 0;
    let k = 2;
    if (at + 5 < length) {
      for (; k < 6; k++) {
        const digit = hexValue(text.charCodeAt(at + k));
        if (digit === -1) break;
        value = value * 16 + digit;
      }
    }
    if (k === 6) {
      parts.push(text.slice(copied, at), String.fromCharCode(value));
      copied = at + 6;
      at = text.indexOf("\\u", copied);
    } else {
      at = text.indexOf("\\u", at + 1);
    }
  }
  parts.push(text.slice(copied));
  return parts.join("");
}

const cap = (text: string, max: number): string => (text.length > max ? text.slice(0, max) : text);

function trimOws(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && (text.charCodeAt(start) === SPACE || text.charCodeAt(start) === TAB)) start++;
  while (end > start && (text.charCodeAt(end - 1) === SPACE || text.charCodeAt(end - 1) === TAB)) end--;
  return start === 0 && end === text.length ? text : text.slice(start, end);
}

/** Whether `text` at `start` reads `needle` (already in lower case), ASCII letters folded. */
function readsAt(text: string, start: number, needle: string): boolean {
  for (let k = 0; k < needle.length; k++) if (lower(text.charCodeAt(start + k)) !== needle.charCodeAt(k)) return false;
  return true;
}

const equalsFolded = (text: string, needle: string): boolean =>
  text.length === needle.length && readsAt(text, 0, needle);

/** `text` with ASCII letters in lower case, nothing else changed; `text` itself when it has none. One pass. */
function fold(text: string): string {
  // Native and fast: when lower-casing changes nothing, there is no ASCII capital (it would have changed).
  if (text.toLowerCase() === text) return text;
  const length = text.length;
  const codes = new Uint16Array(length);
  for (let i = 0; i < length; i++) codes[i] = lower(text.charCodeAt(i));
  return fromCodes(codes, length);
}

/** A condition prepared once per bundle: folded value, `length_over` bound. */
export function prepareCondition(condition: Condition): PreparedCondition {
  const value = condition.value ?? "";
  // `json_key` looks for the value written as a JSON string literal.
  const needle = fold(condition.op === "json_key" ? JSON.stringify(value) : value);
  return Object.freeze({
    condition,
    needle,
    over: condition.op === "length_over" ? Number(value) : 0,
    foldedName: condition.target === "query_value" && condition.name !== undefined ? fold(condition.name) : null,
  });
}

/** The part of a bundle patch that matching reads, prepared once per bundle. */
export function preparePatch(patch: Pick<PatchInput, "methods" | "path" | "conditions">): MatchablePatch {
  const conditions = patch.conditions.map(prepareCondition);
  return Object.freeze({
    methods: patch.methods === undefined ? undefined : Object.freeze([...patch.methods]),
    path: patch.path,
    conditions: Object.freeze(conditions),
    bodyDependent: conditions.some((prepared) => prepared.condition.target === "body"),
  });
}

function compare(prepared: PreparedCondition, text: string): boolean {
  const { needle } = prepared;
  switch (prepared.condition.op) {
    case "equals":
      return text === needle;
    case "starts_with":
      return text.startsWith(needle);
    case "ends_with":
      return text.endsWith(needle);
    case "contains":
      return text.indexOf(needle) !== -1;
    case "json_key":
      return jsonKeyIn(text, needle);
    default:
      return false;
  }
}

/**
 * The strings a target offers (scanned forms, each distinct form once) and the lengths `length_over` measures
 * (whole fields). `undecodable`: a body in a character set not understood — every body condition holds (D-062).
 */
interface Candidates {
  readonly texts: readonly string[];
  readonly lengths: readonly number[];
  readonly undecodable?: boolean;
}

function test(prepared: PreparedCondition, candidates: Candidates): boolean {
  if (candidates.undecodable === true) return true;
  const op = prepared.condition.op;
  if (op === "present") return candidates.texts.length > 0;
  if (op === "length_over") {
    for (const length of candidates.lengths) if (length > prepared.over) return true;
    return false;
  }
  for (const text of candidates.texts) if (compare(prepared, text)) return true;
  return false;
}

interface QueryPair {
  /** The key before the first `=` when it differs from `rawKey` (older qs versions), else null. */
  readonly firstKey: string | null;
  readonly rawKey: string;
  readonly key: string;
  readonly rawValue: string;
  readonly value: string;
}

function parseQuery(query: string): QueryPair[] {
  const text = cap(query, PATCH_LIMITS.queryMax);
  const pairs: QueryPair[] = [];
  let start = 0;
  while (start <= text.length) {
    let end = text.indexOf("&", start);
    if (end === -1) end = text.length;
    if (end > start) {
      const segment = text.slice(start, end);
      // As qs splits: at `]=` when present (the `=` after the `]`), else at the first `=`.
      const bracket = segment.indexOf("]=");
      const equals = bracket === -1 ? segment.indexOf("=") : bracket + 1;
      const rawKey = equals === -1 ? segment : segment.slice(0, equals);
      const rawValue = equals === -1 ? "" : segment.slice(equals + 1);
      const first = bracket === -1 ? -1 : segment.indexOf("=");
      const firstKey = first !== -1 && first !== equals ? segment.slice(0, first) : null;
      pairs.push({ firstKey, rawKey, key: decodeOnce(rawKey, true), rawValue, value: decodeOnce(rawValue, true) });
    }
    start = end + 1;
  }
  return pairs;
}

const NONE: Candidates = Object.freeze({ texts: [], lengths: [] });
const UNDECODABLE: Candidates = Object.freeze({ texts: [], lengths: [], undecodable: true });

/** Adds the raw form, and the decoded form unless it is the same text (no form scanned twice), both folded. */
function pushDistinct(texts: string[], raw: string, decoded: string): void {
  texts.push(fold(raw));
  if (decoded !== raw) texts.push(fold(decoded));
}

/** What a patch is matched against: the protocol's `PatchRequest`. */
export interface PatchRequest {
  /** The method in upper case. */
  readonly method: string;
  /** The path decoded once, with empty, `.` and `..` segments resolved, without the query. */
  readonly path: string;
  /** The path as received, without the query. */
  readonly rawPath: string;
  /** The raw query string, without `?`. */
  readonly query: string;
  /** Header names in lower case. */
  readonly headers: Readonly<Record<string, unknown>>;
  /** The raw body when it was checked; absent or null when it was not. */
  readonly body?: Uint8Array | null;
}

/**
 * One request read lazily and shared by every patch: the query is split once, each header and target read once.
 * The body is read only when a body condition is evaluated with one.
 */
export class RequestView {
  readonly request: PatchRequest;
  #pairs: QueryPair[] | undefined;
  #path: Candidates | undefined;
  #queryKeys: Candidates | undefined;
  #headerNames: Candidates | undefined;
  #headers: Map<string, Candidates> | undefined;
  #values: Map<string | null, Candidates> | undefined;
  #body: Candidates | undefined;
  #bodyOf: Uint8Array | null | undefined;

  constructor(request: PatchRequest) {
    this.request = request;
  }

  #query(): QueryPair[] {
    this.#pairs ??= parseQuery(this.request.query);
    return this.#pairs;
  }

  /** The body is in a character set that cannot be read: its conditions count as holding (D-062). */
  undecodable(body: Uint8Array): boolean {
    if (this.#body === undefined || this.#bodyOf !== body) {
      this.#bodyOf = body;
      this.#body = readBody(body, contentTypeOf(this.request.headers));
    }
    return this.#body.undecodable === true;
  }

  candidates(prepared: PreparedCondition, body: Uint8Array | null | undefined): Candidates {
    const request = this.request;
    const condition = prepared.condition;
    switch (condition.target) {
      case "method":
        return { texts: [fold(request.method)], lengths: [request.method.length] };
      case "path": {
        if (this.#path === undefined) {
          const texts: string[] = [];
          pushDistinct(texts, cap(request.path, PATCH_LIMITS.pathMax), cap(request.rawPath, PATCH_LIMITS.pathMax));
          this.#path = { texts, lengths: [request.path.length, request.rawPath.length] };
        }
        return this.#path;
      }
      case "query_key": {
        if (this.#queryKeys === undefined) {
          const texts: string[] = [];
          for (const pair of this.#query()) {
            pushDistinct(texts, pair.rawKey, pair.key);
            if (pair.firstKey !== null) pushDistinct(texts, pair.firstKey, decodeOnce(pair.firstKey, true));
          }
          this.#queryKeys = { texts, lengths: texts.map((text) => text.length) };
        }
        return this.#queryKeys;
      }
      case "query_value": {
        const name = prepared.foldedName;
        this.#values ??= new Map();
        let found = this.#values.get(name);
        if (found === undefined) {
          const texts: string[] = [];
          for (const pair of this.#query()) {
            if (name !== null && !equalsFolded(pair.rawKey, name) && !equalsFolded(pair.key, name)) continue;
            pushDistinct(texts, pair.rawValue, pair.value);
          }
          found = { texts, lengths: texts.map((text) => text.length) };
          this.#values.set(name, found);
        }
        return found;
      }
      case "header_name": {
        if (this.#headerNames === undefined) {
          const names = Object.keys(request.headers);
          this.#headerNames = {
            texts: names.map((name) => fold(cap(name, PATCH_LIMITS.headerValueMax))),
            lengths: names.map((name) => name.length),
          };
        }
        return this.#headerNames;
      }
      case "header": {
        const name = condition.name ?? "";
        this.#headers ??= new Map();
        let found = this.#headers.get(name);
        if (found === undefined) {
          found = NONE;
          if (Object.hasOwn(request.headers, name)) {
            const value = request.headers[name];
            if (typeof value === "string") {
              const trimmed = trimOws(value);
              const scanned = cap(trimmed, PATCH_LIMITS.headerValueMax);
              const texts: string[] = [];
              pushDistinct(texts, scanned, decodeOnce(scanned, false));
              found = { texts, lengths: [trimmed.length] };
            }
          }
          this.#headers.set(name, found);
        }
        return found;
      }
      case "body": {
        if (this.#body === undefined || this.#bodyOf !== body) {
          this.#bodyOf = body;
          this.#body = readBody(body, contentTypeOf(request.headers));
        }
        return this.#body;
      }
    }
  }
}

/** The request's `content-type` value, read without the prototype chain; undefined without one. */
function contentTypeOf(headers: Readonly<Record<string, unknown>>): string | undefined {
  if (!Object.hasOwn(headers, "content-type")) return undefined;
  const value = headers["content-type"];
  return typeof value === "string" ? value : undefined;
}

/** The body's forms, each decoded form computed once and kept only when it differs (F8). */
function readBody(body: Uint8Array | null | undefined, contentType: string | undefined): Candidates {
  if (body === undefined || body === null || body.byteLength === 0) return NONE;
  const decoded = decodeBody(body, contentType);
  if (decoded === null) return UNDECODABLE;
  const texts: string[] = [];
  for (const text of decoded) {
    texts.push(fold(text));
    const percent = decodeOnce(text, false);
    if (percent !== text) texts.push(fold(percent));
    const escapes = decodeJsonEscapes(text);
    if (escapes !== text && escapes !== percent) texts.push(fold(escapes));
  }
  return { texts, lengths: [body.byteLength] };
}

// --- Body decoding (A6, F1): UTF-8, UTF-16LE/BE, UTF-32LE/BE by charset or byte order mark ------------------------

type BodyEncoding = "utf-8" | "utf-16le" | "utf-16be" | "utf-32le" | "utf-32be" | "latin1";

/**
 * The ASCII-compatible single-byte charsets, read as Latin-1 (one character per byte): every ASCII byte is the ASCII
 * character, so an ASCII pattern is found exactly where the application's decoder finds it. The names are those
 * iconv-lite 0.7 accepts for such charsets (IANA names and aliases, code page numbers), in its canonical form: lower
 * case, letters and digits only (`canonicalCharset`). A test checks each against iconv-lite.
 */
// biome-ignore format: a list of names, packed.
export const LATIN1_CHARSETS = Object.freeze([
  "437", "737", "775", "808", "850", "852", "855", "856", "857", "858", "860", "861", "862", "863", "865", "866",
  "869", "874", "922", "1046", "1124", "1125", "1129", "1133", "1161", "1162", "1163", "1250", "1251", "1252",
  "1253", "1254", "1255", "1256", "1257", "1258", "10000", "10006", "10007", "10029", "10079", "10081", "20866",
  "21866", "28591", "28592", "28593", "28594", "28595", "28596", "28597", "28598", "28599", "28600", "28601",
  "28603", "28604", "28605", "28606", "binary", "maccenteuro", "ibm808", "cp808", "mik", "cp720", "ascii8bit",
  "usascii", "ansix34", "ansix341968", "ansix341986", "csascii", "cp367", "ibm367", "isoir6", "iso646us",
  "iso646irv", "us", "latin1", "latin2", "latin3", "latin4", "latin5", "latin6", "latin7", "latin8", "latin9",
  "latin10", "csisolatin1", "csisolatin2", "csisolatin3", "csisolatin4", "csisolatincyrillic", "csisolatinarabic",
  "csisolatingreek", "csisolatinhebrew", "csisolatin5", "csisolatin6", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
  "l8", "l9", "l10", "isoir100", "isoir101", "isoir109", "isoir110", "isoir144", "isoir127", "isoir126", "isoir138",
  "isoir148", "isoir157", "isoir166", "isoir179", "isoir199", "isoir203", "isoir226", "cp819", "ibm819", "cyrillic",
  "arabic", "arabic8", "ecma114", "asmo708", "greek", "greek8", "ecma118", "elot928", "hebrew", "hebrew8",
  "iso88598i", "iso88598e", "turkish", "turkish8", "thai", "thai8", "celtic", "celtic8", "isoceltic", "tis6200",
  "tis62025291", "tis62025330", "cspc8codepage437", "cspc775baltic", "cspc850multilingual", "cspcp852",
  "cspc862latinhebrew", "cpgr", "msee", "mscyrl", "msansi", "msgreek", "msturk", "mshebr", "msarab", "winbaltrim",
  "cp20866", "ibm878", "cskoi8r", "cp21866", "ibm1168", "strk10482002", "cshproman8", "r8", "roman8", "xroman8",
  "ibm1051", "mac", "csmacintosh", "windows874", "win874", "cp874", "windows1250", "win1250", "cp1250",
  "windows1251", "win1251", "cp1251", "windows1252", "win1252", "cp1252", "windows1253", "win1253", "cp1253",
  "windows1254", "win1254", "cp1254", "windows1255", "win1255", "cp1255", "windows1256", "win1256", "cp1256",
  "windows1257", "win1257", "cp1257", "windows1258", "win1258", "cp1258", "iso88591", "cp28591", "iso88592",
  "cp28592", "iso88593", "cp28593", "iso88594", "cp28594", "iso88595", "cp28595", "iso88596", "cp28596", "iso88597",
  "cp28597", "iso88598", "cp28598", "iso88599", "cp28599", "iso885910", "cp28600", "iso885911", "cp28601",
  "iso885913", "cp28603", "iso885914", "cp28604", "iso885915", "cp28605", "iso885916", "cp28606", "cp437", "ibm437",
  "csibm437", "cp737", "ibm737", "csibm737", "cp775", "ibm775", "csibm775", "cp850", "ibm850", "csibm850", "cp852",
  "ibm852", "csibm852", "cp855", "ibm855", "csibm855", "cp856", "ibm856", "csibm856", "cp857", "ibm857", "csibm857",
  "cp858", "ibm858", "csibm858", "cp860", "ibm860", "csibm860", "cp861", "ibm861", "csibm861", "cp862", "ibm862",
  "csibm862", "cp863", "ibm863", "csibm863", "cp865", "ibm865", "csibm865", "cp866", "ibm866", "csibm866", "cp869",
  "ibm869", "csibm869", "cp922", "ibm922", "csibm922", "cp1046", "ibm1046", "csibm1046", "cp1124", "ibm1124",
  "csibm1124", "cp1125", "ibm1125", "csibm1125", "cp1129", "ibm1129", "csibm1129", "cp1133", "ibm1133", "csibm1133",
  "cp1161", "ibm1161", "csibm1161", "cp1162", "ibm1162", "csibm1162", "cp1163", "ibm1163", "csibm1163",
  "maccroatian", "maccyrillic", "macgreek", "maciceland", "macroman", "macromania", "macthai", "macturkish",
  "macukraine", "koi8r", "koi8u", "koi8ru", "koi8t", "armscii8", "rk1048", "georgianacademy", "georgianps", "pt154",
  "hproman8", "macintosh", "ascii", "tis620",
] as const);
const LATIN1_SET: ReadonlySet<string> = new Set(LATIN1_CHARSETS);

/** The Unicode charsets understood, in canonical form; `utf16`/`utf32` without an order read the byte order mark. */
const CHARSETS: Readonly<Record<string, BodyEncoding | "utf-16" | "utf-32">> = {
  "": "utf-8", // an empty `charset=`
  utf8: "utf-8",
  unicode11utf8: "utf-8",
  cesu8: "utf-8",
  utf16le: "utf-16le",
  ucs2: "utf-16le",
  utf16be: "utf-16be",
  utf16: "utf-16",
  utf32le: "utf-32le",
  ucs4le: "utf-32le",
  utf32be: "utf-32be",
  ucs4be: "utf-32be",
  utf32: "utf-32",
  ucs4: "utf-32",
};

const SEMI = 59;
const EQUALS = 61;
const DQUOTE = 34;
const BSLASH = 92;

const skipOws = (text: string, from: number): number => {
  let index = from;
  while (index < text.length && (text.charCodeAt(index) === SPACE || text.charCodeAt(index) === TAB)) index++;
  return index;
};
const skipValue = (text: string, from: number): number => {
  const next = text.indexOf(";", from);
  return next === -1 ? text.length : next;
};
const trimEnd = (text: string, start: number, from: number): number => {
  let end = from;
  while (end > start && (text.charCodeAt(end - 1) === SPACE || text.charCodeAt(end - 1) === TAB)) end--;
  return end;
};

/**
 * The `charset` parameter of a content-type value in lower case, as body-parser 2 reads it
 * (`contentType.parse(header).parameters.charset?.toLowerCase()`, content-type 2.x, whose parameter parser this
 * repeats by hand): parameter names without regard to case, the first `charset` wins, a quoted value with backslash
 * escapes in which `;` is no separator, an unterminated quoted value is no parameter. Undefined without one. A test
 * checks it against content-type on generated headers. No regular expression.
 */
export function charsetOfContentType(header: string): string | undefined {
  const length = header.length;
  let charset: string | undefined;
  const keep = (key: string, value: string): void => {
    if (charset === undefined && key === "charset") charset = value;
  };
  let index = skipValue(header, skipOws(header, 0));
  parameter: while (index < length) {
    index = skipOws(header, index + 1); // past the `;`
    const keyStart = index;
    while (index < length) {
      const code = header.charCodeAt(index);
      if (code === SEMI) continue parameter;
      if (code === EQUALS) {
        const key = header.slice(keyStart, trimEnd(header, keyStart, index)).toLowerCase();
        index = skipOws(header, index + 1);
        if (index < length && header.charCodeAt(index) === DQUOTE) {
          index++;
          let value = "";
          while (index < length) {
            const quoted = header.charCodeAt(index++);
            if (quoted === DQUOTE) {
              index = skipValue(header, index);
              keep(key, value);
              break;
            }
            if (quoted === BSLASH && index < length) {
              value += header[index++];
              continue;
            }
            value += String.fromCharCode(quoted);
          }
          continue parameter;
        }
        const valueStart = index;
        index = skipValue(header, index);
        keep(key, header.slice(valueStart, trimEnd(header, valueStart, index)));
        continue parameter;
      }
      index++;
    }
  }
  return charset === undefined ? undefined : (charset as string).toLowerCase();
}

/**
 * A charset name as iconv-lite canonicalises it: lower case, a trailing `:` and four digits (a year) dropped, every
 * character that is not a letter or a digit dropped. By hand: no regular expression.
 */
function canonicalCharset(name: string): string {
  let text = name;
  const colon = text.length - 5;
  if (colon >= 0 && text.charCodeAt(colon) === 58) {
    let digits = true;
    for (let i = colon + 1; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code < 48 || code > 57) digits = false;
    }
    if (digits) text = text.slice(0, colon);
  }
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if ((code >= 48 && code <= 57) || (code >= 97 && code <= 122)) out += text[i];
  }
  return out;
}

/**
 * The encodings a body is read in: by charset, else by its byte order mark, else UTF-8. `utf-16` and `utf-32`
 * without a byte order mark give both byte orders (A11, H1: the application's decoder guesses, so a match in either
 * counts). Null for a charset not understood.
 */
function encodingsOf(charset: string | undefined, body: Uint8Array): BodyEncoding[] | null {
  const b0 = body[0];
  const b1 = body[1];
  const le32 = b0 === 0xff && b1 === 0xfe && body[2] === 0 && body[3] === 0;
  const be32 = b0 === 0 && b1 === 0 && body[2] === 0xfe && body[3] === 0xff;
  const le16 = b0 === 0xff && b1 === 0xfe;
  const be16 = b0 === 0xfe && b1 === 0xff;
  if (charset !== undefined) {
    const name = canonicalCharset(charset);
    if (LATIN1_SET.has(name)) return ["latin1"];
    if (!Object.hasOwn(CHARSETS, name)) return null;
    const named = CHARSETS[name] as BodyEncoding | "utf-16" | "utf-32";
    if (named === "utf-16") return be16 ? ["utf-16be"] : le16 ? ["utf-16le"] : ["utf-16le", "utf-16be"];
    if (named === "utf-32") return be32 ? ["utf-32be"] : le32 ? ["utf-32le"] : ["utf-32le", "utf-32be"];
    return [named];
  }
  // A byte order mark alone: also read as UTF-8, so that a mark put in front of a UTF-8 body hides nothing.
  if (le32) return ["utf-32le", "utf-8"];
  if (be32) return ["utf-32be", "utf-8"];
  if (le16) return ["utf-16le", "utf-8"];
  if (be16) return ["utf-16be", "utf-8"];
  return ["utf-8"];
}

const REPLACEMENT = 0xfffd;

/** UTF-16 by hand: code units as they are (a mark at the start dropped), an odd last byte as U+FFFD. */
function decodeUtf16(body: Uint8Array, big: boolean): string {
  let at = (big ? body[0] === 0xfe && body[1] === 0xff : body[0] === 0xff && body[1] === 0xfe) ? 2 : 0;
  const units = new Uint16Array(((body.length - at) >> 1) + 1);
  let written = 0;
  for (; at + 1 < body.length; at += 2) {
    units[written++] = big
      ? ((body[at] as number) << 8) | (body[at + 1] as number)
      : (body[at] as number) | ((body[at + 1] as number) << 8);
  }
  if (at < body.length) units[written++] = REPLACEMENT;
  return fromCodes(units, written);
}

/**
 * UTF-32 by hand: each code point to UTF-16 (a mark at the start dropped); a value above U+10FFFF, a surrogate, or
 * 1–3 trailing bytes become U+FFFD.
 */
function decodeUtf32(body: Uint8Array, big: boolean): string {
  const marked = big
    ? body[0] === 0 && body[1] === 0 && body[2] === 0xfe && body[3] === 0xff
    : body[0] === 0xff && body[1] === 0xfe && body[2] === 0 && body[3] === 0;
  let at = marked ? 4 : 0;
  const units = new Uint16Array(((body.length - at) >> 1) + 2);
  let written = 0;
  for (; at + 3 < body.length; at += 4) {
    const point = big
      ? (((body[at] as number) << 24) |
          ((body[at + 1] as number) << 16) |
          ((body[at + 2] as number) << 8) |
          (body[at + 3] as number)) >>>
        0
      : ((body[at] as number) |
          ((body[at + 1] as number) << 8) |
          ((body[at + 2] as number) << 16) |
          ((body[at + 3] as number) << 24)) >>>
        0;
    if (point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) {
      units[written++] = REPLACEMENT;
    } else if (point > 0xffff) {
      const offset = point - 0x10000;
      units[written++] = 0xd800 + (offset >> 10);
      units[written++] = 0xdc00 + (offset & 0x3ff);
    } else {
      units[written++] = point;
    }
  }
  if (at < body.length) units[written++] = REPLACEMENT;
  return fromCodes(units, written);
}

function decodeAs(body: Uint8Array, encoding: BodyEncoding): string {
  if (encoding === "latin1") return decodeLatin1(body);
  if (encoding === "utf-16le") return decodeUtf16(body, false);
  if (encoding === "utf-16be") return decodeUtf16(body, true);
  if (encoding === "utf-32le") return decodeUtf32(body, false);
  if (encoding === "utf-32be") return decodeUtf32(body, true);
  return new TextDecoder("utf-8").decode(body);
}

/** The body as text in each encoding it is read in; null when its character set is not understood. */
function decodeBody(body: Uint8Array, contentType: string | undefined): string[] | null {
  const encodings = encodingsOf(contentType === undefined ? undefined : charsetOfContentType(contentType), body);
  return encodings === null ? null : encodings.map((encoding) => decodeAs(body, encoding));
}

/** JSON whitespace: space, tab, line feed, carriage return. */
const isJsonSpace = (code: number): boolean => code === 32 || code === 9 || code === 10 || code === 13;

/** Latin-1: each byte its own character. */
function decodeLatin1(body: Uint8Array): string {
  const codes = new Uint16Array(body.length);
  codes.set(body);
  return fromCodes(codes, body.length);
}

/**
 * `json_key` on a folded text: each occurrence of `needle` (the quoted name) found with `indexOf`, the following JSON
 * whitespace skipped and a `:` looked for. At most the text's length × the needle's length; a run of whitespace
 * follows at most one occurrence (an occurrence ends with `"`), so the skipping adds at most the text's length.
 */
function jsonKeyIn(text: string, needle: string): boolean {
  let at = text.indexOf(needle);
  while (at !== -1) {
    let j = at + needle.length;
    while (j < text.length && isJsonSpace(text.charCodeAt(j))) j++;
    if (j < text.length && text.charCodeAt(j) === 58) return true;
    at = text.indexOf(needle, at + 1);
  }
  return false;
}

/** The segments of a path, one trailing slash ignored; null when it does not start with `/`. */
function segmentsOf(path: string): string[] | null {
  if (path.charCodeAt(0) !== SLASH) return null;
  const end = path.length > 1 && path.charCodeAt(path.length - 1) === SLASH ? path.length - 1 : path.length;
  return end <= 1 ? [] : path.slice(1, end).split("/");
}

/** The protocol's `matchGlob`: `*` one non-empty segment, a final `**` zero or more, literals without case. */
function matchGlob(pattern: string, path: string): boolean {
  const segments = segmentsOf(path);
  if (segments === null) return false;
  const parts = pattern === "/" ? [] : pattern.slice(1).split("/");
  const rest = parts[parts.length - 1] === "**";
  const fixed = rest ? parts.length - 1 : parts.length;
  if (segments.length < fixed || (segments.length > fixed && !rest)) return false;
  for (let i = 0; i < fixed; i++) {
    const part = parts[i] as string;
    const segment = segments[i] as string;
    if (part === "*") {
      if (segment.length === 0) return false;
    } else if (!equalsFolded(segment, part.toLowerCase())) {
      return false;
    }
  }
  return true;
}

function matchMethods(methods: readonly string[] | undefined, method: string): boolean {
  if (methods === undefined || methods.length === 0) return true;
  for (const listed of methods) if (listed === method || (method === "HEAD" && listed === "GET")) return true;
  return false;
}

export interface PatchMatch {
  readonly matched: boolean;
  readonly bodyPending: boolean;
  /** Present, and true, only when `matched` rests on a body in a character set that cannot be read (D-062). */
  readonly undecodable?: true;
}

const MISS: PatchMatch = Object.freeze({ matched: false, bodyPending: false });
const MATCHED: PatchMatch = Object.freeze({ matched: true, bodyPending: false });
const PENDING: PatchMatch = Object.freeze({ matched: false, bodyPending: true });
const UNREADABLE: PatchMatch = Object.freeze({ matched: true, bodyPending: false, undecodable: true });

/**
 * The protocol's `matchPatch` on a prepared patch, with the request read through `view` (shared by the patches of
 * one request). `body` is the checked body, or undefined/null when it was not checked: then a body-dependent patch
 * whose other conditions hold is pending. Pure; time linear in the scanned input per condition.
 */
export function matchPatch(patch: MatchablePatch, view: RequestView, body?: Uint8Array | null): PatchMatch {
  const request = view.request;
  if (!matchMethods(patch.methods, request.method)) return MISS;
  if (
    patch.path !== undefined &&
    !matchGlob(patch.path, cap(request.path, PATCH_LIMITS.pathMax)) &&
    !matchGlob(patch.path, cap(request.rawPath, PATCH_LIMITS.pathMax))
  ) {
    return MISS;
  }
  for (const prepared of patch.conditions) {
    if (prepared.condition.target === "body") continue;
    if (!test(prepared, view.candidates(prepared, body))) return MISS;
  }
  if (!patch.bodyDependent) return MATCHED;
  if (body === undefined || body === null) return PENDING;
  if (!matchBody(patch, view, body)) return MISS;
  return view.undecodable(body) ? UNREADABLE : MATCHED;
}

/** Whether every body condition of `patch` holds on `body` (the other conditions already held). */
export function matchBody(patch: MatchablePatch, view: RequestView, body: Uint8Array): boolean {
  for (const prepared of patch.conditions) {
    if (prepared.condition.target === "body" && !test(prepared, view.candidates(prepared, body))) return false;
  }
  return true;
}

/** `scheme://authority` at the start of a request target in absolute form. */
const ABSOLUTE_FORM = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/;

/**
 * The request as a patch reads it, without the body: the target (`originalUrl`, else `url`) split as the protocol's
 * `patchRequestOf` splits a reference target — fragment dropped, path before `?`, query after — and the path decoded
 * once with empty, `.` and `..` segments resolved, never above the root. A target in absolute form loses its
 * `scheme://authority`. Header values are read as Node gives them.
 */
export function patchRequestOf(request: IncomingMessage, method: string): PatchRequest {
  const original = (request as IncomingMessage & { originalUrl?: unknown }).originalUrl;
  const url = typeof original === "string" ? original : typeof request.url === "string" ? request.url : "";
  let target = url;
  if (target.length > 0 && target.charCodeAt(0) !== SLASH) {
    // Only a target that is not origin-form pays for the regular expression, on the target's scheme and authority.
    const absolute = ABSOLUTE_FORM.exec(target);
    if (absolute !== null) target = target.slice(absolute[0].length) || "/";
  }
  const hash = target.indexOf("#");
  if (hash !== -1) target = target.slice(0, hash);
  const question = target.indexOf("?");
  const rawPath = question === -1 ? target : target.slice(0, question);
  const query = question === -1 ? "" : target.slice(question + 1);
  return {
    method,
    path: resolvePath(rawPath),
    rawPath,
    query,
    headers: (request.headers ?? {}) as Readonly<Record<string, unknown>>,
  };
}

/** The protocol's resolution of a reference path: decoded once (no `+`), empty, `.` and `..` segments resolved. */
function resolvePath(rawPath: string): string {
  const resolved: string[] = [];
  for (const segment of decodeOnce(rawPath, false).split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") resolved.pop();
    else resolved.push(segment);
  }
  return `/${resolved.join("/")}`;
}

// --- Per request: decision time, the body hook, and what the Event records ----------------------------------------

/** What a patch decision records about its body condition (`decision.patch_body`). */
export type PatchBody = "checked" | "unchecked" | "undecodable";

/** The patches of one request: evaluated when it arrives, completed by the body hook, read when it closes. */
export interface PatchState {
  /** The enforced patch that refused the request (when it arrived, or in the body hook), or null. */
  blocked: AppliedPatch | null;
  /** `undecodable` when `blocked` (or `monitor`) rests on a body that could not be read (D-062), else `checked`. */
  blockedBody: PatchBody;
  monitorBody: PatchBody;
  /** The first patch in bundle order, in monitor, whose every condition held (the body's included), or null. */
  monitor: AppliedPatch | null;
  monitorIndex: number;
  /** Body-dependent patches whose other conditions held, in bundle order, waiting for the body. */
  readonly pending: { readonly patch: AppliedPatch; readonly index: number }[];
  /** The body hook compared the body with the pending patches. */
  bodyChecked: boolean;
  readonly view: RequestView;
}

const EMPTY_BODY = new Uint8Array(0);

export interface PatchChecker {
  /**
   * Evaluates the patches of `policy` on `request` when it arrives; null when the Policy has none. `hasBody` false
   * means the body is known to be empty: body conditions are then checked at once (and fail). `recordMonitor` false:
   * something before the patches already decided, so only an enforced patch can still change the outcome.
   */
  evaluate(
    policy: AppliedPolicy,
    request: IncomingMessage,
    method: string,
    hasBody: boolean,
    recordMonitor: boolean,
  ): PatchState | null;
  /**
   * The body hook: compares the body bytes with the request's pending patches, once, whatever the media type. True
   * when an enforced patch matched: the caller refuses the request.
   */
  verifyBody(request: IncomingMessage, body: unknown): boolean;
}

/**
 * What the Event of a request records of its patches, when nothing before them decided; null for nothing. A patch
 * whose body was never checked did not block: it is recorded as allow in monitor (A6, F2), whatever its mode.
 */
export function recordedPatch(
  state: PatchState,
): { patch: AppliedPatch; body: PatchBody; decision: AppliedPatch["decision"] } | null {
  if (state.monitor !== null) {
    // A body that could not be read was not compared: recorded with the patch, as allow in monitor (A11, M2).
    return state.monitorBody === "undecodable"
      ? { patch: state.monitor, body: "undecodable", decision: state.monitor.uncheckedDecision }
      : { patch: state.monitor, body: "checked", decision: state.monitor.decision };
  }
  const first = state.pending[0];
  if (!state.bodyChecked && first !== undefined) {
    return { patch: first.patch, body: "unchecked", decision: first.patch.uncheckedDecision };
  }
  return null;
}

export function createPatchChecker(): PatchChecker {
  const states = new WeakMap<IncomingMessage, PatchState>();
  return {
    evaluate(policy, request, method, hasBody, recordMonitor) {
      const patches = policy.patches;
      if (patches.length === 0) return null;
      const view = new RequestView(patchRequestOf(request, method));
      const body = hasBody ? undefined : EMPTY_BODY;
      const state: PatchState = {
        blocked: null,
        blockedBody: "checked",
        monitorBody: "checked",
        monitor: null,
        monitorIndex: -1,
        pending: [],
        bodyChecked: !hasBody,
        view,
      };
      for (let i = 0; i < patches.length; i++) {
        const patch = patches[i] as AppliedPatch;
        // A monitor patch can only be recorded if nothing decided yet and no earlier monitor patch matched.
        if (patch.mode === "monitor" && (!recordMonitor || state.monitor !== null)) continue;
        const result = matchPatch(patch, view, body);
        if (result.matched) {
          if (patch.mode === "enforce") {
            state.blocked = patch;
            break;
          }
          state.monitor = patch;
          state.monitorIndex = i;
        } else if (result.bodyPending) {
          state.pending.push({ patch, index: i });
        }
      }
      if (state.blocked === null && state.pending.length > 0) states.set(request, state);
      return state;
    },
    verifyBody(request, body) {
      if (typeof request !== "object" || request === null) return false;
      const state = states.get(request);
      if (state === undefined || state.bodyChecked || state.blocked !== null) return false;
      if (!(body instanceof Uint8Array)) return false;
      state.bodyChecked = true;
      for (const { patch, index } of state.pending) {
        if (patch.mode === "monitor" && state.monitor !== null && state.monitorIndex < index) continue;
        if (!matchBody(patch, state.view, body)) continue;
        const read: PatchBody = state.view.undecodable(body) ? "undecodable" : "checked";
        if (patch.mode === "enforce") {
          state.blocked = patch;
          state.blockedBody = read;
          return true;
        }
        state.monitor = patch;
        state.monitorIndex = index;
        state.monitorBody = read;
      }
      return false;
    },
  };
}
