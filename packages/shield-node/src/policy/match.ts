// Path patterns of Rules: compiling one, and matching a request path against it.
//
// The grammar is `PATH_PATTERN` of the protocol package (test/match.test.ts pins the agreement): a pattern starts
// with `/`; its segments are literal text over `A-Z a-z 0-9 . _ ~ -`, or `*` (exactly one segment), or, as the
// last segment only, `**` (zero or more segments).
//
// A path has more than one reading. The router of the application reads the text: `/api/%61dmin` and
// `/api/x/../admin` are not `/api/admin` to Express. But a middleware mounted after Shield may read it otherwise:
// `express.static` percent-decodes the path, resolves `.` and `..` and collapses empty segments before it opens a
// file, so `/files/%70rivate/x` is `/files/private/x` to it. Shield cannot know which reading the application acts
// on, so `decide` matches every reading: the text, and the canonical forms of `canonicalPaths` (decoded zero to
// three times, dot segments resolved, a backslash read as text and as a separator). A Rule matches when any form
// matches. That only ever adds matches: what the text alone matched still matches.
//
// Nothing here builds a regular expression from a pattern. Each form is split into segments once per request
// (`splitPath`), and every Rule compares its segments against that shared split: a `*` costs one comparison
// whatever the length of the segment, so the cost of a Decision is linear in the length of the path plus, per
// Rule, the segments it compares.

/** Characters of a pattern at most. Equal to `POLICY_LIMITS.pathMax` of the protocol. */
export const PATTERN_MAX = 256;

const SLASH = 47;
const PERCENT = 37;
const BACKSLASH = 92;
const DOT = 46;
const LITERAL = /^[A-Za-z0-9._~-]+$/;
/** `scheme://authority` at the start of a request target in absolute form. */
const ABSOLUTE_FORM = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/;

export interface PathPattern {
  /** The segments in order: literal text in lower case, or null for `*`. */
  readonly segments: readonly (string | null)[];
  /** The pattern ends in `**`: whatever follows the segments matches. */
  readonly rest: boolean;
}

/** The compiled form of a path pattern, or null when the text is not a pattern. Never throws. */
export function compilePattern(pattern: unknown): PathPattern | null {
  if (typeof pattern !== "string") return null;
  if (pattern.length < 1 || pattern.length > PATTERN_MAX || pattern.charCodeAt(0) !== SLASH) return null;
  if (pattern === "/") return { segments: [], rest: false };
  const parts = pattern.slice(1).split("/");
  const segments: (string | null)[] = [];
  let rest = false;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] as string;
    if (part === "**") {
      if (i !== parts.length - 1) return null;
      rest = true;
    } else if (part === "*") {
      segments.push(null);
    } else if (LITERAL.test(part)) {
      segments.push(part.toLowerCase());
    } else {
      return null;
    }
  }
  return { segments, rest };
}

/**
 * The part of a request target that Rules are matched against: without the query string (and without a
 * fragment, which a client may send although it should not), without `scheme://authority` of a target in
 * absolute form, and without one trailing slash. Text that is not a path comes back as it is and matches nothing.
 */
export function normalisePath(target: string): string {
  let start = 0;
  let end = target.length;
  let root = false;
  if (end > 0 && target.charCodeAt(0) !== SLASH) {
    const absolute = ABSOLUTE_FORM.exec(target);
    if (absolute !== null) {
      start = absolute[0].length;
      root = true; // `http://host` and `http://host?x` name the root
    }
  }
  for (let i = start; i < end; i++) {
    const code = target.charCodeAt(i);
    if (code === 63 || code === 35) {
      end = i; // `?` or `#`
      break;
    }
  }
  if (root && start === end) return "/";
  if (end - start > 1 && target.charCodeAt(end - 1) === SLASH) end -= 1;
  return start === 0 && end === target.length ? target : target.slice(start, end);
}

/**
 * Segments of a path recorded at most. A pattern has at most 128 segments (256 characters), so a path with more
 * than this many can only match a pattern ending in `**`, and only its first segments are ever compared.
 */
const SEGMENTS_MAX = 130;

/**
 * A path split into its segments: segment `i` is `text.slice(starts[i], ends[i])`. Built once per form of a request
 * path and shared by every Rule. The root `/` has no segments; `/a/` has two, the second empty. `more` says that
 * the path has segments beyond the `SEGMENTS_MAX` recorded.
 */
export interface SplitPath {
  readonly text: string;
  readonly starts: readonly number[];
  readonly ends: readonly number[];
  readonly more: boolean;
}

/** The segments of `path`, or null when it is not a path (it does not start with `/`). One pass, no substrings. */
export function splitPath(path: string): SplitPath | null {
  return scan(path)?.split ?? null;
}

/**
 * One pass over a path: its segments (the first `SEGMENTS_MAX`), and whether every reading of it is the text —
 * no `%`, no `\`, no empty, `.` or `..` segment (so no trailing slash either).
 */
function scan(path: string): { split: SplitPath; canonical: boolean } | null {
  const length = path.length;
  if (length === 0 || path.charCodeAt(0) !== SLASH) return null;
  const starts: number[] = [];
  const ends: number[] = [];
  let more = false;
  let canonical = true;
  if (length > 1) {
    let start = 1;
    for (let i = 1; i <= length; i++) {
      const code = i === length ? SLASH : path.charCodeAt(i);
      if (code === PERCENT || code === BACKSLASH) {
        canonical = false;
      } else if (code === SLASH) {
        const size = i - start;
        if (
          size === 0 ||
          (path.charCodeAt(start) === DOT && (size === 1 || (size === 2 && path.charCodeAt(start + 1) === DOT)))
        ) {
          canonical = false;
        }
        if (starts.length < SEGMENTS_MAX) {
          starts.push(start);
          ends.push(i);
        } else {
          more = true;
        }
        start = i + 1;
      }
    }
  }
  return { split: { text: path, starts, ends, more }, canonical };
}

/**
 * Whether a split path matches the pattern. ASCII letters match without regard to case; every other character
 * matches only itself. A `*` is one segment that is not empty, checked by its length alone; a literal is compared
 * only when the lengths agree. No allocation.
 */
export function matchSplit(pattern: PathPattern, split: SplitPath): boolean {
  const segments = pattern.segments;
  const count = split.starts.length;
  if (count < segments.length) return false; // the pattern wants another segment
  if ((count > segments.length || split.more) && !pattern.rest) return false;
  const text = split.text;
  for (let s = 0; s < segments.length; s++) {
    const start = split.starts[s] as number;
    const size = (split.ends[s] as number) - start;
    const literal = segments[s] as string | null;
    if (literal === null) {
      if (size === 0) return false; // `*` is one segment that is not empty
      continue;
    }
    if (size !== literal.length) return false; // `/admin` is not `/administrator`
    for (let k = 0; k < size; k++) {
      let code = text.charCodeAt(start + k);
      if (code >= 65 && code <= 90) code += 32; // A-Z
      if (code !== literal.charCodeAt(k)) return false;
    }
  }
  return true;
}

/** Whether `path` — already through `normalisePath` — matches the pattern, read as text. */
export function matchPath(pattern: PathPattern, path: string): boolean {
  const split = splitPath(path);
  return split !== null && matchSplit(pattern, split);
}

/** Rounds of percent-decoding at most: enough for double and triple encoding, bounded whatever the input. */
const DECODE_ROUNDS = 3;
/** Characters handed to `String.fromCharCode` at once: well below the argument limit of any engine. */
const CHUNK = 8_192;

function hexValue(code: number): number {
  if (code >= 48 && code <= 57) return code - 48; // 0-9
  if (code >= 65 && code <= 70) return code - 55; // A-F
  if (code >= 97 && code <= 102) return code - 87; // a-f
  return -1;
}

/**
 * One round of percent-decoding: every `%XX` becomes the character of that byte value, `%2F` and `%5C` included.
 * A malformed sequence stays as it is. Bytes are not assembled into UTF-8: a pattern is ASCII, so a byte of 0x80 or
 * more can only ever be "a character that is not a separator, not a dot and not a letter" — which it stays.
 * Returns `text` itself when nothing was decoded.
 */
function decodeOnce(text: string): string {
  const first = text.indexOf("%");
  if (first === -1) return text;
  const length = text.length;
  let codes: Uint16Array | undefined;
  let written = 0;
  for (let i = first; i < length; i++) {
    const code = text.charCodeAt(i);
    if (code === PERCENT && i + 2 < length) {
      const high = hexValue(text.charCodeAt(i + 1));
      const low = high === -1 ? -1 : hexValue(text.charCodeAt(i + 2));
      if (low !== -1) {
        if (codes === undefined) {
          codes = new Uint16Array(length);
          for (let k = 0; k < i; k++) codes[k] = text.charCodeAt(k);
          written = i;
        }
        codes[written++] = high * 16 + low;
        i += 2;
        continue;
      }
    }
    if (codes !== undefined) codes[written++] = code;
  }
  if (codes === undefined) return text;
  let out = "";
  for (let at = 0; at < written; at += CHUNK) {
    out += String.fromCharCode.apply(null, codes.subarray(at, Math.min(written, at + CHUNK)) as unknown as number[]);
  }
  return out;
}

/**
 * `text` with empty segments collapsed and `.` and `..` resolved, never above the root, as the segments of `text`
 * that remain: nothing is copied. With `backslash`, a `\` separates segments as `/` does. Null when the text does
 * not start with a separator.
 */
function resolveSplit(text: string, backslash: boolean): SplitPath | null {
  const length = text.length;
  const other = backslash ? BACKSLASH : SLASH; // the second separator, if any
  const lead = text.charCodeAt(0);
  if (length === 0 || (lead !== SLASH && lead !== other)) return null;
  const starts: number[] = [];
  const ends: number[] = [];
  let i = 0;
  while (i < length) {
    let code = text.charCodeAt(i);
    while (code === SLASH || code === other) code = ++i < length ? text.charCodeAt(i) : -1;
    const start = i;
    while (i < length && code !== SLASH && code !== other) code = ++i < length ? text.charCodeAt(i) : -1;
    const size = i - start;
    if (size === 0) break;
    if (text.charCodeAt(start) === DOT && (size === 1 || (size === 2 && text.charCodeAt(start + 1) === DOT))) {
      if (size === 2) {
        starts.pop(); // `..` at the root stays at the root
        ends.pop();
      }
      continue;
    }
    starts.push(start);
    ends.push(i);
  }
  return { text, starts, ends, more: false };
}

/**
 * Every form of `path` (already through `normalisePath`) that Rules are matched against, each split once: the text
 * first, then its canonical forms in a fixed order — for the text decoded 0, 1, 2 and 3 times (fewer once decoding
 * changes nothing), the resolved form with `\` as text, then with `\` as a separator. A path that reads the same
 * in every form — the common case — has the text alone. Empty for text that is not a path. Never throws.
 *
 * Each decoding depth is a form of its own because the middleware that serves the request decodes a fixed number
 * of times — `send` once — and a form decoded further can climb out of the directory the once-decoded form stays
 * in. For the same reason a backslash is read both ways. Forms may repeat; a repeat matches as its twin does.
 */
export function pathForms(path: string): SplitPath[] {
  const scanned = scan(path);
  if (scanned === null) return [];
  if (scanned.canonical) return [scanned.split];
  const forms = [scanned.split];
  let decoded = path;
  for (let round = 0; round <= DECODE_ROUNDS; round++) {
    if (round > 0) {
      const next = decodeOnce(decoded);
      if (next === decoded) break;
      decoded = next;
    }
    const resolved = resolveSplit(decoded, false);
    if (resolved !== null) forms.push(resolved);
    if (decoded.indexOf("\\") !== -1) {
      const separated = resolveSplit(decoded, true);
      if (separated !== null) forms.push(separated);
    }
  }
  return forms;
}

/** Whether any of the forms matches the pattern. */
export function matchForms(pattern: PathPattern, forms: readonly SplitPath[]): boolean {
  for (let i = 0; i < forms.length; i++) if (matchSplit(pattern, forms[i] as SplitPath)) return true;
  return false;
}

/**
 * The canonical forms of `path` as text, without the text itself and without repeats, in the order of `pathForms`.
 * For tests and diagnostics: `decide` matches the split forms and never builds these strings.
 */
export function canonicalPaths(path: string): string[] {
  const texts: string[] = [];
  const forms = pathForms(path);
  for (let f = 1; f < forms.length; f++) {
    const form = forms[f] as SplitPath;
    let text = "";
    for (let s = 0; s < form.starts.length; s++) text += `/${form.text.slice(form.starts[s], form.ends[s])}`;
    if (text === "") text = "/";
    if (text !== path && !texts.includes(text)) texts.push(text);
  }
  return texts;
}

/**
 * Whether a Rule with these methods applies to `method`: an empty list is every method, otherwise an exact match —
 * and `HEAD` also matches a list with `GET`, because Express answers HEAD with the GET handler (review F2).
 */
export function matchMethod(methods: readonly string[], method: string): boolean {
  if (methods.length === 0) return true;
  const head = method === "HEAD";
  for (let i = 0; i < methods.length; i++) {
    const listed = methods[i];
    if (listed === method || (head && listed === "GET")) return true;
  }
  return false;
}
