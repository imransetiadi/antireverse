// The integrity collector (slice 21b): reads the markers Harden planted (`{ b: Build id, f: [paths] }` under
// `globalThis[Symbol.for("ar.build")]`), finds their files among the scripts the page loaded from its own origin
// and hashes them. Only `{ build, files: [{ i, h }], skipped }` leaves this module. Nothing here throws or rejects.
import { INTEGRITY, PATTERNS } from "./constants.js";
import { sha256 } from "./crypto.js";

/** @typedef {{ i: number, url: string, size: number }} PlannedFile `size` is Infinity when the file must not be fetched. */
/** @typedef {{ build: string, files: { i: number, h: string }[], skipped: number }} Report */
/** @typedef {{ aborted: boolean, cancel?: (() => void) | undefined }} Job A collection; `cancel` ends its request in flight. */
/** @typedef {{ url: string, path: string, size: number, listed: boolean, loaded: boolean }} Script */

/** A JavaScript MIME type (parameters ignored). */
const SCRIPT_MIME = /^\s*(text|application)\/(x-)?(java|ecma)script\s*(;|$)/i;

/** The `type` of a script element the browser runs: none, a JavaScript MIME type or "module". */
const SCRIPT_TYPE = /^\s*(module|(text|application)\/(x-)?(java|ecma)script)?\s*$/i;

/** The page-wide claims: the Builds (as `appId/build`) some Guard on this page is collecting or has collected. */
function claims() {
  const page = /** @type {Record<symbol, Record<string, unknown>>} */ (/** @type {unknown} */ (globalThis));
  const key = Symbol.for(INTEGRITY.storageKey);
  try {
    if (typeof page[key] !== "object" || page[key] === null) page[key] = Object.create(null);
    return page[key];
  } catch {
    return Object.create(null);
  }
}

/**
 * The same-origin scripts the page loaded. A URL counts when Resource Timing lists it as loaded by a script, or
 * when a `<script src>` that the browser runs (see SCRIPT_TYPE) or a `<link rel=modulepreload>` names it and
 * Resource Timing has an entry for it: proof that the browser itself requested it. An element without an entry
 * counts only where Resource Timing is missing, or as not fetchable (size Infinity) when its buffer may be full.
 * Each source stands alone and reads at most `scanMax` values; a URL over `urlMax` characters is passed over.
 * Paths are decoded segment by segment. The scripts are returned by file name (the last path segment).
 * @returns {Map<string, Script[]>}
 */
function pageScripts() {
  /** @type {Map<string, Script>} */
  const found = new Map();
  /** What a value read before came to: each distinct value is parsed once. */
  /** @type {Map<string, Script | undefined>} */
  const read = new Map();
  let left = 0;
  /** @type {(value: unknown) => Script | undefined} */
  const add = (value) => {
    left -= 1;
    if (typeof value !== "string" || value === "" || value.length > INTEGRITY.urlMax) return;
    if (read.has(value)) return read.get(value);
    read.set(value, undefined);
    try {
      const url = new URL(value, location.href);
      if (url.origin !== location.origin || !/^https?:$/.test(url.protocol)) return;
      url.hash = "";
      if (url.href.length > INTEGRITY.urlMax) return;
      let script = found.get(url.href);
      if (!script) {
        // Decoded segment by segment where a segment holds an encoded slash: "/x%2Fmain.js" is not "/x/main.js".
        let path = url.pathname;
        if (path.includes("%")) {
          try {
            path = /%2f/i.test(path)
              ? path
                  .split("/")
                  .map((segment) => (/%2f/i.test(segment) ? segment : decodeURIComponent(segment)))
                  .join("/")
              : decodeURIComponent(path);
          } catch {
            // A path that cannot be decoded is compared as it is.
          }
        }
        script = { url: url.href, path, size: 0, listed: false, loaded: false };
        found.set(url.href, script);
      }
      read.set(value, script);
      return script;
    } catch {
      // Not a usable URL.
    }
  };
  let timed = false;
  let full = false;
  try {
    left = INTEGRITY.scanMax;
    const entries = /** @type {PerformanceResourceTiming[]} */ (performance.getEntriesByType("resource"));
    if (Array.isArray(entries)) {
      timed = true;
      full = entries.length >= INTEGRITY.timingFull;
      for (let k = 0; k < entries.length && left > 0; k += 1) {
        try {
          const entry = /** @type {PerformanceResourceTiming} */ (entries[k]);
          const script = add(entry.name);
          if (!script) continue;
          script.loaded = true;
          script.size = Math.max(script.size, Number(entry.decodedBodySize) || 0);
          if (entry.initiatorType === "script") script.listed = true;
        } catch {
          // Not an entry.
        }
      }
    }
  } catch {
    // No Resource Timing.
  }
  // Document.prototype's own query: `document.scripts` and `document.querySelectorAll` can be clobbered by markup.
  for (const selector of ["script[src]", "link[rel~=modulepreload][href]"]) {
    try {
      left = INTEGRITY.scanMax;
      const elements = Document.prototype.querySelectorAll.call(document, selector);
      for (let k = 0; k < elements.length && left > 0; k += 1) {
        const node = /** @type {HTMLScriptElement & HTMLLinkElement} */ (elements[k]);
        const isScript = selector[0] === "s";
        if (isScript && !SCRIPT_TYPE.test(node.getAttribute("type") ?? "")) {
          left -= 1;
          continue;
        }
        const script = add(isScript ? node.src : node.href);
        if (script) script.listed = true;
      }
    } catch {
      // No document to query.
    }
  }
  /** @type {Map<string, Script[]>} */
  const byName = new Map();
  for (const script of found.values()) {
    if (!script.listed || (timed && !script.loaded && !full)) continue;
    if (timed && !script.loaded) script.size = Number.POSITIVE_INFINITY;
    const name = script.path.slice(script.path.lastIndexOf("/") + 1);
    const named = byName.get(name);
    if (named) named.push(script);
    else byName.set(name, [script]);
  }
  return byName;
}

/**
 * The files of one marker on this page, or null. The base of a Build (the URL path prefix its files are under) is
 * taken only from loaded scripts whose path ends like exactly one listed path; a script that ends like two of them
 * ("/assets/utils/index.js" for "index.js" and "utils/index.js") tells nothing. Those scripts must agree on one
 * base: with none, or with two, the Build is ambiguous: null, so that the hash of another directory's file is never
 * sent. Each listed file is then the script at exactly base + its path. Of several URLs with one path (query
 * strings) the first seen is used; a path listed twice names one file.
 * @param {unknown[]} paths
 * @param {Map<string, Script[]>} byName
 * @returns {PlannedFile[] | null}
 */
function resolve(paths, byName) {
  /** Per script that ends like a listed path: where that path starts in it, or -1 when it ends like several. */
  /** @type {Map<Script, number>} */
  const ends = new Map();
  /** @type {string[]} */
  const listed = [];
  for (let i = 0; i < paths.length; i += 1) {
    const path = paths[i];
    if (typeof path !== "string" || listed.includes(path)) continue;
    listed[i] = path;
    for (const script of byName.get(path.slice(path.lastIndexOf("/") + 1)) ?? []) {
      const at = script.path.length - path.length;
      if (at < 1 || script.path[at - 1] !== "/" || !script.path.endsWith(path)) continue;
      ends.set(script, ends.has(script) ? -1 : at);
    }
  }
  /** @type {string | undefined} */
  let base;
  for (const [script, at] of ends) {
    if (at < 0) continue;
    // Compared in place: no base is cut out of a long path more than once.
    if (base === undefined) base = script.path.slice(0, at);
    else if (at !== base.length || !script.path.startsWith(base)) return null;
  }
  if (base === undefined) return null;
  /** @type {PlannedFile[]} */
  const files = [];
  for (let i = 0; i < listed.length; i += 1) {
    const path = listed[i];
    if (path === undefined) continue;
    for (const script of ends.keys()) {
      if (script.path.length !== base.length + path.length) continue;
      if (!script.path.startsWith(base) || !script.path.endsWith(path)) continue;
      files.push({ i, url: script.url, size: script.size });
      break;
    }
  }
  return files;
}

/**
 * The synchronous part: per registered Build that `skip` does not refuse, the listed files the page loaded (see
 * `resolve`); `i` is a file's position in the marker's list. A Build is read once; files past the 32nd, paths that
 * are not strings of 1 to `pathMax` characters, and Builds without a file or with an ambiguous base are left out.
 * A URL that two Builds (skipped or not) would both name is fetched for neither (size Infinity). Registry objects
 * are only read by index: none of their methods is called. Nothing of the page is read when every Build is skipped.
 * @param {(build: string) => boolean} skip
 */
export function plan(skip) {
  /** @type {{ build: string, files: PlannedFile[] }[]} */
  const out = [];
  try {
    const registry = /** @type {Record<symbol, unknown>} */ (/** @type {unknown} */ (globalThis))[
      Symbol.for(INTEGRITY.markerKey)
    ];
    if (!Array.isArray(registry)) return out;
    /** @type {Map<string, unknown[]>} */
    const markers = new Map();
    let wanted = false;
    for (let k = 0; k < registry.length && k < INTEGRITY.markersMax; k += 1) {
      try {
        const b = registry[k].b;
        const f = registry[k].f;
        if (typeof b !== "string" || !PATTERNS.build.test(b) || !Array.isArray(f) || markers.has(b)) continue;
        const paths = [];
        for (let i = 0; i < f.length && i < INTEGRITY.filesMax; i += 1) {
          const path = f[i];
          paths.push(typeof path === "string" && path !== "" && path.length <= INTEGRITY.pathMax ? path : null);
        }
        markers.set(b, paths);
        wanted ||= !skip(b);
      } catch {
        // Not a marker.
      }
    }
    if (!wanted) return out;
    const byName = pageScripts();
    /** @type {Map<string, number>} How many Builds name a URL. */
    const named = new Map();
    /** @type {{ build: string, files: PlannedFile[] }[]} */
    const all = [];
    for (const [build, paths] of markers) {
      const files = resolve(paths, byName);
      if (files === null || files.length === 0) continue;
      for (const file of files) named.set(file.url, (named.get(file.url) ?? 0) + 1);
      all.push({ build, files });
    }
    for (const { build, files } of all) {
      if (out.length >= INTEGRITY.buildsMax || skip(build)) continue;
      for (const file of files) if ((named.get(file.url) ?? 0) > 1) file.size = Number.POSITIVE_INFINITY;
      out.push({ build, files });
    }
  } catch {
    // A hostile registry or no page.
  }
  return out;
}

/**
 * The SHA-256 of the bytes behind a URL, or null: a failed, refused, redirected or non-basic (opaque, cross-origin)
 * answer, one whose Content-Type is not JavaScript (an HTML fallback page), a body over 2 MB (by Content-Length, or
 * once that much was read: the rest is not downloaded), a chunk that is no byte array, or a job cancelled. The
 * request and the read of its body are ended in every case, also when fetch ignores the abort signal.
 * @param {import("./index.js").GuardCrypto} crypto
 * @param {string} url
 * @param {Job} job
 * @returns {Promise<string | null>}
 */
async function hashFile(crypto, url, job) {
  const max = INTEGRITY.fileMaxBytes;
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  /** @type {ReadableStreamDefaultReader<unknown> | undefined} */
  let reader;
  let ended = false;
  const end = () => {
    ended = true;
    controller?.abort();
    void reader?.cancel().catch(() => {});
  };
  try {
    return await Promise.race([
      (async () => {
        /** @type {RequestInit} */
        const init = { cache: "force-cache", credentials: "same-origin" };
        if (controller) init.signal = controller.signal;
        const response = await globalThis.fetch(url, init);
        if (!response.ok || response.redirected || !/^(basic|default)$/.test(response.type || "basic")) return null;
        if (!SCRIPT_MIME.test(response.headers.get("content-type") ?? "")) return null;
        if (Number(response.headers.get("content-length")) > max) return null;
        /** @type {Uint8Array} */
        let bytes;
        reader = response.body?.getReader();
        if (reader) {
          /** @type {Uint8Array[]} */
          const chunks = [];
          let length = 0;
          for (;;) {
            if (ended) return null;
            const { done, value } = await reader.read();
            if (done) break;
            if (!(value instanceof Uint8Array)) return null;
            length += value.byteLength;
            if (length > max) return null;
            chunks.push(value);
          }
          bytes = new Uint8Array(length);
          let offset = 0;
          for (const chunk of chunks) {
            bytes.set(chunk, offset);
            offset += chunk.byteLength;
          }
        } else bytes = new Uint8Array(await response.arrayBuffer());
        return bytes.byteLength > max ? null : sha256(crypto, bytes);
      })(),
      new Promise((resolve) => {
        job.cancel = () => {
          end();
          resolve(null);
        };
      }),
    ]);
  } catch {
    return null;
  } finally {
    job.cancel = undefined;
    end(); // Ends a request that is late, cancelled or whose body is not wanted; nothing to end otherwise.
  }
}

/**
 * The report of the first Build of which a file could be hashed, or null. A Build is passed over when the memo
 * holds it for this App (reported in the last 24 hours, or being collected in another tab) or another collection
 * of this page claimed it for this App; a Build attempted is claimed in both (in the memo for `claimMs`), and given
 * back when `job` is cancelled. Nothing runs without `crypto.subtle` or under Save-Data. Files are fetched one at a
 * time, within `budgetMs` in all (a timer and the monotonic clock, never the wall clock); `skipped` counts the
 * files found on the page but not hashed. A Build the budget did not reach is not claimed.
 * @param {unknown} appId
 * @param {import("./index.js").GuardCrypto | null} crypto
 * @param {import("./index.js").GuardNavigator | null} navigator
 * @param {import("./index.js").GuardStorage | null} storage
 * @param {() => number} now The wall clock, for the memo only.
 * @param {Job} job
 * @returns {Promise<Report | null>}
 */
export async function collect(appId, crypto, navigator, storage, now, job) {
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timer;
  try {
    if (!crypto?.subtle || navigator?.connection?.saveData) return null;
    const at = now();
    const memo = readMemo(storage, at);
    const claimed = claims();
    const planned = plan((id) => `${appId}/${id}` in memo || `${appId}/${id}` in claimed);
    if (planned.length === 0) return null;
    let late = false;
    timer = setTimeout(() => {
      late = true;
      job.cancel?.();
    }, INTEGRITY.budgetMs);
    const started = performance.now();
    const over = () => {
      late ||= performance.now() - started >= INTEGRITY.budgetMs;
      return late;
    };
    for (const { build, files } of planned) {
      if (over()) break;
      const key = `${appId}/${build}`;
      claimed[key] = 1;
      remember(storage, key, at + INTEGRITY.claimMs - INTEGRITY.memoMs, at);
      /** @type {Report} */
      const report = { build, files: [], skipped: 0 };
      for (const file of files) {
        const h = over() || file.size > INTEGRITY.fileMaxBytes ? null : await hashFile(crypto, file.url, job);
        if (job.aborted) {
          delete claimed[key];
          remember(storage, key, 0, at);
          return null;
        }
        if (h === null) report.skipped += 1;
        else report.files.push({ i: file.i, h });
      }
      if (report.files.length > 0) return report;
    }
  } catch {
    // No report.
  } finally {
    clearTimeout(timer);
  }
  return null;
}

/**
 * What this device reported in the last 24 hours (or is collecting) and when, by `appId/build`, from first-party
 * storage (none: `{}`). At most the `memoMax` newest entries are kept; anything else stored there is dropped.
 * @param {import("./index.js").GuardStorage | null} storage
 * @param {number} at
 * @param {number} [max]
 */
export function readMemo(storage, at, max = INTEGRITY.memoMax) {
  /** @type {Record<string, number>} */
  const memo = Object.create(null);
  try {
    const stored = JSON.parse(storage?.getItem(INTEGRITY.storageKey) ?? "");
    /** @type {[string, number][]} */
    const valid = [];
    for (const key of Object.keys(stored)) {
      const time = stored[key];
      if (PATTERNS.memoKey.test(key) && typeof time === "number" && time <= at && at - time < INTEGRITY.memoMs) {
        valid.push([key, time]);
      }
    }
    if (valid.length > max) valid.sort((a, b) => b[1] - a[1]).length = max;
    for (const [key, time] of valid) memo[key] = time;
  } catch {
    // No memo.
  }
  return memo;
}

/**
 * Writes the memo at `at` with `key` (`appId/build`) set to `time`: `at` for a report, earlier for a claim that
 * ends sooner, 0 to drop it. Without usable storage the page-wide claim holds for this page view.
 * @param {import("./index.js").GuardStorage | null} storage
 * @param {string} key
 * @param {number} time
 * @param {number} at
 */
export function remember(storage, key, time, at) {
  try {
    const memo = readMemo(storage, at, INTEGRITY.memoMax - 1);
    if (time > 0) memo[key] = time;
    else delete memo[key];
    storage?.setItem(INTEGRITY.storageKey, JSON.stringify(memo));
  } catch {
    // Kept on the page only.
  }
}
