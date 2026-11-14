// The integrity collector (slice 21b): reads the markers Harden planted (`{ b: Build id, f: [paths] }` under
// `globalThis[Symbol.for("ar.build")]`), finds their files among the scripts the page loaded from its own origin
// and hashes them. Only `{ build, files: [{ i, h }], skipped }` leaves this module. Nothing here throws or rejects.
//
// Where a Build's files are is never guessed from names (D-102, content anchor). Harden plants the marker in the
// first file the marker lists. So the loaded scripts that end like that first path are read, and the one whose
// bytes hold the marker's own literal (`b:"<Build id>",f:[`, which a minifier keeps) is the Build's first file: its
// URL gives the base, and every other listed file is the one loaded script at exactly base + its path, with the
// same query string. It fails closed: no such script, two of them, or a candidate that could not be examined, and
// nothing is sent for the Build.
import { INTEGRITY, PATTERNS } from "./constants.js";
import { sha256 } from "./crypto.js";

/** @typedef {{ i: number, url: string, size: number }} PlannedFile `size` is Infinity when the file must not be fetched. */
/** @typedef {{ build: string, files: { i: number, h: string }[], skipped: number }} Report */
/** @typedef {{ aborted: boolean, cancel?: (() => void) | undefined }} Job A collection; `cancel` ends its request in flight. */
/** @typedef {{ url: string, path: string, search: string, size: number, listed: boolean, loaded: boolean }} Script */
/** @typedef {{ byPath: Map<string, Script[]>, markers: Map<string, (string | null)[]> }} Page The page's scripts by path (in the order seen) and every marker read. */
/** @typedef {{ build: string, paths: (string | null)[], candidates: Script[], page: Page }} Planned A Build and the scripts that may be its first file. */

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
 * Each source stands alone and reads at most `scanMax` values, of which `scanMax` distinct ones are parsed in all;
 * a URL over `urlMax` characters is passed over.
 * Paths are decoded segment by segment. The scripts are returned in the order they were first seen.
 * @returns {Script[]}
 */
function pageScripts() {
  /** @type {Map<string, Script>} */
  const found = new Map();
  /** What a value read before came to: each distinct value is parsed once. */
  /** @type {Map<string, Script | undefined>} */
  const read = new Map();
  let left = 0;
  /** Distinct values parsed so far: `scanMax` in all, whatever the source. */
  let parsed = 0;
  /** @type {(value: unknown) => Script | undefined} */
  const add = (value) => {
    left -= 1;
    if (typeof value !== "string" || value === "" || value.length > INTEGRITY.urlMax) return;
    if (read.has(value)) return read.get(value);
    if (parsed >= INTEGRITY.scanMax) return;
    parsed += 1;
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
        script = { url: url.href, path, search: url.search, size: 0, listed: false, loaded: false };
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
  /** @type {Script[]} */
  const scripts = [];
  for (const script of found.values()) {
    if (!script.listed || (timed && !script.loaded && !full)) continue;
    if (timed && !script.loaded) script.size = Number.POSITIVE_INFINITY;
    scripts.push(script);
  }
  return scripts;
}

/** Whether `path` ends with "/" + `listed`: compared in place, nothing is cut out of a long path. */
/** @type {(path: string, listed: string) => boolean} */
const endsLike = (path, listed) => path[path.length - listed.length - 1] === "/" && path.endsWith(listed);

/**
 * The synchronous part: the registered Builds that `skip` does not refuse and that have one to `candidatesMax`
 * candidates for their first file: the loaded scripts (the first seen of each path) whose path ends with "/" + the
 * marker's first path. Which candidate it is, if any, only its bytes tell (see `collect`). A Build of which a
 * candidate must not be fetched (Resource Timing could not vouch for it, or says it is over 2 MB) cannot be
 * examined in full and is left out. At most `entriesMax` registry entries are scanned and `markersMax` distinct
 * Builds read, by index only: no method of a registry object is called. A Build is read once (its first marker);
 * files past the 32nd and paths that are not strings of 1 to `pathMax` characters are not files. Nothing of the
 * page is read when every Build is skipped.
 * @param {(build: string) => boolean} skip
 * @returns {Planned[]}
 */
export function plan(skip) {
  /** @type {Planned[]} */
  const out = [];
  try {
    const registry = /** @type {Record<symbol, unknown>} */ (/** @type {unknown} */ (globalThis))[
      Symbol.for(INTEGRITY.markerKey)
    ];
    if (!Array.isArray(registry)) return out;
    /** @type {Page} */
    const page = { byPath: new Map(), markers: new Map() };
    let wanted = false;
    for (let k = 0; k < registry.length && k < INTEGRITY.entriesMax; k += 1) {
      if (page.markers.size >= INTEGRITY.markersMax) break;
      try {
        const b = registry[k].b;
        const f = registry[k].f;
        if (typeof b !== "string" || !PATTERNS.build.test(b) || !Array.isArray(f) || page.markers.has(b)) continue;
        /** @type {(string | null)[]} */
        const paths = [];
        for (let i = 0; i < f.length && i < INTEGRITY.filesMax; i += 1) {
          const path = f[i];
          const valid = typeof path === "string" && path !== "" && path.length <= INTEGRITY.pathMax;
          paths.push(valid && !paths.includes(path) ? path : null);
        }
        page.markers.set(b, paths);
        wanted ||= !skip(b);
      } catch {
        // Not a marker.
      }
    }
    if (!wanted) return out;
    for (const script of pageScripts()) {
      const at = page.byPath.get(script.path);
      if (at) at.push(script);
      else page.byPath.set(script.path, [script]);
    }
    for (const [build, paths] of page.markers) {
      const first = paths[0];
      if (out.length >= INTEGRITY.buildsMax || typeof first !== "string" || skip(build)) continue;
      /** @type {Script[]} */
      const candidates = [];
      let examinable = true;
      for (const [path, scripts] of page.byPath) {
        const script = scripts[0];
        if (!script || !endsLike(path, first)) continue;
        candidates.push(script);
        examinable &&= script.size <= INTEGRITY.fileMaxBytes;
        if (candidates.length > INTEGRITY.candidatesMax) break;
      }
      if (examinable && candidates.length > 0 && candidates.length <= INTEGRITY.candidatesMax) {
        out.push({ build, paths, candidates, page });
      }
    }
  } catch {
    // A hostile registry or no page.
  }
  return out;
}

/**
 * The files of a planned Build once `anchor` is known to be its first file. The base is the anchor's path without
 * the first listed path; every other listed file is the script at exactly base + its path, `i` being its position
 * in the marker's list. Such a file is used only when exactly one loaded URL has that path and its query string is
 * the anchor's (none on both sides counts): another spelling may be another deployment's bytes. A file whose URL
 * also ends like a listed path of another Build on the page (reported or not) could be that Build's and is used by
 * neither. A file that is not used has size Infinity, as a script that must not be fetched.
 * @param {Planned} planned
 * @param {Script} anchor
 * @returns {PlannedFile[]}
 */
export function locate(planned, anchor) {
  /** @type {PlannedFile[]} */
  const files = [];
  const first = planned.paths[0] ?? "";
  const base = anchor.path.slice(0, anchor.path.length - first.length);
  for (let i = 0; i < planned.paths.length; i += 1) {
    const path = planned.paths[i];
    if (typeof path !== "string") continue;
    const at = planned.page.byPath.get(base + path) ?? [];
    const script = i === 0 ? anchor : at[0];
    if (!script) continue;
    let size = i === 0 || (at.length === 1 && script.search === anchor.search) ? script.size : Number.POSITIVE_INFINITY;
    for (const [build, paths] of planned.page.markers) {
      if (build === planned.build) continue;
      for (const other of paths) if (other !== null && endsLike(script.path, other)) size = Number.POSITIVE_INFINITY;
    }
    files.push({ i, url: script.url, size });
  }
  return files;
}

/**
 * Whether `bytes` hold `text` (ASCII) somewhere.
 * @param {Uint8Array} bytes
 * @param {string} text
 */
function holds(bytes, text) {
  const first = text.charCodeAt(0);
  for (let at = bytes.indexOf(first); at !== -1; at = bytes.indexOf(first, at + 1)) {
    let k = 1;
    while (k < text.length && bytes[at + k] === text.charCodeAt(k)) k += 1;
    if (k === text.length) return true;
  }
  return false;
}

/**
 * The bytes behind a URL, or null: an answer that is not a whole, direct, same-origin script (a status other than
 * 200, redirected, opaque or cross-origin, or a Content-Type that is not JavaScript, as an HTML fallback page has),
 * a body over 2 MB (by Content-Length, or once that much was read: the rest is not downloaded), a chunk that is no
 * byte array, or a job cancelled. The request and the read of its body are ended in every case, also when fetch
 * ignores the abort signal and answers late.
 * @param {string} url
 * @param {Job} job
 * @returns {Promise<Uint8Array | null>}
 */
async function readFile(url, job) {
  const max = INTEGRITY.fileMaxBytes;
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  /** @type {{ cancel(): unknown } | undefined} */
  let reader;
  let ended = false;
  const end = () => {
    ended = true;
    try {
      controller?.abort();
      // A cancel() that throws, or whose promise rejects, changes nothing.
      Promise.resolve(reader?.cancel()).catch(() => {});
    } catch {
      // Nothing left to end.
    }
  };
  try {
    return await Promise.race([
      (async () => {
        /** @type {RequestInit} */
        const init = { cache: "force-cache", credentials: "same-origin" };
        if (controller) init.signal = controller.signal;
        const response = await globalThis.fetch(url, init);
        const body = response.body?.getReader();
        reader = body;
        if (ended) {
          end(); // The answer came after the job was over: its body is not wanted.
          return null;
        }
        if (response.status !== 200 || response.redirected) return null;
        if (!/^(basic|default)$/.test(response.type || "basic")) return null;
        if (!SCRIPT_MIME.test(response.headers.get("content-type") ?? "")) return null;
        if (Number(response.headers.get("content-length")) > max) return null;
        if (!body) {
          const bytes = new Uint8Array(await response.arrayBuffer());
          return bytes.byteLength > max ? null : bytes;
        }
        /** @type {Uint8Array[]} */
        const chunks = [];
        let length = 0;
        for (;;) {
          if (ended) return null;
          const { done, value } = await body.read();
          if (done) break;
          if (!(value instanceof Uint8Array)) return null;
          length += value.byteLength;
          if (length > max) return null;
          chunks.push(value);
        }
        const bytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.byteLength;
        }
        return bytes;
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
 * back when `job` is cancelled.
 *
 * Per Build: its candidates are read one at a time; the one whose bytes hold the marker's literal is its first
 * file. It fails closed: a candidate that could not be read, none or two that qualify, or the budget ending first
 * (the Build's claims are then given back), and nothing is sent for the Build. Then every other file `locate`
 * finds is read and hashed; the first file is hashed from the bytes already read. `skipped` counts the files found
 * on the page but not hashed.
 *
 * Nothing runs without `crypto.subtle` or under Save-Data. Everything is fetched within `budgetMs` in all (a timer
 * and the monotonic clock, never the wall clock). A Build the budget did not reach is not claimed.
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
    /** The bytes of a file, null when it is not to be fetched, could not be read, or the budget is over. */
    /** @type {(file: { url: string, size: number }) => Promise<Uint8Array | null>} */
    const read = async (file) => (over() || file.size > INTEGRITY.fileMaxBytes ? null : readFile(file.url, job));
    for (const build of planned) {
      if (over()) break;
      const key = `${appId}/${build.build}`;
      claimed[key] = 1;
      remember(storage, key, at + INTEGRITY.claimMs - INTEGRITY.memoMs, now());
      const giveBack = () => {
        delete claimed[key];
        remember(storage, key, 0, now());
        return null;
      };
      // The anchor: the one candidate whose bytes hold the marker's literal. Every candidate must be examined.
      const marker = `b:"${build.build}",f:[`;
      /** @type {{ script: Script, bytes: Uint8Array }[]} */
      const anchors = [];
      let examined = true;
      for (const script of build.candidates) {
        if (job.aborted) return giveBack();
        const bytes = await read(script);
        if (job.aborted) return giveBack();
        if (bytes === null) {
          examined = false;
          break;
        }
        if (holds(bytes, marker)) anchors.push({ script, bytes });
      }
      if (late) {
        giveBack(); // Cut by the budget, not decided: another collection may take the Build.
        break;
      }
      const anchor = anchors[0];
      if (!examined || anchors.length !== 1 || !anchor) continue;
      /** @type {Report} */
      const report = { build: build.build, files: [], skipped: 0 };
      for (const file of locate(build, anchor.script)) {
        if (job.aborted) return giveBack();
        const bytes = file.i === 0 && file.size <= INTEGRITY.fileMaxBytes ? anchor.bytes : await read(file);
        if (job.aborted) return giveBack();
        if (bytes === null) report.skipped += 1;
        else report.files.push({ i: file.i, h: await sha256(crypto, bytes) });
      }
      if (job.aborted) return giveBack();
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
 * storage (none: `{}`). At most the `max` newest entries are kept; anything else stored there is dropped.
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
 * Writes the memo with `key` (`appId/build`) set to `time`: the present for a report, earlier for a claim that ends
 * sooner, 0 to drop it. `at` is the present, read by the caller right now: what other tabs wrote since is kept.
 * Without usable storage the page-wide claim holds for this page view.
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

/**
 * Whether the memo says this App and Build was reported (by any tab), not merely claimed: a claim is written with a
 * time at least `memoMs - pendingMs` in the past.
 * @param {import("./index.js").GuardStorage | null} storage
 * @param {string} key
 * @param {number} at
 */
export function reported(storage, key, at) {
  return (readMemo(storage, at)[key] ?? Number.NEGATIVE_INFINITY) > at + INTEGRITY.pendingMs - INTEGRITY.memoMs;
}
