// The runtime component inventory (slice 19): the packages installed where Shield runs, read once from npm's
// lockfile and posted to `POST /v1/inventory`. Only names, versions and the dev flag leave the process; nothing
// here is logged except fixed sentences without package names. Never on the request path, never throws.
import { randomBytes } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { describeError } from "./emitter.ts";
import type { Transport } from "./types.ts";

/** One installed package, as the protocol's `ComponentSchema`. */
export interface InventoryComponent {
  name: string;
  version: string;
  dev: boolean;
}

export type InventoryState = "off" | "pending" | "sent" | "failed";

/**
 * The protocol's `EXPOSURE_LIMITS` that bind an inventory (pinned by a test). Repeated here because Shield has no
 * runtime dependency, not even on the protocol.
 */
export const INVENTORY_LIMITS = {
  componentsMax: 5_000,
  bytesMax: 2_097_152,
  nameMax: 214,
  versionMax: 256,
} as const;

/** Waits before each retry of a failed POST: three retries, then Shield stays quiet until it restarts. */
export const INVENTORY_RETRY_MS = [5_000, 30_000, 120_000] as const;
/** Without a Policy to fetch, the inventory starts this long after `createShield`, so creating Shield does no I/O. */
export const INVENTORY_START_DELAY_MS = 1_000;
/** With a Policy to fetch, the inventory is sent this long after `createShield` if no fetch has succeeded by then. */
export const INVENTORY_FALLBACK_MS = 60_000;
/** A lockfile larger than this is not read. */
const LOCKFILE_BYTES_MAX = 64 * 1024 * 1024;
/** Up to this share of a wait is added to it at random, so that many Shields do not retry in step. */
const JITTER = 0.25;
/** The longest a 429's `retry-after` may delay a retry: a longer one (or a date) is read as this. */
export const INVENTORY_RETRY_AFTER_MAX_MS = 600_000;
/**
 * After the first successful send, the same inventory (same instance id) is sent again this often, ± up to 10 %:
 * the API drops an instance that has not posted for 24 hours, so a long-running process stays part of the runtime set.
 */
export const INVENTORY_RESEND_MS = 6 * 3_600_000;
const RESEND_JITTER = 0.1;

/** A 429's `retry-after` in milliseconds (delta-seconds only), capped; undefined when absent or unreadable. */
function retryAfterMs(value: string | undefined): number | undefined {
  if (value === undefined || !/^\d{1,10}$/.test(value.trim())) return undefined;
  return Math.min(Number(value.trim()) * 1_000, INVENTORY_RETRY_AFTER_MAX_MS);
}

// npm names, legacy rules, as the protocol's ComponentSchema (pinned against it over a corpus).
const NPM_NAME = /^(?:@(?![._])[a-z0-9._~'!()*-]+\/)?(?![._])[A-Za-z0-9._~'!()*-]+$/;
// semver 2.0 (semver.org's suggested expression), as the protocol's parseSemver.
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
const NUMERIC = /^\d+$/;

/** An npm package name the protocol accepts. */
export function isComponentName(name: unknown): name is string {
  return typeof name === "string" && name.length <= INVENTORY_LIMITS.nameMax && NPM_NAME.test(name);
}

/** A semver 2.0 version the protocol accepts: every number within `Number.MAX_SAFE_INTEGER`. */
export function isComponentVersion(version: unknown): version is string {
  if (typeof version !== "string" || version.length > INVENTORY_LIMITS.versionMax) return false;
  const match = SEMVER.exec(version);
  if (match === null) return false;
  for (const part of [match[1], match[2], match[3]]) if (!Number.isSafeInteger(Number(part))) return false;
  for (const identifier of match[4] === undefined ? [] : match[4].split(".")) {
    if (NUMERIC.test(identifier) && !Number.isSafeInteger(Number(identifier))) return false;
  }
  return true;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const NODE_MODULES = "node_modules/";

/**
 * The components of an npm lockfile (v2/v3 `packages`, else v1 `dependencies`), de-duplicated by name@version and
 * sorted; `skipped` counts entries without a valid name or a semver version. Null when the text is no lockfile.
 * A name@version installed both as a runtime and as a development dependency counts as runtime (`dev: false`).
 */
export function parseLockfile(text: string): { components: InventoryComponent[]; skipped: number } | null {
  let lockfile: unknown;
  try {
    lockfile = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(lockfile)) return null;
  const found = new Map<string, InventoryComponent>();
  let skipped = 0;
  const add = (name: unknown, version: unknown, dev: boolean): void => {
    if (!isComponentName(name) || !isComponentVersion(version)) {
      skipped += 1;
      return;
    }
    const id = `${name}@${version}`;
    const known = found.get(id);
    if (known === undefined) found.set(id, { name, version, dev });
    else known.dev &&= dev;
  };

  const { packages, dependencies } = lockfile;
  if (packages !== undefined) {
    if (!isRecord(packages)) return null;
    for (const [path, entry] of Object.entries(packages)) {
      // The root project (""), and workspace folders (no node_modules/ in the path), are not installed packages.
      const at = path.lastIndexOf(NODE_MODULES);
      if (at === -1) continue;
      if (isRecord(entry) && entry.link === true) continue;
      if (!isRecord(entry)) {
        skipped += 1;
        continue;
      }
      // `name` is present for an alias (npm:real@x): the package's own name, not the folder's.
      const name = typeof entry.name === "string" ? entry.name : path.slice(at + NODE_MODULES.length);
      add(name, entry.version, entry.dev === true || entry.devOptional === true);
    }
  } else if (dependencies !== undefined) {
    if (!isRecord(dependencies)) return null;
    // v1: a tree. Walked with a stack, not recursion: its depth is the lockfile's to choose.
    const stack: Record<string, unknown>[] = [dependencies];
    while (stack.length > 0) {
      const level = stack.pop() as Record<string, unknown>;
      for (const [name, entry] of Object.entries(level)) {
        if (!isRecord(entry)) {
          skipped += 1;
          continue;
        }
        add(name, entry.version, entry.dev === true);
        if (isRecord(entry.dependencies)) stack.push(entry.dependencies);
      }
    }
  } else {
    return null;
  }
  const components = [...found.values()].sort((a, b) =>
    a.name !== b.name ? (a.name < b.name ? -1 : 1) : a.version < b.version ? -1 : a.version > b.version ? 1 : 0,
  );
  return { components: selectComponents(components), skipped };
}

/**
 * At most 5,000 components and 2 MB of body: runtime dependencies first, then development ones, each group in
 * the order given. The result keeps the order given.
 */
export function selectComponents(components: readonly InventoryComponent[]): InventoryComponent[] {
  const keep = new Set<InventoryComponent>();
  let bytes = '{"components":[]}'.length;
  for (const dev of [false, true]) {
    for (const component of components) {
      if (component.dev !== dev) continue;
      if (keep.size >= INVENTORY_LIMITS.componentsMax) break;
      const cost = Buffer.byteLength(JSON.stringify(component)) + 1;
      if (bytes + cost > INVENTORY_LIMITS.bytesMax) continue;
      keep.add(component);
      bytes += cost;
    }
  }
  return components.filter((component) => keep.has(component));
}

async function readText(path: string): Promise<string | null> {
  try {
    const info = await stat(path);
    if (!info.isFile() || info.size > LOCKFILE_BYTES_MAX) return null;
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
}

/**
 * The installed components under `root`: `node_modules/.package-lock.json` (what npm actually installed), else
 * `package-lock.json`. Null when neither is a readable lockfile. Never rejects.
 */
export async function readInventory(root: string): Promise<InventoryComponent[] | null> {
  for (const path of [join(root, "node_modules", ".package-lock.json"), join(root, "package-lock.json")]) {
    const text = await readText(path);
    if (text === null) continue;
    // Parsing yields to the event loop first: a large lockfile is parsed in a turn of its own.
    await new Promise<void>((resolve) => setImmediate(resolve));
    const parsed = parseLockfile(text);
    if (parsed !== null) return parsed.components;
  }
  return null;
}

/** The conditions the sender reports to the host's logger. Shield prints one line per condition. */
export type InventoryCondition = "inventory-lockfile" | "inventory-failed";

export interface InventorySenderOptions {
  key: string;
  /** Base URL of the API. The inventory goes to `{endpoint}/v1/inventory`. */
  endpoint: string;
  requestTimeoutMs: number;
  transport: Transport;
  /** Reads the components; null without a readable lockfile. */
  load: () => Promise<InventoryComponent[] | null>;
  warn: (condition: InventoryCondition, message: string) => void;
}

export interface InventorySender {
  /** Reads and sends, once: later calls do nothing. Never throws. */
  start(): void;
  /** Cancels a pending retry; an answer still under way changes nothing any more. */
  close(): void;
  state(): InventoryState;
}

/**
 * Sends the inventory once, in the background. A transport error, a timeout, 408, 429 or a 5xx is retried after
 * 5 s, 30 s and 120 s — after a 429, no sooner than its `retry-after` (at most 10 minutes); any other status is
 * final. The retry timer is unref'd, so it never holds the process. The body carries a random instance id, the
 * same on every retry (plan A7): the API keeps one inventory per running instance. After the first success the same
 * body is re-sent every 6 h ± 10 % (`INVENTORY_RESEND_MS`), so the API never expires a live process; a re-send that
 * fails only waits for the next one. `close()` cancels every timer.
 */
export function createInventorySender(options: InventorySenderOptions): InventorySender {
  const url = `${options.endpoint.replace(/\/+$/, "")}/v1/inventory`;
  const instanceId = randomBytes(16).toString("hex");
  let state: InventoryState = "pending";
  let started = false;
  let closed = false;
  let timer: NodeJS.Timeout | undefined;

  function warn(condition: InventoryCondition, message: string): void {
    try {
      options.warn(condition, message);
    } catch {
      // a logger that throws changes nothing
    }
  }

  function fail(reason: string): void {
    state = "failed";
    warn(
      "inventory-failed",
      `component inventory not sent (${reason}). Shield does not try again until it restarts; your application is not affected.`,
    );
  }

  /** The next re-send, 6 h ± 10 % from now, on an unref'd timer. */
  function scheduleResend(body: string): void {
    if (closed) return;
    timer = setTimeout(
      () => {
        timer = undefined;
        void attempt(body, 0, true);
      },
      Math.round(INVENTORY_RESEND_MS * (1 + (Math.random() * 2 - 1) * RESEND_JITTER)),
    );
    timer.unref();
  }

  /**
   * One POST. A re-send (after the first success) follows the same retry rules, but when it fails for good it only
   * schedules the next re-send: the state stays "sent" and nothing is logged.
   */
  async function attempt(body: string, retry: number, resend = false): Promise<void> {
    if (closed) return;
    let status: number | undefined;
    let retryAfter: string | undefined;
    let reason: string;
    try {
      const response = await options.transport({
        method: "POST",
        url,
        headers: { authorization: `Bearer ${options.key}`, "content-type": "application/json" },
        body,
        timeoutMs: options.requestTimeoutMs,
      });
      status = response.status;
      retryAfter = response.retryAfter;
      if (typeof status !== "number") throw new TypeError("the transport returned no status");
      reason = `the API responded ${status}`;
    } catch (error) {
      status = undefined;
      reason = `the API is unreachable (${describeError(error)})`;
    }
    if (closed) return;
    if (status !== undefined && status >= 200 && status < 300) {
      state = "sent";
      scheduleResend(body);
      return;
    }
    const retryable = status === undefined || status === 408 || status === 429 || status >= 500;
    const wait = INVENTORY_RETRY_MS[retry];
    if (!retryable || wait === undefined) {
      if (resend) scheduleResend(body);
      else fail(reason);
      return;
    }
    timer = setTimeout(
      () => {
        timer = undefined;
        void attempt(body, retry + 1, resend);
      },
      Math.max(Math.round(wait * (1 + Math.random() * JITTER)), (status === 429 && retryAfterMs(retryAfter)) || 0),
    );
    timer.unref();
  }

  async function run(): Promise<void> {
    let components: InventoryComponent[] | null;
    try {
      components = await options.load();
    } catch {
      components = null;
    }
    if (closed) return;
    if (components === null) {
      state = "failed";
      warn("inventory-lockfile", "component inventory skipped: no readable lockfile");
      return;
    }
    await attempt(JSON.stringify({ components, instance_id: instanceId }), 0);
  }

  return {
    start() {
      if (started || closed) return;
      started = true;
      run().catch(() => {
        state = "failed"; // only the host's clock or random source can throw here
      });
    },
    close() {
      closed = true;
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
    },
    state: () => state,
  };
}
