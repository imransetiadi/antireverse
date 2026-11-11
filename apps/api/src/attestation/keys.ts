import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";
import type { AttestationClaims, BundleAttestationKey } from "@antireverse/protocol";
import { attestationKid, signAttestationToken } from "@antireverse/protocol/server";
import { consoleLogger, type Logger, redacting } from "../log.ts";

// The Attestation key set (slice 03): Ed25519 keys that sign Attestation Tokens, separate from the key that signs
// Policy Bundles (`signer.ts`) and kept in a file of their own, `attestation-keys.json`, beside the data directory.
// Development key handling like the signing key: a managed key service replaces the file later.
//
// The set is { previous?, current, next }. Tokens are signed with current. The bundle carries the public halves of
// all of them, so a Shield holds the next key long before it signs anything and the previous key while tokens it
// signed can still be in use. Rotation, checked on every use against the injectable clock:
//   - 24 hours after current became current, next becomes current, but only once next has been published (in the
//     set, so in every bundle issued since) for at least an hour; otherwise the rotation waits.
//   - The old current becomes previous; a new next is made and published at once.
//   - A previous key is dropped 24 hours after it was retired.
//   - A key counts as published no earlier than this process's start (in memory only; the file keeps the original
//     time): after a stop, next is promoted only once this process has served it for an hour (review F3).
// One writer per key file is expected. A second process on the same file adopts the file's set: before it rotates,
// it reads the file again, and a set whose current key became current later than its own replaces its own (F2).
// A rotation whose write fails is retried at most once a minute, with one warning per attempt (F4).
// Private keys never leave this module except into the key file.

/** Current signs for this long before next takes over. */
export const ATTESTATION_KEY_ROTATION_MS = 24 * 60 * 60 * 1_000;
/** Next must have been published for at least this long before it signs. */
export const NEXT_KEY_LEAD_MS = 60 * 60 * 1_000;
/** A retired key stays in the set this long. */
export const PREVIOUS_KEY_KEPT_MS = 24 * 60 * 60 * 1_000;
/** After a failed rotation write, the next attempt waits this long. */
export const ROTATION_RETRY_MS = 60_000;

/** The key set as the rest of the API sees it: public halves, the current kid, and signing. */
export interface AttestationKeys {
  /** The public halves in the order previous (while kept), current, next: what the Policy Bundle carries. */
  attestationKeys(): BundleAttestationKey[];
  /** The kid of the key that signs now. */
  currentKid(): string;
  /** Signs the claims with the current key (`signAttestationToken`). */
  sign(claims: AttestationClaims): string;
}

const FILE_FORMAT = 1;
const ALGORITHM = "Ed25519";
const PURPOSE = "attestation";
const KEY_TEXT = /^[A-Za-z0-9_-]{43}$/;
const OWNER_ONLY = 0o600;
const ROLES = ["previous", "current", "next"] as const;

interface Key {
  kid: string;
  publicKey: string;
  privateKey: KeyObject;
  createdAt: number;
  publishedAt: number;
  /** When it became current; absent for next. */
  activatedAt?: number;
  /** When it stopped being current; previous only. */
  retiredAt?: number;
}

interface KeySet {
  previous?: Key;
  current: Key;
  next: Key;
}

function rawPublicKey(privateKey: KeyObject): string {
  const { x } = createPublicKey(privateKey).export({ format: "jwk" });
  if (typeof x !== "string" || !KEY_TEXT.test(x)) throw new Error("An attestation key is not an Ed25519 key.");
  return x;
}

/** Makes a new private Ed25519 key. */
export type GenerateKey = () => KeyObject;
const generateEd25519: GenerateKey = () => generateKeyPairSync("ed25519").privateKey;

function newKey(ms: number, generate: GenerateKey): Key {
  const privateKey = generate();
  const publicKey = rawPublicKey(privateKey);
  return {
    kid: attestationKid(Buffer.from(publicKey, "base64url")),
    publicKey,
    privateKey,
    createdAt: ms,
    publishedAt: ms,
  };
}

const iso = (ms: number | undefined) => (ms === undefined ? undefined : new Date(ms).toISOString());

/** The text of the key file. It holds private keys: it is written to the key file and goes nowhere else. */
function serialise(set: KeySet): string {
  const content: Record<string, unknown> = { format: FILE_FORMAT, algorithm: ALGORITHM, purpose: PURPOSE };
  for (const role of ROLES) {
    const key = set[role];
    if (key === undefined) continue;
    content[role] = {
      kid: key.kid,
      public_key: key.publicKey,
      private_key: key.privateKey.export({ format: "jwk" }).d,
      created_at: iso(key.createdAt),
      published_at: iso(key.publishedAt),
      activated_at: iso(key.activatedAt),
      retired_at: iso(key.retiredAt),
    };
  }
  return `${JSON.stringify(content, null, 2)}\n`;
}

function parseTime(value: unknown, required: boolean): number | undefined | null {
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string") return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString() === value ? ms : null;
}

function parseKey(value: unknown, role: (typeof ROLES)[number]): Key | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { kid, public_key: x, private_key: d } = value as Record<string, unknown>;
  const record = value as Record<string, unknown>;
  if (typeof x !== "string" || typeof d !== "string" || !KEY_TEXT.test(x) || !KEY_TEXT.test(d)) return null;
  const privateKey = createPrivateKey({ key: { kty: "OKP", crv: ALGORITHM, x, d }, format: "jwk" });
  if (rawPublicKey(privateKey) !== x) return null;
  if (kid !== attestationKid(Buffer.from(x, "base64url"))) return null;
  const createdAt = parseTime(record.created_at, true);
  const publishedAt = parseTime(record.published_at, true);
  const activatedAt = parseTime(record.activated_at, role !== "next");
  const retiredAt = parseTime(record.retired_at, role === "previous");
  if (createdAt == null || publishedAt == null || activatedAt === null || retiredAt === null) return null;
  const key: Key = { kid, publicKey: x, privateKey, createdAt, publishedAt };
  if (activatedAt !== undefined) key.activatedAt = activatedAt;
  if (retiredAt !== undefined) key.retiredAt = retiredAt;
  return key;
}

function parse(text: string): KeySet | null {
  try {
    const content: unknown = JSON.parse(text);
    if (typeof content !== "object" || content === null || Array.isArray(content)) return null;
    const record = content as Record<string, unknown>;
    if (record.format !== FILE_FORMAT || record.algorithm !== ALGORITHM || record.purpose !== PURPOSE) return null;
    const current = parseKey(record.current, "current");
    const next = parseKey(record.next, "next");
    if (current === null || next === null) return null;
    const set: KeySet = { current, next };
    if (record.previous !== undefined) {
      const previous = parseKey(record.previous, "previous");
      if (previous === null) return null;
      set.previous = previous;
    }
    const kids = [set.previous?.kid, current.kid, next.kid].filter((kid) => kid !== undefined);
    return new Set(kids).size === kids.length ? set : null;
  } catch {
    // The reason is dropped on purpose: a parser's message quotes the text it could not read.
    return null;
  }
}

function invalid(file: string): Error {
  return new Error(
    `The attestation key file ${file} is not a valid attestation key file. Restore it from a backup, or remove it ` +
      "to start with new attestation keys (tokens issued before then stop verifying once Shields fetch the bundle).",
  );
}

function load(file: string): KeySet | null {
  let text: string;
  try {
    if ((statSync(file).mode & 0o077) !== 0) chmodSync(file, OWNER_ONLY);
    text = readFileSync(file, "utf8");
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    if (code === "ENOENT") return null;
    throw new Error(`The attestation key file ${file} cannot be read (${code ?? "unknown error"}).`);
  }
  const set = parse(text);
  if (set === null) throw invalid(file);
  return set;
}

/** Writes `text` to a new owner-only temporary file beside `file`, synced; returns its name. */
function writeTemporary(file: string, text: string): string {
  mkdirSync(dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const descriptor = openSync(temporary, "wx", OWNER_ONLY);
  try {
    writeSync(descriptor, text);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  return temporary;
}

/** Creates the key file, never over an existing one (like the signing key). False when it exists. */
function create(file: string, text: string): boolean {
  let temporary: string | undefined;
  try {
    temporary = writeTemporary(file, text);
    linkSync(temporary, file);
    return true;
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    if (code === "EEXIST") return false;
    throw new Error(`The attestation key file ${file} cannot be created (${code ?? "unknown error"}).`);
  } finally {
    if (temporary !== undefined) rmSync(temporary, { force: true });
  }
}

/** Replaces the key file whole, or not at all. Throws an error that names the file and the code only. */
function replace(file: string, text: string): void {
  let temporary: string | undefined;
  try {
    temporary = writeTemporary(file, text);
    renameSync(temporary, file);
    temporary = undefined;
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    throw new Error(`The attestation key file ${file} cannot be written (${code ?? "unknown error"}).`);
  } finally {
    if (temporary !== undefined) rmSync(temporary, { force: true });
  }
}

/** What the schedule asks for at `ms`. A key counts as published no earlier than `servedSince` (process start). */
function schedule(set: KeySet, ms: number, servedSince: number): { drop: boolean; rotate: boolean } {
  const { previous } = set;
  const drop = previous?.retiredAt !== undefined && ms - previous.retiredAt >= PREVIOUS_KEY_KEPT_MS;
  const activatedAt = set.current.activatedAt ?? set.current.publishedAt;
  const published = Math.max(set.next.publishedAt, servedSince);
  const rotate = ms - activatedAt >= ATTESTATION_KEY_ROTATION_MS && ms - published >= NEXT_KEY_LEAD_MS;
  return { drop, rotate };
}

/** The set after the schedule ran at `ms`, or null when nothing is due. Makes a key pair only for a rotation. */
function due(set: KeySet, ms: number, servedSince: number, generate: GenerateKey): KeySet | null {
  const { drop, rotate } = schedule(set, ms, servedSince);
  if (!drop && !rotate) return null;
  const kept: KeySet = drop || set.previous === undefined ? { current: set.current, next: set.next } : set;
  if (!rotate) return kept;
  return {
    previous: { ...kept.current, retiredAt: ms },
    current: { ...kept.next, activatedAt: ms },
    next: newKey(ms, generate),
  };
}

/**
 * The API's attestation key set. With `file`: the set of that file, created once (JSON, mode 0600) and loaded and
 * rewritten (on rotation) from then on. Without: a new set in memory, gone with the process. No error it throws and
 * no line it logs carries any part of a private key.
 */
export function createAttestationKeys(
  options: {
    file?: string | undefined;
    now?: (() => Date) | undefined;
    logger?: Logger | undefined;
    /** Makes new private keys. Default: `generateKeyPairSync("ed25519")`; tests count the calls. */
    generate?: GenerateKey | undefined;
  } = {},
): AttestationKeys {
  const { file } = options;
  const now = options.now ?? (() => new Date());
  const logger = redacting(options.logger ?? consoleLogger);
  const generate = options.generate ?? generateEd25519;
  const startedAt = now().getTime();
  /** No rotation is attempted before this time (ms): set after a failed write. */
  let retryAt = Number.NEGATIVE_INFINITY;

  let set: KeySet;
  const existing = file === undefined ? null : load(file);
  if (existing !== null) {
    set = existing;
  } else {
    const ms = now().getTime();
    const fresh: KeySet = { current: { ...newKey(ms, generate), activatedAt: ms }, next: newKey(ms, generate) };
    if (file === undefined || create(file, serialise(fresh))) {
      set = fresh;
    } else {
      const winner = load(file);
      if (winner === null) throw new Error(`The attestation key file ${file} cannot be created.`);
      set = winner;
    }
  }

  /** The file's set when another process wrote a later one than ours; else null. */
  function laterOnDisk(path: string): KeySet | null {
    let onDisk: KeySet | null;
    try {
      onDisk = load(path);
    } catch {
      // Unreadable or invalid: our own rotation (which replaces the file whole) goes ahead.
      return null;
    }
    if (onDisk === null) return null;
    const theirs = onDisk.current.activatedAt ?? onDisk.current.publishedAt;
    const ours = set.current.activatedAt ?? set.current.publishedAt;
    return theirs > ours ? onDisk : null;
  }

  function refresh(): KeySet {
    const ms = now().getTime();
    if (ms < retryAt) return set;
    const wanted = schedule(set, ms, startedAt);
    if (!wanted.drop && !wanted.rotate) return set;
    if (file !== undefined) {
      const adopted = laterOnDisk(file);
      if (adopted !== null) {
        set = adopted;
        logger.info(`attestation keys adopted from the key file current=${set.current.kid}`);
      }
    }
    const updated = due(set, ms, startedAt, generate);
    if (updated === null) return set;
    if (file !== undefined) {
      try {
        replace(file, serialise(updated));
      } catch (error) {
        // The set stays as it was: a set that is not on disk would be lost on a restart with the tokens it signed.
        // The next attempt waits a minute, so a failing disk costs one warning and one key pair per minute.
        retryAt = ms + ROTATION_RETRY_MS;
        logger.warn(`attestation keys not rotated: ${(error as Error).message}`);
        return set;
      }
    }
    if (updated.current.kid !== set.current.kid) {
      logger.info(`attestation keys rotated current=${updated.current.kid} next=${updated.next.kid}`);
    } else {
      logger.info("attestation keys: previous key dropped");
    }
    set = updated;
    return set;
  }

  return Object.freeze({
    attestationKeys(): BundleAttestationKey[] {
      const current = refresh();
      return [current.previous, current.current, current.next]
        .filter((key): key is Key => key !== undefined)
        .map((key) => ({ kid: key.kid, public_key: key.publicKey }));
    },
    currentKid(): string {
      return refresh().current.kid;
    },
    sign(claims: AttestationClaims): string {
      const { current } = refresh();
      return signAttestationToken(current.privateKey, current.kid, claims);
    },
  });
}
