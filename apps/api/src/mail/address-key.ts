import { createHmac, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

// The key of the confirmation-mail count (slice 06b, Jev review change 1): the count is kept across Organizations by
// a hash of the address, and an unkeyed hash of an address can be reversed with a list of addresses. So the hash is
// HMAC-SHA-256 under a 32-byte server secret, kept beside the API's other secrets (like the signing key: one JSON
// file, mode 0600, created once on the first start, never overwritten). The secret is never logged or returned.

export interface AddressHasher {
  /** HMAC-SHA-256 of the (lower-case) address under the server secret, as 64 lowercase hex characters. */
  hash(address: string): string;
}

const FILE_FORMAT = 1;
const PURPOSE = "confirmation-mail-address-hmac";
const SECRET_TEXT = /^[A-Za-z0-9_-]{43}$/;
const OWNER_ONLY = 0o600;

function hasherOf(secret: Buffer): AddressHasher {
  return Object.freeze({
    hash: (address: string) => createHmac("sha256", secret).update(address, "utf8").digest("hex"),
  });
}

function parse(text: string): Buffer | null {
  try {
    const content: unknown = JSON.parse(text);
    if (typeof content !== "object" || content === null) return null;
    const { format, purpose, secret } = content as Record<string, unknown>;
    if (format !== FILE_FORMAT || purpose !== PURPOSE || typeof secret !== "string" || !SECRET_TEXT.test(secret)) {
      return null;
    }
    return Buffer.from(secret, "base64url");
  } catch {
    // The parser's message would quote the text: dropped.
    return null;
  }
}

function load(file: string): Buffer | null {
  let text: string;
  try {
    if ((statSync(file).mode & 0o077) !== 0) chmodSync(file, OWNER_ONLY);
    text = readFileSync(file, "utf8");
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    if (code === "ENOENT") return null;
    throw new Error(`The address key file ${file} cannot be read (${code ?? "unknown error"}).`);
  }
  const secret = parse(text);
  if (secret === null) {
    throw new Error(
      `The address key file ${file} is not a valid address key. Restore it from a backup, or remove it to start ` +
        "with a new key (the confirmation-mail counts of the day then start again).",
    );
  }
  return secret;
}

/** Writes the file complete or not at all, never over an existing one. False when another process wrote it first. */
function store(file: string, text: string): boolean {
  mkdirSync(dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    const descriptor = openSync(temporary, "wx", OWNER_ONLY);
    try {
      writeSync(descriptor, text);
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    linkSync(temporary, file);
    return true;
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    if (code === "EEXIST") return false;
    throw new Error(`The address key file ${file} cannot be created (${code ?? "unknown error"}).`);
  } finally {
    rmSync(temporary, { force: true });
  }
}

/**
 * The address hasher. With `file`: the secret of that file, created once (JSON, mode 0600) and loaded on every later
 * start. Without: a secret in memory, gone on close (tests, and an API without a data directory).
 */
export function createAddressHasher(options: { file?: string } = {}): AddressHasher {
  const { file } = options;
  if (file === undefined) return hasherOf(randomBytes(32));
  const existing = load(file);
  if (existing !== null) return hasherOf(existing);
  const secret = randomBytes(32);
  const text = `${JSON.stringify(
    {
      format: FILE_FORMAT,
      purpose: PURPOSE,
      secret: secret.toString("base64url"),
      created_at: new Date().toISOString(),
    },
    null,
    2,
  )}\n`;
  if (store(file, text)) return hasherOf(secret);
  const winner = load(file);
  if (winner === null) throw new Error(`The address key file ${file} cannot be created.`);
  return hasherOf(winner);
}
