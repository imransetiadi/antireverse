import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
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
import { keyIdOf } from "@antireverse/protocol/server";

/**
 * Signs Policy Bundles with the API's Ed25519 key. The private key stays inside: a signer shows the
 * public key and its identifier, and nothing else.
 */
export interface Signer {
  /** The first 16 hex characters of the SHA-256 of the raw public key. */
  keyId: string;
  /** The raw public key, 32 bytes, as 43 base64url characters: what Shield is configured with. */
  publicKey: string;
  /** The Ed25519 signature of exactly these bytes: 64 bytes as 86 base64url characters. */
  sign(data: Uint8Array): string;
}

// This is development key handling (plan 02, Global Constraints): a managed key service replaces the file later.

const ALGORITHM = "Ed25519";
const FILE_FORMAT = 1;
/** 32 bytes as base64url: the length of an Ed25519 public key and of its private seed. */
const KEY_TEXT = /^[A-Za-z0-9_-]{43}$/;
const OWNER_ONLY = 0o600;

function signerOf(privateKey: KeyObject): Signer {
  const raw = Buffer.from(rawPublicKey(privateKey), "base64url");
  return Object.freeze({
    keyId: keyIdOf(raw),
    publicKey: raw.toString("base64url"),
    sign: (data: Uint8Array) => sign(null, data, privateKey).toString("base64url"),
  });
}

function rawPublicKey(privateKey: KeyObject): string {
  const { x } = createPublicKey(privateKey).export({ format: "jwk" });
  if (typeof x !== "string" || !KEY_TEXT.test(x)) throw new Error("The signing key is not an Ed25519 key.");
  return x;
}

/** The text of a key file. It holds the private key: it is written to the key file and goes nowhere else. */
function serialise(privateKey: KeyObject): string {
  const { d } = privateKey.export({ format: "jwk" });
  const publicKey = rawPublicKey(privateKey);
  const content = {
    format: FILE_FORMAT,
    algorithm: ALGORITHM,
    key_id: keyIdOf(Buffer.from(publicKey, "base64url")),
    public_key: publicKey,
    private_key: d,
    created_at: new Date().toISOString(),
  };
  return `${JSON.stringify(content, null, 2)}\n`;
}

function parse(text: string): KeyObject | null {
  try {
    const content: unknown = JSON.parse(text);
    if (typeof content !== "object" || content === null) return null;
    const { format, algorithm, public_key: x, private_key: d } = content as Record<string, unknown>;
    if (format !== FILE_FORMAT || algorithm !== ALGORITHM) return null;
    if (typeof x !== "string" || typeof d !== "string" || !KEY_TEXT.test(x) || !KEY_TEXT.test(d)) return null;
    const privateKey = createPrivateKey({ key: { kty: "OKP", crv: ALGORITHM, x, d }, format: "jwk" });
    // The public key in the file is what an operator copies into Shield: it must be the one that verifies.
    return rawPublicKey(privateKey) === x ? privateKey : null;
  } catch {
    // The reason is dropped on purpose: a parser's message quotes the text it could not read.
    return null;
  }
}

/** The key of an existing key file, or null when there is no file. A file that is not a key is an error. */
function load(file: string): KeyObject | null {
  let text: string;
  try {
    // A key file that its group or everyone could read is closed before it is used.
    if ((statSync(file).mode & 0o077) !== 0) chmodSync(file, OWNER_ONLY);
    text = readFileSync(file, "utf8");
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    if (code === "ENOENT") return null;
    throw new Error(`The signing key file ${file} cannot be read (${code ?? "unknown error"}).`);
  }
  const privateKey = parse(text);
  if (privateKey === null) {
    // Never replaced by a new key: every Shield configured with the old public key would refuse its bundles.
    throw new Error(
      `The signing key file ${file} is not a valid signing key. Restore it from a backup, or remove it to ` +
        "start with a new key and give every Shield the new policy public key.",
    );
  }
  return privateKey;
}

/**
 * Writes a new key file, complete or not at all, and never over an existing one: the text goes to a
 * temporary file that only its owner can read and is then linked under the final name, which fails when
 * that name exists. False when it does: another process created the key first, and that key stays.
 */
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
    throw new Error(`The signing key file ${file} cannot be created (${code ?? "unknown error"}).`);
  } finally {
    rmSync(temporary, { force: true });
  }
}

/**
 * The API's signer. With `file`: the key of that file, which is created once (JSON, mode 0600) and loaded
 * from then on, so the key survives a restart. Without: a new key in memory, gone with the process.
 * No error it throws carries any part of a key.
 */
export function createSigner(options: { file?: string } = {}): Signer {
  const { file } = options;
  if (file === undefined) return signerOf(generateKeyPairSync("ed25519").privateKey);

  const existing = load(file);
  if (existing !== null) return signerOf(existing);

  const { privateKey } = generateKeyPairSync("ed25519");
  if (store(file, serialise(privateKey))) return signerOf(privateKey);
  const winner = load(file);
  if (winner === null) throw new Error(`The signing key file ${file} cannot be created.`);
  return signerOf(winner);
}
