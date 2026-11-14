// The gate key and the report signature (slice 18e). Ed25519 through node:crypto. The key file lives outside the
// repository (AR_GATE_KEY_FILE, default $XDG_CONFIG_HOME/airverse/gate-key.json or ~/.config/airverse/gate-key.json),
// is created on first use with mode 0600 in a 0700 directory, and is refused when others can read it. The report
// embeds the public key and its fingerprint (SHA-256 of the raw 32-byte key); the private key never leaves the file.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign,
  verify,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { REPO_ROOT } from "./paths.ts";

export interface GateKey {
  file: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** Base64url of the raw 32-byte public key. */
  publicRaw: string;
  fingerprint: string;
  created: boolean;
}

export function defaultKeyFile(env: Record<string, string | undefined>): string {
  if (env.AR_GATE_KEY_FILE) return env.AR_GATE_KEY_FILE;
  const config = env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(config, "airverse", "gate-key.json");
}

/**
 * Whether `path` lies inside the repository (review M5). Walks from the path's nearest existing ancestor up to the
 * file system root and compares each directory's device and inode with the repository root's, so a symlink, a
 * differently cased path on a case-insensitive volume, or a directory named `..something` cannot hide it.
 */
function insideRepo(path: string): boolean {
  const repo = statSync(REPO_ROOT);
  let dir = resolve(path);
  while (!existsSync(dir)) {
    const parent = dirname(dir);
    if (parent === dir) return false;
    dir = parent;
  }
  dir = realpathSync.native(dir);
  for (;;) {
    const here = statSync(dir);
    if (here.dev === repo.dev && here.ino === repo.ino) return true;
    const parent = dirname(dir);
    if (parent === dir) return false;
    dir = parent;
  }
}

const rawOf = (publicKey: KeyObject) => (publicKey.export({ format: "jwk" }) as { x: string }).x;
const fingerprintOf = (raw: string) => createHash("sha256").update(Buffer.from(raw, "base64url")).digest("hex");

export function loadOrCreateKey(file: string): GateKey {
  if (insideRepo(file)) throw new Error(`the gate key file must not be inside the repository: ${file}`);
  let created = false;
  if (!existsSync(file)) {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const body = { version: 1, algorithm: "Ed25519", created_at: new Date().toISOString(), private_key: pem };
    writeFileSync(file, `${JSON.stringify(body, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    created = true;
  }
  const mode = statSync(file).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(`the gate key file ${file} has mode ${mode.toString(8)}; it must be 600 (chmod 600 it)`);
  }
  const stored = JSON.parse(readFileSync(file, "utf8")) as { private_key?: string };
  if (typeof stored.private_key !== "string") throw new Error(`the gate key file ${file} holds no private key`);
  const privateKey = createPrivateKey(stored.private_key);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error(`the gate key file ${file} is not an Ed25519 key`);
  const publicKey = createPublicKey(privateKey);
  const publicRaw = rawOf(publicKey);
  return { file, privateKey, publicKey, publicRaw, fingerprint: fingerprintOf(publicRaw), created };
}

/** JSON with keys sorted at every depth: the bytes that are signed. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

export interface Signature {
  algorithm: "Ed25519";
  /** Base64url of the raw public key. */
  public_key: string;
  /** SHA-256 hex of the raw public key. */
  fingerprint: string;
  /** What was signed. */
  payload: "canonical JSON of the report without `signature`";
  value: string;
}

export function signReport<T extends object>(report: T, key: GateKey): T & { signature: Signature } {
  const { signature: _drop, ...body } = report as T & { signature?: unknown };
  const value = sign(null, Buffer.from(canonicalJson(body)), key.privateKey).toString("base64url");
  return {
    ...(body as T),
    signature: {
      algorithm: "Ed25519",
      public_key: key.publicRaw,
      fingerprint: key.fingerprint,
      payload: "canonical JSON of the report without `signature`",
      value,
    },
  };
}

export type Verification = { ok: true; fingerprint: string } | { ok: false; reason: string };

export function verifyReport(report: unknown, options: { expectedFingerprint?: string } = {}): Verification {
  if (report === null || typeof report !== "object") return { ok: false, reason: "not a report" };
  const { signature, ...body } = report as { signature?: Partial<Signature> };
  if (!signature || typeof signature !== "object") return { ok: false, reason: "no signature" };
  if (
    signature.algorithm !== "Ed25519" ||
    typeof signature.public_key !== "string" ||
    typeof signature.value !== "string"
  ) {
    return { ok: false, reason: "malformed signature" };
  }
  if (fingerprintOf(signature.public_key) !== signature.fingerprint) {
    return { ok: false, reason: "fingerprint does not match the public key" };
  }
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: signature.public_key }, format: "jwk" });
  } catch {
    return { ok: false, reason: "malformed public key" };
  }
  const valid = verify(null, Buffer.from(canonicalJson(body)), publicKey, Buffer.from(signature.value, "base64url"));
  if (!valid) return { ok: false, reason: "signature does not verify" };
  if (options.expectedFingerprint !== undefined && options.expectedFingerprint !== signature.fingerprint) {
    return { ok: false, reason: "signed by another key" };
  }
  return { ok: true, fingerprint: signature.fingerprint };
}
