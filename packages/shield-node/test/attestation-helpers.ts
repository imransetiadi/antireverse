// Shared by the attestation tests. Not a test file: Vitest collects only *.test.ts.
// Tokens are made here with node:crypto as the API makes them, and also in shapes the API never makes (another alg,
// a header without kid, a tampered payload), so that each rejection can be shown. Synthetic keys and claims only.
import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { type AttestationClaims, type BundleAttestationKey, EXAMPLE_ATTESTATION_CLAIMS } from "@antireverse/protocol";
import { attestationKid, signAttestationToken } from "@antireverse/protocol/server";

export const APP_ID = "app_89abcdef0123456789abcdef";
export const OTHER_APP_ID = "app_0123456789abcdef01234567";

export interface AttestationKeyPair {
  kid: string;
  /** The raw public key as 43 base64url characters, as the bundle carries it. */
  publicKey: string;
  privateKey: KeyObject;
  /** The entry of `attestation_keys`. */
  entry: BundleAttestationKey;
}

export function createAttestationKey(): AttestationKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "jwk" }).x as string;
  const kid = attestationKid(new Uint8Array(Buffer.from(raw, "base64url")));
  return { kid, publicKey: raw, privateKey, entry: { kid, public_key: raw } };
}

/** Claims for `APP_ID` issued at `iatS`, valid for 300 s. `n` gives a distinct jti. */
export function claims(iatS: number, overrides: Partial<AttestationClaims> = {}, n = 1): AttestationClaims {
  return {
    ...EXAMPLE_ATTESTATION_CLAIMS,
    sig: [...EXAMPLE_ATTESTATION_CLAIMS.sig],
    cnf: { ...EXAMPLE_ATTESTATION_CLAIMS.cnf },
    aud: APP_ID,
    iat: iatS,
    exp: iatS + 300,
    jti: n.toString(16).padStart(32, "0"),
    ...overrides,
  };
}

/** A token as the API signs it (the protocol's reference signer). */
export function token(key: AttestationKeyPair, given: AttestationClaims): string {
  return signAttestationToken(key.privateKey, key.kid, given);
}

const encode = (value: unknown): string =>
  Buffer.from(typeof value === "string" ? value : JSON.stringify(value), "utf8").toString("base64url");

/**
 * A token of any shape, signed with Ed25519 over `<header>.<payload>` as given. `header` and `payload` are JSON
 * values, or strings used as the JSON text.
 */
export function craft(key: AttestationKeyPair, header: unknown, payload: unknown): string {
  const input = `${encode(header)}.${encode(payload)}`;
  return `${input}.${sign(null, Buffer.from(input, "ascii"), key.privateKey).toString("base64url")}`;
}

/** The header the API writes. */
export function header(key: AttestationKeyPair, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { alg: "EdDSA", typ: "JWT", kid: key.kid, ...overrides };
}
