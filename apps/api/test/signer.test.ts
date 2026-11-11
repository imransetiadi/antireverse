import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { SigningKeyResponseSchema } from "@antireverse/protocol";
import { keyIdOf } from "@antireverse/protocol/server";
import { afterAll, describe, expect, it } from "vitest";
import { createSigner } from "../src/signer.ts";
import { verifySignature } from "./helpers.ts";

const mode = (file: string): number => statSync(file).mode & 0o777;

describe("signer", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-signer-"));
  let files = 0;
  const freshFile = (): string => join(root, `key-${++files}`, "signing-key.json");

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("signs with an Ed25519 key whose public half verifies the signature", () => {
    const signer = createSigner();

    expect(
      SigningKeyResponseSchema.safeParse({
        key_id: signer.keyId,
        algorithm: "Ed25519",
        public_key: signer.publicKey,
      }).success,
    ).toBe(true);
    expect(signer.keyId).toBe(keyIdOf(Buffer.from(signer.publicKey, "base64url")));

    const text = '{"format":1,"rules":[]}';
    const signature = signer.sign(Buffer.from(text, "utf8"));
    expect(signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(verifySignature(signer.publicKey, text, signature)).toBe(true);
    // One changed byte, or another key, and the signature no longer verifies.
    expect(verifySignature(signer.publicKey, '{"format":1,"rules":[] }', signature)).toBe(false);
    expect(verifySignature(createSigner().publicKey, text, signature)).toBe(false);
  });

  it("makes a new key each time when it has no file", () => {
    expect(createSigner().publicKey).not.toBe(createSigner().publicKey);
    expect(createSigner({}).keyId).not.toBe(createSigner({}).keyId);
  });

  it("creates the key file once, readable by its owner only, and loads the same key from then on", () => {
    const file = freshFile();

    const first = createSigner({ file });
    expect(mode(file)).toBe(0o600);
    // Nothing but the key file is left behind: no temporary file that holds a private key.
    expect(readdirSync(join(file, ".."))).toEqual(["signing-key.json"]);
    const written = readFileSync(file, "utf8");

    const second = createSigner({ file });
    expect(second.publicKey).toBe(first.publicKey);
    expect(second.keyId).toBe(first.keyId);
    expect(readFileSync(file, "utf8")).toBe(written);
    expect(verifySignature(first.publicKey, "policy", second.sign(Buffer.from("policy", "utf8")))).toBe(true);
  });

  it("closes a key file that others could read", () => {
    const file = freshFile();
    const first = createSigner({ file });
    chmodSync(file, 0o644);

    const second = createSigner({ file });

    expect(mode(file)).toBe(0o600);
    expect(second.publicKey).toBe(first.publicKey);
  });

  it("shows the public key and the key identifier, and nothing of the private key", () => {
    const file = freshFile();
    const signer = createSigner({ file });
    const stored = JSON.parse(readFileSync(file, "utf8")) as Record<string, string>;
    const privateKey = stored.private_key;
    if (privateKey === undefined) throw new Error("The key file has no private key.");
    expect(privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(stored.public_key).toBe(signer.publicKey);

    expect(Object.keys(signer).sort()).toEqual(["keyId", "publicKey", "sign"]);
    expect(JSON.stringify(signer)).not.toContain(privateKey);
    expect(inspect(signer, { depth: null, showHidden: true, getters: true })).not.toContain(privateKey);
    expect(String(signer.sign)).not.toContain(privateKey);
  });

  it.each([
    ["text that is not JSON", (key: Record<string, string>) => `private_key=${key.private_key}`],
    ["a truncated file", (key: Record<string, string>) => JSON.stringify(key).slice(0, -20)],
    ["an empty file", () => ""],
    [
      "a file without a private key",
      (key: Record<string, string>) => JSON.stringify({ ...key, private_key: undefined }),
    ],
    [
      "a private key of the wrong length",
      (key: Record<string, string>) => JSON.stringify({ ...key, private_key: `${key.private_key}AAAA` }),
    ],
    [
      "a public key that does not belong to the private key",
      (key: Record<string, string>) => JSON.stringify({ ...key, public_key: createSigner().publicKey }),
    ],
    ["another algorithm", (key: Record<string, string>) => JSON.stringify({ ...key, algorithm: "RSA" })],
    ["a JSON array", (key: Record<string, string>) => JSON.stringify([key])],
  ])("refuses %s as a key file, without quoting or replacing it", (_label, corrupt) => {
    const file = freshFile();
    createSigner({ file });
    const key = JSON.parse(readFileSync(file, "utf8")) as Record<string, string>;
    const content = corrupt(key);
    writeFileSync(file, content);

    let message = "";
    try {
      createSigner({ file });
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).toContain(file);
    expect(message).toMatch(/is not a valid signing key/);
    // The message goes to the start-up log: it must not carry any part of the key.
    if (key.private_key !== undefined) expect(message).not.toContain(key.private_key.slice(0, 8));
    // A broken key file is the operator's to repair: a new key in its place would silently orphan every Shield.
    expect(readFileSync(file, "utf8")).toBe(content);
  });
});
