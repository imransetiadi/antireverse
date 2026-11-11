import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ENVIRONMENTS, type Environment, EXAMPLE_BUNDLE_PAYLOAD, SigningKeyResponseSchema } from "../src/index.ts";
import {
  bundleAudience,
  type GeneratedKey,
  generateKey,
  hashKey,
  type KeyKind,
  keyIdOf,
  parseKey,
} from "../src/server.ts";

const SCHEME: Record<Environment, string> = {
  production: "ark_prod_",
  staging: "ark_stg_",
  development: "ark_dev_",
};

describe("generateKey", () => {
  it("returns an admin key of the form aro_<43 base64url characters>", () => {
    expect(generateKey("admin").key).toMatch(/^aro_[A-Za-z0-9_-]{43}$/);
  });

  it("returns a Shield key whose scheme names the Environment", () => {
    expect(generateKey("shield", "production").key).toMatch(/^ark_prod_[A-Za-z0-9_-]{43}$/);
    expect(generateKey("shield", "staging").key).toMatch(/^ark_stg_[A-Za-z0-9_-]{43}$/);
    expect(generateKey("shield", "development").key).toMatch(/^ark_dev_[A-Za-z0-9_-]{43}$/);
  });

  it("returns the scheme plus the first 6 secret characters as prefix and the last 4 characters as last4", () => {
    const admin: GeneratedKey = generateKey("admin");
    expect(admin.prefix).toBe(admin.key.slice(0, "aro_".length + 6));
    expect(admin.prefix).toMatch(/^aro_[A-Za-z0-9_-]{6}$/);
    expect(admin.last4).toBe(admin.key.slice(-4));

    for (const environment of ENVIRONMENTS) {
      const shield = generateKey("shield", environment);
      expect(shield.prefix).toBe(shield.key.slice(0, SCHEME[environment].length + 6));
      expect(shield.prefix.startsWith(SCHEME[environment])).toBe(true);
      expect(shield.last4).toBe(shield.key.slice(-4));
      expect(Object.keys(shield).sort()).toEqual(["key", "last4", "prefix"]);
    }
  });

  it("returns 1,000 unique keys", () => {
    const keys = new Set(Array.from({ length: 1000 }, () => generateKey("admin").key));
    expect(keys.size).toBe(1000);
  });

  it("refuses a Shield key without a known Environment", () => {
    // @ts-expect-error a Shield key needs an Environment
    expect(() => generateKey("shield")).toThrow(TypeError);
    // @ts-expect-error not an Environment
    expect(() => generateKey("shield", "qa")).toThrow(TypeError);
  });
});

describe("parseKey", () => {
  it("recognises an admin key", () => {
    expect(parseKey(generateKey("admin").key)).toEqual({ kind: "admin" });
  });

  it("recognises a Shield key and its Environment", () => {
    for (const environment of ENVIRONMENTS) {
      expect(parseKey(generateKey("shield", environment).key)).toEqual({ kind: "shield", environment });
    }
  });

  it("names the two kinds of key", () => {
    const kinds: KeyKind[] = ["admin", "shield"];
    expect(kinds).toContain(parseKey(generateKey("admin").key)?.kind);
  });

  it("returns null for anything that is not a well-formed key", () => {
    const secret = "A".repeat(43);
    const admin = generateKey("admin").key;
    const malformed: unknown[] = [
      "",
      "aro_short",
      `ark_xxx_${secret}`,
      42,
      undefined,
      null,
      {},
      [admin],
      `aro_${secret}A`, // 44 secret characters
      `aro_${secret.slice(1)}`, // 42 secret characters
      `ARO_${secret}`,
      `ark_${secret}`, // no Environment
      `ark_prod${secret}`,
      `aro_${"A".repeat(42)}+`, // not base64url
      ` ${admin}`,
      `${admin}\n`,
      `Bearer ${admin}`,
    ];
    for (const value of malformed) {
      expect(parseKey(value), JSON.stringify(value)).toBeNull();
    }
  });
});

describe("hashKey", () => {
  it("returns 64 lowercase hex characters", () => {
    expect(hashKey(generateKey("admin").key)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is SHA-256", () => {
    expect(hashKey("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("is deterministic and differs between keys", () => {
    const a = generateKey("admin").key;
    const b = generateKey("admin").key;
    expect(hashKey(a)).toBe(hashKey(a));
    expect(hashKey(a)).not.toBe(hashKey(b));
  });
});

describe("bundleAudience", () => {
  it("returns 32 lowercase hex characters", () => {
    for (const environment of ENVIRONMENTS) {
      expect(bundleAudience(generateKey("shield", environment).key)).toMatch(/^[0-9a-f]{32}$/);
    }
  });

  it("is the first 32 hex characters of the SHA-256 of the key", () => {
    const key = generateKey("shield", "production").key;
    expect(bundleAudience(key)).toBe(hashKey(key).slice(0, 32));
    expect(bundleAudience("abc")).toBe("ba7816bf8f01cfea414140de5dae2223");
  });

  it("is deterministic and differs between keys", () => {
    const a = generateKey("shield", "production").key;
    const b = generateKey("shield", "production").key;
    expect(bundleAudience(a)).toBe(bundleAudience(a));
    expect(bundleAudience(a)).not.toBe(bundleAudience(b));
    const audiences = new Set(Array.from({ length: 1000 }, () => bundleAudience(generateKey("shield", "staging").key)));
    expect(audiences.size).toBe(1000);
  });

  it("never contains the key or a part of it", () => {
    const key = generateKey("shield", "development").key;
    expect(key).not.toContain(bundleAudience(key));
    expect(bundleAudience(key)).not.toContain(key.slice(-4));
  });

  it("is the audience of the documented bundle for the synthetic key it names", () => {
    expect(bundleAudience(`ark_dev_${"A".repeat(43)}`)).toBe(EXAMPLE_BUNDLE_PAYLOAD.audience);
  });
});

describe("keyIdOf", () => {
  const rawPublicKey = (): Uint8Array =>
    Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x as string, "base64url");

  it("returns 16 lowercase hex characters", () => {
    expect(keyIdOf(rawPublicKey())).toMatch(/^[0-9a-f]{16}$/);
  });

  it("is the first 16 hex characters of the SHA-256 of the raw public key", () => {
    const raw = rawPublicKey();
    expect(keyIdOf(raw)).toBe(createHash("sha256").update(raw).digest("hex").slice(0, 16));
    expect(keyIdOf(new Uint8Array(32))).toBe("66687aadf862bd77");
  });

  it("is deterministic, differs between keys and reads the bytes, not the container", () => {
    const a = rawPublicKey();
    const b = rawPublicKey();
    expect(keyIdOf(a)).toBe(keyIdOf(a));
    expect(keyIdOf(a)).not.toBe(keyIdOf(b));
    expect(keyIdOf(new Uint8Array(a))).toBe(keyIdOf(a));
    const padded = new Uint8Array(40);
    padded.set(a, 4);
    expect(keyIdOf(padded.subarray(4, 36))).toBe(keyIdOf(a));
  });

  it("fits the key identifier of the signing key response", () => {
    const raw = rawPublicKey();
    const body = { key_id: keyIdOf(raw), algorithm: "Ed25519", public_key: Buffer.from(raw).toString("base64url") };
    expect(SigningKeyResponseSchema.parse(body)).toEqual(body);
  });

  it("refuses anything but the 32 raw bytes of an Ed25519 public key", () => {
    const der = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" });
    expect(der).toHaveLength(44);
    const refusal = new TypeError("An Ed25519 public key is 32 raw bytes.");
    expect(() => keyIdOf(der)).toThrow(refusal);
    expect(() => keyIdOf(new Uint8Array(0))).toThrow(refusal);
    expect(() => keyIdOf(new Uint8Array(31))).toThrow(refusal);
    expect(() => keyIdOf(new Uint8Array(33))).toThrow(refusal);
    // @ts-expect-error the encoded key is not the raw key
    expect(() => keyIdOf("A".repeat(43))).toThrow(refusal);
    // @ts-expect-error a list of numbers is not a byte array
    expect(() => keyIdOf(Array.from({ length: 32 }, () => 0))).toThrow(refusal);
  });
});
