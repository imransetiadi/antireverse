import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import {
  ATTESTATION_LIMITS,
  type AttestationClaims,
  BundleAttestationKeySchema,
  EXAMPLE_ATTESTATION_CLAIMS,
} from "@antireverse/protocol";
import { attestationKid, verifyAttestationToken } from "@antireverse/protocol/server";
import { afterAll, describe, expect, it } from "vitest";
import {
  ATTESTATION_KEY_ROTATION_MS,
  type AttestationKeys,
  createAttestationKeys,
  NEXT_KEY_LEAD_MS,
  PREVIOUS_KEY_KEPT_MS,
} from "../src/attestation/keys.ts";
import { captureLogger } from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const mode = (file: string): number => statSync(file).mode & 0o777;

interface StoredKey {
  kid: string;
  public_key: string;
  private_key: string;
  created_at: string;
  published_at: string;
  activated_at?: string;
  retired_at?: string;
}
interface StoredSet {
  format: number;
  algorithm: string;
  purpose: string;
  previous?: StoredKey;
  current: StoredKey;
  next: StoredKey;
}

const read = (file: string): StoredSet => JSON.parse(readFileSync(file, "utf8")) as StoredSet;

/** Claims issued at `ms` for the example App, valid 300 s. */
function claimsAt(ms: number): AttestationClaims {
  const iat = Math.floor(ms / 1_000);
  return { ...EXAMPLE_ATTESTATION_CLAIMS, iat, exp: iat + ATTESTATION_LIMITS.ttlS };
}

function verify(token: string, keys: AttestationKeys, ms: number) {
  return verifyAttestationToken(token, keys.attestationKeys(), {
    appId: EXAMPLE_ATTESTATION_CLAIMS.aud,
    nowS: Math.floor(ms / 1_000),
  });
}

function kidOf(token: string): string {
  const header = JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8")) as { kid: string };
  return header.kid;
}

describe("attestation keys", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-attestation-keys-"));
  let files = 0;
  const freshFile = (): string => join(root, `set-${++files}`, "attestation-keys.json");

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("rotates daily, keeps the previous key 24 hours and needs the next key published an hour", () => {
    expect(ATTESTATION_KEY_ROTATION_MS).toBe(DAY);
    expect(PREVIOUS_KEY_KEPT_MS).toBe(DAY);
    expect(NEXT_KEY_LEAD_MS).toBe(HOUR);
  });

  it("starts with a current and a next key, public halves only, each kid derived from its raw key", () => {
    const clock = { ms: T0 };
    const keys = createAttestationKeys({ now: () => new Date(clock.ms) });

    const published = keys.attestationKeys();
    expect(published).toHaveLength(2);
    for (const key of published) {
      expect(Object.keys(key).sort()).toEqual(["kid", "public_key"]);
      expect(BundleAttestationKeySchema.parse(key)).toEqual(key);
      expect(key.kid).toBe(attestationKid(Buffer.from(key.public_key, "base64url")));
    }
    expect(new Set(published.map((key) => key.kid)).size).toBe(2);
    // Order: (previous,) current, next. The current key signs.
    expect(keys.currentKid()).toBe(published[0]?.kid);

    const token = keys.sign(claimsAt(clock.ms));
    expect(kidOf(token)).toBe(published[0]?.kid);
    expect(verify(token, keys, clock.ms)).toEqual({ status: "valid", claims: claimsAt(clock.ms) });
  });

  it("makes new keys each time when it has no file", () => {
    const a = createAttestationKeys().attestationKeys();
    const b = createAttestationKeys().attestationKeys();
    expect(a.map((key) => key.kid)).not.toEqual(b.map((key) => key.kid));
  });

  it("promotes next to current after 24 hours, makes a new next and keeps the previous key for 24 hours", () => {
    const clock = { ms: T0 };
    const keys = createAttestationKeys({ now: () => new Date(clock.ms) });
    const [first, second] = keys.attestationKeys();

    clock.ms = T0 + DAY - 1;
    expect(keys.attestationKeys()).toEqual([first, second]);
    const lastOfFirst = keys.sign(claimsAt(clock.ms));
    expect(kidOf(lastOfFirst)).toBe(first?.kid);

    clock.ms = T0 + DAY;
    const rotated = keys.attestationKeys();
    expect(rotated).toHaveLength(3);
    expect(rotated[0]).toEqual(first);
    expect(rotated[1]).toEqual(second);
    const third = rotated[2];
    expect(third?.kid).not.toBe(first?.kid);
    expect(third?.kid).not.toBe(second?.kid);
    expect(keys.currentKid()).toBe(second?.kid);
    const firstOfSecond = keys.sign(claimsAt(clock.ms));
    expect(kidOf(firstOfSecond)).toBe(second?.kid);
    // A token signed just before the rotation still verifies with the set after it: its key is the previous one.
    expect(verify(lastOfFirst, keys, clock.ms).status).toBe("valid");
    expect(verify(firstOfSecond, keys, clock.ms).status).toBe("valid");

    clock.ms = T0 + 2 * DAY - 1;
    expect(keys.attestationKeys()).toEqual(rotated);

    // The second rotation: the first key, retired 24 hours ago, is dropped; never more than 3 keys.
    clock.ms = T0 + 2 * DAY;
    const again = keys.attestationKeys();
    expect(again).toHaveLength(ATTESTATION_LIMITS.keysMax);
    expect(again.slice(0, 2)).toEqual([second, third]);
    expect(again.map((key) => key.kid)).not.toContain(first?.kid);
    expect(keys.currentKid()).toBe(third?.kid);
    expect(verify(lastOfFirst, keys, clock.ms).status).toBe("invalid");
  });

  it("signs with a key only after it was published for at least an hour", () => {
    const clock = { ms: T0 };
    const keys = createAttestationKeys({ now: () => new Date(clock.ms) });
    // Every kid seen in the set, with the first moment it was seen.
    const firstSeen = new Map<string, number>();
    for (let ms = T0; ms <= T0 + 5 * DAY; ms += HOUR / 2) {
      clock.ms = ms;
      for (const key of keys.attestationKeys()) if (!firstSeen.has(key.kid)) firstSeen.set(key.kid, ms);
      const kid = kidOf(keys.sign(claimsAt(ms)));
      // The two keys of the very first start are the exception: nothing could have been published before them.
      if (firstSeen.get(kid) !== T0) expect(ms - (firstSeen.get(kid) ?? ms)).toBeGreaterThanOrEqual(NEXT_KEY_LEAD_MS);
      expect(keys.attestationKeys().length).toBeLessThanOrEqual(ATTESTATION_LIMITS.keysMax);
    }
    expect(firstSeen.size).toBe(7);
  });

  it("waits with the rotation while the next key has been published for less than an hour", () => {
    const file = freshFile();
    const clock = { ms: T0 };
    createAttestationKeys({ file, now: () => new Date(clock.ms) });
    const stored = read(file);
    // As if the next key had been published only 30 minutes before the rotation is due.
    const late = new Date(T0 + DAY - HOUR / 2).toISOString();
    writeFileSync(file, JSON.stringify({ ...stored, next: { ...stored.next, published_at: late } }));

    // This process started when the next key was published, so it has served it since.
    clock.ms = T0 + DAY - HOUR / 2;
    const keys = createAttestationKeys({ file, now: () => new Date(clock.ms) });
    clock.ms = T0 + DAY;
    expect(keys.currentKid()).toBe(stored.current.kid);
    clock.ms = T0 + DAY + HOUR / 2 - 1;
    expect(keys.currentKid()).toBe(stored.current.kid);
    expect(keys.attestationKeys()).toHaveLength(2);

    clock.ms = T0 + DAY + HOUR / 2;
    expect(keys.currentKid()).toBe(stored.next.kid);
    expect(
      keys
        .attestationKeys()
        .map((key) => key.kid)
        .slice(0, 2),
    ).toEqual([stored.current.kid, stored.next.kid]);
  });

  it("does not rotate when the clock goes back", () => {
    const clock = { ms: T0 };
    const keys = createAttestationKeys({ now: () => new Date(clock.ms) });
    const before = keys.attestationKeys();
    clock.ms = T0 - 3 * DAY;
    expect(keys.attestationKeys()).toEqual(before);
    clock.ms = T0 + DAY - 1;
    expect(keys.attestationKeys()).toEqual(before);
  });

  it("creates its file once, readable by its owner only, and loads the same set from then on", () => {
    const file = freshFile();
    const clock = { ms: T0 };
    const first = createAttestationKeys({ file, now: () => new Date(clock.ms) });
    expect(mode(file)).toBe(0o600);
    expect(readdirSync(join(file, ".."))).toEqual(["attestation-keys.json"]);

    const stored = read(file);
    expect(stored.format).toBe(1);
    expect(stored.algorithm).toBe("Ed25519");
    expect(stored.purpose).toBe("attestation");
    expect(stored.previous).toBeUndefined();
    expect(stored.current.private_key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(stored.next.private_key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(stored.current.published_at).toBe(new Date(T0).toISOString());
    expect(stored.current.activated_at).toBe(new Date(T0).toISOString());
    expect(stored.next.published_at).toBe(new Date(T0).toISOString());
    expect(first.attestationKeys()).toEqual([
      { kid: stored.current.kid, public_key: stored.current.public_key },
      { kid: stored.next.kid, public_key: stored.next.public_key },
    ]);

    const second = createAttestationKeys({ file, now: () => new Date(clock.ms) });
    expect(second.attestationKeys()).toEqual(first.attestationKeys());
    const token = second.sign(claimsAt(clock.ms));
    expect(verify(token, first, clock.ms).status).toBe("valid");
  });

  it("writes every rotation to its file, still owner-only, and a restart continues the schedule", () => {
    const file = freshFile();
    const clock = { ms: T0 };
    const keys = createAttestationKeys({ file, now: () => new Date(clock.ms) });
    const before = read(file);

    clock.ms = T0 + DAY + 5;
    const rotated = keys.attestationKeys();
    const after = read(file);
    expect(mode(file)).toBe(0o600);
    expect(readdirSync(join(file, ".."))).toEqual(["attestation-keys.json"]);
    expect(after.previous?.kid).toBe(before.current.kid);
    expect(after.previous?.retired_at).toBe(new Date(clock.ms).toISOString());
    expect(after.current.kid).toBe(before.next.kid);
    expect(after.current.activated_at).toBe(new Date(clock.ms).toISOString());
    expect(after.next.published_at).toBe(new Date(clock.ms).toISOString());

    const restarted = createAttestationKeys({ file, now: () => new Date(clock.ms) });
    expect(restarted.attestationKeys()).toEqual(rotated);
    clock.ms = T0 + 2 * DAY;
    expect(restarted.currentKid()).toBe(before.next.kid);
    clock.ms = T0 + 2 * DAY + 5;
    expect(restarted.currentKid()).toBe(after.next.kid);
  });

  it("after a long stop, promotes next only once this process has served it for an hour, then rotates once", () => {
    const file = freshFile();
    createAttestationKeys({ file, now: () => new Date(T0) });
    const before = read(file);

    const clock = { ms: T0 + 10 * DAY };
    const keys = createAttestationKeys({ file, now: () => new Date(clock.ms) });
    // Next was never served by a running API since the stop: no Shield can hold it yet.
    expect(keys.currentKid()).toBe(before.current.kid);
    expect(keys.attestationKeys().map((key) => key.kid)).toEqual([before.current.kid, before.next.kid]);
    clock.ms = T0 + 10 * DAY + HOUR - 1;
    expect(keys.currentKid()).toBe(before.current.kid);
    clock.ms = T0 + 10 * DAY + HOUR;
    expect(keys.currentKid()).toBe(before.next.kid);
    expect(
      keys
        .attestationKeys()
        .map((key) => key.kid)
        .slice(0, 2),
    ).toEqual([before.current.kid, before.next.kid]);
    // The file keeps the original publication time of each key.
    expect(read(file).current.published_at).toBe(before.next.published_at);
  });

  it("keeps two processes on one key file on one set: the second adopts the rotation the first wrote", () => {
    const file = freshFile();
    const clock = { ms: T0 };
    const a = createAttestationKeys({ file, now: () => new Date(clock.ms) });
    const b = createAttestationKeys({ file, now: () => new Date(clock.ms) });
    expect(b.attestationKeys()).toEqual(a.attestationKeys());

    for (const [first, second] of [
      [a, b],
      [b, a],
      [a, b],
    ] as const) {
      clock.ms += DAY;
      const rotated = first.attestationKeys();
      expect(second.attestationKeys()).toEqual(rotated);
      expect(second.currentKid()).toBe(first.currentKid());
      const token = second.sign(claimsAt(clock.ms));
      expect(kidOf(token)).toBe(first.currentKid());
      expect(verify(token, first, clock.ms).status).toBe("valid");
      expect(read(file).current.kid).toBe(first.currentKid());
    }
  });

  it("backs off for a minute after a failed rotation write: one warning and one new key pair per minute", () => {
    const file = freshFile();
    const directory = join(file, "..");
    const clock = { ms: T0 };
    const logger = captureLogger();
    let generated = 0;
    const generate = () => {
      generated++;
      return generateKeyPairSync("ed25519").privateKey;
    };
    const keys = createAttestationKeys({ file, now: () => new Date(clock.ms), logger, generate });
    const first = keys.currentKid();
    const made = generated;
    chmodSync(directory, 0o500);
    try {
      clock.ms = T0 + DAY;
      for (let i = 0; i < 100; i++) {
        clock.ms += 100;
        expect(kidOf(keys.sign(claimsAt(clock.ms)))).toBe(first);
      }
      expect(generated - made).toBe(1);
      expect(logger.lines.filter((line) => line.includes("not rotated"))).toHaveLength(1);

      // A minute after the failure, one more attempt.
      clock.ms = T0 + DAY + 100 + MINUTE;
      for (let i = 0; i < 100; i++) keys.sign(claimsAt(clock.ms));
      expect(generated - made).toBe(2);
      expect(logger.lines.filter((line) => line.includes("not rotated"))).toHaveLength(2);
    } finally {
      chmodSync(directory, 0o700);
    }
    clock.ms = T0 + DAY + 3 * MINUTE;
    expect(keys.currentKid()).not.toBe(first);
    expect(read(file).previous?.kid).toBe(first);
  });

  it("closes a key file that others could read", () => {
    const file = freshFile();
    const first = createAttestationKeys({ file, now: () => new Date(T0) });
    chmodSync(file, 0o644);
    const second = createAttestationKeys({ file, now: () => new Date(T0) });
    expect(mode(file)).toBe(0o600);
    expect(second.attestationKeys()).toEqual(first.attestationKeys());
  });

  it("shows public halves and kids, and nothing of a private key, in its object, its output or its log", () => {
    const file = freshFile();
    const logger = captureLogger();
    const clock = { ms: T0 };
    const keys = createAttestationKeys({ file, now: () => new Date(clock.ms), logger });
    clock.ms = T0 + DAY;
    keys.attestationKeys();
    clock.ms = T0 + 2 * DAY;
    keys.attestationKeys();
    const stored = read(file);
    const secrets = [stored.previous, stored.current, stored.next].map((key) => key?.private_key ?? "");
    expect(secrets.every((secret) => secret.length === 43)).toBe(true);

    expect(Object.keys(keys).sort()).toEqual(["attestationKeys", "currentKid", "sign"]);
    const views = [
      JSON.stringify(keys),
      inspect(keys, { depth: null, showHidden: true, getters: true }),
      String(keys.sign),
      JSON.stringify(keys.attestationKeys()),
      keys.sign(claimsAt(clock.ms)),
      ...logger.lines,
    ];
    expect(logger.lines.length).toBeGreaterThan(0);
    for (const view of views) for (const secret of secrets) expect(view).not.toContain(secret);
  });

  it.each([
    ["text that is not JSON", (set: StoredSet) => `private_key=${set.current.private_key}`],
    ["an empty file", () => ""],
    ["a set without a current key", (set: StoredSet) => JSON.stringify({ ...set, current: undefined })],
    [
      "a public key that does not belong to its private key",
      (set: StoredSet) => JSON.stringify({ ...set, current: { ...set.current, public_key: set.next.public_key } }),
    ],
    [
      "a kid that is not derived from its key",
      (set: StoredSet) => JSON.stringify({ ...set, next: { ...set.next, kid: "0000000000000000" } }),
    ],
    ["another purpose", (set: StoredSet) => JSON.stringify({ ...set, purpose: "policy" })],
    [
      "a time that is not a date",
      (set: StoredSet) => JSON.stringify({ ...set, next: { ...set.next, published_at: "soon" } }),
    ],
  ])("refuses %s as a key file, without quoting or replacing it", (_label, corrupt) => {
    const file = freshFile();
    createAttestationKeys({ file, now: () => new Date(T0) });
    const set = read(file);
    const content = corrupt(set);
    writeFileSync(file, content);

    let message = "";
    try {
      createAttestationKeys({ file, now: () => new Date(T0) });
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).toContain(file);
    expect(message).toMatch(/is not a valid attestation key file/);
    expect(message).not.toContain(set.current.private_key.slice(0, 8));
    expect(readFileSync(file, "utf8")).toBe(content);
  });
});
