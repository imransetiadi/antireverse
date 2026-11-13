import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createAddressHasher } from "../src/mail/address-key.ts";
import { ADDRESS_KEY_FILE, startApi } from "../src/server.ts";
import { captureLogger } from "./helpers.ts";

const root = mkdtempSync(join(tmpdir(), "ar-address-key-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("the address key of the confirmation-mail count", () => {
  it("hashes an address with HMAC-SHA-256 under a secret, never as its plain SHA-256", () => {
    const hasher = createAddressHasher();
    const hash = hasher.hash("alice@example.com");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toBe(createHash("sha256").update("alice@example.com").digest("hex"));
    expect(hasher.hash("alice@example.com")).toBe(hash);
    expect(createAddressHasher().hash("alice@example.com")).not.toBe(hash);
  });

  it("creates its key file once (owner only) and reads the same secret back", () => {
    const file = join(root, "one", "mail-hash-key.json");
    const first = createAddressHasher({ file });
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const content = JSON.parse(readFileSync(file, "utf8")) as { secret: string };
    expect(content.secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const expected = createHmac("sha256", Buffer.from(content.secret, "base64url"))
      .update("alice@example.com", "utf8")
      .digest("hex");
    expect(first.hash("alice@example.com")).toBe(expected);
    expect(createAddressHasher({ file }).hash("alice@example.com")).toBe(expected);
  });

  it("refuses a file that is not a key, without quoting it", () => {
    const file = join(root, "bad.json");
    writeFileSync(file, '{"secret":"leaky-not-a-key"}', { mode: 0o600 });
    expect(() => createAddressHasher({ file })).toThrow(/is not a valid address key/);
    try {
      createAddressHasher({ file });
    } catch (error) {
      expect((error as Error).message).not.toContain("leaky");
    }
  });

  it("lives beside the data directory of a started API", async () => {
    const dataDir = join(root, "api", "pg");
    const api = await startApi({ dataDir, smtp: null, logger: captureLogger() });
    try {
      expect(statSync(join(root, "api", ADDRESS_KEY_FILE)).mode & 0o777).toBe(0o600);
    } finally {
      await api.close();
    }
  });
});
