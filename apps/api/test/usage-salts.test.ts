import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createUsageSalts } from "../src/usage/salts.ts";

// Review M3 (Jev memory_key_file_per_month): the month salts of the Guard device references never enter the database.
// They live in a small key file beside the data directory (or in memory), one random 32-byte key per UTC month,
// created on first use and deleted once the month is rolled up.

describe("usage salts", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-usage-salts-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("in memory: one random 32-byte key per month, the same on every use, gone once forgotten", () => {
    const salts = createUsageSalts();
    const nov = salts.saltFor("2026-11");
    expect(nov.length).toBe(32);
    expect(salts.saltFor("2026-11").equals(nov)).toBe(true);
    const dec = salts.saltFor("2026-12");
    expect(dec.equals(nov)).toBe(false);
    expect(salts.months()).toEqual(["2026-11", "2026-12"]);
    expect(salts.forgetBefore("2026-12")).toEqual(["2026-11"]);
    expect(salts.months()).toEqual(["2026-12"]);
    // A forgotten month gets a new key if it is ever used again.
    expect(salts.saltFor("2026-11").equals(nov)).toBe(false);
  });

  it("with a file: created on first use (mode 0600), reloaded by the next process, rewritten without the forgotten month", () => {
    const file = join(root, "usage-salts.json");
    const first = createUsageSalts({ file });
    expect(() => statSync(file)).toThrow();
    const nov = first.saltFor("2026-11");
    const dec = first.saltFor("2026-12");
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const content = JSON.parse(readFileSync(file, "utf8")) as { salts: Record<string, string> };
    expect(Object.keys(content.salts)).toEqual(["2026-11", "2026-12"]);

    const second = createUsageSalts({ file });
    expect(second.saltFor("2026-11").equals(nov)).toBe(true);
    expect(second.forgetBefore("2026-12")).toEqual(["2026-11"]);
    const text = readFileSync(file, "utf8");
    expect(text).not.toContain(nov.toString("base64url"));
    expect(text).toContain(dec.toString("base64url"));
    expect(createUsageSalts({ file }).months()).toEqual(["2026-12"]);
    // No temporary file is left beside it.
    expect(readdirSync(root)).toEqual(["usage-salts.json"]);
  });

  it("refuses a file that is not a salt file, without quoting it", () => {
    const file = join(root, "broken.json");
    writeFileSync(file, '{"salts": {"2026-11": "not a key"}}', { mode: 0o600 });
    expect(() => createUsageSalts({ file })).toThrow(/is not a valid usage salt file/);
    try {
      createUsageSalts({ file });
    } catch (error) {
      expect((error as Error).message).not.toContain("not a key");
    }
  });
});
