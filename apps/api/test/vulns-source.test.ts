import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Advisory, EXAMPLE_ADVISORY } from "@antireverse/protocol";
import { afterAll, describe, expect, it } from "vitest";
import {
  FIXTURE_ADVISORIES_FILE,
  fixtureSource,
  fixtureSourceFromFile,
  osvZipSource,
  type VulnerabilitySource,
} from "../src/vulns/source.ts";
import { ZipError } from "../src/vulns/zip.ts";
import { buildZip } from "./zip-builder.ts";

const root = mkdtempSync(join(tmpdir(), "ar-vulns-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

async function collect(source: VulnerabilitySource): Promise<Advisory[]> {
  const out: Advisory[] = [];
  for await (const advisory of source.advisories()) out.push(advisory);
  return out;
}

describe("fixture source", () => {
  it("yields each valid advisory, validated and stripped, and counts the invalid ones", async () => {
    const source = fixtureSource([
      { ...EXAMPLE_ADVISORY, details: "long text that is never stored", references: [{ type: "WEB", url: "x" }] },
      { id: "not an id", affected: [] },
    ]);
    const advisories = await collect(source);
    expect(advisories).toEqual([EXAMPLE_ADVISORY]);
    expect(source.stats).toMatchObject({ valid: 1, invalid: 1 });
  });

  it("reads the test fixture file", async () => {
    const source = fixtureSourceFromFile(FIXTURE_ADVISORIES_FILE);
    const advisories = await collect(source);
    expect(advisories.length).toBe(10);
    expect(source.stats.invalid).toBe(0);
  });
});

describe("OSV zip source", () => {
  function write(name: string, archive: Buffer): string {
    const path = join(root, name);
    writeFileSync(path, archive);
    return path;
  }

  it("yields the valid JSON advisories and counts the rest, reading nothing but *.json entries", async () => {
    const second = { ...EXAMPLE_ADVISORY, id: "GHSA-zz99-0000-0002", aliases: [] };
    const path = write(
      "mixed.zip",
      buildZip([
        { name: `${EXAMPLE_ADVISORY.id}.json`, data: JSON.stringify(EXAMPLE_ADVISORY) },
        { name: "GHSA-zz99-0000-0002.json", data: JSON.stringify(second), method: 0 },
        { name: "broken.json", data: "{ not json" },
        { name: "wrong-shape.json", data: JSON.stringify({ id: "GHSA-zz99-0000-0003" }) },
        { name: "README.txt", data: "not an advisory" },
      ]),
    );
    const source = osvZipSource(path);
    const advisories = await collect(source);
    expect(advisories.map((advisory) => advisory.id)).toEqual([EXAMPLE_ADVISORY.id, second.id]);
    expect(source.stats).toEqual({ entries: 5, valid: 2, invalid: 2, skipped: 1 });
  });

  it("fails on a malicious archive instead of yielding from it", async () => {
    const path = write("evil.zip", buildZip([{ name: "../../evil.json", data: JSON.stringify(EXAMPLE_ADVISORY) }]));
    await expect(collect(osvZipSource(path))).rejects.toThrow(ZipError);
  });

  it("refuses a file larger than the archive limit before reading it", async () => {
    const path = write("large.zip", buildZip([{ name: "a.json", data: "x".repeat(5_000), method: 0 }]));
    await expect(collect(osvZipSource(path, { archiveBytesMax: 1_000 }))).rejects.toThrow(/archive/);
  });
});
