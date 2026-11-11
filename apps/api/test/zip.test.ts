import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { readZip, ZIP_LIMITS, ZipError } from "../src/vulns/zip.ts";
import { buildZip } from "./zip-builder.ts";

const all = (archive: Buffer, limits = {}) => [...readZip(archive, limits)];

describe("zip reader", () => {
  it("reads stored and deflated entries, in central directory order", () => {
    const random = randomBytes(5_000);
    const archive = buildZip([
      { name: "a.json", data: '{"id":"A"}', method: 0 },
      { name: "dir/b.json", data: JSON.stringify({ text: "x".repeat(2_000) }), method: 8 },
      { name: "c.bin", data: random, method: 8 },
    ]);
    const entries = all(archive);
    expect(entries.map((entry) => entry.name)).toEqual(["a.json", "dir/b.json", "c.bin"]);
    expect(entries[0]?.data.toString("utf8")).toBe('{"id":"A"}');
    expect(JSON.parse(entries[1]?.data.toString("utf8") ?? "")).toEqual({ text: "x".repeat(2_000) });
    expect(entries[2]?.data.equals(random)).toBe(true);
  });

  it("reads an empty archive and skips directory entries", () => {
    expect(all(buildZip([]))).toEqual([]);
    expect(all(buildZip([{ name: "dir/", data: "", method: 0 }])).map((entry) => entry.name)).toEqual([]);
  });

  it("has the documented limits", () => {
    expect(ZIP_LIMITS).toMatchObject({
      archiveBytesMax: 200 * 1024 * 1024,
      entryBytesMax: 1024 * 1024,
      entriesMax: 100_000,
    });
  });

  it("refuses an entry whose CRC-32 does not match its data", () => {
    const archive = buildZip([{ name: "a.json", data: "{}", crc: 0x12345678 }]);
    expect(() => all(archive)).toThrow(ZipError);
    expect(() => all(archive)).toThrow(/CRC/);
  });

  it("refuses an entry declared larger than the per-entry limit, before inflating it", () => {
    const archive = buildZip([{ name: "big.json", data: "x".repeat(ZIP_LIMITS.entryBytesMax + 1), method: 0 }]);
    expect(() => all(archive)).toThrow(/too large/);
  });

  it("refuses an entry that inflates to more than it declared (a lying size)", () => {
    const archive = buildZip([{ name: "lie.json", data: "y".repeat(50_000), uncompressedSize: 100 }]);
    expect(() => all(archive)).toThrow(ZipError);
  });

  it("refuses an entry that inflates past the per-entry limit, whatever it declared", () => {
    const archive = buildZip([{ name: "bomb.json", data: Buffer.alloc(3 * 1024 * 1024), uncompressedSize: 1_000 }]);
    expect(() => all(archive)).toThrow(ZipError);
  });

  it("refuses a zip bomb by its compression ratio", () => {
    const archive = buildZip([{ name: "zeros.json", data: Buffer.alloc(ZIP_LIMITS.entryBytesMax) }]);
    expect(() => all(archive)).toThrow(/ratio/);
  });

  it.each([
    "../evil.json",
    "a/../../evil.json",
    "/etc/evil.json",
    "C:/evil.json",
    "a\\..\\evil.json",
    "a/./b.json",
    "nul\u0000.json",
    "",
  ])("refuses the entry name %j", (name) => {
    const archive = buildZip([{ name, data: "{}" }]);
    expect(() => all(archive)).toThrow(/name/);
  });

  it("refuses an encrypted entry", () => {
    expect(() => all(buildZip([{ name: "a.json", data: "{}", flags: 0x0001 }]))).toThrow(/encrypted/);
  });

  it("refuses an unsupported compression method", () => {
    expect(() => all(buildZip([{ name: "a.json", data: "{}", method: 12 }]))).toThrow(/method/);
  });

  it("refuses ZIP64 markers", () => {
    expect(() => all(buildZip([{ name: "a.json", data: "{}", compressedSize: 0xffffffff }]))).toThrow(/ZIP64/);
    expect(() => all(buildZip([{ name: "a.json", data: "{}" }], { entryCount: 0xffff }))).toThrow(ZipError);
  });

  it("refuses more entries than the limit", () => {
    const archive = buildZip([
      { name: "a.json", data: "{}" },
      { name: "b.json", data: "{}" },
      { name: "c.json", data: "{}" },
    ]);
    expect(() => all(archive, { entriesMax: 2 })).toThrow(/entries/);
  });

  it("refuses an archive larger than the limit", () => {
    const archive = buildZip([{ name: "a.json", data: "x".repeat(2_000), method: 0 }]);
    expect(() => all(archive, { archiveBytesMax: 1_000 })).toThrow(/archive/);
  });

  it("refuses truncated archives wherever they are cut", () => {
    const archive = buildZip([
      { name: "a.json", data: JSON.stringify({ a: "x".repeat(300) }) },
      { name: "b.json", data: JSON.stringify({ b: "y".repeat(300) }), method: 0 },
    ]);
    for (let length = 0; length < archive.length; length += 7) {
      expect(() => all(archive.subarray(0, length)), `cut at ${length}`).toThrow(ZipError);
    }
    expect(() => all(Buffer.from("not a zip at all"))).toThrow(ZipError);
  });

  it("refuses two central entries that share one local entry (L1: overlapping ranges)", () => {
    const single = buildZip([{ name: "a.json", data: JSON.stringify({ x: "y".repeat(100) }) }]);
    // Repeat the one central record (46 + 6 bytes): both point at offset 0.
    const end = single.length - 22;
    const centralStart = single.readUInt32LE(end + 16);
    const record = single.subarray(centralStart, end);
    // The copy gets another name, so that only the shared range is wrong.
    const copy = Buffer.from(record);
    copy.write("b", 46, "utf8");
    const directory = Buffer.concat([record, copy]);
    const eocd = Buffer.from(single.subarray(end));
    eocd.writeUInt16LE(2, 8);
    eocd.writeUInt16LE(2, 10);
    eocd.writeUInt32LE(directory.length, 12);
    const forged = Buffer.concat([single.subarray(0, centralStart), directory, eocd]);
    expect(() => all(forged)).toThrow(/overlap/);
  });

  it("refuses an entry whose data overlaps another entry's local range (L1)", () => {
    const two = buildZip([
      { name: "a.json", data: "x".repeat(200), method: 0 },
      { name: "b.json", data: "y".repeat(200), method: 0 },
    ]);
    // Point the second central record at the middle of the first entry.
    const end = two.length - 22;
    const centralStart = two.readUInt32LE(end + 16);
    const second = centralStart + 46 + "a.json".length;
    const forged = Buffer.from(two);
    forged.writeUInt32LE(10, second + 42);
    expect(() => all(forged)).toThrow(ZipError);
  });

  it("refuses two entries with the same name (L1)", () => {
    const archive = buildZip([
      { name: "a.json", data: "{}" },
      { name: "a.json", data: "{}" },
    ]);
    expect(() => all(archive)).toThrow(/name/);
  });

  it("checks the whole archive before yielding its first entry (M3)", () => {
    const archive = buildZip([
      { name: "a.json", data: "{}" },
      { name: "b.json", data: "{}", crc: 1 },
    ]);
    const entries = readZip(archive);
    expect(() => entries.next()).toThrow(/CRC/);
  });

  it("refuses a central directory that points outside the archive", () => {
    const archive = buildZip([{ name: "a.json", data: "{}" }], { centralOffset: 0x7fffffff });
    expect(() => all(archive)).toThrow(ZipError);
  });

  it("refuses a local header whose data runs past the archive", () => {
    const archive = buildZip([
      { name: "a.json", data: "{}", method: 0, compressedSize: 10_000, uncompressedSize: 10_000 },
    ]);
    expect(() => all(archive)).toThrow(ZipError);
  });
});
