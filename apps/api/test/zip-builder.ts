import { crc32, deflateRawSync } from "node:zlib";

/** One entry of a test archive. Every field after `data` lets a test forge a malformed entry. */
export interface TestEntry {
  name: string;
  data: Buffer | string;
  /** 0 stored, 8 deflate (default), anything else unsupported. */
  method?: number;
  /** Replaces the computed CRC-32 in both headers. */
  crc?: number;
  /** Replaces the uncompressed size in both headers. */
  uncompressedSize?: number;
  /** Replaces the compressed size in both headers (the bytes written stay the real ones). */
  compressedSize?: number;
  /** General-purpose flags (bit 0: encrypted). */
  flags?: number;
}

export interface TestArchiveOptions {
  /** Replaces the entry counts of the end record. */
  entryCount?: number;
  /** Replaces the central directory offset of the end record. */
  centralOffset?: number;
}

/** Builds a ZIP archive in memory: local headers and data, the central directory, the end record. */
export function buildZip(entries: TestEntry[], options: TestArchiveOptions = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const raw = typeof entry.data === "string" ? Buffer.from(entry.data, "utf8") : entry.data;
    const method = entry.method ?? 8;
    const body = method === 8 ? deflateRawSync(raw) : raw;
    const name = Buffer.from(entry.name, "utf8");
    const crc = entry.crc ?? crc32(raw);
    const compressed = entry.compressedSize ?? body.length;
    const uncompressed = entry.uncompressedSize ?? raw.length;
    const flags = entry.flags ?? 0x0800;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc >>> 0, 14);
    local.writeUInt32LE(compressed >>> 0, 18);
    local.writeUInt32LE(uncompressed >>> 0, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc >>> 0, 16);
    central.writeUInt32LE(compressed >>> 0, 20);
    central.writeUInt32LE(uncompressed >>> 0, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset >>> 0, 42);
    centrals.push(central, name);

    offset += local.length + name.length + body.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(options.entryCount ?? entries.length, 8);
  end.writeUInt16LE(options.entryCount ?? entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(options.centralOffset ?? offset, 16);
  return Buffer.concat([...locals, directory, end]);
}
