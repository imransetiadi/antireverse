import { crc32, inflateRawSync } from "node:zlib";

// A minimal, defensive ZIP reader for the OSV archive (no dependency, D-059). It reads only what the archive's
// central directory declares, checks every bound before it allocates, and refuses anything unusual instead of
// guessing: ZIP64, encryption, methods other than stored and deflate, multi-disk archives, names that could
// leave a directory, entries that are too large or inflate too well, and data whose CRC-32 does not match. It
// never writes a file: entries are handed to the caller as buffers.

export const ZIP_LIMITS = {
  /** Bytes of the whole archive. */
  archiveBytesMax: 200 * 1024 * 1024,
  /** Uncompressed bytes of one entry. */
  entryBytesMax: 1024 * 1024,
  /** Entries in the central directory. */
  entriesMax: 100_000,
  /** Uncompressed to compressed bytes, at most, for an entry larger than `ratioFloorBytes`: a zip bomb guard. */
  ratioMax: 200,
  /** Entries at most this large are never refused by ratio (small JSON files compress unpredictably). */
  ratioFloorBytes: 4096,
} as const;

export type ZipLimits = { -readonly [K in keyof typeof ZIP_LIMITS]: number };

export class ZipError extends Error {
  override name = "ZipError";
}

export interface ZipEntry {
  name: string;
  data: Buffer;
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const EOCD_SIZE = 22;
const CENTRAL_SIZE = 46;
const LOCAL_SIZE = 30;
const COMMENT_MAX = 0xffff;

/** A name that stays inside the directory it is extracted to: relative, no `.`/`..`/empty segment, no `\`, no NUL. */
function safeName(name: string): boolean {
  if (name.length === 0 || name.length > 1024) return false;
  if (name.includes("\\") || name.includes("\u0000") || name.startsWith("/") || /^[A-Za-z]:/.test(name)) return false;
  const segments = name.endsWith("/") ? name.slice(0, -1).split("/") : name.split("/");
  return segments.every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

function findEndRecord(archive: Buffer): number {
  const lowest = Math.max(0, archive.length - EOCD_SIZE - COMMENT_MAX);
  for (let at = archive.length - EOCD_SIZE; at >= lowest; at--) {
    // The comment length must reach exactly to the end of the archive: a signature inside data does not count.
    if (
      archive.readUInt32LE(at) === EOCD_SIGNATURE &&
      at + EOCD_SIZE + archive.readUInt16LE(at + 20) === archive.length
    ) {
      return at;
    }
  }
  throw new ZipError("Not a ZIP archive, or truncated: no end of central directory record.");
}

interface Located {
  name: string;
  method: number;
  crc: number;
  size: number;
  /** Where the entry's local header starts and where its data ends: the bytes no other entry may share. */
  localOffset: number;
  dataStart: number;
  dataEnd: number;
}

/** Inflates (or copies) one entry and checks its size and CRC-32. */
function extract(archive: Buffer, entry: Located, bound: ZipLimits): Buffer {
  const raw = archive.subarray(entry.dataStart, entry.dataEnd);
  let data: Buffer;
  if (entry.method === 0) {
    data = Buffer.from(raw);
  } else {
    try {
      // Never more than the entry limit, whatever the header declared.
      data = inflateRawSync(raw, { maxOutputLength: bound.entryBytesMax });
    } catch {
      throw new ZipError("An entry does not inflate within the limit.");
    }
  }
  if (data.length !== entry.size) throw new ZipError("An entry's size differs from its header.");
  if (crc32(data) >>> 0 !== entry.crc) throw new ZipError("An entry's CRC-32 does not match its data.");
  return data;
}

/**
 * The file entries of an archive, in central directory order; directory entries are skipped. The whole archive is
 * checked before the first entry is yielded (plan A7, M3/L1): the central directory and every local header, unique
 * names, local ranges that neither overlap nor repeat, and every entry inflated and CRC-checked (then dropped, so
 * memory stays one entry). Any problem throws a `ZipError` and nothing is yielded.
 */
export function* readZip(archive: Buffer, limits: Partial<ZipLimits> = {}): Generator<ZipEntry> {
  const bound: ZipLimits = { ...ZIP_LIMITS, ...limits };
  if (archive.length > bound.archiveBytesMax) throw new ZipError("The archive is larger than the limit.");
  if (archive.length < EOCD_SIZE) throw new ZipError("Not a ZIP archive, or truncated: too short.");

  const end = findEndRecord(archive);
  const disk = archive.readUInt16LE(end + 4);
  const directoryDisk = archive.readUInt16LE(end + 6);
  const entriesOnDisk = archive.readUInt16LE(end + 8);
  const entries = archive.readUInt16LE(end + 10);
  const directorySize = archive.readUInt32LE(end + 12);
  const directoryOffset = archive.readUInt32LE(end + 16);
  if (entries === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff) {
    throw new ZipError("ZIP64 archives are not supported.");
  }
  if (disk !== 0 || directoryDisk !== 0 || entriesOnDisk !== entries) {
    throw new ZipError("Multi-disk archives are not supported.");
  }
  if (entries > bound.entriesMax) throw new ZipError("The archive has more entries than the limit.");
  if (directoryOffset + directorySize > end) throw new ZipError("The central directory lies outside the archive.");

  const located: Located[] = [];
  const names = new Set<string>();
  let at = directoryOffset;
  for (let index = 0; index < entries; index++) {
    if (at + CENTRAL_SIZE > directoryOffset + directorySize || archive.readUInt32LE(at) !== CENTRAL_SIGNATURE) {
      throw new ZipError("Malformed central directory.");
    }
    const flags = archive.readUInt16LE(at + 8);
    const method = archive.readUInt16LE(at + 10);
    const crc = archive.readUInt32LE(at + 16);
    const compressedSize = archive.readUInt32LE(at + 20);
    const size = archive.readUInt32LE(at + 24);
    const nameLength = archive.readUInt16LE(at + 28);
    const extraLength = archive.readUInt16LE(at + 30);
    const commentLength = archive.readUInt16LE(at + 32);
    const startDisk = archive.readUInt16LE(at + 34);
    const localOffset = archive.readUInt32LE(at + 42);
    const next = at + CENTRAL_SIZE + nameLength + extraLength + commentLength;
    if (next > directoryOffset + directorySize) throw new ZipError("Malformed central directory.");
    const name = archive.toString("utf8", at + CENTRAL_SIZE, at + CENTRAL_SIZE + nameLength);
    at = next;

    if (compressedSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff || startDisk === 0xffff) {
      throw new ZipError("ZIP64 entries are not supported.");
    }
    if (!safeName(name)) throw new ZipError("An entry has an unsafe name.");
    if (names.has(name)) throw new ZipError("Two entries have the same name.");
    names.add(name);
    if ((flags & 0x0001) !== 0 || (flags & 0x0040) !== 0) throw new ZipError("An entry is encrypted: not supported.");
    if (method !== 0 && method !== 8) throw new ZipError("An entry uses an unsupported compression method.");
    if (size > bound.entryBytesMax) throw new ZipError("An entry is too large.");
    if (method === 0 && compressedSize !== size) throw new ZipError("A stored entry's sizes differ.");
    if (size > bound.ratioFloorBytes && size > bound.ratioMax * Math.max(compressedSize, 1)) {
      throw new ZipError("An entry exceeds the compression ratio limit.");
    }

    // The local header repeats the name and may carry its own extra field; only its lengths are used.
    if (localOffset + LOCAL_SIZE > directoryOffset || archive.readUInt32LE(localOffset) !== LOCAL_SIGNATURE) {
      throw new ZipError("Malformed local header.");
    }
    const dataStart =
      localOffset + LOCAL_SIZE + archive.readUInt16LE(localOffset + 26) + archive.readUInt16LE(localOffset + 28);
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > directoryOffset) throw new ZipError("An entry's data runs past its bounds.");
    if (name.endsWith("/") && size !== 0) throw new ZipError("A directory entry has data.");
    located.push({ name, method, crc, size, localOffset, dataStart, dataEnd });
  }

  // Every byte of entry data belongs to one entry only: no repeated or overlapping local ranges (a zip bomb that
  // points many central records at one compressed entry is refused here, before anything is inflated).
  const byOffset = [...located].sort((a, b) => a.localOffset - b.localOffset);
  for (let index = 1; index < byOffset.length; index++) {
    const previous = byOffset[index - 1] as Located;
    if ((byOffset[index] as Located).localOffset < previous.dataEnd) {
      throw new ZipError("Two entries overlap in the archive.");
    }
  }

  const files = located.filter((entry) => !entry.name.endsWith("/"));
  for (const entry of files) extract(archive, entry, bound);
  for (const entry of files) yield { name: entry.name, data: extract(archive, entry, bound) };
}
