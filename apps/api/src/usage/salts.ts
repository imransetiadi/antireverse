import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

// The month salts of the Guard device references (slice 17a, review M3, Jev memory_key_file_per_month). A device's
// monthly reference is HMAC-SHA-256 (salt of its UTC month, per-App device subject), computed in this process. The salt
// never enters the database: PostgreSQL keeps deleted rows in its heap and WAL until they are vacuumed and recycled, so
// a salt deleted there could be recovered and the references of a closed month linked again. It lives in memory and,
// with a data directory, in one small JSON file beside it (mode 0600, like the other key files): created on the first
// use of a month, rewritten without a month once the rollup closed it. Every write is a complete new file (temporary
// file, fsync, rename, fsync of the directory). The salts are never logged or returned.

export interface UsageSalts {
  /** The 32-byte salt of a UTC month (`YYYY-MM`), created (and saved) on first use. */
  saltFor(month: string): Buffer;
  /** Deletes (and saves the deletion of) the salts of every month before `month`; answers the months deleted. */
  forgetBefore(month: string): string[];
  /** The months that have a salt, in order. */
  months(): string[];
}

const FILE_FORMAT = 1;
const PURPOSE = "usage-device-month-salts";
const MONTH = /^[0-9]{4}-(0[1-9]|1[0-2])$/;
const SALT_TEXT = /^[A-Za-z0-9_-]{43}$/;
const OWNER_ONLY = 0o600;

function invalid(file: string): Error {
  return new Error(
    `The usage salt file ${file} is not a valid usage salt file. Restore it from a backup, or remove it to start ` +
      "with new salts (the Guard devices of the current month are then counted again from zero).",
  );
}

function load(file: string): Map<string, Buffer> | null {
  let text: string;
  try {
    if ((statSync(file).mode & 0o077) !== 0) chmodSync(file, OWNER_ONLY);
    text = readFileSync(file, "utf8");
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    if (code === "ENOENT") return null;
    throw new Error(`The usage salt file ${file} cannot be read (${code ?? "unknown error"}).`);
  }
  let content: unknown;
  try {
    content = JSON.parse(text);
  } catch {
    // The parser's message would quote the text: dropped.
    throw invalid(file);
  }
  const { format, purpose, salts } = (content ?? {}) as Record<string, unknown>;
  if (format !== FILE_FORMAT || purpose !== PURPOSE || typeof salts !== "object" || salts === null) throw invalid(file);
  const map = new Map<string, Buffer>();
  for (const [month, salt] of Object.entries(salts)) {
    if (!MONTH.test(month) || typeof salt !== "string" || !SALT_TEXT.test(salt)) throw invalid(file);
    map.set(month, Buffer.from(salt, "base64url"));
  }
  return map;
}

/** Replaces the file with `text`, complete or not at all, and makes the replacement durable. */
function save(file: string, text: string): void {
  const directory = dirname(file);
  mkdirSync(directory, { recursive: true });
  const temporary = `${file}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    const descriptor = openSync(temporary, "wx", OWNER_ONLY);
    try {
      writeSync(descriptor, text);
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    renameSync(temporary, file);
    try {
      const dir = openSync(directory, "r");
      try {
        fsyncSync(dir);
      } finally {
        closeSync(dir);
      }
    } catch {
      // Some platforms cannot fsync a directory; the rename itself is atomic.
    }
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    throw new Error(`The usage salt file ${file} cannot be written (${code ?? "unknown error"}).`);
  } finally {
    rmSync(temporary, { force: true });
  }
}

/**
 * The month salts. With `file`: those of that file (beside the data directory), loaded now and saved on every change.
 * Without: in memory only, gone on close (tests, and an API without a data directory).
 */
export function createUsageSalts(options: { file?: string } = {}): UsageSalts {
  const { file } = options;
  const salts = (file === undefined ? null : load(file)) ?? new Map<string, Buffer>();
  const persist = () => {
    if (file === undefined) return;
    const ordered = [...salts.keys()].sort();
    const text = `${JSON.stringify(
      {
        format: FILE_FORMAT,
        purpose: PURPOSE,
        salts: Object.fromEntries(ordered.map((month) => [month, salts.get(month)?.toString("base64url")])),
      },
      null,
      2,
    )}\n`;
    save(file, text);
  };
  return Object.freeze({
    saltFor(month: string): Buffer {
      if (!MONTH.test(month)) throw new TypeError("A month is YYYY-MM.");
      const existing = salts.get(month);
      if (existing !== undefined) return existing;
      const salt = randomBytes(32);
      salts.set(month, salt);
      try {
        persist();
      } catch (error) {
        // Not saved: not used, so that no reference is made with a salt a restart would lose.
        salts.delete(month);
        throw error;
      }
      return salt;
    },
    forgetBefore(month: string): string[] {
      const gone = [...salts.keys()].filter((m) => m < month).sort();
      if (gone.length === 0) return [];
      for (const m of gone) salts.delete(m);
      persist();
      return gone;
    },
    months(): string[] {
      return [...salts.keys()].sort();
    },
  });
}
