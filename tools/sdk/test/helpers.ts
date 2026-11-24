import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterAll } from "vitest";
import { type Layout, TEMP_PREFIX, tempLayout } from "../src/safe.ts";

/** A temporary folder of this test file, removed when the file is done. */
export function tempBase(name: string): string {
  const base = mkdtempSync(join(tmpdir(), `${TEMP_PREFIX}${name}-`));
  afterAll(() => rmSync(base, { recursive: true, force: true }));
  return base;
}

export function layoutIn(base: string, name: string): Layout {
  return tempLayout(join(base, name));
}

/** Every file below `dir`, relative, sorted. */
export function filesOf(dir: string): string[] {
  const out: string[] = [];
  const walk = (at: string): void => {
    for (const entry of readdirSync(at).sort()) {
      const path = join(at, entry);
      if (statSync(path).isDirectory()) walk(path);
      else out.push(relative(dir, path));
    }
  };
  walk(dir);
  return out;
}

export interface TarEntry {
  name: string;
  mode: number;
  size: number;
  mtime: number;
  uid: number;
  gid: number;
}

/** The entries of an uncompressed tar archive (ustar headers; npm writes long names as pax records, shown too). */
export function tarEntries(tar: Buffer): TarEntry[] {
  const entries: TarEntry[] = [];
  const text = (from: number, length: number, at: number) =>
    tar
      .subarray(at + from, at + from + length)
      .toString("utf8")
      .replace(/\0.*$/, "");
  const octal = (from: number, length: number, at: number) => Number.parseInt(text(from, length, at).trim() || "0", 8);
  for (let at = 0; at + 512 <= tar.length; ) {
    if (tar.subarray(at, at + 512).every((byte) => byte === 0)) break;
    const prefix = text(345, 155, at);
    const size = octal(124, 12, at);
    entries.push({
      name: prefix ? `${prefix}/${text(0, 100, at)}` : text(0, 100, at),
      mode: octal(100, 8, at),
      size,
      mtime: octal(136, 12, at),
      uid: octal(108, 8, at),
      gid: octal(116, 8, at),
    });
    at += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}
