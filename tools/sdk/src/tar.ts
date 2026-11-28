// Reads one file out of an uncompressed tar archive (ustar; the names npm writes fit the header). Used to look at
// a packed package.json or README: what is in the tarball is what will be published, not what was staged.

export function tarFile(tar: Buffer, name: string): Buffer {
  const text = (at: number, from: number, length: number) =>
    tar
      .subarray(at + from, at + from + length)
      .toString("utf8")
      .replace(/\0.*$/, "");
  for (let at = 0; at + 512 <= tar.length; ) {
    if (tar.subarray(at, at + 512).every((byte) => byte === 0)) break;
    const prefix = text(at, 345, 155);
    const entry = prefix ? `${prefix}/${text(at, 0, 100)}` : text(at, 0, 100);
    const size = Number.parseInt(text(at, 124, 12).trim() || "0", 8);
    if (entry === name) return tar.subarray(at + 512, at + 512 + size);
    at += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error(`${name} is not in the archive`);
}

/** The names of the entries of an uncompressed tar archive, in order. */
export function tarNames(tar: Buffer): string[] {
  const text = (at: number, from: number, length: number) =>
    tar
      .subarray(at + from, at + from + length)
      .toString("utf8")
      .replace(/\0.*$/, "");
  const names: string[] = [];
  for (let at = 0; at + 512 <= tar.length; ) {
    if (tar.subarray(at, at + 512).every((byte) => byte === 0)) break;
    const prefix = text(at, 345, 155);
    names.push(prefix ? `${prefix}/${text(at, 0, 100)}` : text(at, 0, 100));
    at += 512 + Math.ceil(Number.parseInt(text(at, 124, 12).trim() || "0", 8) / 512) * 512;
  }
  return names;
}
