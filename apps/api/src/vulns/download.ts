import { createWriteStream } from "node:fs";
import { finished } from "node:stream/promises";
import { ZIP_LIMITS } from "./zip.ts";

/** The OSV archive of every npm advisory. Public data; nothing is sent with the request but the URL. */
export const OSV_NPM_ARCHIVE_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

/**
 * Downloads `url` (https only, no redirect to another scheme) to the file `dest`, refusing more than `maxBytes`
 * (default: the archive limit) and anything slower than `timeoutMs` in all. Used by the `vulns:sync` command only:
 * never at request time, never in tests. Returns the bytes written.
 */
export async function downloadToFile(
  url: string,
  dest: string,
  options: { maxBytes?: number; timeoutMs?: number } = {},
): Promise<number> {
  const maxBytes = options.maxBytes ?? ZIP_LIMITS.archiveBytesMax;
  if (new URL(url).protocol !== "https:") throw new Error("Only https downloads are allowed.");
  const response = await fetch(url, {
    signal: AbortSignal.timeout(options.timeoutMs ?? 10 * 60_000),
    headers: { "user-agent": "Airverse-VulnSync/1" },
  });
  if (new URL(response.url).protocol !== "https:") throw new Error("The download was redirected away from https.");
  if (!response.ok || response.body === null) throw new Error(`The download failed with status ${response.status}.`);
  const declared = Number(response.headers.get("content-length"));
  if (declared > maxBytes) throw new Error("The archive is larger than the limit.");

  const out = createWriteStream(dest, { flags: "wx", mode: 0o600 });
  let written = 0;
  try {
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
      written += chunk.byteLength;
      if (written > maxBytes) throw new Error("The archive is larger than the limit.");
      if (!out.write(chunk)) await new Promise<void>((resolve) => out.once("drain", resolve));
    }
  } finally {
    out.end();
    await finished(out).catch(() => {});
  }
  return written;
}
