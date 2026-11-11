import { fileURLToPath } from "node:url";

export interface Config {
  host: string;
  port: number;
  /** The PGlite data directory. Exactly one process may have it open. */
  dataDir: string;
}

export const DEFAULT_HOST = "127.0.0.1";
export const DEFAULT_PORT = 8787;
/** `apps/api/.data/pg`, wherever the process was started from. */
export const DEFAULT_DATA_DIR = fileURLToPath(new URL("../.data/pg", import.meta.url));

/**
 * Reads `HOST`, `PORT` and `AR_DATA_DIR`; an unset or empty variable takes its default.
 * `PORT=0` asks the operating system for a free port.
 */
export function readConfig(env: Record<string, string | undefined>): Config {
  const portText = env.PORT || String(DEFAULT_PORT);
  const port = /^[0-9]{1,5}$/.test(portText) ? Number(portText) : Number.NaN;
  if (!(port >= 0 && port <= 65_535)) {
    throw new Error(`PORT must be an integer from 0 to 65535, got "${portText}".`);
  }
  return { host: env.HOST || DEFAULT_HOST, port, dataDir: env.AR_DATA_DIR || DEFAULT_DATA_DIR };
}
