import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

// PGlite has no lock of its own: a second process that merely opens a data directory in use corrupts
// it. This pid file beside the directory makes that a clear start-up error instead.

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: the process exists but belongs to someone else. ESRCH: there is no such process.
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readHolder(lockFile: string): number | null {
  try {
    const pid = Number.parseInt(readFileSync(lockFile, "utf8").trim(), 10);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

/**
 * Takes the lock `<dataDir>.lock` for this process and returns the function that releases it.
 * A lock left by a dead process is replaced; one held by a live process (this one included) is an error.
 */
export function acquireDataDirLock(dataDir: string): () => void {
  const lockFile = `${dataDir}.lock`;
  mkdirSync(dirname(dataDir), { recursive: true });

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      writeFileSync(lockFile, `${process.pid}\n`, { flag: "wx" });
      let released = false;
      return () => {
        if (released) return;
        released = true;
        if (readHolder(lockFile) === process.pid) rmSync(lockFile, { force: true });
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const holder = readHolder(lockFile);
      if (holder !== null && isAlive(holder)) {
        throw new Error(
          `The data directory ${dataDir} is in use by process ${holder}. ` +
            `Only one process may open it; stop that process, or remove ${lockFile} if it is not an Anti Reverse API.`,
        );
      }
      rmSync(lockFile, { force: true });
    }
  }
  throw new Error(`Could not take the lock ${lockFile}: another process is starting on the same data directory.`);
}
