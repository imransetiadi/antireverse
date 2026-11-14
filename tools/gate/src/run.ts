// Child processes for the checks (slice 18e): a timeout that kills the whole process group, then anything the run
// left listening on its own ports (review L1: a grandchild that detached into a group of its own), and the output
// captured (both streams, interleaved) for parsing, with a trimmed excerpt for the report. The gate key's path is
// never passed to a child.
import { execFileSync, spawn } from "node:child_process";
import { stripAnsi } from "./parsers.ts";

export interface RunOptions {
  command: string;
  args: string[];
  cwd?: string;
  env?: Record<string, string | undefined>;
  timeoutMs: number;
  /**
   * Ports the run's servers listen on: after a timeout, a process listening on one of them that was not listening
   * before the run is stopped. Only these ports are touched.
   */
  cleanupPorts?: number[];
}

export interface RunResult {
  /** Null when the process was killed or could not start. */
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  durationMs: number;
  /** Everything it printed (capped at 64 MB, oldest output dropped first). */
  output: string;
}

const MAX_OUTPUT = 64 * 1024 * 1024;
/** SIGTERM first; what is still there this much later gets SIGKILL. */
const KILL_GRACE_MS = 10_000;
/** Environment variables a check never needs and never gets. */
const WITHHELD = ["AR_GATE_KEY_FILE"];

/** The process ids listening on a TCP port (lsof); none when lsof is missing. */
function listeners(port: number): number[] {
  try {
    const out = execFileSync("lsof", ["-nP", "-t", `-iTCP:${port}`, "-sTCP:LISTEN"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out
      .split("\n")
      .map((l) => Number(l.trim()))
      .filter((n) => Number.isInteger(n) && n > 0 && n !== process.pid);
  } catch {
    return [];
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Stops what listens on `ports` now and did not before; SIGTERM, then SIGKILL after the grace. */
async function stopNewListeners(
  ports: readonly number[],
  before: ReadonlySet<number>,
  graceMs: number,
): Promise<number[]> {
  const fresh = () => [...new Set(ports.flatMap(listeners))].filter((pid) => !before.has(pid));
  const found = fresh();
  for (const pid of found) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {}
  }
  for (let waited = 0; waited < graceMs && fresh().length > 0; waited += 200) await sleep(200);
  for (const pid of fresh()) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {}
  }
  for (let waited = 0; waited < 2_000 && fresh().length > 0; waited += 100) await sleep(100);
  return found;
}

export function runCommand(options: RunOptions): Promise<RunResult> {
  const started = performance.now();
  const ports = options.cleanupPorts ?? [];
  const before = new Set(ports.flatMap(listeners));
  return new Promise((resolvePromise) => {
    let output = "";
    let timedOut = false;
    let settled = false;
    const append = (chunk: Buffer) => {
      output += chunk.toString("utf8");
      if (output.length > MAX_OUTPUT) output = output.slice(output.length - MAX_OUTPUT);
    };
    const finish = async (exitCode: number | null, signal: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (timedOut && ports.length > 0) {
        const stopped = await stopNewListeners(ports, before, Math.min(KILL_GRACE_MS, 3_000));
        if (stopped.length > 0)
          append(Buffer.from(`\n[gate] stopped ${stopped.length} process(es) left listening on ${ports.join(", ")}\n`));
      }
      resolvePromise({
        exitCode,
        signal,
        timedOut,
        durationMs: Math.max(1, Math.round(performance.now() - started)),
        output,
      });
    };
    const env: Record<string, string | undefined> = { ...process.env, ...options.env, FORCE_COLOR: "0", NO_COLOR: "1" };
    for (const name of WITHHELD) delete env[name];
    const child = spawn(options.command, options.args, {
      cwd: options.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      // Its own process group, so that a timeout reaches the grandchildren (npm → vitest workers, servers).
      detached: true,
    });
    child.stdout?.on("data", append);
    child.stderr?.on("data", append);
    const killGroup = (signal: NodeJS.Signals) => {
      try {
        if (child.pid !== undefined) process.kill(-child.pid, signal);
      } catch {
        // Already gone.
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup("SIGTERM");
      setTimeout(() => killGroup("SIGKILL"), KILL_GRACE_MS).unref();
    }, options.timeoutMs);
    child.on("error", (error) => {
      append(Buffer.from(`\n${String(error)}\n`));
      void finish(null, null);
    });
    child.on("close", (code, signal) => {
      // Whatever the child left running in its group goes with it.
      killGroup("SIGKILL");
      void finish(timedOut ? null : code, signal);
    });
  });
}

/** The last `lines` lines, within `chars` characters, without colours; says what was dropped. */
export function trimOutput(text: string, limits: { lines: number; chars: number }): string {
  const all = stripAnsi(text).replace(/\r/g, "").trimEnd().split("\n");
  let kept = all.slice(-limits.lines);
  const droppedLines = all.length - kept.length;
  let joined = kept.join("\n");
  let note = droppedLines > 0 ? `… ${droppedLines} earlier lines trimmed` : "";
  if (joined.length > limits.chars) {
    const dropped = joined.length - limits.chars;
    joined = joined.slice(dropped);
    kept = [joined];
    note =
      droppedLines > 0
        ? `… ${droppedLines} earlier lines and ${dropped} characters trimmed`
        : `… ${dropped} characters trimmed`;
  }
  return note ? `${note}\n${joined}` : joined;
}
