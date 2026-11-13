// Starting a sandbox child process (review 12b F1, Jev 1.0 "child_process_permission"). Every sandbox runs in a
// fresh `node` process (sandbox-child.mjs) under the permission model — it may read only its own script (and,
// Babel's parser file, which every mode uses to refuse import()); no writes, child processes, workers or addons — with code generation from strings
// disabled in its own realm, an empty environment and a heap limit. The parent kills it on timeout (SIGKILL), on
// an idle watchdog, or when it prints too much. The request goes in on stdin with a random token; only stdout lines
// that carry the token are accepted, so nothing the sandboxed code could print is mistaken for a result.
// Honest limit: the permission model of this Node version does not restrict the network; the vm context and the
// disabled code generation are what keep the sandboxed code away from it.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CHILD_SCRIPT = fileURLToPath(new URL("./sandbox-child.mjs", import.meta.url));
const require = createRequire(import.meta.url);

/** Babel's parser (one self-contained file) and its package.json: the only extra files the child may read. */
function parserFiles(): { entry: string; packageJson: string } | null {
  try {
    const packageJson = require.resolve("@babel/parser/package.json");
    return { entry: join(dirname(packageJson), "lib", "index.js"), packageJson };
  } catch {
    return null;
  }
}
const PARSER = parserFiles();

const PERMISSION_FLAG = process.allowedNodeEnvironmentFlags.has("--permission")
  ? "--permission"
  : "--experimental-permission";

export interface ChildOptions {
  /** Old-generation heap of the child, in MB. */
  heapMb: number;
  /** Milliseconds after which the child is killed. */
  timeoutMs: number;
  /** Milliseconds without an accepted line after which the child is killed (a watchdog). Default: none. */
  idleMs?: number;
  /** Bytes of stdout accepted; beyond it the child is killed. */
  maxOutputBytes: number;
  /** Deprecated: every child may read Babel's parser now (review N1 refuses import() with it). Ignored. */
  parser?: boolean;
  /** Called with each accepted line, in order. Return true to kill the child now (it said it is done). */
  onLine?: (line: Record<string, unknown>) => boolean | undefined;
  /** Called once the child has exited. */
  onExit?: (code: number | null) => void;
}

export interface ChildOutcome {
  /** The accepted lines (token removed), in order. */
  lines: Record<string, unknown>[];
  /** The parent killed the child (timeout, watchdog or too much output). */
  killed: boolean;
  /** Why: the overall timeout, the idle watchdog, too much output, or an `onLine` that said it was done. */
  killedBy: "timeout" | "idle" | "output" | "done" | null;
  /** The child ran out of heap. */
  outOfMemory: boolean;
}

/**
 * The lines of `text` that are JSON objects carrying exactly `token`, with the token removed. Anything else —
 * text the sandboxed code might print, a line with another token — is ignored.
 */
export function parseChildLines(text: string, token: string): Record<string, unknown>[] {
  const accepted: Record<string, unknown>[] = [];
  for (const line of text.split("\n")) {
    const parsed = parseLine(line, token);
    if (parsed !== null) accepted.push(parsed);
  }
  return accepted;
}

function parseLine(line: string, token: string): Record<string, unknown> | null {
  if (line.length === 0) return null;
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { token: carried, ...rest } = value as Record<string, unknown>;
  return carried === token ? rest : null;
}

/** Runs one request in a fresh sandbox child. Never rejects. */
export function runChild(request: Record<string, unknown>, options: ChildOptions): Promise<ChildOutcome> {
  const token = randomBytes(16).toString("hex");
  const reads = [CHILD_SCRIPT];
  if (PARSER !== null) reads.push(PARSER.entry, PARSER.packageJson);
  const args = [
    PERMISSION_FLAG,
    ...reads.map((path) => `--allow-fs-read=${path}`),
    "--disallow-code-generation-from-strings",
    `--max-old-space-size=${options.heapMb}`,
    "--experimental-vm-modules",
    "--no-warnings",
    CHILD_SCRIPT,
  ];
  const payload = {
    ...request,
    token,
    ...(PARSER !== null ? { parserPath: PARSER.entry } : {}),
  };

  return new Promise((resolve) => {
    const lines: Record<string, unknown>[] = [];
    let killed = false;
    let killedBy: ChildOutcome["killedBy"] = null;
    let settled = false;
    let pending = "";
    let outputBytes = 0;
    let stderrTail = "";
    let outOfMemory = false;
    let idle: ReturnType<typeof setTimeout> | undefined;
    const child = spawn(process.execPath, args, { env: {}, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    const kill = (reason: NonNullable<ChildOutcome["killedBy"]>) => {
      if (child.exitCode === null && child.signalCode === null) {
        killed = true;
        killedBy ??= reason;
        child.kill("SIGKILL");
      }
    };
    const timer = setTimeout(() => kill("timeout"), options.timeoutMs);
    const armIdle = () => {
      if (options.idleMs === undefined) return;
      clearTimeout(idle);
      idle = setTimeout(() => kill("idle"), options.idleMs);
    };
    armIdle();
    child.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > options.maxOutputBytes) {
        kill("output");
        return;
      }
      pending += chunk.toString("utf8");
      let newline = pending.indexOf("\n");
      while (newline !== -1) {
        const line = parseLine(pending.slice(0, newline), token);
        pending = pending.slice(newline + 1);
        if (line !== null) {
          lines.push(line);
          armIdle();
          if (options.onLine?.(line) === true) kill("done");
        }
        newline = pending.indexOf("\n");
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const window = stderrTail + chunk.toString("utf8");
      if (/heap out of memory|Reached heap limit|allocation failure/i.test(window)) outOfMemory = true;
      stderrTail = window.slice(-256);
    });
    child.stdin.on("error", () => {});
    child.on("error", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(idle);
      resolve({ lines, killed, killedBy, outOfMemory: false });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      clearTimeout(idle);
      try {
        options.onExit?.(code);
      } catch {
        // An observer's failure changes nothing.
      }
      if (settled) return;
      settled = true;
      resolve({ lines, killed, killedBy, outOfMemory: outOfMemory || (!killed && signal === "SIGABRT") });
    });
    child.stdin.end(`${JSON.stringify(payload)}\n`);
  });
}

/** What the permission model lets the child do (tests): read `path`, write beside it, spawn, start a worker, compile. */
export async function probeSandbox(path: string): Promise<Record<string, unknown> | null> {
  const outcome = await runChild({ mode: "probe", path }, { heapMb: 64, timeoutMs: 5_000, maxOutputBytes: 65_536 });
  return outcome.lines[0] ?? null;
}

/** Asks the child to change one watched object of its own realm, then send a result (tests of the snapshot). */
export async function probePollution(target: string): Promise<Record<string, unknown> | null> {
  const outcome = await runChild({ mode: "pollute", target }, { heapMb: 64, timeoutMs: 5_000, maxOutputBytes: 4_096 });
  return outcome.lines[0] ?? null;
}
