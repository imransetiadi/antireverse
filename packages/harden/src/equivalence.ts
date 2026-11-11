// The equivalence gate: proof that the protected output behaves exactly like the source. It copies the
// bundle to a throwaway directory, overwrites it with the protected files, runs the bundle's OWN test
// command there, and reports pass/fail with the captured output. The source directory is never touched, and
// the temp copy is always removed. This is how "behaviour is never changed" is enforced in practice.
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

export interface EquivalenceArgs {
  /** The bundle directory (read-only here: it is copied, never modified). */
  dir: string;
  /** The command that proves behaviour, e.g. `npm test` or `node run.mjs`. Run in the temp copy. */
  testCommand: string;
  /** Protected files, keyed by path relative to `dir`, written over the copy before the command runs. */
  protectedFiles: Record<string, string>;
}

export interface EquivalenceResult {
  passed: boolean;
  output: string;
}

/** Runs a shell command in `cwd`, capturing stdout+stderr, resolving (never rejecting) with the exit code. */
function runCommand(command: string, cwd: string): Promise<{ code: number; output: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, { cwd, shell: true });
    let output = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.on("error", (error) => {
      resolve({ code: 1, output: `${output}\n${error.message}` });
    });
    child.on("close", (code) => {
      resolve({ code: code ?? 1, output });
    });
  });
}

export async function checkEquivalence(args: EquivalenceArgs): Promise<EquivalenceResult> {
  const temp = await mkdtemp(join(tmpdir(), "harden-equiv-"));
  try {
    await cp(args.dir, temp, { recursive: true });
    for (const [rel, code] of Object.entries(args.protectedFiles)) {
      const dest = join(temp, rel);
      mkdirSync(dirname(dest), { recursive: true });
      await writeFile(dest, code, "utf8");
    }
    const { code, output } = await runCommand(args.testCommand, temp);
    return { passed: code === 0, output };
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}
