// Child processes of the SDK tooling: never through a shell, always with a time limit.
import { execFile } from "node:child_process";

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export function exec(
  command: string,
  args: string[],
  options: { cwd: string; env?: NodeJS.ProcessEnv; timeoutMs?: number },
): Promise<ExecResult> {
  return new Promise((done) => {
    execFile(
      command,
      args,
      {
        cwd: options.cwd,
        env: options.env ?? process.env,
        timeout: options.timeoutMs ?? 180_000,
        maxBuffer: 64 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        done({ code, stdout, stderr: error !== null && code === -1 ? `${stderr}\n${error.message}` : stderr });
      },
    );
  });
}
