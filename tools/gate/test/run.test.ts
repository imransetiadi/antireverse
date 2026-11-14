// Slice 18e: checks run as child processes with a timeout; their output is captured and trimmed.
import { describe, expect, it } from "vitest";
import { runCommand, trimOutput } from "../src/run.ts";

describe("runCommand", () => {
  it("captures stdout and stderr, the exit code and the duration", async () => {
    const out = await runCommand({
      command: process.execPath,
      args: ["-e", "console.log('out'); console.error('err'); process.exit(3)"],
      timeoutMs: 10_000,
    });
    expect(out.exitCode).toBe(3);
    expect(out.timedOut).toBe(false);
    expect(out.output).toContain("out");
    expect(out.output).toContain("err");
    expect(out.durationMs).toBeGreaterThan(0);
  });

  it("kills the process and its children on timeout", async () => {
    const started = Date.now();
    const out = await runCommand({
      command: process.execPath,
      args: [
        "-e",
        "require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'inherit' }); setInterval(() => {}, 1000)",
      ],
      timeoutMs: 500,
    });
    expect(out.timedOut).toBe(true);
    expect(out.exitCode).toBeNull();
    expect(Date.now() - started).toBeLessThan(8_000);
  });

  it("reports a command that cannot start", async () => {
    const out = await runCommand({ command: "/nonexistent/binary", args: [], timeoutMs: 1_000 });
    expect(out.exitCode).toBeNull();
    expect(out.output).toMatch(/ENOENT/);
  });
});

describe("trimOutput", () => {
  it("keeps the last lines within the character budget and says what it dropped", () => {
    const text = Array.from({ length: 100 }, (_, i) => `line ${i}`).join("\n");
    const trimmed = trimOutput(text, { lines: 5, chars: 1_000 });
    expect(trimmed).toBe(
      ["… 95 earlier lines trimmed", "line 95", "line 96", "line 97", "line 98", "line 99"].join("\n"),
    );
    expect(trimOutput("short", { lines: 5, chars: 1_000 })).toBe("short");
    expect(trimOutput("x".repeat(50), { lines: 5, chars: 10 })).toBe("… 40 characters trimmed\nxxxxxxxxxx");
  });

  it("removes ANSI colours", () => {
    expect(trimOutput("\u001b[32mok\u001b[39m", { lines: 5, chars: 100 })).toBe("ok");
  });
});
