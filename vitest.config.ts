import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";
import { TIMED_PROJECTS, timingFilesOf, timingProjectOf } from "./vitest.timing.ts";

// Vitest 5 has no workspace file: every workspace is an inline project here.
// Five projects have a twin named <project>-timing (guard-timing, shield-node-timing, harden-timing, prove-timing,
// api-timing): the files listed in vitest.timing.ts, which hold a time bound that the load of the full run distorts,
// run there — whole, one file at a time, after every other file. To run all of a package's tests, name both:
// `npx vitest run --project guard --project guard-timing`.
// Run one project with `npx vitest run --project <name>` (names: protocol, shield-node, guard, harden, prove, api, range, console, e2e, gate, sdk).
// Vitest 5 no longer excludes build output by default, so every project has an explicit include.
const include = ["test/**/*.test.{ts,tsx}"];
const abs = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

interface PackageProject {
  name: string;
  root: string;
  environment: "node" | "happy-dom";
  testTimeout?: number;
}

/**
 * A package's project, and — when vitest.timing.ts lists files of it — its late twin: the same settings, only those
 * files, one at a time (`fileParallelism: false`), in a group of its own after the ordinary projects (group 0).
 */
function packageProjects(project: PackageProject) {
  const { name, root, environment, testTimeout } = project;
  const shared = { root, environment, ...(testTimeout === undefined ? {} : { testTimeout }) };
  const late = timingFilesOf(name);
  if (late.length === 0) return [{ extends: true as const, test: { name, ...shared, include } }];
  return [
    { extends: true as const, test: { name, ...shared, include, exclude: late } },
    {
      extends: true as const,
      test: {
        name: timingProjectOf(name),
        ...shared,
        include: late,
        fileParallelism: false,
        sequence: { groupOrder: TIMED_PROJECTS.indexOf(name) + 1 },
      },
    },
  ];
}

export default defineConfig({
  test: {
    projects: [
      ...packageProjects({ name: "protocol", root: "./packages/protocol", environment: "node" }),
      ...packageProjects({ name: "shield-node", root: "./packages/shield-node", environment: "node" }),
      // Guard is browser code: happy-dom gives it browser globals; every browser API it uses is also injectable.
      ...packageProjects({ name: "guard", root: "./packages/guard", environment: "happy-dom" }),
      ...packageProjects({ name: "harden", root: "./packages/harden", environment: "node" }),
      // The Reverse Assessment core: its code runner starts worker_threads workers, each call up to 5 s.
      ...packageProjects({ name: "prove", root: "./packages/prove", environment: "node", testTimeout: 20_000 }),
      ...packageProjects({ name: "api", root: "./apps/api", environment: "node" }),
      ...packageProjects({ name: "range", root: "./apps/range", environment: "node" }),
      {
        extends: true,
        plugins: [react()],
        resolve: {
          alias: [
            // The Console's import alias (tsconfig "paths").
            { find: /^@\//, replacement: `${abs("./apps/console/src")}/` },
            // Next resolves "server-only" itself; outside Next it must resolve to an empty module.
            { find: /^server-only$/, replacement: abs("./node_modules/next/dist/compiled/server-only/empty.js") },
          ],
        },
        test: {
          name: "console",
          root: "./apps/console",
          environment: "happy-dom",
          include,
          setupFiles: ["./test/setup.ts"],
        },
      },
      {
        extends: true,
        // The release-gate runner (slice 18e): its own unit tests; the gate's real checks run only from `npm run gate:release`.
        test: { name: "gate", root: "./tools/gate", environment: "node", include },
      },
      {
        extends: true,
        // The SDK build, pack and verify tooling (slice 23). Its tests compile and pack into temporary folders, run a
        // real `npm install` against a loopback registry and run three suites again on the compiled output.
        test: {
          name: "sdk",
          root: "./tools/sdk",
          environment: "node",
          include,
          testTimeout: 300_000,
          hookTimeout: 300_000,
        },
      },
      {
        extends: true,
        test: {
          name: "e2e",
          root: "./tests/e2e",
          environment: "node",
          // The HTTP journey lives at the workspace root (journey.http.test.ts); Playwright files are *.e2e.ts.
          include: ["*.test.ts", ...include],
          testTimeout: 20_000,
          hookTimeout: 30_000,
        },
      },
    ],
  },
});
