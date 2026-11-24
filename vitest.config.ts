import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Vitest 5 has no workspace file: every workspace is an inline project here.
// Run one project with `npx vitest run --project <name>` (names: protocol, shield-node, guard, harden, prove, api, range, console, e2e, gate, sdk).
// Vitest 5 no longer excludes build output by default, so every project has an explicit include.
const include = ["test/**/*.test.{ts,tsx}"];
const abs = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  test: {
    projects: [
      {
        extends: true,
        test: { name: "protocol", root: "./packages/protocol", environment: "node", include },
      },
      {
        extends: true,
        test: { name: "shield-node", root: "./packages/shield-node", environment: "node", include },
      },
      {
        extends: true,
        // Guard is browser code: happy-dom gives it browser globals; every browser API it uses is also injectable.
        test: { name: "guard", root: "./packages/guard", environment: "happy-dom", include },
      },
      {
        extends: true,
        test: { name: "harden", root: "./packages/harden", environment: "node", include },
      },
      {
        extends: true,
        // The Reverse Assessment core: its code runner starts worker_threads workers, each call up to 5 s.
        test: { name: "prove", root: "./packages/prove", environment: "node", include, testTimeout: 20_000 },
      },
      {
        extends: true,
        test: { name: "api", root: "./apps/api", environment: "node", include },
      },
      {
        extends: true,
        test: { name: "range", root: "./apps/range", environment: "node", include },
      },
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
