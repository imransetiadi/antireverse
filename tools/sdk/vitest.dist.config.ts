// The suites of protocol, shield-node and harden on the compiled output (slice 23, D-132). Started by
// tools/sdk/test/equivalence.test.ts with AR_SDK_BUILD_ROOT naming a folder that holds one compiled folder per
// package; not part of `npm test`. See src/dist-plugin.ts.
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { DIST_EXCLUDED, DIST_PACKAGES, distRedirect } from "./src/dist-plugin.ts";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url)).replace(/\/$/, "");
const buildRoot = process.env.AR_SDK_BUILD_ROOT;
if (!buildRoot) throw new Error("AR_SDK_BUILD_ROOT must name the folder of the compiled packages");

export default defineConfig({
  plugins: [distRedirect({ repoRoot, buildRoot }) as never],
  test: {
    // Vitest keeps transformed modules on disk between runs. A cached test file carries the compiled paths of the
    // run that cached it, and a cached module is not passed through the plugin again — the load guard would not see
    // it. This run transforms everything itself, every time.
    fsModuleCache: false,
    // For the processes tests start (review M1): where the compiled files are, and a load guard of their own.
    env: {
      AR_SDK_COMPILED_ROOT: realpathSync(buildRoot),
      AR_SDK_GUARD_ROOT: repoRoot,
      NODE_OPTIONS: `--import ${JSON.stringify(`${repoRoot}/tools/sdk/src/child-guard.mjs`)}`,
    },
    projects: DIST_PACKAGES.map((pkg) => ({
      extends: true as const,
      test: {
        name: `${pkg.short}-dist`,
        root: `${repoRoot}/packages/${pkg.short}`,
        environment: "node",
        fsModuleCache: false,
        include: ["test/**/*.test.{ts,tsx}"],
        exclude: DIST_EXCLUDED.filter((entry) => entry.file.startsWith(`packages/${pkg.short}/`)).map((entry) =>
          entry.file.slice(`packages/${pkg.short}/`.length),
        ),
      },
    })),
  },
});
