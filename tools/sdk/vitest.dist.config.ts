// The suites of protocol, shield-node and harden on the compiled output (slice 23, D-132). Started by
// tools/sdk/test/equivalence.test.ts with AR_SDK_BUILD_ROOT naming a folder that holds one compiled folder per
// package; not part of `npm test`. See src/dist-plugin.ts.
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { TIMED_PROJECTS, timingFilesOf, timingProjectOf } from "../../vitest.timing.ts";
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
    // As in the root configuration (vitest.timing.ts, D-147): the files with a load-sensitive time bound run in a
    // late twin of their project, one at a time, after every other file of this run.
    projects: DIST_PACKAGES.flatMap((pkg) => {
      const root = `${repoRoot}/packages/${pkg.short}`;
      const excluded = DIST_EXCLUDED.filter((entry) => entry.file.startsWith(`packages/${pkg.short}/`)).map((entry) =>
        entry.file.slice(`packages/${pkg.short}/`.length),
      );
      const late = timingFilesOf(pkg.short);
      const shared = { root, environment: "node", fsModuleCache: false };
      return [
        {
          extends: true as const,
          test: {
            name: `${pkg.short}-dist`,
            ...shared,
            include: ["test/**/*.test.{ts,tsx}"],
            exclude: [...excluded, ...late],
          },
        },
        ...(late.length === 0
          ? []
          : [
              {
                extends: true as const,
                test: {
                  name: `${timingProjectOf(pkg.short)}-dist`,
                  ...shared,
                  include: late,
                  exclude: excluded,
                  fileParallelism: false,
                  sequence: { groupOrder: TIMED_PROJECTS.indexOf(pkg.short) + 1 },
                },
              },
            ]),
      ];
    }),
  },
});
