import { fileURLToPath } from "node:url";

/** The monorepo root (tools/gate/src → ../../..), without a trailing slash. */
export const REPO_ROOT = fileURLToPath(new URL("../../..", import.meta.url)).replace(/\/$/, "");
