// Module hooks registered by child-guard.mjs: resolving to a file below packages/<compiled package>/src fails.
import { realpathSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

/** The packages whose suites run on the compiled output (DIST_PACKAGES of dist-plugin.ts; pinned by a test). */
const COMPILED = ["protocol", "shield-node", "harden"];
const root = realpathSync(process.env.AR_SDK_GUARD_ROOT ?? "");
const sources = COMPILED.map((name) => join(root, "packages", name, "src"));

export async function resolve(specifier, context, next) {
  const result = await next(specifier, context);
  if (typeof result.url === "string" && result.url.startsWith("file:")) {
    let path = fileURLToPath(result.url);
    try {
      path = realpathSync(path);
    } catch {
      // A file that does not exist fails on its own.
    }
    for (const dir of sources) {
      const inside = relative(dir, path);
      if (inside !== "" && !inside.startsWith("..") && !isAbsolute(inside)) {
        throw new Error(`a source module was loaded in a run on the compiled output: ${relative(root, path)}`);
      }
    }
  }
  return result;
}
