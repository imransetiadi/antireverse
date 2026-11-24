// The load guard for child processes of the run on the compiled output (slice 23, review M1). The Vitest plugin
// (dist-plugin.ts) sees the modules Vite loads; a process a test starts is outside it. The compiled run puts
// `--import <this file>` into NODE_OPTIONS, so every Node process started from a test registers the hooks beside
// this file, and loading a source module of a compiled package fails there too. Plain JavaScript: it runs in
// processes that have no TypeScript loader.
import { register } from "node:module";

if (!process.env.AR_SDK_GUARD_ROOT) throw new Error("AR_SDK_GUARD_ROOT must name the repository root");
register("./child-guard-hooks.mjs", import.meta.url);
