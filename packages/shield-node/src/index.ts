// Entry "@antireverse/shield-node": contract C3. Zero runtime dependencies.
export { createShield } from "./shield.ts";
export type {
  DecideInput,
  Decision,
  Shield,
  ShieldConfig,
  ShieldErrorHandler,
  ShieldLogger,
  ShieldMiddleware,
  ShieldStats,
  Transport,
} from "./types.ts";
export { SDK_NAME, SDK_VERSION } from "./types.ts";
