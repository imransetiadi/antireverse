// Entry "@antireverse/api": everything needed to run the API in-process (tests) or as a server (main.ts).
export { type AppDeps, createApp } from "./app.ts";
export { type AttestationKeys, createAttestationKeys } from "./attestation/keys.ts";
export type { AppEnv, Principal } from "./auth/authenticate.ts";
export { createEventBus, type EventBus } from "./bus.ts";
export { type Config, readConfig } from "./config.ts";
export { type Db, type OwnedDb, openDb, type Queryable, type Scope } from "./db/db.ts";
export { createDetector, type Detector, type DetectorDeps } from "./detect/detector.ts";
export type { Logger } from "./log.ts";
export {
  type AlertFetch,
  createNotifier,
  type Notifier,
  type NotifierDeps,
  type Pin,
  pinnedFetch,
} from "./notify/notifier.ts";
export { checkDestination, type DestinationCheck, isForbiddenAddress, type Resolve } from "./notify/ssrf.ts";
export { type Listening, listen, type RunningApi, type StartApiOptions, startApi } from "./server.ts";
export { createSigner, type Signer } from "./signer.ts";
