// Entry "@antireverse/harden": the build-time protection engine and its helpers. Babel lives only in this
// package. The engine is pure and deterministic; the equivalence runner, manifest builder and register client
// are the I/O around it.
export { type BeaconConfig, beaconEndpointUrl, beaconStatement } from "./beacon.ts";
export { canaryStatement, plantCanaries } from "./canaries.ts";
export type { BundleInput, BundleLeakScan, BundleOptions, BundleResult } from "./engine.ts";
export { DEFAULT_BUDGET, harden, hardenBundle } from "./engine.ts";
export type { EquivalenceArgs, EquivalenceResult } from "./equivalence.ts";
export { checkEquivalence } from "./equivalence.ts";
export type { LeakFinding, LeakScanResult } from "./leaks/scan.ts";
export { DEFAULT_ALLOWLIST_PATH, loadAllowlist, maskValue, scanLeaks } from "./leaks/scan.ts";
export { type BuildManifestArgs, buildManifest } from "./manifest.ts";
export { applyIntegrity, containsEsm } from "./passes/integrity.ts";
export { type RegisterArgs, type RegisterResult, registerBuild } from "./register.ts";
export type { FileResult, HardenOptions, HardenResult, Pass, PassContext, Profile, TransformSummary } from "./types.ts";
