// Builds the Build Manifest: the signed-record-to-be that `--register` sends to the API. It carries NO source
// and NO secret — only per-artifact digests, transform counts, measured costs, and the seed's fingerprint
// (`seed_id`, never the seed value). It is shaped to pass `BuildManifestSchema` in the protocol.
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import type {
  BuildManifest,
  Canary,
  Environment,
  LeakScanSummary,
  ManifestBeacon,
  Profile,
  TransformSummary,
} from "@antireverse/protocol";
import { seedId } from "@antireverse/protocol/server";

export interface BuildManifestArgs {
  buildId: string;
  appId: string;
  environment: Environment;
  version: string;
  profile: Profile;
  /** The numeric seed. Only its fingerprint (`seed_id`) reaches the Manifest. */
  seed: number;
  /** The protected artifacts: their path and final code. */
  artifacts: Array<{ path: string; code: string }>;
  /** The original source per path, used to measure gzip size overhead. Omit to report 0. */
  originals?: Record<string, string>;
  transform: TransformSummary;
  equivalence: "passed" | "skipped";
  /** Measured runtime overhead, or null when not measured (the default in this slice). */
  runOverheadPct?: number | null;
  /** ISO timestamp; defaults to now. */
  createdAt?: string;
  /** The leak-scan summary (status and suppressed count only — never a finding). Omitted when absent. */
  leakScan?: LeakScanSummary;
  /** The planted Canaries (decoy values, not secrets). Omitted when absent. */
  canaries?: readonly Canary[];
  /** The planted Clone Beacon: its token and allowed origins (slice 10). Omitted when absent. */
  beacon?: ManifestBeacon;
  /** The component inventory in summary (slice 19): its length and `componentsDigest`. Omitted when absent. */
  components?: { count: number; digest: string };
  /** The route inventory in summary (slice 12a): its length and `routesDigest`. Never the routes. Omitted when absent. */
  routes?: { count: number; digest: string };
  /** The designated protected functions in summary (slice 12b): their number and `logicDigest`. Never the file. Omitted when absent. */
  logic?: { count: number; digest: string };
}

function gzipLen(code: string): number {
  return gzipSync(Buffer.from(code, "utf8")).length;
}

export function buildManifest(args: BuildManifestArgs): BuildManifest {
  const artifacts = args.artifacts.map((a) => ({
    path: a.path,
    sha256: createHash("sha256").update(a.code, "utf8").digest("hex"),
    bytes: Buffer.byteLength(a.code, "utf8"),
  }));

  // Aggregate gzip size overhead across artifacts that have a known original.
  let origTotal = 0;
  let outTotal = 0;
  for (const a of args.artifacts) {
    const original = args.originals?.[a.path];
    if (original === undefined) continue;
    origTotal += gzipLen(original);
    outTotal += gzipLen(a.code);
  }
  const sizeOverheadPct = origTotal === 0 ? 0 : ((outTotal - origTotal) / origTotal) * 100;

  return {
    format: 1,
    build_id: args.buildId,
    app_id: args.appId,
    environment: args.environment,
    version: args.version,
    profile: args.profile,
    seed_id: seedId(String(args.seed)),
    artifacts,
    transform: args.transform,
    costs: {
      size_overhead_pct: Number(sizeOverheadPct.toFixed(2)),
      run_overhead_pct: args.runOverheadPct ?? null,
    },
    equivalence: args.equivalence,
    created_at: args.createdAt ?? new Date().toISOString(),
    ...(args.leakScan ? { leak_scan: { status: args.leakScan.status, suppressed: args.leakScan.suppressed } } : {}),
    ...(args.canaries ? { canaries: args.canaries.map((c) => ({ ...c })) } : {}),
    ...(args.beacon ? { beacon: { token: args.beacon.token, origins: [...args.beacon.origins] } } : {}),
    ...(args.components ? { components_digest: args.components.digest, component_count: args.components.count } : {}),
    ...(args.routes ? { routes_digest: args.routes.digest, route_count: args.routes.count } : {}),
    ...(args.logic ? { logic_digest: args.logic.digest, logic_count: args.logic.count } : {}),
  };
}
