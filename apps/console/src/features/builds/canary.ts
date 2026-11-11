import type { Build, CanaryKind } from "@antireverse/protocol";
import type { MessageKey } from "@/lib/t.ts";
import { t } from "@/lib/t.ts";

/** The word for each kind of Canary: always a word, never a colour or an icon alone. */
export const CANARY_KIND_LABEL: Readonly<Record<CanaryKind, MessageKey>> = {
  key: "canary.kind.key",
  route: "canary.kind.route",
};

/** "1 Canary" or "N Canaries". */
export function canaryCount(count: number): string {
  return count === 1 ? t("build.canaries.count.one") : t("build.canaries.count", { count });
}

/** The leak-scan outcome of a Build: clean, clean with suppressed findings, or none (registered before the scan). */
export function leakScanState(build: Build): { status: "clean" | "suppressed" | "none"; text: string } {
  const scan = build.leak_scan;
  if (scan === undefined) return { status: "none", text: t("build.leakScan.none") };
  if (scan.status === "suppressed") {
    return { status: "suppressed", text: t("build.leakScan.suppressed", { count: scan.suppressed }) };
  }
  return { status: "clean", text: t("build.leakScan.clean") };
}
