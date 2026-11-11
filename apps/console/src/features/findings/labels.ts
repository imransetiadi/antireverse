import type { FindingSeverity, FindingSource, FindingStatus } from "@antireverse/protocol";
import type { MessageKey } from "@/lib/t.ts";

export const SEVERITY_LABEL: Record<FindingSeverity, MessageKey> = {
  critical: "severity.critical",
  high: "severity.high",
  medium: "severity.medium",
  low: "severity.low",
  unknown: "severity.unknown",
};

export const STATUS_LABEL: Record<FindingStatus, MessageKey> = {
  open: "finding.status.open",
  fixed: "finding.status.fixed",
  ignored: "finding.status.ignored",
  withdrawn: "finding.status.withdrawn",
};

export const SOURCE_LABEL: Record<FindingSource, MessageKey> = {
  build: "finding.source.build",
  runtime: "finding.source.runtime",
};
