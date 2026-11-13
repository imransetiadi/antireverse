import { t } from "@/lib/t.ts";

// Why an export did not download (slice 18a): the export route answers a refusal by going back to the Audit log with
// `?export=limited&retry=<seconds>` or `?export=failed`, so that the person reads a sentence, not a problem document.

export type ExportNoticeState = { kind: "limited"; retryAfter: number | undefined } | { kind: "failed" } | null;

/** The notice the address asks for, or null. */
export function exportNoticeFrom(params: {
  export?: string | string[] | undefined;
  retry?: string | string[] | undefined;
}): ExportNoticeState {
  if (params.export === "failed") return { kind: "failed" };
  if (params.export !== "limited") return null;
  const retry =
    typeof params.retry === "string" && /^[0-9]{1,5}$/.test(params.retry) ? Number(params.retry) : undefined;
  return { kind: "limited", retryAfter: retry };
}

export function ExportNotice({ notice }: { notice: ExportNoticeState }) {
  if (notice === null) return null;
  const text =
    notice.kind === "failed"
      ? t("audit.export.failed")
      : notice.retryAfter === undefined
        ? t("audit.export.limited.soon")
        : t("audit.export.limited", { seconds: Math.max(1, notice.retryAfter) });
  return (
    <p role="alert" data-testid="audit-export-notice" className="max-w-xs body-5 text-sev-critical-text">
      {text}
    </p>
  );
}
