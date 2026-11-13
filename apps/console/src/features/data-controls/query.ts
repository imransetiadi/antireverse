import type { DataDone, DataStep } from "@/lib/routes.ts";

// The address of Settings → Data controls (slice 18b): `?step=&done=&blocked=1&subject_export=`. Anything else is
// ignored — an actor hash in particular never comes from the address (review 18b, L2).

export interface DataQuery {
  step: DataStep | undefined;
  done: DataDone | undefined;
  /** Another page was refused because a deletion was pending; shown only while one still is. */
  blocked: boolean;
  /** Why the subject export did not download. */
  subjectExport: "failed" | "invalid" | undefined;
}

type Params = Record<string, string | string[] | undefined>;

const one = (value: string | string[] | undefined): string | undefined =>
  typeof value === "string" ? value : undefined;

export function dataQueryFrom(params: Params): DataQuery {
  const step = one(params.step);
  const done = one(params.done);
  const subjectExport = one(params.subject_export);
  return {
    step: step === "delete" || step === "cancel" ? step : undefined,
    done: done === "requested" || done === "cancelled" ? done : undefined,
    blocked: one(params.blocked) === "1",
    subjectExport: subjectExport === "failed" || subjectExport === "invalid" ? subjectExport : undefined,
  };
}
