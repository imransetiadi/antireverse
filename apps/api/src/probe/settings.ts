import { PROBES_VARIABLE } from "@antireverse/protocol";

// Slice 18g: the synthetic probes' switch, read from the environment at start-up. Off by default, like Pentest
// Campaigns: `AR_PROBES=1` turns them on; unset, empty or `0` leaves them off; anything else stops the start (a typo
// must not silently leave SLO-06 unmeasured). No error message quotes a value.

export interface ProbeSettings {
  enabled: boolean;
}

export const PROBE_VARIABLES = [PROBES_VARIABLE] as const;

export function readProbeSettings(env: Record<string, string | undefined>): ProbeSettings {
  const value = env[PROBES_VARIABLE];
  if (value === undefined || value === "" || value === "0") return { enabled: false };
  if (value === "1") return { enabled: true };
  throw new Error(`${PROBES_VARIABLE} must be 1 (on) or 0 (off).`);
}
