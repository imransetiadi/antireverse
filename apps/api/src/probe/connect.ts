import type { ProbeTransport } from "./runner.ts";
import type { ProbeTenant } from "./tenant.ts";

// Slice 18g, review F1: how the prober is set up. The probe's Organization is provisioned once per process — its keys
// are made then, and never again while the process lives — and only the transport is opened again after a failure.
// (Provisioning on every attempt made a new pair of keys each failed minute.) A provisioning that itself failed is
// tried again at the next attempt.

export interface ProbeConnectOptions {
  /** Finds or creates the probe's Organization and makes its keys. Called until it succeeds once. */
  provision: () => Promise<ProbeTenant>;
  /** Told the Organization as soon as it is provisioned, before any request of the probe is sent. */
  register?: ((organizationId: string) => void) | undefined;
  /** Opens the transport for the provisioned tenant. Called again after a failure. */
  open: (tenant: ProbeTenant, signal: AbortSignal) => Promise<ProbeTransport>;
}

export function createProbeConnect(options: ProbeConnectOptions): (signal: AbortSignal) => Promise<ProbeTransport> {
  let tenant: ProbeTenant | undefined;
  return async (signal) => {
    if (tenant === undefined) {
      tenant = await options.provision();
      options.register?.(tenant.organizationId);
    }
    return options.open(tenant, signal);
  };
}
