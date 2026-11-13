import type { VerifyResult } from "@antireverse/protocol";
import type { CheckOutcome } from "../stores/targets.ts";
import {
  checkOwnership,
  createDnsResolver,
  createGuardedFetcher,
  type Fetcher,
  type FileCheckFailure,
  publicFileFailure,
  type Resolver,
} from "./verify.ts";

// The network seams of Prove, as `createApp` and `startApi` take them, and the one place a check's outcome is turned
// into what the target records and what the API answers.

export interface ProveDeps {
  /** TXT, A and AAAA lookups. Default: `createDnsResolver()` (node:dns). */
  resolver?: Resolver;
  /** The guarded HTTPS GET of the verification file. Default: `createGuardedFetcher({ resolver })`. */
  fetcher?: Fetcher;
}

export interface ProveNetwork {
  resolver: Resolver;
  fetcher: Fetcher;
}

/** The seams with their production defaults filled in. The default fetcher never has the test-only option. */
export function proveNetwork(deps: ProveDeps = {}): ProveNetwork {
  const resolver = deps.resolver ?? createDnsResolver();
  return { resolver, fetcher: deps.fetcher ?? createGuardedFetcher({ resolver }) };
}

/**
 * One ownership check of `host`: what to record, the API's `VerifyResult` (protocol reasons only) and, on failure,
 * the internal file reason (for the re-check rule and its counts; never shown per target).
 */
export async function runCheck(
  network: ProveNetwork,
  host: string,
  token: string,
  at: Date,
): Promise<{ outcome: CheckOutcome; result: VerifyResult; fileFailure?: FileCheckFailure }> {
  const checked = await checkOwnership(host, token, network);
  const checkedAt = at.toISOString();
  if (checked.verified) {
    return {
      outcome: { verified: true, method: checked.method },
      result: { verified: true, method: checked.method, checked_at: checkedAt },
    };
  }
  const file = publicFileFailure(checked.file);
  return {
    // Fixed words only: the reason never quotes a record, a body or an address.
    outcome: { verified: false, reason: `DNS: ${checked.dns}; file: ${file}` },
    result: { verified: false, dns: checked.dns, file, checked_at: checkedAt },
    fileFailure: checked.file,
  };
}
