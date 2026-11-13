// Entry "@antireverse/api": everything needed to run the API in-process (tests) or as a server (main.ts).
export { type AppDeps, createApp } from "./app.ts";
export { type AttestationKeys, createAttestationKeys } from "./attestation/keys.ts";
export type { AppEnv, Principal } from "./auth/authenticate.ts";
export { createEventBus, type EventBus } from "./bus.ts";
export { type Config, readConfig } from "./config.ts";
export { type Db, type OwnedDb, openDb, type Queryable, type Scope } from "./db/db.ts";
export { createDetector, type Detector, type DetectorDeps } from "./detect/detector.ts";
export type { Logger } from "./log.ts";
export { type AddressHasher, createAddressHasher } from "./mail/address-key.ts";
export { decodeQuotedPrintable, type Sender } from "./mail/message.ts";
export { readSmtpSettings, SMTP_VARIABLES, type SmtpSettings, type SmtpTlsMode } from "./mail/settings.ts";
export { createSmtpMailer, type MailEnvelope, type Mailer, type MailResult, SMTP_TIMEOUTS } from "./mail/smtp.ts";
export {
  type AlertFetch,
  type ConfirmationMail,
  createNotifier,
  type EmailDeps,
  type Notifier,
  type NotifierDeps,
  type Pin,
  pinnedFetch,
} from "./notify/notifier.ts";
export { checkDestination, type DestinationCheck, isForbiddenAddress, type Resolve } from "./notify/ssrf.ts";
export { isPublicAddress } from "./prove/address.ts";
export { type Authorize, type AuthorizeTarget, createAuthorize, evaluateAuthorization } from "./prove/authorize.ts";
export type { ProveDeps, ProveNetwork } from "./prove/deps.ts";
export {
  createRecheckJob,
  RECHECK_DEFAULTS,
  RECHECK_MISSES_MAX,
  type RecheckCounts,
  type RecheckJob,
  type RecheckOptions,
} from "./prove/recheck.ts";
export {
  checkOwnership,
  createDnsResolver,
  createGuardedFetcher,
  type Fetcher,
  type FetchOutcome,
  type FileCheckFailure,
  type GuardedFetcherOptions,
  type GuardedFetcherTesting,
  type OwnershipResult,
  publicFileFailure,
  type Resolver,
} from "./prove/verify.ts";
export { type Listening, listen, type RunningApi, type StartApiOptions, startApi } from "./server.ts";
export { createSigner, type Signer } from "./signer.ts";
