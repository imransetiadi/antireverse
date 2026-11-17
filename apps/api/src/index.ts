// Entry "@antireverse/api": everything needed to run the API in-process (tests) or as a server (main.ts).
export { type AppDeps, createApp } from "./app.ts";
export {
  type Assessor,
  type AssessorBuildFacts,
  type AssessorInput,
  type AssessorLeakFinding,
  type AssessorOutcome,
  ENGINE_UNAVAILABLE,
  unavailableAssessor,
} from "./assess/assessor.ts";
export { proveAssessor } from "./assess/prove-assessor.ts";
export {
  type AssessmentQueue,
  type AssessmentRunner,
  type AssessmentRunnerOptions,
  createAssessmentRunner,
  FAILURE_REASONS,
  RUNNER_DEFAULTS,
} from "./assess/runner.ts";
export { type AttestationKeys, createAttestationKeys } from "./attestation/keys.ts";
export type { AppEnv, Principal } from "./auth/authenticate.ts";
export { createEventBus, type EventBus } from "./bus.ts";
export {
  CAMPAIGN_ID_HEADER,
  CAMPAIGN_USER_AGENT,
  createGate,
  type Gate,
  type GateControl,
  type GateDeps,
  type GateRecord,
  type GateSend,
} from "./campaign/gate.ts";
export {
  BODY_WITHHELD,
  evidenceWindow,
  locationOf,
  redactBody,
  redactHeaders,
  redactText,
} from "./campaign/redact.ts";
export {
  type CampaignEngineRunner,
  type CampaignRunner,
  type CampaignRunnerOptions,
  type CampaignService,
  type CampaignTesting,
  createCampaignRunner,
} from "./campaign/runner.ts";
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
  type PinnedRequest,
  type PinnedResponse,
  pinnedRequest,
  publicFileFailure,
  type Resolver,
  resolvePinned,
} from "./prove/verify.ts";
export { type Listening, listen, type RunningApi, type StartApiOptions, startApi } from "./server.ts";
export { createSigner, type Signer } from "./signer.ts";
export type { AlertTransition } from "./slo/evaluate.ts";
export type { SloRecorder, SloSink } from "./slo/recorder.ts";
export { createSloService, SLO_JOB_DEFAULTS, type SloService, type SloServiceOptions } from "./slo/service.ts";
export { OPS_VARIABLES, type OpsSettings, type OpsWebhook, readOpsSettings } from "./slo/settings.ts";
