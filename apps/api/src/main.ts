// The server entry point: `npm run dev:api`, or `tsx apps/api/src/main.ts`.
// Environment: HOST (default 127.0.0.1), PORT (default 8787, 0 = any free port), AR_DATA_DIR (default apps/api/.data/pg).
// The key that signs Policy Bundles is the file signing-key.json beside the data directory, created on the first start;
// the keys that sign Attestation Tokens are attestation-keys.json beside it (a separate purpose, rotated daily).
// Alerts: AR_CONSOLE_URL (default http://127.0.0.1:3000) for the links in alerts; AR_ALLOW_PRIVATE_ALERT_URLS=1
// allows http: and private addresses as alert channel URLs, for local development only.
// Email alerts (slice 06b): AR_SMTP_HOST, AR_SMTP_PORT (default 587), AR_SMTP_TLS (starttls, the default, or implicit),
// AR_SMTP_USER, AR_SMTP_PASSWORD or AR_SMTP_PASSWORD_FILE, AR_SMTP_FROM, AR_SMTP_FROM_NAME (default Airverse); all or
// none, a partial set stops the start naming the missing variable. AR_SMTP_TEST_CA_FILE: a local test server's CA only.
// The secret that keys the per-address count of confirmation mails is mail-hash-key.json beside the data directory.
import { readConfig } from "./config.ts";
import { consoleLogger } from "./log.ts";
import { type RunningApi, startApi } from "./server.ts";

async function main(): Promise<void> {
  const config = readConfig(process.env);
  const api: RunningApi = await startApi({ ...config, logger: consoleLogger });
  consoleLogger.info(`api listening on ${api.url} (data directory: ${config.dataDir})`);

  let stopping = false;
  const stop = (signal: NodeJS.Signals) => {
    if (stopping) return;
    stopping = true;
    consoleLogger.info(`api stopping on ${signal}`);
    api.close().then(
      () => process.exit(0),
      (error: unknown) => {
        consoleLogger.warn(`api failed to stop cleanly: ${error instanceof Error ? error.message : String(error)}`);
        process.exit(1);
      },
    );
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

main().catch((error: unknown) => {
  // Start-up failures are configuration problems (a port in use, a data directory held by another
  // process): one line, no stack.
  consoleLogger.warn(`api failed to start: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
