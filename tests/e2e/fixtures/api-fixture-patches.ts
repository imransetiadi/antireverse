// The API of the Playwright runs: apps/api/src/main.ts with one difference, the fixture Virtual patch catalog of the
// API tests (slice 20). The advisories this API knows are the fixture advisories (synthetic packages such as
// vuln-range and @fixture/vuln-scoped); the shipped catalog covers qs, lodash and xml2js, so none of its entries could
// ever activate here. The fixture catalog is built for exactly those fixture advisories, the way the API tests and
// exposure-patches.http.test.ts inject it. Same environment variables as main.ts (HOST, PORT, AR_DATA_DIR,
// AR_ALLOW_PRIVATE_ALERT_URLS, AR_CONSOLE_URL); tests only.
import { readConfig, startApi } from "@antireverse/api";
import { FIXTURE_PATCH_CATALOG } from "../../../apps/api/test/fixtures/patch-catalog.ts";

const logger = {
  info: (line: string) => console.log(line),
  warn: (line: string) => console.warn(line),
};

async function main(): Promise<void> {
  const config = readConfig(process.env);
  const api = await startApi({ ...config, logger, patches: FIXTURE_PATCH_CATALOG });
  logger.info(`api (fixture patch catalog ${FIXTURE_PATCH_CATALOG.version}) listening on ${api.url}`);
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    api.close().then(
      () => process.exit(0),
      () => process.exit(1),
    );
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

main().catch((error: unknown) => {
  logger.warn(`api failed to start: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
