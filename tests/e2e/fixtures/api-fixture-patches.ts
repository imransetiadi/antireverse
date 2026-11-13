// The API of the Playwright runs: apps/api/src/main.ts with one difference, the fixture Virtual patch catalog of the
// API tests (slice 20). The advisories this API knows are the fixture advisories (synthetic packages such as
// vuln-range and @fixture/vuln-scoped); the shipped catalog covers qs, lodash and xml2js, so none of its entries could
// ever activate here. The fixture catalog is built for exactly those fixture advisories, the way the API tests and
// exposure-patches.http.test.ts inject it. Same environment variables as main.ts (HOST, PORT, AR_DATA_DIR,
// AR_ALLOW_PRIVATE_ALERT_URLS, AR_CONSOLE_URL); tests only.
//
// Prove (slice 14): when E2E_FAKE_DNS_FILE is set, the API's resolver is a stand-in that reads TXT records from that
// JSON file ({ "<record name>": [["chunk", ...], ...] }) on every lookup, as the journey publishes them; every other
// lookup (and any name not in the file) answers ENOTFOUND, so the file method fails as not_reachable and the e2e
// API never asks real DNS. The fetcher stays the default guarded fetcher, without its test-only option.
//
// Email (slice 06b): when E2E_FAKE_MAIL_FILE is set, this process starts the local SMTP server of the API tests
// (apps/api/test/fake-smtp.ts, STARTTLS, its own test CA) on a free port, gives the API SMTP settings for it through
// the real AR_SMTP_* reader, and writes every mail it receives to that JSON file ([{ from, to, data, overTls }]),
// which the journey reads. No mail leaves 127.0.0.1.
//
// Reverse Assessment (slice 12a): the Assessor is the real one (`proveAssessor`, the prove engine with its stand-in
// agent). When E2E_ASSESS_HOLD_FILE is set and that file exists, a run the runner has claimed waits (status running)
// until the file is removed, and only then starts the engine; the journey uses it to see an Assessment queued and
// running. Without the file nothing waits.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  type Assessor,
  type ProveDeps,
  proveAssessor,
  type Resolver,
  readConfig,
  readSmtpSettings,
  type SmtpSettings,
  startApi,
} from "@antireverse/api";
import { SMTP_PASSWORD, SMTP_USER, startFakeSmtp } from "../../../apps/api/test/fake-smtp.ts";
import { FIXTURE_PATCH_CATALOG } from "../../../apps/api/test/fixtures/patch-catalog.ts";

const logger = {
  info: (line: string) => console.log(line),
  warn: (line: string) => console.warn(line),
};

const notFound = (name: string) => Object.assign(new Error(`${name}: not found`), { code: "ENOTFOUND" });

function fileResolver(file: string): Resolver {
  return {
    async txt(name) {
      let records: Record<string, string[][]>;
      try {
        records = JSON.parse(readFileSync(file, "utf8")) as Record<string, string[][]>;
      } catch {
        throw notFound(name);
      }
      const answer = records[name];
      if (!Array.isArray(answer)) throw notFound(name);
      return answer;
    },
    async addresses(host) {
      throw notFound(host);
    },
  };
}

/** Starts the fake SMTP server and returns the API's settings for it; every mail received is written to `file`. */
async function fakeMail(file: string): Promise<{ smtp: SmtpSettings; close: () => Promise<void> }> {
  writeFileSync(file, "[]");
  const server = await startFakeSmtp({ mode: "starttls" });
  const record = server.mails.push.bind(server.mails);
  server.mails.push = (...mails) => {
    const length = record(...mails);
    writeFileSync(file, JSON.stringify(server.mails));
    return length;
  };
  const smtp = readSmtpSettings({
    AR_SMTP_HOST: "127.0.0.1",
    AR_SMTP_PORT: String(server.port),
    AR_SMTP_TLS: "starttls",
    AR_SMTP_USER: SMTP_USER,
    AR_SMTP_PASSWORD: SMTP_PASSWORD,
    AR_SMTP_FROM: "alerts@airverse.example",
    AR_SMTP_TEST_CA_FILE: fileURLToPath(new URL("../../../apps/api/test/fixtures/smtp-tls/ca.pem", import.meta.url)),
  });
  if (smtp === null) throw new Error("fake SMTP settings missing");
  return { smtp, close: () => server.close() };
}

/** The real Assessor, held before each run while `holdFile` exists (the runner's abort signal ends the wait). */
function heldAssessor(holdFile: string): Assessor {
  const real = proveAssessor();
  return {
    scope: (tier) => real.scope(tier),
    async assess(input) {
      while (existsSync(holdFile) && !input.signal.aborted) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      return real.assess(input);
    },
  };
}

async function main(): Promise<void> {
  const config = readConfig(process.env);
  const dnsFile = process.env.E2E_FAKE_DNS_FILE;
  const prove: ProveDeps | undefined = dnsFile ? { resolver: fileResolver(dnsFile) } : undefined;
  const mailFile = process.env.E2E_FAKE_MAIL_FILE;
  const mail = mailFile ? await fakeMail(mailFile) : undefined;
  const holdFile = process.env.E2E_ASSESS_HOLD_FILE;
  const api = await startApi({
    ...config,
    logger,
    patches: FIXTURE_PATCH_CATALOG,
    ...(prove === undefined ? {} : { prove }),
    ...(mail === undefined ? {} : { smtp: mail.smtp }),
    ...(holdFile ? { assessor: heldAssessor(holdFile) } : {}),
  });
  logger.info(`api (fixture patch catalog ${FIXTURE_PATCH_CATALOG.version}) listening on ${api.url}`);
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    api
      .close()
      .then(() => mail?.close())
      .then(
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
