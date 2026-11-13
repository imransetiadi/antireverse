import { describe, expect, it } from "vitest";
import { readSmtpSettings, SMTP_VARIABLES, smtpSummary } from "../src/mail/settings.ts";

const PASSWORD = "s3cret-Pa55word!";
const FULL = {
  AR_SMTP_HOST: "smtp.example.com",
  AR_SMTP_USER: "alerts@airverse.example",
  AR_SMTP_PASSWORD: PASSWORD,
  AR_SMTP_FROM: "Alerts@Airverse.example",
};
const noFile = (): string => {
  throw new Error("no file expected");
};

/** The error thrown, whose message must never quote a value of the environment. */
function failure(env: Record<string, string | undefined>, readFile: (path: string) => string = noFile): Error {
  try {
    readSmtpSettings(env, { readFile });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    for (const value of Object.values(env)) {
      if (value !== undefined && value.length > 0) expect(error.message).not.toContain(value);
    }
    return error;
  }
  throw new Error("expected a start-up error");
}

describe("readSmtpSettings", () => {
  it("lists the variables it reads", () => {
    expect(SMTP_VARIABLES).toEqual([
      "AR_SMTP_HOST",
      "AR_SMTP_PORT",
      "AR_SMTP_TLS",
      "AR_SMTP_USER",
      "AR_SMTP_PASSWORD",
      "AR_SMTP_PASSWORD_FILE",
      "AR_SMTP_FROM",
      "AR_SMTP_FROM_NAME",
      "AR_SMTP_TEST_CA_FILE",
      "AR_SMTP_CONFIRMATIONS_PER_DAY",
    ]);
  });

  it("is null when no AR_SMTP_* variable is set (empty counts as unset)", () => {
    expect(readSmtpSettings({}, { readFile: noFile })).toBeNull();
    expect(readSmtpSettings({ AR_SMTP_HOST: "", AR_SMTP_PORT: "" }, { readFile: noFile })).toBeNull();
  });

  it("reads a full set with the defaults: port 587, STARTTLS, sender name Airverse, sender lower-cased", () => {
    expect(readSmtpSettings(FULL, { readFile: noFile })).toEqual({
      host: "smtp.example.com",
      port: 587,
      tls: "starttls",
      user: "alerts@airverse.example",
      password: PASSWORD,
      from: { address: "alerts@airverse.example", name: "Airverse" },
      ca: undefined,
      confirmationsPerDay: 500,
    });
  });

  it("reads the port, implicit TLS, the sender name and a test CA", () => {
    const settings = readSmtpSettings(
      { ...FULL, AR_SMTP_PORT: "465", AR_SMTP_TLS: "implicit", AR_SMTP_FROM_NAME: "Ops", AR_SMTP_TEST_CA_FILE: "/ca" },
      { readFile: (path) => (path === "/ca" ? "PEM" : noFile()) },
    );
    expect(settings).toMatchObject({ port: 465, tls: "implicit", from: { name: "Ops" }, ca: "PEM" });
  });

  it("reads the service's confirmation mails per day (review F1), a whole number from 1 to 1,000,000", () => {
    expect(
      readSmtpSettings({ ...FULL, AR_SMTP_CONFIRMATIONS_PER_DAY: "50" }, { readFile: noFile })?.confirmationsPerDay,
    ).toBe(50);
    for (const value of ["0", "-1", "1.5", "abc", "1000001"]) {
      expect(failure({ ...FULL, AR_SMTP_CONFIRMATIONS_PER_DAY: value }).message).toMatch(
        /AR_SMTP_CONFIRMATIONS_PER_DAY/,
      );
    }
  });

  it("reads the password from a file, without its final line break", () => {
    const { AR_SMTP_PASSWORD: _, ...withoutPassword } = FULL;
    const settings = readSmtpSettings(
      { ...withoutPassword, AR_SMTP_PASSWORD_FILE: "/run/secrets/smtp" },
      { readFile: (path) => (path === "/run/secrets/smtp" ? `${PASSWORD}\n` : noFile()) },
    );
    expect(settings?.password).toBe(PASSWORD);
  });

  it("refuses a partial set, naming the first missing variable and never a value", () => {
    expect(failure({ AR_SMTP_HOST: "smtp.example.com" }).message).toMatch(/AR_SMTP_USER/);
    expect(failure({ ...FULL, AR_SMTP_HOST: "" }).message).toMatch(/AR_SMTP_HOST/);
    expect(failure({ ...FULL, AR_SMTP_FROM: undefined }).message).toMatch(/AR_SMTP_FROM\b/);
    expect(failure({ ...FULL, AR_SMTP_PASSWORD: undefined }).message).toMatch(
      /AR_SMTP_PASSWORD or AR_SMTP_PASSWORD_FILE/,
    );
    // Only an optional variable set: the set is still partial.
    expect(failure({ AR_SMTP_PORT: "2525" }).message).toMatch(/AR_SMTP_HOST/);
  });

  it("refuses both password variables, an unreadable or empty password file", () => {
    expect(failure({ ...FULL, AR_SMTP_PASSWORD_FILE: "/x" }).message).toMatch(/only one of/);
    const { AR_SMTP_PASSWORD: _, ...withoutPassword } = FULL;
    expect(
      failure({ ...withoutPassword, AR_SMTP_PASSWORD_FILE: "/missing" }, () => {
        throw Object.assign(new Error(`ENOENT: /missing ${PASSWORD}`), { code: "ENOENT" });
      }).message,
    ).toBe("AR_SMTP_PASSWORD_FILE could not be read.");
    expect(failure({ ...withoutPassword, AR_SMTP_PASSWORD_FILE: "/empty" }, () => "\n").message).toMatch(/empty/);
  });

  it("refuses an invalid port, TLS mode, host or sender, naming the variable only", () => {
    for (const port of ["0", "65536", "25.5", "abc", "-1"]) {
      expect(failure({ ...FULL, AR_SMTP_PORT: port }).message).toMatch(/AR_SMTP_PORT/);
    }
    expect(failure({ ...FULL, AR_SMTP_TLS: "none" }).message).toMatch(/AR_SMTP_TLS must be starttls or implicit/);
    expect(failure({ ...FULL, AR_SMTP_HOST: "smtp.example.com\r\nX" }).message).toMatch(/AR_SMTP_HOST/);
    expect(failure({ ...FULL, AR_SMTP_FROM: "not an address" }).message).toMatch(/AR_SMTP_FROM/);
    expect(failure({ ...FULL, AR_SMTP_FROM_NAME: "a\r\nBcc: x@y.z" }).message).toMatch(/AR_SMTP_FROM_NAME/);
  });

  it("summarises the settings for the start-up log without the user or the password", () => {
    const settings = readSmtpSettings(FULL, { readFile: noFile });
    if (settings === null) throw new Error("settings");
    const line = smtpSummary(settings);
    expect(line).toBe("smtp host=smtp.example.com port=587 tls=starttls");
    expect(line).not.toContain(PASSWORD);
    expect(line).not.toContain("alerts@");
  });
});
