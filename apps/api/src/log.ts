/** Where the API writes its log lines. Injectable so that tests can capture every line. */
export interface Logger {
  info(line: string): void;
  warn(line: string): void;
}

export const consoleLogger: Logger = {
  info: (line) => console.log(line),
  warn: (line) => console.warn(line),
};

// Anything shaped like the start of an admin key, a Shield key or a webhook signing secret, followed by at
// least 8 secret characters.
const KEY_LIKE = /(aro|ark_(?:prod|stg|dev)|whsec)_[A-Za-z0-9_-]{8,}/g;

/** Replaces the secret part of anything that looks like a key, and keeps the text on one line. */
export function redact(text: string): string {
  return text.replace(KEY_LIKE, "$1_[redacted]").replace(/[\r\n]+/g, " ");
}

/**
 * A logger that redacts every line. The API never passes a key, an Authorization header or a request
 * body to its logger; this is the second line of defence for text it does not control, such as the
 * message of an unexpected error.
 */
export function redacting(logger: Logger): Logger {
  return {
    info: (line) => logger.info(redact(line)),
    warn: (line) => logger.warn(redact(line)),
  };
}
