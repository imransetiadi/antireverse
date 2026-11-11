import { en } from "./messages/en.ts";

export type MessageKey = keyof typeof en;

const PLACEHOLDER = /\{([a-zA-Z]+)\}/g;

/**
 * The catalog text for `key`, with `{name}` placeholders replaced from `values`.
 * Throws on an unknown key and on a placeholder without a value, so a broken string cannot ship unnoticed.
 */
export function t(key: MessageKey, values: Readonly<Record<string, string | number>> = {}): string {
  if (!Object.hasOwn(en, key)) throw new Error(`Unknown message key: ${String(key)}`);
  // A function replacement inserts the value literally: `$&` and friends in a value are not patterns.
  return en[key].replace(PLACEHOLDER, (_match, name: string) => {
    if (!Object.hasOwn(values, name)) throw new Error(`Message ${key} needs a value for {${name}}`);
    return String(values[name]);
  });
}
