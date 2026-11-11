// Signals v1. A missing navigator, a missing property or a getter that throws shows no signal. Only the ids leave
// this module, never the values they were derived from.
import { ATTESTATION_SIGNALS } from "./constants.js";

/** @typedef {import("./index.js").GuardNavigator} GuardNavigator */
/** @typedef {import("./index.js").AttestationSignal} AttestationSignal */
/** @typedef {"windows" | "apple" | "linux"} OsFamily */

/**
 * @template T
 * @param {() => T} read
 * @returns {T | undefined}
 */
function attempt(read) {
  try {
    return read();
  } catch {
    return undefined;
  }
}

/** @param {unknown} value */
const text = (value) => (typeof value === "string" ? value : "");

/**
 * The OS family a user agent claims. Android and Chrome OS count as Linux (their `navigator.platform` reads
 * "Linux …"); iOS counts as Apple (an iPad in desktop mode claims a Mac).
 * @param {string} userAgent
 * @returns {OsFamily | undefined}
 */
function familyOfUserAgent(userAgent) {
  if (/Windows/.test(userAgent)) return "windows";
  if (/iPhone|iPad|iPod|Macintosh|Mac OS X/.test(userAgent)) return "apple";
  if (/Android|CrOS|Linux|X11/.test(userAgent)) return "linux";
  return undefined;
}

/**
 * The OS family of `navigator.platform` or `navigator.userAgentData.platform`.
 * @param {string} platform
 * @returns {OsFamily | undefined}
 */
function familyOfPlatform(platform) {
  if (/^Win|^Windows$/.test(platform)) return "windows";
  if (/^Mac|^macOS$|^iPhone|^iPad|^iPod|^iOS$/.test(platform)) return "apple";
  if (/^Linux|^Android$|^Chrome OS$|^Chromium OS$/.test(platform)) return "linux";
  return undefined;
}

// A check may throw (a hostile getter); collectSignals then counts it as not shown.

/** @param {GuardNavigator} navigator */
function webdriver(navigator) {
  return navigator.webdriver === true;
}

/** @param {GuardNavigator} navigator */
function headless(navigator) {
  const userAgent = text(navigator.userAgent);
  if (/HeadlessChrome/.test(userAgent)) return true;
  if (!/Chrome\//.test(userAgent) || /Mobile|Android/.test(userAgent)) return false;
  const plugins = navigator.plugins;
  return plugins === undefined || plugins === null || plugins.length === 0;
}

/** @param {GuardNavigator} navigator */
function inconsistent(navigator) {
  const claimed = familyOfUserAgent(text(navigator.userAgent));
  if (claimed === undefined) return false;
  return [text(navigator.platform), text(navigator.userAgentData?.platform)].some((platform) => {
    const family = familyOfPlatform(platform);
    return family !== undefined && family !== claimed;
  });
}

/** @type {Record<AttestationSignal, (navigator: GuardNavigator) => boolean>} */
const CHECKS = {
  "automation.webdriver": webdriver,
  "automation.headless": headless,
  "env.inconsistent": inconsistent,
};

/**
 * The signal ids a navigator shows, in canonical order. Never throws.
 * @param {GuardNavigator | null | undefined} navigator
 * @returns {AttestationSignal[]}
 */
export function collectSignals(navigator) {
  if (typeof navigator !== "object" || navigator === null) return [];
  return ATTESTATION_SIGNALS.filter((id) => attempt(() => CHECKS[id](navigator)) === true);
}
