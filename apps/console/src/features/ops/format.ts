import { SLO_THRESHOLD_TOLERANCE } from "@antireverse/protocol";

// Slice 18d: how the operator dashboard writes its figures. Pure, so a server render and any later render agree.

/** A relative epsilon of a few ulps: it absorbs binary rounding (0.29 × 100 = 28.999…) and nothing more. */
const ROUNDING = 1e-12;

const trim = (text: string): string => text.replace(/\.?0+$/, "");

/** An objective as a percentage without trailing zeros: 0.9999 → `99.99 %`, 0.95 → `95 %`. */
export function formatObjective(fraction: number): string {
  return `${trim((Math.round(fraction * 1_000_000) / 10_000).toFixed(4))} %`;
}

/**
 * A fraction as a percentage with `digits` decimals, cut rather than rounded: an attainment of 99.9899 % is never
 * shown as the 99.99 % objective it misses.
 */
export function formatPercent(fraction: number, digits: number): string {
  const scale = 10 ** digits;
  // A relative epsilon keeps 0.29 (28.999… in binary) whole without lifting 99.98999999995 % to 99.990 %.
  const cut = Math.floor(fraction * 100 * scale * (1 + ROUNDING)) / scale;
  return `${cut.toFixed(digits)} %`;
}

/**
 * A burn rate: two decimals below 10, one from 10 on, cut rather than rounded, so 14.36 never shows as the 14.4×
 * threshold it misses. The cut allows the threshold tolerance of the API's rule (`atThreshold`): a burn the API counts
 * as reaching 14.4 shows as 14.4×.
 */
export function formatBurn(rate: number): string {
  const digits = rate < 10 ? 2 : 1;
  const scale = 10 ** digits;
  return `${(Math.floor(rate * scale * (1 + SLO_THRESHOLD_TOLERANCE)) / scale).toFixed(digits)}×`;
}

/** A duration in ms, in the largest unit that keeps it whole or short: `120 ms`, `5 s`, `30 min`, `1 h`. */
export function formatDuration(ms: number): string {
  if (ms < 1_000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${trim((ms / 1_000).toFixed(1))} s`;
  if (ms < 3_600_000) return `${trim((ms / 60_000).toFixed(1))} min`;
  return `${trim((ms / 3_600_000).toFixed(1))} h`;
}
