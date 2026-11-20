import { describe, expect, it } from "vitest";
import { PROBE_VARIABLES, readProbeSettings } from "../src/probe/settings.ts";

// Slice 18g: `AR_PROBES` turns the synthetic probes on. Off by default; a value that is neither on nor off stops the
// start, naming the variable and never the value.

describe("readProbeSettings", () => {
  it("is off unless AR_PROBES is exactly 1", () => {
    expect(readProbeSettings({})).toEqual({ enabled: false });
    expect(readProbeSettings({ AR_PROBES: "" })).toEqual({ enabled: false });
    expect(readProbeSettings({ AR_PROBES: "0" })).toEqual({ enabled: false });
    expect(readProbeSettings({ AR_PROBES: "1" })).toEqual({ enabled: true });
    expect([...PROBE_VARIABLES]).toEqual(["AR_PROBES"]);
  });

  it("refuses any other value without quoting it", () => {
    for (const value of ["true", "yes", "on", " 1", "2", "secret-looking-value"]) {
      let message = "";
      try {
        readProbeSettings({ AR_PROBES: value });
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message, value).toBe("AR_PROBES must be 1 (on) or 0 (off).");
    }
  });
});
