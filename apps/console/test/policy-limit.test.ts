// @vitest-environment node
import { EXAMPLE_LIMIT_RULE, LIMIT_LIMITS } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { LOGIN_PROTECTION, limitText, wholeNumber, windowText } from "@/features/policy/limit.ts";

// The words of a limit (slice 08): how the Rule list and the form's hint say a window and a limit.

describe("windowText", () => {
  it("says a window in the largest units that fit, without a decimal", () => {
    expect(windowText(1)).toBe("1 s");
    expect(windowText(45)).toBe("45 s");
    expect(windowText(60)).toBe("1 min");
    expect(windowText(90)).toBe("1 min 30 s");
    expect(windowText(300)).toBe("5 min");
    expect(windowText(3_599)).toBe("59 min 59 s");
    expect(windowText(3_600)).toBe("1 h");
  });
});

describe("limitText", () => {
  it("says what is counted, the window and what it is counted per", () => {
    expect(limitText(EXAMPLE_LIMIT_RULE.limit)).toBe("10 failed responses / 5 min per address");
    expect(limitText({ requests: 100, window_s: 60, key: "device", count: "requests" })).toBe(
      "100 requests / 1 min per device",
    );
  });

  it("uses the singular for one and groups thousands", () => {
    expect(limitText({ requests: 1, window_s: 1, key: "ip", count: "requests" })).toBe("1 request / 1 s per address");
    expect(limitText({ requests: 1, window_s: 3_600, key: "device", count: "failures" })).toBe(
      "1 failed response / 1 h per device",
    );
    expect(limitText({ requests: 1_000, window_s: 3_600, key: "ip", count: "requests" })).toBe(
      "1,000 requests / 1 h per address",
    );
  });

  it("says About for a limit above 1,000, which Shield counts approximately (A7 F2)", () => {
    expect(limitText({ requests: 1_000, window_s: 60, key: "ip", count: "failures" })).toBe(
      "1,000 failed responses / 1 min per address",
    );
    expect(limitText({ requests: 1_001, window_s: 60, key: "ip", count: "requests" })).toBe(
      "About 1,001 requests / 1 min per address",
    );
    expect(limitText({ requests: 5_000, window_s: 60, key: "ip", count: "requests" })).toBe(
      "About 5,000 requests / 1 min per address",
    );
    expect(limitText({ requests: 100_000, window_s: 3_600, key: "device", count: "failures" })).toBe(
      "About 100,000 failed responses / 1 h per device",
    );
  });
});

describe("wholeNumber", () => {
  it("reads a whole number from 1 to the largest allowed, and nothing else", () => {
    expect(wholeNumber("1", LIMIT_LIMITS.requestsMax)).toBe(1);
    expect(wholeNumber("100000", LIMIT_LIMITS.requestsMax)).toBe(100_000);
    expect(wholeNumber("3600", LIMIT_LIMITS.windowSecondsMax)).toBe(3_600);
    for (const bad of ["", "0", "-1", "1.5", "1e3", "010", " 5", "5 ", "ten", "100001", "9999999999999999999"]) {
      expect(wholeNumber(bad, LIMIT_LIMITS.requestsMax)).toBeNull();
    }
    expect(wholeNumber("3601", LIMIT_LIMITS.windowSecondsMax)).toBeNull();
  });
});

describe("the Login protection preset", () => {
  it("is the protocol's example limit: POST, 10 failed responses per 300 s per address", () => {
    expect(LOGIN_PROTECTION.methods).toEqual(EXAMPLE_LIMIT_RULE.methods);
    expect(LOGIN_PROTECTION.limit).toEqual({ requests: "10", window: "300", key: "ip", count: "failures" });
    expect(Number(LOGIN_PROTECTION.limit.requests)).toBe(EXAMPLE_LIMIT_RULE.limit.requests);
    expect(Number(LOGIN_PROTECTION.limit.window)).toBe(EXAMPLE_LIMIT_RULE.limit.window_s);
  });
});
