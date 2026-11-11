// @vitest-environment node
import { describe, expect, it } from "vitest";
import { formatBytes, formatDateTime, formatLatency, formatOverhead, formatTime, statusClass } from "@/lib/format.ts";

describe("formatTime", () => {
  it("renders HH:MM:SS in UTC and keeps the ISO value for a title", () => {
    expect(formatTime("2026-11-10T08:15:30.123Z")).toEqual({ text: "08:15:30", iso: "2026-11-10T08:15:30.123Z" });
    expect(formatTime("2026-11-10T23:59:59.999Z").text).toBe("23:59:59");
    expect(formatTime("2026-01-02T00:00:00Z").text).toBe("00:00:00");
  });

  it("does not invent a time for a value that is not a date", () => {
    expect(formatTime("not-a-date")).toEqual({ text: "--:--:--", iso: "not-a-date" });
  });
});

describe("formatDateTime", () => {
  it("renders YYYY-MM-DD HH:MM:SS in UTC and keeps the ISO value", () => {
    expect(formatDateTime("2026-11-10T08:15:30.123Z")).toEqual({
      text: "2026-11-10 08:15:30",
      iso: "2026-11-10T08:15:30.123Z",
    });
    expect(formatDateTime("2026-01-02T00:00:00Z").text).toBe("2026-01-02 00:00:00");
    // Another offset is shown in UTC, whatever the time zone of the machine.
    expect(formatDateTime("2026-11-10T01:00:00+07:00").text).toBe("2026-11-09 18:00:00");
  });

  it("does not invent a date for a value that is not a date", () => {
    expect(formatDateTime("not-a-date")).toEqual({ text: "---- -- -- --:--:--", iso: "not-a-date" });
  });
});

describe("formatLatency", () => {
  it("renders sub-millisecond latency as <1 ms", () => {
    expect(formatLatency(0)).toBe("<1 ms");
    expect(formatLatency(0.42)).toBe("<1 ms");
    expect(formatLatency(0.99)).toBe("<1 ms");
  });

  it("renders whole milliseconds below one second", () => {
    expect(formatLatency(1)).toBe("1 ms");
    expect(formatLatency(3.25)).toBe("3 ms");
    expect(formatLatency(999.4)).toBe("999 ms");
  });

  it("renders seconds with one decimal from one second up", () => {
    expect(formatLatency(999.6)).toBe("1.0 s");
    expect(formatLatency(1000)).toBe("1.0 s");
    expect(formatLatency(1234)).toBe("1.2 s");
    expect(formatLatency(600_000)).toBe("600.0 s");
  });
});

describe("formatOverhead", () => {
  it("shows a positive overhead with a plus sign and one decimal at most", () => {
    expect(formatOverhead(12.5)).toBe("+12.5 %");
    expect(formatOverhead(3.2)).toBe("+3.2 %");
    expect(formatOverhead(42)).toBe("+42 %");
    expect(formatOverhead(20)).toBe("+20 %");
  });

  it("shows zero without a sign and a reduction with a minus sign", () => {
    expect(formatOverhead(0)).toBe("0 %");
    expect(formatOverhead(-4)).toBe("-4 %");
    expect(formatOverhead(-2.2)).toBe("-2.2 %");
  });
});

describe("formatBytes", () => {
  it("groups thousands with a comma, the same on the server and in the browser", () => {
    expect(formatBytes(0)).toBe("0");
    expect(formatBytes(2048)).toBe("2,048");
    expect(formatBytes(1048576)).toBe("1,048,576");
  });
});

describe("statusClass", () => {
  it("maps 2xx and 3xx to ok, 4xx to client and 5xx to server", () => {
    expect(statusClass(200)).toBe("ok");
    expect(statusClass(204)).toBe("ok");
    expect(statusClass(302)).toBe("ok");
    expect(statusClass(399)).toBe("ok");
    expect(statusClass(400)).toBe("client");
    expect(statusClass(404)).toBe("client");
    expect(statusClass(499)).toBe("client");
    expect(statusClass(500)).toBe("server");
    expect(statusClass(599)).toBe("server");
  });

  it("treats informational statuses as ok", () => {
    expect(statusClass(101)).toBe("ok");
  });
});
