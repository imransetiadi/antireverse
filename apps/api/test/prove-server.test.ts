import { describe, expect, it, vi } from "vitest";
import { startApi } from "../src/server.ts";
import { captureLogger } from "./helpers.ts";

vi.setConfig({ testTimeout: 30_000, hookTimeout: 30_000 });

// startApi and Prove (slice 14): the re-check job starts with the server and stops on close; `authorize` is handed
// out for slice 15; the network seams are injectable.

describe("startApi with Prove", () => {
  it("starts the re-check job, hands out authorize, and stops the job on close", async () => {
    const timers: { ms: number; cleared: boolean }[] = [];
    const api = await startApi({
      logger: captureLogger(),
      prove: {
        resolver: { txt: async () => [], addresses: async () => [] },
        fetcher: async () => ({ ok: false, reason: "status" }),
      },
      recheck: {
        random: () => 0,
        setTimer: (_fn, ms) => {
          const timer = { ms, cleared: false };
          timers.push(timer);
          return timer;
        },
        clearTimer: (handle) => {
          (handle as { cleared: boolean }).cleared = true;
        },
      },
    });
    try {
      expect(timers).toEqual([{ ms: 0, cleared: false }]);
      expect(
        await api.authorize("org_0123456789abcdef01234567", {
          host: "shop.acme-shop.io",
          path: "/",
          intensity: "passive",
          at: "2026-11-16T10:00:00.000Z",
        }),
      ).toEqual({ allowed: false, reason: "target_unknown" });
    } finally {
      await api.close();
    }
    expect(timers[0]?.cleared).toBe(true);
  });
});
