// Shared by the adapter tests. Not a test file: Vitest collects only *.test.ts.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { EventBatchSchema, type ShieldEvent } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { createShield, type Shield, type ShieldConfig, type Transport } from "../src/index.ts";

export const KEY = generateKey("shield", "development").key;

export interface Listening {
  server: http.Server;
  base: string;
  port: number;
  stop(): Promise<void>;
}

/** Serves on port 0. `stop()` closes keep-alive sockets first: `close()` alone waits about 5 s for them. */
export async function listen(handler: http.RequestListener, host = "127.0.0.1"): Promise<Listening> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    server,
    port,
    base: `http://127.0.0.1:${port}`,
    stop: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

export interface Captured {
  shield: Shield;
  /** Every request the fake transport received. */
  requests: Parameters<Transport>[0][];
  warnings: string[];
  /** Waits until `count` Events were recorded in total, flushes, and returns every Event sent so far, in order. */
  events(count: number): Promise<ShieldEvent[]>;
  /** Events recorded so far: sent, waiting, dropped or in a failed batch. */
  recorded(): number;
}

/** A Shield whose batches are captured instead of sent. Every captured batch is validated against the protocol. */
export function captureShield(config: Partial<ShieldConfig> = {}): Captured {
  const requests: Parameters<Transport>[0][] = [];
  const warnings: string[] = [];
  const transport: Transport = async (request) => {
    requests.push(request);
    return { status: 202 };
  };
  const shield = createShield({
    key: KEY,
    endpoint: "http://ingest.test",
    transport,
    flushIntervalMs: 3_600_000, // tests flush explicitly
    inventory: false, // every request is an Event batch here; the inventory has tests of its own
    logger: { warn: (message) => void warnings.push(message) },
    ...config,
  });
  const recorded = (): number => {
    const stats = shield.stats();
    return stats.buffered + stats.sent + stats.dropped;
  };
  return {
    shield,
    requests,
    warnings,
    recorded,
    async events(count) {
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return requests.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    },
  };
}

/** The request line and everything else the client learns: status, headers without `date`, body. */
export async function exchange(
  url: string,
  init?: RequestInit,
): Promise<{ status: number; headers: [string, string][]; body: string }> {
  const response = await fetch(url, init);
  const body = await response.text();
  const headers = [...response.headers.entries()].filter(([name]) => name !== "date").sort();
  return { status: response.status, headers, body };
}
