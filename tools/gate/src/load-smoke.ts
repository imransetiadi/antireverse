// The load smoke's child (slice 18e): starts the API in this process on a free loopback port (never 8787 or 3000),
// with an in-memory database, and drives a fixed amount of work — Control API reads and writes, Event batches, and
// attestation challenge-and-attest pairs — timing each round trip from the client. Prints one
// `GATE-RESULT {"series":…,"errors":…}` line; the gate computes the percentiles and judges them (load.ts).
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { startApi } from "@antireverse/api";
import { EXAMPLE_SHIELD_EVENT } from "@antireverse/protocol";
import { jwkThumbprint } from "@antireverse/protocol/server";
import { LOAD_PLAN, type Series } from "./load.ts";

const series: Record<Series, number[]> = { "control-read": [], "control-write": [], ingest: [], attest: [] };
const errors: string[] = [];

function uuidv7(ms: number, n: number): string {
  const hex = ms.toString(16).padStart(12, "0");
  const tail = n.toString(16).padStart(12, "0");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-7000-8000-${tail}`;
}

async function main(): Promise<void> {
  const api = await startApi({ host: "127.0.0.1", port: 0, logger: { info() {}, warn() {} }, smtp: null });
  try {
    if (/:(8787|3000)$/.test(api.url)) throw new Error(`refusing a reserved port: ${api.url}`);
    const call = async (
      label: Series | null,
      method: string,
      path: string,
      expected: number,
      body?: unknown,
      key?: string,
    ): Promise<unknown> => {
      const headers: Record<string, string> = {};
      if (key) headers.authorization = `Bearer ${key}`;
      if (body !== undefined) headers["content-type"] = "application/json";
      const started = performance.now();
      const res = await fetch(`${api.url}${path}`, {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const text = await res.text();
      const ms = performance.now() - started;
      if (res.status !== expected) {
        if (errors.length < 20)
          errors.push(`${method} ${path.replace(/\/[a-z]+_[0-9a-f]{24}/g, "/:id")}: ${res.status}`);
        return null;
      }
      if (label) series[label].push(Math.round(ms * 100) / 100);
      return text === "" ? null : JSON.parse(text);
    };
    const pool = async (count: number, task: (i: number) => Promise<unknown>) => {
      let next = 0;
      const worker = async () => {
        while (next < count) await task(next++);
      };
      await Promise.all(Array.from({ length: LOAD_PLAN.concurrency }, worker));
    };

    // Setup (not measured): an Organization and an App with its keys.
    const org = (await call(null, "POST", "/v1/organizations", 201, { name: "Gate load smoke" })) as {
      admin_key: { key: string };
    } | null;
    if (!org) throw new Error(`could not create an Organization (${errors.join("; ")})`);
    const admin = org.admin_key.key;
    const app = (await call(null, "POST", "/v1/apps", 201, { name: "load-smoke" }, admin)) as {
      app: { id: string };
      shield_key: { key: string };
    } | null;
    if (!app) throw new Error(`could not create an App (${errors.join("; ")})`);
    const shield = app.shield_key.key;
    // Warm-up (not measured): the first requests compile routes and fill caches.
    for (let i = 0; i < 5; i++) await call(null, "GET", "/v1/apps", 200, undefined, admin);

    const reads = ["/v1/apps", "/v1/organization", `/v1/apps/${app.app.id}`];
    await pool(LOAD_PLAN.controlReads, (i) =>
      call("control-read", "GET", reads[i % reads.length] as string, 200, undefined, admin),
    );
    await pool(LOAD_PLAN.controlWrites, (i) =>
      call("control-write", "POST", "/v1/apps", 201, { name: `load-${i}` }, admin),
    );

    const start = Date.now();
    await pool(LOAD_PLAN.ingestBatches, (b) => {
      const events = Array.from({ length: LOAD_PLAN.eventsPerBatch }, (_, e) => ({
        ...EXAMPLE_SHIELD_EVENT,
        event_id: uuidv7(start, b * LOAD_PLAN.eventsPerBatch + e),
        ts: new Date(start).toISOString(),
      }));
      return call(
        "ingest",
        "POST",
        "/v1/events",
        202,
        { protocol: 1, sdk: { name: "gate", version: "0.0.0" }, events },
        shield,
      );
    });

    // Attestation as Guard does it: a challenge, then attest with a fresh device and session key. Sequential, and
    // within the 60-requests-a-minute budget of one caller prefix.
    for (let i = 0; i < LOAD_PLAN.attestPairs; i++) {
      const challenge = (await call("attest", "POST", "/v1/attest/challenge", 200, { app_id: app.app.id })) as {
        nonce: string;
      } | null;
      if (!challenge) continue;
      const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const exported = publicKey.export({ format: "jwk" }) as { x: string; y: string };
      const jwk = { kty: "EC" as const, crv: "P-256" as const, x: exported.x, y: exported.y };
      await call("attest", "POST", "/v1/attest", 200, {
        app_id: app.app.id,
        nonce: challenge.nonce,
        device: randomBytes(16).toString("base64url"),
        signals: [],
        cnf: { jkt: jwkThumbprint(jwk), jwk },
      });
    }
    process.stdout.write(`GATE-RESULT ${JSON.stringify({ series, errors, plan: LOAD_PLAN })}\n`);
  } finally {
    await api.close();
  }
}

main().catch((error: unknown) => {
  process.stdout.write(
    `GATE-RESULT ${JSON.stringify({ error: error instanceof Error ? error.message : String(error) })}\n`,
  );
  process.exitCode = 1;
});
