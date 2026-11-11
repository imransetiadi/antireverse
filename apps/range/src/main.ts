// Entry point of the reference target: `npm run dev:range`.
//   AR_SHIELD_KEY         the Shield key of the App (without it Shield is disabled and the server still runs)
//   AR_API_URL            base URL of the Anti Reverse API   (default http://127.0.0.1:8787)
//   AR_POLICY_PUBLIC_KEY  the policy public key of the API, as the Console shows it (without it Shield observes
//                         only: it records Events and applies no Policy)
//   AR_ACTOR_KEY          the customer-held key of the actor hash (the startup line says "actor hashing on/off"): at least 32 characters, no whitespace, never
//                         the Shield key (without it Events carry no actor hash and actor blocks never match;
//                         network blocks still apply). Never printed. Generate one with
//                         `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`
//   HOST                  address to bind                     (default 127.0.0.1)
//   PORT                  port to bind; 0 = any free port     (default 4010)
import http from "node:http";
import type { AddressInfo } from "node:net";
import { createShield } from "@antireverse/shield-node";
import { createRangeServer } from "./server.ts";

const DEFAULT_PORT = 4010;
/** Shutdown never takes longer than this, even when ingest does not answer. */
const SHUTDOWN_DEADLINE_MS = 2_000;

function portFrom(value: string | undefined): number {
  if (value === undefined || value.trim() === "") return DEFAULT_PORT;
  const port = Number(value);
  return Number.isInteger(port) && port >= 0 && port <= 65_535 ? port : DEFAULT_PORT;
}

const host = process.env.HOST || "127.0.0.1";
const port = portFrom(process.env.PORT);

const policyPublicKey = process.env.AR_POLICY_PUBLIC_KEY?.trim() ?? "";
const actorKey = process.env.AR_ACTOR_KEY ?? "";

const shield = createShield({
  key: process.env.AR_SHIELD_KEY ?? "",
  endpoint: process.env.AR_API_URL || "http://127.0.0.1:8787",
  ...(policyPublicKey === "" ? {} : { policyPublicKey }),
  // Passed explicitly; Shield validates it and says once, without the value, when it cannot use it.
  ...(actorKey === "" ? {} : { actorKey }),
});

const server = http.createServer(createRangeServer({ shield }));

server.on("error", (error) => {
  console.error(`range: cannot listen on ${host}:${port}: ${error.message}`);
  process.exit(1);
});

server.listen(port, host, () => {
  const address = server.address() as AddressInfo;
  const shown = address.family === "IPv6" ? `[${address.address}]` : address.address;
  const reason = shield.stats().disabledReason;
  // Neither key is ever printed, only whether Shield is active and whether it applies a Policy.
  const active =
    policyPublicKey === ""
      ? "active (observes only: AR_POLICY_PUBLIC_KEY is not set)"
      : "active (applies the Policy of the App)";
  // Whether Shield accepted the actor key, from Shield itself; the key is never printed.
  const hashing = shield.stats().actorHashing ? "actor hashing on" : "actor hashing off";
  console.log(
    `range: listening on http://${shown}:${address.port} — Shield ${reason === null ? `${active}, ${hashing}` : `disabled (${reason})`}`,
  );
});

let stopping = false;
function shutdown(): void {
  if (stopping) return;
  stopping = true;
  const deadline = setTimeout(() => process.exit(0), SHUTDOWN_DEADLINE_MS);
  deadline.unref();
  server.close();
  server.closeAllConnections();
  // close() sends what is still buffered, once and without retries, and never rejects.
  void shield.close().finally(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
