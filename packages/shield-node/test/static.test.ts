// Review 02, finding F1: a middleware mounted after Shield may read the path differently from the router.
// `express.static` (serve-static and send) percent-decodes the path once, resolves `.` and `..` and collapses empty
// segments before it opens a file, so a spelling that is not `/files/private/...` as text can still serve a file
// below `private/`. Shield matches a canonical form of the path besides the text: these spellings are blocked.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { BLOCK_RESPONSE_BODY, EventBatchSchema, type ShieldEvent } from "@antireverse/protocol";
import express from "express";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { createShield, type Shield } from "../src/index.ts";
import { KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, type FakeApi, fakeApi, payload, rule, signed } from "./policy-helpers.ts";

const signer = createSigner();
const PRIVATE = rule(0xf1, { path: "/files/private/**", mode: "enforce" });
const SECRET = "zq-top-secret-file-content";
const PUBLIC = "public file content";

let dir = "";
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "shield-static-"));
  mkdirSync(join(dir, "public"));
  mkdirSync(join(dir, "private"));
  writeFileSync(join(dir, "public", "a.txt"), PUBLIC);
  writeFileSync(join(dir, "public", "a b.txt"), PUBLIC);
  writeFileSync(join(dir, "private", "secret.txt"), SECRET);
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

const open: Listening[] = [];
const shields: Shield[] = [];
afterEach(async () => {
  for (const listening of open.splice(0)) await listening.stop();
  for (const shield of shields.splice(0)) await shield.close();
});

/** `app.use(shield.express()); app.use("/files", express.static(dir))`, or the same without Shield. */
async function serveFiles(shield?: Shield): Promise<Listening> {
  const app = express();
  app.disable("x-powered-by");
  if (shield) app.use(shield.express());
  app.use("/files", express.static(dir));
  const listening = await listen(app);
  open.push(listening);
  return listening;
}

async function protect(): Promise<{ shield: Shield; api: FakeApi; events(count: number): Promise<ShieldEvent[]> }> {
  const api = fakeApi();
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    logger: { warn: () => {} },
  });
  shields.push(shield);
  api.publish(signed(signer, payload(KEY, { version: 3, rules: [PRIVATE], issued_at: new Date().toISOString() })));
  await shield.refreshPolicy();
  expect(shield.stats()).toMatchObject({ policyVersion: 3, policyRules: 1, lastPolicyError: null });
  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  return {
    shield,
    api,
    async events(count) {
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return api.posts.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    },
  };
}

/** One request with the request target exactly as given: `fetch` would resolve the dot segments itself. */
function raw(port: number, target: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write(`GET ${target} HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n`);
    });
    let data = "";
    socket.setEncoding("latin1");
    socket.on("data", (chunk: string) => {
      data += chunk;
    });
    socket.on("error", reject);
    socket.on("close", () => {
      const split = data.indexOf("\r\n\r\n");
      const head = split === -1 ? data : data.slice(0, split);
      resolve({
        status: Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? 0),
        body: split === -1 ? "" : data.slice(split + 4),
      });
    });
  });
}

describe("an Enforce Rule on /files/private/** in front of express.static", () => {
  // Without Shield every one of these serves private/secret.txt (pinned below), so the 403 is all that stands
  // between the client and the file.
  const spellings = [
    "/files/private/secret.txt",
    "/files/PRIVATE/secret.txt",
    "/files/%70rivate/secret.txt", // a percent-encoded letter
    "/files/private%2fsecret.txt", // an encoded slash
    "/files/private%2Fsecret.txt",
    "/files/public/../private/secret.txt", // a dot segment
    "/files/public/%2e%2e/private/secret.txt", // an encoded dot segment
    "/files/public/%2E%2e/private/secret.txt",
    "/files/./private/secret.txt",
    "/files//private/secret.txt", // an empty segment
    "/files/public%2f..%2fprivate%2fsecret.txt",
    "/files/x%2f/../private/secret.txt",
    // Decoded once, as send does, these resolve into private/; decoded until nothing is left to decode, or with
    // the backslash read as a separator, they would climb out of /files. Each decoding depth is matched on its own.
    "/files/public/a%252f..%2f..%2f..%2fprivate/secret.txt",
    "/files/public/a%5c..%2f..%2f..%2fprivate/secret.txt",
    "/files/public/a%255c..%2f..%2f..%2fprivate/secret.txt",
  ];

  it("without Shield, every spelling serves the private file: what the Rule must stop", async () => {
    const { port } = await serveFiles();
    for (const target of spellings) {
      const response = await raw(port, target);
      expect(response.status, target).toBe(200);
      expect(response.body, target).toBe(SECRET);
    }
  });

  it("with Shield, every spelling is answered 403 with the block body and nothing of the file", async () => {
    const guarded = await protect();
    const { port } = await serveFiles(guarded.shield);
    for (const target of spellings) {
      const response = await raw(port, target);
      expect(response.status, target).toBe(403);
      expect(response.body, target).toBe(BLOCK_RESPONSE_BODY);
      expect(response.body, target).not.toContain(SECRET);
    }
    // Each Event names the Rule's pattern as route, never the spelling.
    const events = await guarded.events(spellings.length);
    expect(events).toHaveLength(spellings.length);
    for (const event of events) {
      expect(event.request.route).toBe("/files/private/**");
      expect(event.decision).toEqual({
        action: "block",
        mode: "enforce",
        rule_id: PRIVATE.id,
        policy_version: 3,
        containment_id: null,
        patch_id: null,
        patch_body: null,
      });
    }
  });

  it("still serves the public files, including a name with an encoded character", async () => {
    const guarded = await protect();
    const { port } = await serveFiles(guarded.shield);
    for (const target of [
      "/files/public/a.txt",
      "/files/public/a%20b.txt",
      "/files/public/./a.txt",
      "/files/private/../public/a.txt", // the text names private/, the file is public: the text form still blocks
    ]) {
      const response = await raw(port, target);
      if (target.startsWith("/files/private/")) {
        expect(response.status, target).toBe(403);
      } else {
        expect(response.status, target).toBe(200);
        expect(response.body, target).toBe(PUBLIC);
      }
    }
    expect((await raw(port, "/files/privateer.txt")).status).toBe(404);
    // Malformed: send cannot decode it and express.static passes the request on (404). Shield does not block it.
    expect((await raw(port, "/files/public/%zz.txt")).status).toBe(404);
  });
});
