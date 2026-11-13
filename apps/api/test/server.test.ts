import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BundlePayloadSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  PolicyResponseSchema,
  SignedBundleSchema,
  SigningKeyResponseSchema,
} from "@antireverse/protocol";
import { bundleAudience } from "@antireverse/protocol/server";
import { afterAll, describe, expect, it } from "vitest";
import { readConfig } from "../src/config.ts";
import { type RunningApi, startApi } from "../src/server.ts";
import { createSigner } from "../src/signer.ts";
import { bearer, captureLogger, json, put, sseReader, verifySignature, within, withReason } from "./helpers.ts";

describe("configuration", () => {
  it("defaults to 127.0.0.1:8787 and the package's own data directory", () => {
    const config = readConfig({});
    expect(config.host).toBe("127.0.0.1");
    expect(config.port).toBe(8787);
    expect(config.dataDir.replaceAll("\\", "/")).toMatch(/\/apps\/api\/\.data\/pg$/);
  });

  it("reads HOST, PORT and AR_DATA_DIR, and honours PORT=0", () => {
    expect(readConfig({ HOST: "0.0.0.0", PORT: "0", AR_DATA_DIR: "/var/lib/antireverse/pg" })).toEqual({
      host: "0.0.0.0",
      port: 0,
      dataDir: "/var/lib/antireverse/pg",
    });
    expect(readConfig({ PORT: "4321" }).port).toBe(4321);
    expect(readConfig({ HOST: "", PORT: "", AR_DATA_DIR: "" })).toEqual(readConfig({}));
  });

  it.each(["abc", "-1", "65536", "80.5", "8787 "])("refuses PORT=%s", (port) => {
    expect(() => readConfig({ PORT: port })).toThrow(/PORT/);
  });
});

describe("server", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-server-"));
  const dataDir = join(root, "pg");
  const running: RunningApi[] = [];

  afterAll(async () => {
    for (const api of running) await api.close();
    rmSync(root, { recursive: true, force: true });
  });

  it("serves on a free port, stops while a live stream is open, and keeps its data for the next start", async () => {
    const logger = captureLogger();
    const api = await startApi({ port: 0, dataDir, logger });
    running.push(api);
    expect(api.port).toBeGreaterThan(0);
    expect(api.url).toBe(`http://127.0.0.1:${api.port}`);

    const health = await fetch(`${api.url}/healthz`);
    expect(await health.json()).toEqual({ status: "ok" });

    const created = await fetch(`${api.url}/v1/organizations`, json({ name: "Acme" }));
    const { admin_key, organization } = CreateOrganizationResponseSchema.parse(await created.json());
    const app = CreateAppResponseSchema.parse(
      await (await fetch(`${api.url}/v1/apps`, json({ name: "Storefront" }, bearer(admin_key.key)))).json(),
    );

    const stream = await fetch(`${api.url}/v1/apps/${app.app.id}/events/stream`, { headers: bearer(admin_key.key) });
    expect(stream.status).toBe(200);
    if (stream.body === null) throw new Error("The stream has no body.");
    const reader = sseReader(stream.body);
    expect(await reader.next()).toBe(": connected");
    expect(api.bus.count()).toBe(1);

    await within(api.close(), 3_000, "the server to stop");

    // The consumer sees the stream end, the subscription is gone and the port is closed.
    await expect(reader.next()).rejects.toThrow();
    expect(api.bus.count()).toBe(0);
    await expect(fetch(`${api.url}/healthz`)).rejects.toThrow();
    expect(existsSync(`${dataDir}.lock`)).toBe(false);
    expect(logger.lines.join("\n")).not.toContain(admin_key.key);

    // A new process on the same data directory serves what the first one stored.
    const next = await startApi({ port: 0, dataDir, logger: captureLogger() });
    running.push(next);
    const res = await fetch(`${next.url}/v1/organization`, { headers: bearer(admin_key.key) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ organization });
  });

  it("keeps its signing key and its Policies across a restart, in a key file only its owner can read", async () => {
    const directory = join(root, "signing");
    const signingDataDir = join(directory, "pg");
    const keyFile = join(directory, "signing-key.json");
    const logger = captureLogger();

    const first = await startApi({ port: 0, dataDir: signingDataDir, logger });
    running.push(first);
    // The key file sits beside the database directory, as the lock does.
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);
    const { private_key: privateKey } = JSON.parse(readFileSync(keyFile, "utf8")) as { private_key: string };
    expect(privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const keyResponse = await fetch(`${first.url}/v1/signing-key`);
    const keyText = await keyResponse.text();
    const signingKey = SigningKeyResponseSchema.parse(JSON.parse(keyText));
    expect(signingKey).toEqual({
      key_id: first.signer.keyId,
      algorithm: "Ed25519",
      public_key: first.signer.publicKey,
    });
    expect(keyText).not.toContain(privateKey);

    const created = await fetch(`${first.url}/v1/organizations`, json({ name: "Acme" }));
    const { admin_key } = CreateOrganizationResponseSchema.parse(await created.json());
    const app = CreateAppResponseSchema.parse(
      await (await fetch(`${first.url}/v1/apps`, json({ name: "Storefront" }, bearer(admin_key.key)))).json(),
    );
    const policyUrl = `/v1/apps/${app.app.id}/policies/development`;
    const rules = [{ name: "Admin area", path: "/api/admin/**", mode: "enforce" }];
    const published = await fetch(`${first.url}${policyUrl}`, put({ rules }, withReason(bearer(admin_key.key))));
    expect(published.status).toBe(201);
    const { policy } = PolicyResponseSchema.parse(await published.json());
    const firstBundle = await fetch(`${first.url}/v1/policy-bundle`, { headers: bearer(app.shield_key.key) });
    const firstSigned = SignedBundleSchema.parse(await firstBundle.json());
    const firstEpoch = BundlePayloadSchema.parse(JSON.parse(firstSigned.bundle)).epoch;
    await within(first.close(), 3_000, "the server to stop");

    const second = await startApi({ port: 0, dataDir: signingDataDir, logger });
    running.push(second);
    expect(second.signer.publicKey).toBe(signingKey.public_key);
    expect(await (await fetch(`${second.url}/v1/signing-key`)).json()).toEqual(signingKey);
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);

    const read = await fetch(`${second.url}${policyUrl}`, { headers: bearer(admin_key.key) });
    expect(PolicyResponseSchema.parse(await read.json()).policy).toEqual(policy);

    // A Shield that was configured with the key before the restart still accepts the bundle after it.
    const bundle = await fetch(`${second.url}/v1/policy-bundle`, { headers: bearer(app.shield_key.key) });
    expect(bundle.status).toBe(200);
    const bundleText = await bundle.text();
    const signed = SignedBundleSchema.parse(JSON.parse(bundleText));
    expect(signed.key_id).toBe(signingKey.key_id);
    expect(verifySignature(signingKey.public_key, signed.bundle, signed.signature)).toBe(true);
    expect(BundlePayloadSchema.parse(JSON.parse(signed.bundle))).toMatchObject({
      audience: bundleAudience(app.shield_key.key),
      app_id: app.app.id,
      environment: "development",
      version: 1,
      rules: [{ id: policy.rules[0]?.id, path: "/api/admin/**", methods: [], action: "block", mode: "enforce" }],
    });
    expect(bundleText).not.toContain(privateKey);
    // The epoch belongs to the data directory: the same after a restart, so the versions stay comparable.
    expect(BundlePayloadSchema.parse(JSON.parse(signed.bundle)).epoch).toBe(firstEpoch);

    expect(logger.lines.length).toBeGreaterThan(5);
    for (const line of logger.lines) {
      expect(line).not.toContain(privateKey);
      expect(line).not.toContain(app.shield_key.key);
    }
  });

  it("keeps its attestation keys in their own owner-only file beside the data directory, across a restart", async () => {
    const directory = join(root, "attestation");
    const attestDataDir = join(directory, "pg");
    const keyFile = join(directory, "attestation-keys.json");
    const signingFile = join(directory, "signing-key.json");
    const logger = captureLogger();

    const first = await startApi({ port: 0, dataDir: attestDataDir, logger });
    running.push(first);
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);
    const stored = JSON.parse(readFileSync(keyFile, "utf8")) as {
      purpose: string;
      current: { kid: string; public_key: string; private_key: string };
      next: { kid: string; public_key: string; private_key: string };
    };
    expect(stored.purpose).toBe("attestation");
    // A separate key purpose: no attestation key is the policy signing key.
    const signing = JSON.parse(readFileSync(signingFile, "utf8")) as { public_key: string };
    expect([stored.current.public_key, stored.next.public_key]).not.toContain(signing.public_key);

    const created = await fetch(`${first.url}/v1/organizations`, json({ name: "Acme" }));
    const { admin_key } = CreateOrganizationResponseSchema.parse(await created.json());
    const app = CreateAppResponseSchema.parse(
      await (await fetch(`${first.url}/v1/apps`, json({ name: "Storefront" }, bearer(admin_key.key)))).json(),
    );
    const challenge = await fetch(`${first.url}/v1/attest/challenge`, json({ app_id: app.app.id }));
    expect(challenge.status).toBe(200);
    expect(challenge.headers.get("access-control-allow-origin")).toBe("*");
    await within(first.close(), 3_000, "the server to stop");

    const second = await startApi({ port: 0, dataDir: attestDataDir, logger });
    running.push(second);
    const bundle = await fetch(`${second.url}/v1/policy-bundle`, { headers: bearer(app.shield_key.key) });
    const bundleText = await bundle.text();
    const payload = BundlePayloadSchema.parse(JSON.parse(SignedBundleSchema.parse(JSON.parse(bundleText)).bundle));
    expect(payload.attestation_keys).toEqual([
      { kid: stored.current.kid, public_key: stored.current.public_key },
      { kid: stored.next.kid, public_key: stored.next.public_key },
    ]);
    for (const text of [bundleText, ...logger.lines]) {
      expect(text).not.toContain(stored.current.private_key);
      expect(text).not.toContain(stored.next.private_key);
    }
  });

  it("starts a new epoch when the database is new but the signing key is kept, so Shield can tell the reset", async () => {
    const directory = join(root, "reset");
    const keyFile = join(directory, "signing-key.json");

    async function publishedBundle(dataDir: string): Promise<{ epoch: string; version: number; keyId: string }> {
      const api = await startApi({ port: 0, dataDir, logger: captureLogger() });
      running.push(api);
      try {
        const created = await fetch(`${api.url}/v1/organizations`, json({ name: "Acme" }));
        const { admin_key } = CreateOrganizationResponseSchema.parse(await created.json());
        const app = CreateAppResponseSchema.parse(
          await (await fetch(`${api.url}/v1/apps`, json({ name: "Storefront" }, bearer(admin_key.key)))).json(),
        );
        const rules = [{ name: "Admin area", path: "/api/admin/**" }];
        const url = `${api.url}/v1/apps/${app.app.id}/policies/development`;
        expect((await fetch(url, put({ rules }, withReason(bearer(admin_key.key))))).status).toBe(201);
        const res = await fetch(`${api.url}/v1/policy-bundle`, { headers: bearer(app.shield_key.key) });
        const signed = SignedBundleSchema.parse(await res.json());
        expect(verifySignature(api.signer.publicKey, signed.bundle, signed.signature)).toBe(true);
        const payload = BundlePayloadSchema.parse(JSON.parse(signed.bundle));
        return { epoch: payload.epoch, version: payload.version, keyId: signed.key_id };
      } finally {
        await within(api.close(), 3_000, "the server to stop");
      }
    }

    const before = await publishedBundle(join(directory, "pg"));
    const keyText = readFileSync(keyFile, "utf8");
    // The database is wiped; the signing key beside it is kept.
    rmSync(join(directory, "pg"), { recursive: true, force: true });
    const after = await publishedBundle(join(directory, "pg"));

    expect(readFileSync(keyFile, "utf8")).toBe(keyText);
    expect(after.keyId).toBe(before.keyId);
    expect(after.version).toBe(before.version);
    expect(after.epoch).toMatch(/^[0-9a-f]{32}$/);
    expect(after.epoch).not.toBe(before.epoch);
  });

  it("signs with a key in memory when it has no data directory, and with the signer it is given", async () => {
    const own = await startApi({ logger: captureLogger() });
    running.push(own);
    const signer = createSigner();
    const given = await startApi({ signer, logger: captureLogger() });
    running.push(given);

    expect(given.signer).toBe(signer);
    expect(own.signer.publicKey).not.toBe(signer.publicKey);
    expect(await (await fetch(`${own.url}/v1/signing-key`)).json()).toMatchObject({ public_key: own.signer.publicKey });
    expect(await (await fetch(`${given.url}/v1/signing-key`)).json()).toMatchObject({ public_key: signer.publicKey });
  });

  it("fails to start on a key file that is not a signing key, and releases the data directory", async () => {
    const directory = join(root, "broken-key");
    const brokenDataDir = join(directory, "pg");
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, "signing-key.json"), '{"private_key":"c2VjcmV0LXNlY3JldC1zZWNyZXQ"}');

    await expect(startApi({ port: 0, dataDir: brokenDataDir, logger: captureLogger() })).rejects.toThrow(
      /signing key/i,
    );
    await expect(startApi({ port: 0, dataDir: brokenDataDir, logger: captureLogger() })).rejects.not.toThrow(
      /c2VjcmV0/,
    );

    expect(existsSync(`${brokenDataDir}.lock`)).toBe(false);
    expect(readFileSync(join(directory, "signing-key.json"), "utf8")).toContain("c2VjcmV0");
  });

  it("fails to start when the port is taken, and releases the data directory it had opened", async () => {
    const holder = createServer().listen(0, "127.0.0.1");
    await once(holder, "listening");
    const { port } = holder.address() as AddressInfo;
    const other = join(root, "port-taken", "pg");
    try {
      await expect(startApi({ port, dataDir: other, logger: captureLogger() })).rejects.toThrow(/EADDRINUSE/);
      expect(existsSync(`${other}.lock`)).toBe(false);
    } finally {
      holder.close();
    }
  });
});
