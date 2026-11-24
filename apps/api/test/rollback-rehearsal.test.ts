import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  AuditVerifyResponseSchema,
  BundlePayloadSchema,
  CreateAppResponseSchema,
  ListAppsResponseSchema,
  ListEventsResponseSchema,
  SignedBundleSchema,
} from "@antireverse/protocol";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAttestationKeys } from "../src/attestation/keys.ts";
import { runBackupCli } from "../src/backup/cli.ts";
import {
  ADDRESS_KEY_FILE,
  ATTESTATION_KEY_FILE,
  AUDIT_KEY_FILE,
  KEY_FILES,
  SIGNING_KEY_FILE,
  USAGE_SALTS_FILE,
} from "../src/key-files.ts";
import { createAddressHasher } from "../src/mail/address-key.ts";
import { type RunningApi, startApi } from "../src/server.ts";
import { createSigner } from "../src/signer.ts";
import { createUsageSalts } from "../src/usage/salts.ts";
import {
  applyEra,
  type EraContext,
  eraContext,
  migrationFiles,
  snapshotTables,
  type TableSnapshot,
} from "./era-seed.ts";
import { batchOf, bearer, captureLogger, json, put, shieldEvent, verifySignature, withReason } from "./helpers.ts";

// Slice 18h: the rollback rehearsal (gate criterion gate-rollback-local). There is no staging deployment and no build
// of a previous version, so the rollback rehearsed is the one an operator can perform today: restoring the cold
// backup taken before an upgrade (`npm run data:backup` / `data:restore`). The tests run in order, on one data
// directory under the temporary directory:
//   the version before the head, with data and key files → backup → the API starts on it (the upgrade) and takes new
//   writes → a key file is replaced and another lost → restore → the directory is the old version again, byte for byte
//   in its rows and keys → the API starts on it and serves the state from before the upgrade.
// Not rehearsed: the previous version's code on the upgraded schema. There is no previous build to run.

const FILES = migrationFiles();
const HEAD = FILES[FILES.length - 1] as string;
const PREVIOUS = FILES.slice(0, -1);

describe("rollback rehearsal: backup, upgrade, restore (slice 18h)", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-rollback-"));
  const dataDir = join(root, "data", "pg");
  const backup = join(root, "backups", "before-upgrade");
  const logger = captureLogger();
  const running: RunningApi[] = [];
  let ctx: EraContext;
  let before: TableSnapshot;
  let keyFiles: Record<string, string>;
  let publicKeys: { policy: string; audit: string; attestation: string[] };
  let upgradedAppId: string;
  const output: string[] = [];

  const cli = (...argv: string[]): number =>
    runBackupCli(argv, {
      env: {},
      cwd: root,
      // Never the developer's own data directory.
      defaultDataDir: join(root, "default", "pg"),
      print: (line) => output.push(line),
      error: (line) => output.push(line),
    });
  const start = async (): Promise<RunningApi> => {
    const api = await startApi({
      dataDir,
      logger,
      smtp: null,
      ops: { token: null, webhook: null },
      campaigns: { enabled: false },
      probes: { enabled: false },
    });
    running.push(api);
    return api;
  };
  const get = async (api: RunningApi, path: string, key?: string) => {
    const res = await fetch(`${api.url}${path}`, key === undefined ? {} : { headers: bearer(key) });
    expect(res.status, `${path}: ${await res.clone().text()}`).toBe(200);
    return res.json();
  };
  const readKeyFiles = (): Record<string, string> =>
    Object.fromEntries(
      KEY_FILES.filter((name) => existsSync(join(dirname(dataDir), name))).map((name) => [
        name,
        readFileSync(join(dirname(dataDir), name), "utf8"),
      ]),
    );
  /** The schema version and every row, read straight from the directory (no API, no migration). */
  const readDirectory = async (): Promise<{ versions: unknown[]; rows: TableSnapshot }> => {
    const pg = await PGlite.create(dataDir);
    try {
      const rows = await snapshotTables(pg);
      return { versions: (rows.get("schema_migrations") ?? []).map((row) => row.version).sort(), rows };
    } finally {
      await pg.close();
    }
  };

  beforeAll(() => {
    ctx = eraContext();
  });

  afterAll(async () => {
    for (const api of running) await api.close();
    rmSync(root, { recursive: true, force: true });
  });

  it("the version before the head exists on disk, with a row in every table and its key files", async () => {
    const step = mkdtempSync(join(tmpdir(), "ar-rollback-step-"));
    mkdirSync(dirname(dataDir), { recursive: true });
    const pg = await PGlite.create(dataDir);
    try {
      for (const file of PREVIOUS) await applyEra(pg, ctx, step, file);
      before = await snapshotTables(pg);
    } finally {
      await pg.close();
      rmSync(step, { recursive: true, force: true });
    }
    // The key files, made by the code a first start runs.
    const beside = dirname(dataDir);
    const policy = createSigner({ file: join(beside, SIGNING_KEY_FILE) });
    const audit = createSigner({ file: join(beside, AUDIT_KEY_FILE) });
    const attestation = createAttestationKeys({ file: join(beside, ATTESTATION_KEY_FILE), logger });
    createAddressHasher({ file: join(beside, ADDRESS_KEY_FILE) });
    // The salts file is written on the first use of a month.
    createUsageSalts({ file: join(beside, USAGE_SALTS_FILE) }).saltFor("2026-11");
    publicKeys = {
      policy: policy.publicKey,
      audit: audit.publicKey,
      attestation: attestation.attestationKeys().map((key) => key.kid),
    };
    keyFiles = readKeyFiles();
    expect(Object.keys(keyFiles).sort()).toEqual([...KEY_FILES].sort());
    expect((await readDirectory()).versions).toEqual(PREVIOUS);
  });

  it("the backup command copies it, and prints nothing of a key", () => {
    expect(cli("backup", "--to", backup, "--data-dir", dataDir)).toBe(0);
    expect(output.join("\n")).toMatch(/Key files in the backup: .*signing-key\.json/);
  });

  it("the API starts on the old version (the upgrade), takes new writes, and the tool refuses while it runs", async () => {
    const api = await start();
    const { a } = ctx;
    // Upgraded: the head's migrations are applied, and the old data is served.
    const apps = ListAppsResponseSchema.parse(await get(api, "/v1/apps", a.adminKey));
    expect(apps.apps.map((app) => app.id)).toEqual([a.appId]);
    // New writes, through the routes: an App, a Policy version, Events.
    const created = await fetch(`${api.url}/v1/apps`, json({ name: "After the upgrade" }, bearer(a.adminKey)));
    expect(created.status).toBe(201);
    upgradedAppId = CreateAppResponseSchema.parse(await created.json()).app.id;
    const published = await fetch(
      `${api.url}/v1/apps/${a.appId}/policies/production`,
      put({ rules: [{ name: "Login", path: "/login", methods: ["POST"], mode: "monitor" }] }, bearer(a.adminKey)),
    );
    expect(published.status, await published.clone().text()).toBe(201);
    const ingested = await fetch(
      `${api.url}/v1/events`,
      json(batchOf([shieldEvent(Date.now()), shieldEvent(Date.now() + 1)]), bearer(a.shieldKey)),
    );
    expect(ingested.status).toBe(202);
    const signed = SignedBundleSchema.parse(await get(api, "/v1/policy-bundle", a.shieldKey));
    expect(BundlePayloadSchema.parse(JSON.parse(signed.bundle)).version).toBe(3);

    // While the API holds the directory, neither command touches it.
    const keysNow = readKeyFiles();
    expect(cli("backup", "--to", join(root, "backups", "while-running"), "--data-dir", dataDir)).toBe(1);
    expect(cli("restore", "--from", backup, "--data-dir", dataDir, "--force")).toBe(1);
    expect(output.filter((line) => /failed: .* is in use by process/.test(line))).toHaveLength(2);
    expect(existsSync(join(root, "backups", "while-running"))).toBe(false);
    expect(readKeyFiles()).toEqual(keysNow);
    expect(ListAppsResponseSchema.parse(await get(api, "/v1/apps", a.adminKey)).apps).toHaveLength(2);

    await api.close();
    expect((await readDirectory()).versions).toEqual(FILES);
  });

  it("after the upgrade a key file is replaced and another is lost", () => {
    const beside = dirname(dataDir);
    const other = join(root, "another-key.json");
    const replacement = createSigner({ file: other });
    expect(replacement.publicKey).not.toBe(publicKeys.policy);
    writeFileSync(join(beside, SIGNING_KEY_FILE), readFileSync(other));
    rmSync(other);
    rmSync(join(beside, ATTESTATION_KEY_FILE));
  });

  it("restore refuses without --force and changes nothing; with it, the directory is the old version again", async () => {
    const damaged = readKeyFiles();
    expect(cli("restore", "--from", backup, "--data-dir", dataDir)).toBe(1);
    expect(output.at(-1)).toMatch(/--force/);
    expect(readKeyFiles()).toEqual(damaged);
    expect((await readDirectory()).versions).toEqual(FILES);

    expect(cli("restore", "--from", backup, "--data-dir", dataDir, "--force"), output.at(-1)).toBe(0);
    // Before any API starts on it: the schema of the old version (the head's migration is not there), every row as it
    // was, and the key files byte for byte.
    const restored = await readDirectory();
    expect(restored.versions).toEqual(PREVIOUS);
    expect(restored.versions).not.toContain(HEAD);
    expect(restored.rows).toEqual(before);
    expect(readKeyFiles()).toEqual(keyFiles);
  });

  it("the API starts on the restored directory and serves the state from before the upgrade, keys intact", async () => {
    const api = await start();
    const { a, b } = ctx;
    // What was written after the backup is gone; what was there is served.
    const apps = ListAppsResponseSchema.parse(await get(api, "/v1/apps", a.adminKey)).apps.map((app) => app.id);
    expect(apps).toEqual([a.appId]);
    expect(apps).not.toContain(upgradedAppId);
    const events = ListEventsResponseSchema.parse(await get(api, `/v1/apps/${a.appId}/events`, a.adminKey));
    expect(events.events.map((event) => event.event_id).sort()).toEqual([...a.eventIds].sort());

    // The Shield key authenticates; its bundle is version 2 again and verifies under the public key from before.
    const signingKey = (await get(api, "/v1/signing-key")) as { public_key: string };
    expect(signingKey.public_key).toBe(publicKeys.policy);
    const signed = SignedBundleSchema.parse(await get(api, "/v1/policy-bundle", a.shieldKey));
    expect(verifySignature(publicKeys.policy, signed.bundle, signed.signature)).toBe(true);
    const bundle = BundlePayloadSchema.parse(JSON.parse(signed.bundle));
    expect(bundle.version).toBe(2);
    expect(bundle.rules).toEqual([expect.objectContaining({ path: "/login", mode: "enforce" })]);
    // The attestation keys loaded from the restored file: the same key ids as before, in the bundle too.
    expect(api.attestation.attestationKeys().map((key) => key.kid)).toEqual(publicKeys.attestation);
    expect(bundle.attestation_keys?.map((key) => key.kid)).toEqual(publicKeys.attestation);

    // The audit chains verify with the entries from before, under the audit key from before.
    expect(((await get(api, "/v1/audit/public-key")) as { public_key: string }).public_key).toBe(publicKeys.audit);
    for (const tenant of [a, b]) {
      const { verify } = AuditVerifyResponseSchema.parse(await get(api, "/v1/audit/verify", tenant.adminKey));
      expect(verify).toEqual({
        valid: true,
        entries: tenant.auditEntries,
        last_seq: tenant.auditEntries,
        first_broken_seq: null,
      });
    }
    // And it takes writes again.
    const next = await fetch(
      `${api.url}/v1/apps/${a.appId}/policies/production`,
      put({ rules: [] }, withReason(bearer(a.adminKey))),
    );
    expect(next.status, await next.clone().text()).toBe(201);
    await api.close();
    expect((await readDirectory()).versions).toEqual(FILES);
    // Two starts later, everything the API keeps beside its data directory is a file the backup knows.
    expect(readdirSync(dirname(dataDir)).filter((name) => name !== "pg" && !KEY_FILES.includes(name))).toEqual([]);
  });

  it("nothing the commands printed, and nothing the API logged, holds key material", () => {
    const secrets = new Set<string>();
    const collect = (value: unknown): void => {
      if (typeof value === "string" && value.length >= 20) secrets.add(value);
      else if (Array.isArray(value)) value.forEach(collect);
      else if (typeof value === "object" && value !== null) Object.values(value).forEach(collect);
    };
    for (const text of Object.values(keyFiles)) collect(JSON.parse(text));
    // The public halves may be printed; everything else of a key file may not.
    for (const known of [publicKeys.policy, publicKeys.audit]) secrets.delete(known);
    expect(secrets.size).toBeGreaterThanOrEqual(KEY_FILES.length);
    const printed = [...output, ...logger.lines].join("\n");
    expect(output.length).toBeGreaterThan(6);
    for (const secret of secrets) expect(printed).not.toContain(secret);
  });
});
