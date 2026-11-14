import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SloReportSchema } from "@antireverse/protocol";
import { afterAll, describe, expect, it } from "vitest";
import { openDb } from "../src/db/db.ts";
import { startApi } from "../src/server.ts";
import { readSloBuckets } from "../src/slo/store.ts";
import { bearer, captureLogger } from "./helpers.ts";

// Slice 18d: `startApi` with the operator settings — a bad AR_OPS_TOKEN stops the start, the operator routes answer
// with the token, requests over HTTP are recorded, and the close flushes the recorder so the next start finds them.

const TOKEN = "ops-token-".padEnd(44, "Z");

describe("startApi and the SLOs", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-slo-"));
  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("refuses to start with a short AR_OPS_TOKEN, naming the variable and not the value", async () => {
    const before = process.env.AR_OPS_TOKEN;
    process.env.AR_OPS_TOKEN = "short-token";
    try {
      await expect(startApi({ logger: captureLogger(), smtp: null })).rejects.toThrow(
        /^AR_OPS_TOKEN must be at least 32/,
      );
    } finally {
      if (before === undefined) delete process.env.AR_OPS_TOKEN;
      else process.env.AR_OPS_TOKEN = before;
    }
  });

  it("serves the report with the token, 404 without one configured, and keeps the last minute across a restart", async () => {
    const dataDir = join(root, "pg");
    const api = await startApi({
      dataDir,
      logger: captureLogger(),
      smtp: null,
      ops: { token: TOKEN, webhook: null },
    });
    let closed = false;
    try {
      for (let i = 0; i < 3; i++) expect((await fetch(`${api.url}/v1/signing-key`)).status).toBe(200);
      const res = await fetch(`${api.url}/v1/ops/slo`, { headers: bearer(TOKEN) });
      expect(res.status).toBe(200);
      const report = SloReportSchema.parse(await res.json());
      expect(report.slos.find((s) => s.id === "SLO-03")).toMatchObject({ good: 3, total: 3, attainment: 1 });
      // Two more after the report's flush: only the close writes them.
      for (let i = 0; i < 2; i++) expect((await fetch(`${api.url}/v1/signing-key`)).status).toBe(200);
      await api.close();
      closed = true;
    } finally {
      if (!closed) await api.close();
    }
    const db = await openDb({ dataDir });
    try {
      const buckets = (await db.owner((q) => readSloBuckets(q))).filter((b) => b.slo === "SLO-03");
      expect(buckets.reduce((sum, b) => sum + b.total, 0)).toBe(5);
    } finally {
      await db.close();
    }

    const off = await startApi({ logger: captureLogger(), smtp: null, ops: { token: null, webhook: null } });
    try {
      expect((await fetch(`${off.url}/v1/ops/slo`, { headers: bearer(TOKEN) })).status).toBe(404);
      expect((await fetch(`${off.url}/metrics`, { headers: bearer(TOKEN) })).status).toBe(404);
    } finally {
      await off.close();
    }
  });
});
