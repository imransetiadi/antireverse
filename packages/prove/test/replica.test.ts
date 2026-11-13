// Task 2.4 (Review Focus 1 and 2) — W5 Replay: the submitted request goes to an in-process replica Shield with a
// signature requirement enforced on the target route and a tiny handler; achieved only on a 2xx answer. Nothing
// is ever sent out of the process: no socket, no HTTP client, no fetch.
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { EvidenceSchema } from "@antireverse/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { replayAgainstReplica, verifyReplay } from "../src/replica.ts";
import type { Submission } from "../src/toolbelt.ts";

afterEach(() => {
  vi.restoreAllMocks();
});

function replay(request: {
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Submission {
  return {
    objective: "W5",
    payload: { request: { headers: {}, ...request } },
    callIndex: 4,
    cost: { calls: 5, seconds: 1 },
  };
}

describe("replayAgainstReplica", () => {
  it("refuses an unsigned request on the protected route with 403, with or without a body", async () => {
    expect(
      await replayAgainstReplica({ method: "GET", path: "/api/orders/1", headers: {} }, { path: "/api/orders/**" }),
    ).toEqual({
      status: 403,
    });
    expect(
      await replayAgainstReplica(
        { method: "POST", path: "/api/orders", headers: { "content-type": "application/json" }, body: '{"qty":1}' },
        { path: "/api/orders/**" },
      ),
    ).toEqual({ status: 403 });
  });

  it("refuses forged signature headers", async () => {
    const forged = {
      "ar-attestation": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
      "ar-signature": "t=1;n=AAAAAAAAAAAAAAAAAAAAAA;sig=AAAA",
      "ar-content-sha256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    };
    expect(
      await replayAgainstReplica({ method: "GET", path: "/api/orders/1", headers: forged }, { path: "/api/orders/**" }),
    ).toEqual({
      status: 403,
    });
  });

  it("protects every route by default", async () => {
    expect(await replayAgainstReplica({ method: "GET", path: "/anything", headers: {} })).toEqual({ status: 403 });
  });

  it("answers 404 for a route outside the target: not a protected call", async () => {
    expect(
      await replayAgainstReplica({ method: "GET", path: "/api/products", headers: {} }, { path: "/api/orders/**" }),
    ).toEqual({
      status: 404,
    });
    expect(
      await replayAgainstReplica(
        { method: "GET", path: "/api/orders/1", headers: {} },
        { path: "/api/orders/**", methods: ["POST"] },
      ),
    ).toEqual({ status: 404 });
  });

  it("a CORS preflight is not a replay: OPTIONS never gets a 2xx, even where Shield exempts it", async () => {
    const preflight = { "access-control-request-method": "POST", origin: "https://shop.example" };
    for (const target of [undefined, { path: "/api/orders/**" }]) {
      const { status } = await replayAgainstReplica(
        { method: "OPTIONS", path: "/api/orders", headers: preflight },
        target,
      );
      expect(status < 200 || status >= 300, `status ${status}`).toBe(true);
    }
    const unenforced = await replayAgainstReplica(
      { method: "OPTIONS", path: "/api/orders/1", headers: preflight },
      { path: "/api/orders/**" },
      { enforce: false },
    );
    expect(unenforced.status < 200 || unenforced.status >= 300).toBe(true);
  });

  it("answers 200 when the requirement is not enforced (the handler is reached)", async () => {
    expect(
      await replayAgainstReplica(
        { method: "GET", path: "/api/orders/1", headers: {} },
        { path: "/api/orders/**" },
        { enforce: false },
      ),
    ).toEqual({ status: 200 });
  });

  it("never opens a socket or makes an HTTP request", async () => {
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const httpRequest = vi.spyOn(http, "request");
    const httpsRequest = vi.spyOn(https, "request");
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await replayAgainstReplica({ method: "POST", path: "/x", headers: {}, body: "{}" });
    expect(connect).not.toHaveBeenCalled();
    expect(httpRequest).not.toHaveBeenCalled();
    expect(httpsRequest).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("verifyReplay (W5)", () => {
  it("is not achieved when the replica refuses; evidence keeps only the status", async () => {
    const submission = replay({ method: "POST", path: "/api/orders", body: "{}" });
    const verdict = await verifyReplay([submission], { path: "/api/orders/**" });
    expect(verdict).toEqual({
      kind: "judged",
      achievedAt: null,
      evidence: {
        summary: "Replayed one POST request without the genuine Guard; the replica answered 403 (refused).",
        recovered: [{ kind: "replay", status: 403 }],
        calls: [4],
      },
    });
    if (verdict?.kind === "judged") expect(EvidenceSchema.safeParse(verdict.evidence).success).toBe(true);
  });

  it("is achieved only on a 2xx answer", async () => {
    const submission = replay({ method: "GET", path: "/api/orders/1" });
    const verdict = await verifyReplay([submission], { path: "/api/orders/**" }, { enforce: false });
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: { callIndex: 4, cost: submission.cost } });
  });

  it("an OPTIONS preflight submission is not achieved", async () => {
    const submission = replay({
      method: "OPTIONS",
      path: "/api/orders",
      headers: { "access-control-request-method": "POST" },
    });
    expect(await verifyReplay([submission], undefined)).toMatchObject({ kind: "judged", achievedAt: null });
  });

  it("judges the first W5 submission only, and nothing submitted as not judged here", async () => {
    expect(await verifyReplay([], undefined)).toBeNull();
  });

  it("a replica that cannot start is a sandbox error, not resistance", async () => {
    const verdict = await verifyReplay([replay({ method: "GET", path: "/a" })], { path: "not a pattern" });
    expect(verdict).toMatchObject({ kind: "not_attempted", reason: "sandbox_error" });
  });
});
