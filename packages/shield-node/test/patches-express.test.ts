// Slice 20 through the Express adapter: a Virtual patch records an exploit request (monitor, response unchanged)
// or refuses it (enforce, the standard block response before the handler); it comes after Containments and Rules;
// a body condition is checked only by `shield.verifyBody` and never blocks when the body was not checked; internal
// errors fail open; no header value, query value or body ever reaches an Event or a log line.
import { setTimeout as sleep } from "node:timers/promises";
import {
  type BundlePatch,
  type BundlePayload,
  type BundleRule,
  EventBatchSchema,
  type ShieldEvent,
} from "@antireverse/protocol";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createShield, type Shield, type ShieldConfig } from "../src/index.ts";
import { exchange, KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, fakeApi, NOW, payload, rule, signed } from "./policy-helpers.ts";

const signer = createSigner();
const CLOCK = NOW + 60_000;
const BLOCK_BODY = '{"error":"request_blocked"}';
const UNMATCHED = "(unmatched)";

/** Markers that must never leave the process: a header value, a query value and a body value. */
const SECRET_HEADER = "hv-7a1c9e";
const SECRET_QUERY = "qv-3b8d2f";
const SECRET_BODY = "bv-5e0a4c";

const QUERY_PROTO: BundlePatch = {
  id: "vp_query_proto",
  mode: "monitor",
  methods: ["GET"],
  conditions: [{ target: "query_key", op: "contains", value: "__proto__" }],
  advisory: "CVE-2022-24999",
};
const HEADER_JNDI: BundlePatch = {
  id: "vp_header_jndi",
  mode: "monitor",
  conditions: [{ target: "header", name: "x-probe", op: "contains", value: "${jndi:" }],
  advisory: "CVE-2021-44228",
};
const BODY_PROTO: BundlePatch = {
  id: "vp_body_proto",
  mode: "monitor",
  methods: ["POST"],
  path: "/api/**",
  conditions: [
    { target: "header", name: "content-type", op: "present" },
    { target: "body", op: "contains", value: "__proto__" },
  ],
  advisory: "CVE-2019-10744",
};
const enforce = (patch: BundlePatch): BundlePatch => ({ ...patch, mode: "enforce" });

const open: Listening[] = [];
const shields: Shield[] = [];
let consoleLines: string[] = [];

beforeEach(() => {
  consoleLines = [];
  for (const method of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      consoleLines.push(args.map(String).join(" "));
    });
  }
});

afterEach(async () => {
  for (const listening of open.splice(0)) await listening.stop();
  for (const shield of shields.splice(0)) await shield.close();
  vi.restoreAllMocks();
});

interface Setup {
  shield: Shield;
  base: string;
  calls: string[];
  events(count: number): Promise<ShieldEvent[]>;
  leaked(): string;
}

async function setup(
  bundle: Partial<BundlePayload>,
  options: {
    config?: Partial<ShieldConfig>;
    withShield?: boolean;
    before?: (app: express.Express) => void;
    /** No `bodyVerified` option at all. */
    noBodyTypes?: boolean;
  } = {},
): Promise<Setup> {
  const api = fakeApi();
  const warnings: string[] = [];
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    now: () => CLOCK,
    clientAddress: () => "203.0.113.9",
    actorKey: `ck_test_${"9".repeat(32)}`,
    logger: { warn: (message) => void warnings.push(message) },
    ...(options.noBodyTypes === true ? {} : { bodyVerified: { types: ["application/json"] } }),
    ...options.config,
  });
  shields.push(shield);
  api.publish(signed(signer, payload(KEY, { rules: [], ...bundle })));
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();

  const withShield = options.withShield ?? true;
  const calls: string[] = [];
  const app = express();
  app.disable("x-powered-by");
  app.disable("etag");
  options.before?.(app);
  if (withShield) app.use(shield.express());
  app.use(withShield ? express.json({ verify: shield.verifyBody }) : express.json());
  app.use(withShield ? express.text({ verify: shield.verifyBody }) : express.text());
  app.use(
    withShield
      ? express.urlencoded({ extended: false, verify: shield.verifyBody })
      : express.urlencoded({ extended: false }),
  );
  app.get("/api/search", (_req, res) => {
    calls.push("search");
    res.setHeader("x-data", "yes");
    res.json({ items: [1, 2, 3] });
  });
  app.get("/api/admin/report", (_req, res) => {
    calls.push("admin");
    res.json({ admin: true });
  });
  app.post("/api/items", (req, res) => {
    calls.push(`items ${typeof req.body}`);
    res.status(201).json({ ok: true });
  });
  app.post("/api/raw", (req, res) => {
    // No parser reads this route's type: the body never reaches the hook.
    req.resume();
    req.on("end", () => {
      calls.push("raw");
      res.json({ ok: true });
    });
  });
  if (withShield) app.use(shield.errorHandler());
  app.use((_req, res) => void res.status(404).send("no such page"));
  const listening = await listen(app);
  open.push(listening);

  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  return {
    shield,
    base: listening.base,
    calls,
    async events(count) {
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return api.posts.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    },
    leaked: () =>
      [
        ...api.posts.map((request) => `${JSON.stringify(request.headers)} ${request.body ?? ""}`),
        ...warnings,
        ...consoleLines,
        shield.stats().lastPolicyError ?? "",
        shield.stats().lastError ?? "",
      ].join("\n"),
  };
}

const EXPLOIT_QUERY = `/api/search?q[__proto__][polluted]=${SECRET_QUERY}`;
const BENIGN_QUERY = `/api/search?q[name]=proto&sort=${SECRET_QUERY}`;
const JSON_TYPE = { "content-type": "application/json" };
const exploitBody = JSON.stringify({ name: SECRET_BODY, ["__proto__"]: { polluted: 1 } });
const escapedExploitBody = `{"name":"${SECRET_BODY}","\\u005f\\u005fproto\\u005f\\u005f":{"polluted":1}}`;
const benignBody = JSON.stringify({ name: SECRET_BODY, proto: "x" });

/** A patch decision; an unchecked one never blocked: recorded as allow in monitor, whatever the patch's mode (A6 F2). */
const patchDecision = (patch: BundlePatch, body: "checked" | "unchecked" | "undecodable") => ({
  action: body === "unchecked" || (body === "undecodable" && patch.mode === "monitor") ? "allow" : "block",
  mode: body === "unchecked" ? "monitor" : patch.mode,
  rule_id: null,
  policy_version: 1,
  containment_id: null,
  patch_id: patch.id,
  patch_body: body,
});
const ALLOW = {
  action: "allow",
  mode: "enforce",
  rule_id: null,
  policy_version: 1,
  containment_id: null,
  patch_id: null,
  patch_body: null,
};

describe("a patch in monitor", () => {
  it("records the exploit request and leaves the response exactly as without Shield", async () => {
    const shielded = await setup({ patches: [QUERY_PROTO] });
    const plain = await setup({ patches: [QUERY_PROTO] }, { withShield: false });
    expect(await exchange(`${shielded.base}${EXPLOIT_QUERY}`)).toEqual(await exchange(`${plain.base}${EXPLOIT_QUERY}`));
    expect(shielded.calls).toEqual(["search"]);
    const [event] = await shielded.events(1);
    expect(event?.decision).toEqual(patchDecision(QUERY_PROTO, "checked"));
    expect(event?.request).toMatchObject({ method: "GET", route: "/api/search", status: 200 });
  });

  it("does not record a benign request", async () => {
    const s = await setup({ patches: [QUERY_PROTO] });
    expect((await exchange(`${s.base}${BENIGN_QUERY}`)).status).toBe(200);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(ALLOW);
  });

  it("sees through one percent-encoding, mixed case and a header condition", async () => {
    const s = await setup({ patches: [QUERY_PROTO, HEADER_JNDI] });
    await exchange(`${s.base}/api/search?q[%5F%5FPROTO__]=1`);
    await exchange(`${s.base}/api/search`, { headers: { "x-probe": "  %24%7Bjndi:ldap://x}" } });
    const events = await s.events(2);
    expect(events.map((event) => event.decision.patch_id)).toEqual([QUERY_PROTO.id, HEADER_JNDI.id]);
  });
});

describe("a patch in enforce", () => {
  it("answers the exploit request with the standard block response before the handler", async () => {
    const s = await setup({ patches: [enforce(QUERY_PROTO)] });
    const response = await exchange(`${s.base}${EXPLOIT_QUERY}`);
    expect(response.status).toBe(403);
    expect(response.body).toBe(BLOCK_BODY);
    expect(response.headers).toContainEqual(["content-type", "application/json"]);
    expect(s.calls).toEqual([]);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(patchDecision(enforce(QUERY_PROTO), "checked"));
    expect(event?.request).toMatchObject({ route: UNMATCHED, status: 403 });
  });

  it("lets a benign request and a request of another method through", async () => {
    const s = await setup({ patches: [enforce(QUERY_PROTO)] });
    expect((await exchange(`${s.base}${BENIGN_QUERY}`)).status).toBe(200);
    expect((await exchange(`${s.base}/api/items?__proto__=1`, { method: "POST" })).status).toBe(201);
    expect((await exchange(`${s.base}${EXPLOIT_QUERY}`, { method: "HEAD" })).status).toBe(403); // HEAD counts as GET
    const events = await s.events(3);
    expect(events.map((event) => event.decision.patch_id)).toEqual([null, null, QUERY_PROTO.id]);
  });
});

describe("the order: Containment, then Rules, then patches", () => {
  const ADMIN = (mode: BundleRule["mode"]): BundleRule => rule(1, { path: "/api/admin/**", mode });
  const ADMIN_EXPLOIT = "/api/admin/report?__proto__=1";

  it("a Containment decides before an enforced patch", async () => {
    const block = {
      id: `cnt_${"c".repeat(24)}`,
      kind: "prefix" as const,
      ip_prefix: "203.0.113.0/24",
      expires_at: new Date(CLOCK + 3_600_000).toISOString(),
    };
    const s = await setup({ patches: [enforce(QUERY_PROTO)], blocks: [block] });
    expect((await exchange(`${s.base}${EXPLOIT_QUERY}`)).status).toBe(403);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ containment_id: block.id, patch_id: null, patch_body: null });
  });

  it("an enforced Rule decides before an enforced patch", async () => {
    const s = await setup({ rules: [ADMIN("enforce")], patches: [enforce(QUERY_PROTO)] });
    expect((await exchange(`${s.base}${ADMIN_EXPLOIT}`)).status).toBe(403);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ rule_id: ADMIN("enforce").id, mode: "enforce", patch_id: null });
  });

  it("an enforced patch wins over a Rule in monitor: the first enforced match", async () => {
    const s = await setup({ rules: [ADMIN("monitor")], patches: [enforce(QUERY_PROTO)] });
    expect((await exchange(`${s.base}${ADMIN_EXPLOIT}`)).status).toBe(403);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(patchDecision(enforce(QUERY_PROTO), "checked"));
  });

  it("a monitor patch is not recorded when a monitor Rule already decided", async () => {
    const s = await setup({ rules: [ADMIN("monitor")], patches: [QUERY_PROTO] });
    expect((await exchange(`${s.base}${ADMIN_EXPLOIT}`)).status).toBe(200);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({
      action: "block",
      mode: "monitor",
      rule_id: ADMIN("monitor").id,
      patch_id: null,
      patch_body: null,
    });
  });

  it("among patches the first enforced match wins, else the first monitor match in bundle order", async () => {
    const second = { ...QUERY_PROTO, id: "vp_second_proto" };
    const s = await setup({ patches: [QUERY_PROTO, second, enforce({ ...QUERY_PROTO, id: "vp_third_proto" })] });
    expect((await exchange(`${s.base}${EXPLOIT_QUERY}`)).status).toBe(403);
    const t = await setup({ patches: [QUERY_PROTO, second] });
    expect((await exchange(`${t.base}${EXPLOIT_QUERY}`)).status).toBe(200);
    expect((await s.events(1))[0]?.decision.patch_id).toBe("vp_third_proto");
    expect((await t.events(1))[0]?.decision.patch_id).toBe(QUERY_PROTO.id);
  });
});

describe("a body condition", () => {
  it("enforce: a matching JSON body is refused with the standard block response before the handler", async () => {
    const s = await setup({ patches: [enforce(BODY_PROTO)] });
    for (const body of [exploitBody, escapedExploitBody]) {
      const response = await exchange(`${s.base}/api/items`, { method: "POST", headers: JSON_TYPE, body });
      expect(response.status).toBe(403);
      expect(response.body).toBe(BLOCK_BODY);
      expect(response.headers).toContainEqual(["content-type", "application/json"]);
    }
    expect(s.calls).toEqual([]);
    const events = await s.events(2);
    for (const event of events) {
      expect(event.decision).toEqual(patchDecision(enforce(BODY_PROTO), "checked"));
      expect(event.request.status).toBe(403);
    }
  });

  it("enforce: a benign body passes, and is not recorded", async () => {
    const s = await setup({ patches: [enforce(BODY_PROTO)] });
    const response = await exchange(`${s.base}/api/items`, { method: "POST", headers: JSON_TYPE, body: benignBody });
    expect(response.status).toBe(201);
    expect(s.calls).toEqual(["items object"]);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(ALLOW);
  });

  it("monitor: a matching body is recorded as checked and the response is unchanged", async () => {
    const s = await setup({ patches: [BODY_PROTO] });
    const response = await exchange(`${s.base}/api/items`, { method: "POST", headers: JSON_TYPE, body: exploitBody });
    expect(response.status).toBe(201);
    expect(s.calls).toEqual(["items object"]);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(patchDecision(BODY_PROTO, "checked"));
  });

  it("never checked because no parser carries the hook: recorded unchecked in monitor, never blocked", async () => {
    const s = await setup({ patches: [enforce(BODY_PROTO)] });
    const response = await exchange(`${s.base}/api/raw`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: exploitBody,
    });
    expect(response.status).toBe(200);
    expect(s.calls).toEqual(["raw"]);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "allow", mode: "monitor", patch_body: "unchecked" });
    expect(event?.decision).toEqual(patchDecision(enforce(BODY_PROTO), "unchecked"));
  });

  it("checked whenever the hook sees the body, a type outside bodyVerified.types included: enforce refuses", async () => {
    const s = await setup({ patches: [enforce(BODY_PROTO)] });
    const response = await exchange(`${s.base}/api/items`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: exploitBody,
    });
    expect(response.status).toBe(403);
    expect(response.body).toBe(BLOCK_BODY);
    expect(s.calls).toEqual([]);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(patchDecision(enforce(BODY_PROTO), "checked"));
  });

  it("checked without bodyVerified at all, when the hook sees the body: enforce refuses", async () => {
    const s = await setup({ patches: [enforce(BODY_PROTO)] }, { noBodyTypes: true });
    const response = await exchange(`${s.base}/api/items`, { method: "POST", headers: JSON_TYPE, body: exploitBody });
    expect(response.status).toBe(403);
    expect(s.calls).toEqual([]);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(patchDecision(enforce(BODY_PROTO), "checked"));
  });

  it("a monitor patch whose body was never checked is recorded unchecked in monitor", async () => {
    const s = await setup({ patches: [BODY_PROTO] });
    await exchange(`${s.base}/api/raw`, { method: "POST", headers: { "content-type": "text/csv" }, body: exploitBody });
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(patchDecision(BODY_PROTO, "unchecked"));
  });

  it("a request without a body does not match a body condition and is not recorded", async () => {
    const s = await setup({ patches: [enforce({ ...BODY_PROTO, methods: ["GET"] })] });
    expect((await exchange(`${s.base}/api/search`, { headers: JSON_TYPE })).status).toBe(200);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(ALLOW);
  });

  it("an unchecked patch is not recorded when a Rule in monitor decided", async () => {
    const s = await setup({ rules: [rule(1, { path: "/api/raw", mode: "monitor" })], patches: [enforce(BODY_PROTO)] });
    await exchange(`${s.base}/api/raw`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: exploitBody,
    });
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ rule_id: rule(1).id, patch_id: null, patch_body: null });
  });

  it("a monitor patch matched without the body is preferred to an unchecked one", async () => {
    const s = await setup({ patches: [enforce(BODY_PROTO), { ...HEADER_JNDI }] });
    await exchange(`${s.base}/api/raw`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream", "x-probe": "$" + "{jndi:x}" },
      body: exploitBody,
    });
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(patchDecision(HEADER_JNDI, "checked"));
  });
});

describe("a bundle from a newer API", () => {
  it("applies the Rules and the patches this Shield can read; one it cannot read is skipped", async () => {
    const newer = {
      ...QUERY_PROTO,
      id: "vp_newer",
      mode: "enforce",
      conditions: [{ target: "cookie", name: "sid", op: "present" }],
    } as unknown as BundlePatch;
    const s = await setup({
      rules: [rule(1, { path: "/api/admin/**", mode: "enforce" })],
      patches: [newer, enforce(QUERY_PROTO)],
    });
    expect((await exchange(`${s.base}/api/admin/report`)).status).toBe(403);
    expect((await exchange(`${s.base}${EXPLOIT_QUERY}`)).status).toBe(403);
    expect((await exchange(`${s.base}/api/search`, { headers: { cookie: "sid=1" } })).status).toBe(200);
    const events = await s.events(3);
    expect(events.map((event) => [event.decision.rule_id, event.decision.patch_id])).toEqual([
      [rule(1).id, null],
      [null, QUERY_PROTO.id],
      [null, null],
    ]);
  });
});

describe("review fixes (A6)", () => {
  const LODASH: BundlePatch = {
    id: "vp_lodash_ctor",
    mode: "enforce",
    conditions: [
      { target: "body", op: "json_key", value: "constructor" },
      { target: "body", op: "json_key", value: "prototype" },
    ],
    advisory: "CVE-2019-10744",
  };
  const CTOR = '{"constructor" : {"prototype":{"isAdmin":true}}}';
  const utf16le = (text: string) => Buffer.from(text, "utf16le");

  it("F1: a UTF-16LE JSON body is decoded and refused under enforce", async () => {
    const s = await setup({ patches: [LODASH] });
    const response = await exchange(`${s.base}/api/items`, {
      method: "POST",
      headers: { "content-type": "application/json; charset=utf-16le" },
      body: utf16le(CTOR),
    });
    expect(response.status).toBe(403);
    expect(s.calls).toEqual([]);
    const [event] = await s.events(1);
    expect(event?.decision).toEqual(patchDecision(LODASH, "checked"));
  });

  it("F1: windows-1252 and iso-8859-1 bodies are scanned as Latin-1: an exploit is refused, a benign one passes", async () => {
    const FORM_PROTO: BundlePatch = {
      id: "vp_form_proto",
      mode: "enforce",
      conditions: [{ target: "body", op: "contains", value: "[__proto__]" }],
      advisory: "CVE-2022-24999",
    };
    const s = await setup({ patches: [FORM_PROTO] });
    const latin1 = (text: string) => Buffer.from(text, "latin1");
    const send = (type: string, text: string) =>
      exchange(`${s.base}/api/items`, { method: "POST", headers: { "content-type": type }, body: latin1(text) });
    const FORM = "application/x-www-form-urlencoded; charset=iso-8859-1";
    const TEXT_1252 = "text/plain; charset=windows-1252";
    expect((await send(FORM, "caf\xe9=1&a[__proto__][x]=1")).status).toBe(403);
    expect((await send(TEXT_1252, "caf\xe9 a[__proto__][x]=1")).status).toBe(403);
    expect((await send(FORM, "caf\xe9=1&a[name]=proto")).status).toBe(201);
    expect((await send(TEXT_1252, "caf\xe9 a[name]=proto")).status).toBe(201);
    expect(s.calls).toEqual(["items object", "items string"]);
  });

  it("F1: a body in a character set Shield cannot read is refused under enforce (D-062), recorded in monitor", async () => {
    const latin = { "content-type": "text/plain; charset=shift_jis" };
    const s = await setup({ patches: [LODASH] });
    const refused = await exchange(`${s.base}/api/items`, { method: "POST", headers: latin, body: "hello" });
    expect(refused.status).toBe(403);
    // M2 (A11): the Event says the body could not be read — block/enforce here, allow/monitor below.
    expect((await s.events(1))[0]?.decision).toEqual(patchDecision(LODASH, "undecodable"));
    const m = await setup({ patches: [{ ...LODASH, mode: "monitor" }] });
    const passed = await exchange(`${m.base}/api/items`, { method: "POST", headers: latin, body: "hello" });
    expect(passed.status).toBe(201);
    const [event] = await m.events(1);
    expect(event?.decision).toEqual({
      ...ALLOW,
      mode: "monitor",
      patch_id: LODASH.id,
      patch_body: "undecodable",
    });
  });

  it("H1/H2 (A11): utf-16 without a byte order mark in big-endian, and a quoted ; before the charset, are read", async () => {
    const s = await setup({ patches: [LODASH] });
    const be = Buffer.from(CTOR, "utf16le").swap16();
    const noMark = await exchange(`${s.base}/api/items`, {
      method: "POST",
      headers: { "content-type": "text/plain; charset=utf-16" },
      body: be,
    });
    const quoted = await exchange(`${s.base}/api/items`, {
      method: "POST",
      headers: { "content-type": 'application/json; x="a;charset=utf-8;"; charset=utf-16le' },
      body: utf16le(CTOR),
    });
    expect([noMark.status, quoted.status]).toEqual([403, 403]);
    const events = await s.events(2);
    expect(events.map((event) => event.decision.patch_body)).toEqual(["checked", "checked"]);
  });

  it("F6: json_key refuses the key and lets the same words through as values", async () => {
    const s = await setup({ patches: [LODASH] });
    const exploit = await exchange(`${s.base}/api/items`, { method: "POST", headers: JSON_TYPE, body: CTOR });
    const benign = await exchange(`${s.base}/api/items`, {
      method: "POST",
      headers: JSON_TYPE,
      body: '{"role":"constructor","stage":"prototype","note":"a constructor: prototype"}',
    });
    expect([exploit.status, benign.status]).toEqual([403, 201]);
  });

  it("F2: a body never checked is recorded as allow in monitor with the patch, whatever its mode", async () => {
    const s = await setup({ patches: [LODASH] });
    await exchange(`${s.base}/api/raw`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: CTOR,
    });
    const [event] = await s.events(1);
    expect(event?.decision).toEqual({ ...ALLOW, mode: "monitor", patch_id: LODASH.id, patch_body: "unchecked" });
  });

  it("F3: a key qs reads past an earlier = is matched", async () => {
    const s = await setup({ patches: [enforce(QUERY_PROTO)] });
    expect((await exchange(`${s.base}/api/search?a[b=c][__proto__]=x`)).status).toBe(403);
    expect((await exchange(`${s.base}/api/search?q=__proto__&sort[name]=asc`)).status).toBe(200);
  });
});

describe("failing open", () => {
  it("an internal error while evaluating patches lets the request through and is counted", async () => {
    // Headers whose names cannot be listed: a header_name condition throws while it is evaluated.
    const byName: BundlePatch = {
      ...enforce(QUERY_PROTO),
      conditions: [...QUERY_PROTO.conditions, { target: "header_name", op: "equals", value: "x-probe" }],
    };
    const s = await setup(
      { patches: [byName] },
      {
        before: (app) =>
          app.use((req, _res, next) => {
            req.headers = new Proxy(req.headers, {
              ownKeys() {
                throw new Error("unreadable");
              },
            });
            next();
          }),
      },
    );
    const response = await exchange(`${s.base}${EXPLOIT_QUERY}`);
    expect(response.status).toBe(200);
    expect(s.calls).toEqual(["search"]);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "allow", patch_id: null, patch_body: null });
    expect(s.shield.stats().internalErrors).toBeGreaterThan(0);
  });

  it("verifyBody given something that is not a body checks nothing and throws nothing", async () => {
    const s = await setup({ patches: [enforce(BODY_PROTO)] });
    expect(() => s.shield.verifyBody({ headers: {} } as never, {} as never, "x" as never, "utf8")).not.toThrow();
  });
});

describe("nothing of the request leaves the process", () => {
  it("no header value, query value or body in Events or log lines, whatever matched", async () => {
    const s = await setup({
      patches: [
        QUERY_PROTO,
        enforce(BODY_PROTO),
        { ...HEADER_JNDI, conditions: [{ target: "header", name: "x-probe", op: "contains", value: "hv-" }] },
      ],
    });
    await exchange(`${s.base}${EXPLOIT_QUERY}`, { headers: { "x-probe": SECRET_HEADER } });
    await exchange(`${s.base}/api/items?k=${SECRET_QUERY}`, {
      method: "POST",
      headers: { ...JSON_TYPE, "x-probe": SECRET_HEADER },
      body: exploitBody,
    });
    await exchange(`${s.base}/api/raw`, { method: "POST", headers: { "content-type": "text/csv" }, body: exploitBody });
    const events = await s.events(3);
    expect(events).toHaveLength(3);
    const leaked = s.leaked();
    for (const secret of [SECRET_HEADER, SECRET_QUERY, SECRET_BODY, "__proto__", "polluted"]) {
      expect(leaked).not.toContain(secret);
    }
  });
});
