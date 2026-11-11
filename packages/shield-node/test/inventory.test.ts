// The runtime component inventory (slice 19): lockfile parsing, the name and version rules mirrored from the
// protocol, and the sender with its retries. Shield-level behaviour is in inventory-shield.test.ts.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ComponentSchema,
  EXAMPLE_INVENTORY,
  EXPOSURE_LIMITS,
  InventorySchema,
  SemverSchema,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Transport } from "../src/index.ts";
import {
  createInventorySender,
  INVENTORY_LIMITS,
  INVENTORY_RESEND_MS,
  INVENTORY_RETRY_MS,
  type InventoryComponent,
  isComponentName,
  isComponentVersion,
  parseLockfile,
  readInventory,
  selectComponents,
} from "../src/inventory.ts";

const KEY = generateKey("shield", "development").key;
const fixture = (name: string): string =>
  readFileSync(new URL(`./fixtures/lockfiles/${name}.json`, import.meta.url), "utf8");

describe("the rules mirrored from the protocol", () => {
  it("has the protocol's limits", () => {
    expect(INVENTORY_LIMITS).toEqual({
      componentsMax: EXPOSURE_LIMITS.componentsMax,
      bytesMax: EXPOSURE_LIMITS.componentsBytesMax,
      nameMax: EXPOSURE_LIMITS.nameMax,
      versionMax: EXPOSURE_LIMITS.versionMax,
    });
  });

  const names = [
    "example",
    "example-parser",
    "JSONStream",
    "@example/ui",
    "@Example/ui",
    "@example/UI",
    "@ex.ample/ui",
    "@_example/ui",
    "@.example/ui",
    "@example/_ui",
    "@example/.ui",
    "@example/",
    "@/ui",
    "@example",
    "@example/ui/extra",
    "_private",
    ".hidden",
    "a",
    "",
    "-leading-dash",
    "trailing-dash-",
    "under_score",
    "dot.ted",
    "tilde~",
    "bang!",
    "quote'",
    "paren()",
    "star*",
    "with space",
    "slash/name",
    "percent%20",
    "hash#",
    "question?",
    "colon:",
    "emoji😀",
    "ünicode",
    "UPPER",
    "node_modules",
    "favicon.ico",
    "a".repeat(214),
    "a".repeat(215),
    `@scope/${"a".repeat(207)}`,
    `@scope/${"a".repeat(208)}`,
    "name\n",
    "\tname",
  ];
  it.each(names.map((name) => [JSON.stringify(name), name]))("names: %s as the protocol decides", (_label, name) => {
    expect(isComponentName(name)).toBe(ComponentSchema.shape.name.safeParse(name).success);
  });

  const versions = [
    "1.2.3",
    "0.0.0",
    "1.0.0-rc.1",
    "1.0.0-alpha.beta",
    "1.0.0-0.3.7",
    "1.0.0-x.7.z.92",
    "1.0.0+build.5",
    "1.0.0-rc.1+build.5",
    "1.0.0-01",
    "01.0.0",
    "1.01.0",
    "1.0.01",
    "v1.0.0",
    "1.0",
    "1",
    "^1.0.0",
    "~1.0.0",
    ">=1.0.0",
    "1.0.0 ",
    " 1.0.0",
    "1.0.0-",
    "1.0.0+",
    "1.0.0-rc..1",
    "1.0.0-rc.1+build..5",
    "file:../x.tgz",
    "github:example/repo#abc",
    "git+https://example.test/repo.git",
    "npm:example-real@2.3.4",
    "latest",
    "",
    "9007199254740991.0.0",
    "9007199254740992.0.0",
    "1.0.0-9007199254740992",
    "1.0.0-9007199254740991",
    `1.0.0-${"a".repeat(250)}`,
    `1.0.0-${"a".repeat(251)}`,
    "1.0.0\n",
  ];
  it.each(versions.map((version) => [JSON.stringify(version), version]))(
    "versions: %s as the protocol decides",
    (_label, version) => {
      expect(isComponentVersion(version)).toBe(SemverSchema.safeParse(version).success);
    },
  );

  it("accepts the protocol's example inventory", () => {
    for (const { name, version } of EXAMPLE_INVENTORY.components) {
      expect(isComponentName(name)).toBe(true);
      expect(isComponentVersion(version)).toBe(true);
    }
  });
});

describe("parseLockfile", () => {
  it("reads a v3 packages map: root, links, workspace folders, non-semver and invalid names are skipped", () => {
    const parsed = parseLockfile(fixture("v3"));
    expect(parsed?.components).toEqual([
      { name: "@example/ui", version: "3.9.0", dev: true },
      { name: "@example/ui", version: "4.0.0-rc.1", dev: false },
      { name: "JSONStream", version: "1.3.5", dev: false },
      { name: "example-dev-only", version: "0.4.0", dev: true },
      { name: "example-git-semver", version: "0.1.0", dev: false },
      { name: "example-optional-dev", version: "2.0.0", dev: true },
      // installed twice (top level and nested under a dev dependency): one component, not dev
      { name: "example-parser", version: "1.2.3", dev: false },
      // an alias: the package's own name, not the folder's
      { name: "example-real", version: "2.3.4", dev: false },
      { name: "example-test-runner", version: "9.1.0", dev: true },
    ]);
    // git and file versions, an invalid name, a range, an entry without a version, and null
    expect(parsed?.skipped).toBe(6);
    expect(InventorySchema.safeParse({ components: parsed?.components }).success).toBe(true);
  });

  it("reads the packages map of a v2 lockfile and ignores its v1 section", () => {
    expect(parseLockfile(fixture("v2"))?.components).toEqual([
      { name: "example-parser", version: "1.2.3", dev: false },
      { name: "example-test-runner", version: "9.1.0", dev: true },
    ]);
  });

  it("walks the dependencies tree of a v1 lockfile", () => {
    const parsed = parseLockfile(fixture("v1"));
    expect(parsed?.components).toEqual([
      { name: "@example/ui", version: "3.9.0", dev: true },
      { name: "@example/ui", version: "4.0.0-rc.1", dev: false },
      { name: "JSONStream", version: "1.3.5", dev: false },
      { name: "example-dupe", version: "1.0.0", dev: false },
      { name: "example-parser", version: "1.2.3", dev: false },
      { name: "example-parser", version: "2.0.1", dev: true },
      { name: "example-test-runner", version: "9.1.0", dev: true },
    ]);
    expect(parsed?.skipped).toBe(4);
  });

  it("reads npm's hidden lockfile, which has no root entry", () => {
    expect(parseLockfile(fixture("hidden"))?.components).toEqual([
      { name: "@example/scoped-installed", version: "1.0.0", dev: true },
      { name: "example-installed", version: "3.0.0", dev: false },
    ]);
  });

  it("gives an empty list for a lockfile with only its root", () => {
    const text = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "x", version: "1.0.0" } } });
    expect(parseLockfile(text)).toEqual({ components: [], skipped: 0 });
  });

  it.each([
    ["not JSON", "{"],
    ["an array", "[]"],
    ["null", "null"],
    ["a string", '"x"'],
    ["no packages and no dependencies", '{"lockfileVersion":3}'],
    ["packages that is an array", '{"packages":[]}'],
    ["dependencies that is a string", '{"dependencies":"x"}'],
  ])("returns null for %s", (_label, text) => {
    expect(parseLockfile(text)).toBeNull();
  });

  it("survives a deeply nested v1 tree without overflowing the stack", () => {
    // Built as text: JSON.stringify itself would overflow on this depth.
    const depth = 20_000;
    let text = '{"lockfileVersion":1,"dependencies":';
    for (let i = 0; i < depth; i++) text += `{"pkg${i}":{"version":"1.0.0","dependencies":`;
    text += `{}${"}}".repeat(depth)}}`;
    const parsed = parseLockfile(text);
    expect(parsed?.components.length).toBe(INVENTORY_LIMITS.componentsMax);
  });
});

describe("selectComponents", () => {
  const component = (n: number, dev: boolean): InventoryComponent => ({
    name: `pkg-${String(n).padStart(5, "0")}`,
    version: "1.0.0",
    dev,
  });

  it("keeps at most 5,000 components, runtime dependencies first", () => {
    const many = [
      ...Array.from({ length: 3_000 }, (_, i) => component(i, true)),
      ...Array.from({ length: 3_000 }, (_, i) => component(10_000 + i, false)),
    ];
    const kept = selectComponents(many);
    expect(kept).toHaveLength(5_000);
    expect(kept.filter((c) => !c.dev)).toHaveLength(3_000);
    expect(InventorySchema.safeParse({ components: kept }).success).toBe(true);
  });

  it("keeps the body within 2 MB", () => {
    const long = Array.from({ length: 5_000 }, (_, i) => ({
      name: `${String(i).padStart(5, "0")}${"n".repeat(209)}`,
      version: `1.0.0-${"p".repeat(250)}`,
      dev: false,
    }));
    const kept = selectComponents(long);
    expect(kept.length).toBeGreaterThan(0);
    expect(kept.length).toBeLessThan(5_000);
    expect(Buffer.byteLength(JSON.stringify({ components: kept }))).toBeLessThanOrEqual(INVENTORY_LIMITS.bytesMax);
  });
});

describe("readInventory", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "shield-inventory-"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("prefers node_modules/.package-lock.json", async () => {
    mkdirSync(join(root, "node_modules"));
    writeFileSync(join(root, "node_modules", ".package-lock.json"), fixture("hidden"));
    writeFileSync(join(root, "package-lock.json"), fixture("v2"));
    expect((await readInventory(root))?.map((c) => c.name)).toEqual(["@example/scoped-installed", "example-installed"]);
  });

  it("falls back to package-lock.json", async () => {
    writeFileSync(join(root, "package-lock.json"), fixture("v2"));
    expect((await readInventory(root))?.map((c) => c.name)).toEqual(["example-parser", "example-test-runner"]);
  });

  it("falls back to package-lock.json when the hidden lockfile is unparseable", async () => {
    mkdirSync(join(root, "node_modules"));
    writeFileSync(join(root, "node_modules", ".package-lock.json"), "{ not json");
    writeFileSync(join(root, "package-lock.json"), fixture("v2"));
    expect((await readInventory(root))?.map((c) => c.name)).toEqual(["example-parser", "example-test-runner"]);
  });

  it("gives null without a readable lockfile, and never rejects", async () => {
    expect(await readInventory(root)).toBeNull();
    expect(await readInventory(join(root, "missing"))).toBeNull();
    writeFileSync(join(root, "package-lock.json"), "garbage");
    expect(await readInventory(root)).toBeNull();
    mkdirSync(join(root, "node_modules"));
    mkdirSync(join(root, "node_modules", ".package-lock.json")); // a directory, not a file
    expect(await readInventory(root)).toBeNull();
  });
});

describe("the inventory sender", () => {
  const COMPONENTS: InventoryComponent[] = [
    { name: "example-parser", version: "1.2.3", dev: false },
    { name: "@example/ui", version: "4.0.0-rc.1", dev: false },
  ];
  type Sent = Parameters<Transport>[0];

  function harness(
    answers: (number | Error | { status: number; retryAfter: string })[],
    load: () => Promise<InventoryComponent[] | null> = async () => COMPONENTS,
  ) {
    const sent: Sent[] = [];
    const warnings: string[] = [];
    const transport: Transport = async (request) => {
      sent.push(request);
      const answer = answers.length > 1 ? answers.shift() : answers[0];
      if (answer instanceof Error) throw answer;
      if (typeof answer === "object") return answer;
      return { status: answer ?? 202 };
    };
    const sender = createInventorySender({
      key: KEY,
      endpoint: "http://api.test/",
      requestTimeoutMs: 5_000,
      transport,
      load,
      warn: (_condition, message) => void warnings.push(message),
    });
    return { sender, sent, warnings };
  }

  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("is pending until started, then posts the components once with the Shield key", async () => {
    const { sender, sent, warnings } = harness([202]);
    expect(sender.state()).toBe("pending");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(sent).toHaveLength(0);
    sender.start();
    sender.start();
    await vi.advanceTimersByTimeAsync(0);
    const instance = (JSON.parse(sent[0]?.body ?? "{}") as { instance_id?: string }).instance_id;
    expect(instance).toMatch(/^[0-9a-f]{32}$/);
    expect(sent).toEqual([
      {
        method: "POST",
        url: "http://api.test/v1/inventory",
        headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
        body: JSON.stringify({ components: COMPONENTS, instance_id: instance }),
        timeoutMs: 5_000,
      },
    ]);
    expect(InventorySchema.parse(JSON.parse(sent[0]?.body ?? ""))).toEqual({
      components: COMPONENTS,
      instance_id: instance,
    });
    expect(sender.state()).toBe("sent");
    sender.start();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(sent).toHaveLength(1);
    expect(warnings).toEqual([]);
  });

  it("retries after 5 s, 30 s and 120 s, then fails quietly with one warning", async () => {
    const { sender, sent, warnings } = harness([503]);
    sender.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(1);
    expect(INVENTORY_RETRY_MS).toEqual([5_000, 30_000, 120_000]);
    await vi.advanceTimersByTimeAsync(4_999);
    expect(sent).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(sent).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(29_999);
    expect(sent).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(sent).toHaveLength(3);
    expect(sender.state()).toBe("pending");
    await vi.advanceTimersByTimeAsync(120_000);
    expect(sent).toHaveLength(4);
    expect(sender.state()).toBe("failed");
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(sent).toHaveLength(4);
    expect(vi.getTimerCount()).toBe(0);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/component inventory/);
  });

  it("sends a random instance id per sender, the same on every retry (A7)", async () => {
    const first = harness([503, 202]);
    const second = harness([202]);
    first.sender.start();
    second.sender.start();
    await vi.advanceTimersByTimeAsync(10_000);
    const ids = [...first.sent, ...second.sent].map((request) => JSON.parse(request.body ?? "{}").instance_id);
    expect(ids).toHaveLength(3);
    expect(ids[0]).toBe(ids[1]);
    expect(ids[2]).not.toBe(ids[0]);
  });

  it("waits at least the 429's retry-after before trying again, at most 10 minutes (A7)", async () => {
    const { sender, sent } = harness([{ status: 429, retryAfter: "60" }, 202]);
    sender.start();
    await vi.advanceTimersByTimeAsync(59_999);
    expect(sent).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(sent).toHaveLength(2);
    expect(sender.state()).toBe("sent");

    const capped = harness([{ status: 429, retryAfter: "86400" }, 202]);
    capped.sender.start();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(capped.sent).toHaveLength(2);

    // A retry-after shorter than the schedule, or unreadable, leaves the schedule as it is.
    const short = harness([{ status: 429, retryAfter: "soon" }, 202]);
    short.sender.start();
    await vi.advanceTimersByTimeAsync(4_999);
    expect(short.sent).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(short.sent).toHaveLength(2);
  });

  it("retries a transport error and a 429, and succeeds", async () => {
    const { sender, sent } = harness([new Error("boom"), 429, 202]);
    sender.start();
    await vi.advanceTimersByTimeAsync(35_000);
    expect(sent).toHaveLength(3);
    expect(sender.state()).toBe("sent");
  });

  it.each([400, 401, 403, 404, 413])("gives up at once on HTTP %i", async (status) => {
    const { sender, sent, warnings } = harness([status]);
    sender.start();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(sent).toHaveLength(1);
    expect(sender.state()).toBe("failed");
    expect(warnings).toHaveLength(1);
  });

  describe("re-send every 6 hours (an instance expires after 24 h without a POST)", () => {
    const HOUR = 3_600_000;
    beforeEach(() => {
      // 0.5: no jitter, so the re-send lands at exactly 6 h.
      vi.spyOn(Math, "random").mockReturnValue(0.5);
    });

    it("re-sends the same body (same instance id) at 6 h, not before, and keeps doing so", async () => {
      expect(INVENTORY_RESEND_MS).toBe(6 * HOUR);
      const { sender, sent } = harness([202]);
      sender.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(sent).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(6 * HOUR - 1);
      expect(sent).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(sent).toHaveLength(2);
      expect(sent[1]?.body).toBe(sent[0]?.body);
      await vi.advanceTimersByTimeAsync(6 * HOUR);
      expect(sent).toHaveLength(3);
      expect(sender.state()).toBe("sent");
      sender.close();
    });

    it("jitters the interval by at most 10 %", async () => {
      vi.spyOn(Math, "random").mockReturnValue(0);
      const early = harness([202]);
      early.sender.start();
      await vi.advanceTimersByTimeAsync(0);
      await vi.advanceTimersByTimeAsync(5.4 * HOUR - 1);
      expect(early.sent).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(early.sent).toHaveLength(2);
      early.sender.close();
    });

    it("close() cancels the pending re-send and leaves no timer", async () => {
      const { sender, sent } = harness([202]);
      sender.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(vi.getTimerCount()).toBe(1);
      sender.close();
      expect(vi.getTimerCount()).toBe(0);
      await vi.advanceTimersByTimeAsync(24 * HOUR);
      expect(sent).toHaveLength(1);
    });

    it("a 429 on a re-send honours its retry-after; the state stays sent", async () => {
      const { sender, sent } = harness([202, { status: 429, retryAfter: "120" }, 202]);
      sender.start();
      await vi.advanceTimersByTimeAsync(6 * HOUR);
      expect(sent).toHaveLength(2);
      expect(sender.state()).toBe("sent");
      await vi.advanceTimersByTimeAsync(119_999);
      expect(sent).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(1);
      expect(sent).toHaveLength(3);
      sender.close();
    });

    it("a re-send that fails for good never stops the next one, and warns nothing", async () => {
      const { sender, sent, warnings } = harness([202, 503, 503, 503, 503, 202]);
      sender.start();
      await vi.advanceTimersByTimeAsync(6 * HOUR);
      // The three retries, with their 12.5 % jitter at random 0.5.
      await vi.advanceTimersByTimeAsync(175_000);
      expect(sent).toHaveLength(5);
      expect(sender.state()).toBe("sent");
      await vi.advanceTimersByTimeAsync(6 * HOUR);
      expect(sent).toHaveLength(6);
      expect(warnings).toEqual([]);
      const final = harness([202, 400, 202]);
      final.sender.start();
      await vi.advanceTimersByTimeAsync(12 * HOUR);
      expect(final.sent).toHaveLength(3);
      sender.close();
      final.sender.close();
    });
  });

  it("close() cancels a pending retry and leaves no timer", async () => {
    const { sender, sent } = harness([503]);
    sender.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(1);
    sender.close();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(sent).toHaveLength(1);
    sender.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(1);
  });

  it("close() before the lockfile was read sends nothing", async () => {
    let release: (value: InventoryComponent[]) => void = () => {};
    const { sender, sent } = harness([202], () => new Promise((resolve) => (release = resolve)));
    sender.start();
    sender.close();
    release(COMPONENTS);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(sent).toHaveLength(0);
  });

  it("without a readable lockfile: one warning line, nothing sent, failed", async () => {
    const { sender, sent, warnings } = harness([202], async () => null);
    sender.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(0);
    expect(sender.state()).toBe("failed");
    expect(warnings).toEqual(["component inventory skipped: no readable lockfile"]);
  });

  it("contains a loader that throws and a transport that throws synchronously", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => void unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      const loading = harness([202], () => {
        throw new Error("synthetic");
      });
      expect(() => loading.sender.start()).not.toThrow();
      await vi.advanceTimersByTimeAsync(0);
      expect(loading.sender.state()).toBe("failed");

      const throwing = createInventorySender({
        key: KEY,
        endpoint: "http://api.test",
        requestTimeoutMs: 5_000,
        transport: () => {
          throw new Error("synchronous");
        },
        load: async () => COMPONENTS,
        warn: () => {
          throw new Error("logger");
        },
      });
      expect(() => throwing.start()).not.toThrow();
      await vi.advanceTimersByTimeAsync(200_000);
      expect(throwing.state()).toBe("failed");
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
    expect(unhandled).toEqual([]);
  });

  it("never names a package in a warning", async () => {
    for (const answers of [[400], [503], [new Error("ECONNREFUSED")]] as (number | Error)[][]) {
      const { sender, warnings } = harness(answers);
      sender.start();
      await vi.advanceTimersByTimeAsync(200_000);
      expect(warnings.length).toBeGreaterThan(0);
      for (const line of warnings) {
        for (const { name, version } of COMPONENTS) {
          expect(line).not.toContain(name);
          expect(line).not.toContain(version);
        }
        expect(line).not.toContain(KEY);
      }
    }
  });
});
