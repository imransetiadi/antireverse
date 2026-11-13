// @vitest-environment node
// Slice 18b: the Organization export and the subject export go through the Console, which checks the session and
// streams the API's NDJSON through as a download. The admin key never reaches the browser; a refusal is never a file.
import { generateKey } from "@antireverse/protocol/server";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as exportRoute from "@/app/api/data/export/route.ts";
import * as subjectRoute from "@/app/api/data/subject-export/route.ts";
import { IP_HASH, PENDING_PROBLEM } from "./helpers/deletion.ts";

const key = generateKey("admin").key;
const fetchMock = vi.fn<typeof fetch>();
const getExport = (cookie?: string, headers: Record<string, string> = {}) =>
  exportRoute.GET(
    new NextRequest("http://127.0.0.1:3000/api/data/export", {
      headers: { host: "127.0.0.1:3000", ...(cookie ? { cookie } : {}), ...headers },
    }),
  );
function postSubject(fields: Record<string, string>, cookie?: string, headers: Record<string, string> = {}) {
  const body = new URLSearchParams(fields);
  return subjectRoute.POST(
    new NextRequest("http://127.0.0.1:3000/api/data/subject-export", {
      method: "POST",
      body,
      headers: {
        host: "127.0.0.1:3000",
        "content-type": "application/x-www-form-urlencoded",
        ...(cookie ? { cookie } : {}),
        ...headers,
      },
    }),
  );
}
const refusal = (status: number, headers: Record<string, string> = {}, body: object = {}) =>
  new Response(JSON.stringify({ type: "about:blank", title: "Refused", status, ...body }), {
    status,
    headers: { "content-type": "application/problem+json", ...headers },
  });

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", "http://api.test:9999");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("cross-site requests (review 18b, L3)", () => {
  const cases = [
    ["GET /api/data/export", (headers: Record<string, string>) => getExport(`ar_admin=${key}`, headers)],
    [
      "POST /api/data/subject-export",
      (headers: Record<string, string>) => postSubject({ subject: IP_HASH }, `ar_admin=${key}`, headers),
    ],
  ] as const;
  for (const [name, send] of cases) {
    it(`${name} refuses another site with 403 and no API call`, async () => {
      fetchMock.mockResolvedValue(new Response("", { status: 200 }));
      for (const headers of <Record<string, string>[]>[
        { "sec-fetch-site": "cross-site" },
        { "sec-fetch-site": "same-site" },
        { origin: "https://evil.example" },
        { origin: "null" },
        { "sec-fetch-site": "same-origin", origin: "http://127.0.0.1:3001" },
      ]) {
        const response = await send(headers);
        expect(response.status).toBe(403);
        expect(response.headers.get("location")).toBeNull();
      }
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it(`${name} serves its own origin and a typed-in address`, async () => {
      fetchMock.mockImplementation(async () => new Response("", { status: 200 }));
      for (const headers of <Record<string, string>[]>[
        { "sec-fetch-site": "same-origin", origin: "http://127.0.0.1:3000" },
        { "sec-fetch-site": "none" },
        {},
      ]) {
        expect((await send(headers)).status).toBe(200);
      }
    });
  }
});

describe("GET /api/data/export", () => {
  it("exports the GET handler only", () => {
    expect(Object.keys(exportRoute)).toEqual(["GET"]);
  });

  it("sends a browser without a session home, without calling the API", async () => {
    const response = await getExport();
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("streams the API's body through unread, as an attachment with the API's file name, never cached", async () => {
    const encoder = new TextEncoder();
    let pulled = 0;
    // A body that is never ended by the test: the route must hand it on, not read it to the end first.
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(encoder.encode('{"kind":"manifest"}\n'));
        if (pulled === 2) controller.close();
      },
    });
    fetchMock.mockResolvedValue(
      new Response(body, {
        status: 200,
        headers: {
          "content-type": "application/x-ndjson",
          "content-disposition": 'attachment; filename="airverse-org_0123456789abcdef01234567-2026-11-14.ndjson"',
        },
      }),
    );
    const response = await getExport(`ar_admin=${key}`);
    expect(response.status).toBe(200);
    expect(response.body).toBe(body);
    expect(response.headers.get("content-type")).toBe("application/x-ndjson");
    expect(response.headers.get("content-disposition")).toBe(
      'attachment; filename="airverse-org_0123456789abcdef01234567-2026-11-14.ndjson"',
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe("http://api.test:9999/v1/organization/export");
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${key}`);
  });

  it("names the file itself when the API's name is not one it expects", async () => {
    fetchMock.mockResolvedValue(
      new Response("", { status: 200, headers: { "content-disposition": 'attachment; filename="../x.sh"' } }),
    );
    const response = await getExport(`ar_admin=${key}`);
    expect(response.headers.get("content-disposition")).toBe('attachment; filename="airverse-export.ndjson"');
  });

  it("goes back to Data controls with a notice on a refusal, never as a download", async () => {
    fetchMock.mockResolvedValue(refusal(429, { "retry-after": "30" }));
    let response = await getExport(`ar_admin=${key}`);
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/settings/data?export=limited&retry=30");
    expect(response.headers.get("content-disposition")).toBeNull();
    fetchMock.mockResolvedValue(refusal(401));
    response = await getExport(`ar_admin=${key}`);
    expect(response.headers.get("location")).toBe("/sign-in?reason=expired");
    fetchMock.mockResolvedValue(refusal(500));
    response = await getExport(`ar_admin=${key}`);
    expect(response.headers.get("location")).toBe("/settings/data?export=failed");
    fetchMock.mockRejectedValue(new Error(`connect ECONNREFUSED with ${key}`));
    response = await getExport(`ar_admin=${key}`);
    expect(response.headers.get("location")).toBe("/settings/data?export=failed");
    expect(await response.text()).not.toContain(key);
  });
});

describe("POST /api/data/subject-export", () => {
  it("exports the POST handler only", () => {
    expect(Object.keys(subjectRoute)).toEqual(["POST"]);
  });

  it("sends a browser without a session home, without calling the API", async () => {
    const response = await postSubject({ subject: IP_HASH });
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("checks the session before it reads any of the body (review 18b, M2)", async () => {
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new TextEncoder().encode("a".repeat(1024 * 1024)));
        if (pulled === 64) controller.close();
      },
    });
    const response = await subjectRoute.POST(
      new NextRequest("http://127.0.0.1:3000/api/data/subject-export", {
        method: "POST",
        body,
        // Node needs `duplex: "half"` to send a stream body.
        duplex: "half",
        headers: { "content-type": "application/x-www-form-urlencoded", cookie: "ar_admin=not-a-key" },
      }),
    );
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    expect(pulled).toBeLessThanOrEqual(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a body over 4 KiB by its Content-Length, and by what it reads when none is given", async () => {
    let response = await subjectRoute.POST(
      new NextRequest("http://127.0.0.1:3000/api/data/subject-export", {
        method: "POST",
        body: `subject=${"a".repeat(5000)}`,
        headers: { "content-type": "application/x-www-form-urlencoded", cookie: `ar_admin=${key}` },
      }),
    );
    expect(response.status).toBe(413);
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new TextEncoder().encode("a".repeat(1024)));
        if (pulled === 1024) controller.close();
      },
    });
    response = await subjectRoute.POST(
      new NextRequest("http://127.0.0.1:3000/api/data/subject-export", {
        method: "POST",
        body,
        // Node needs `duplex: "half"` to send a stream body.
        duplex: "half",
        headers: { "content-type": "application/x-www-form-urlencoded", cookie: `ar_admin=${key}` },
      }),
    );
    expect(response.status).toBe(413);
    expect(pulled).toBeLessThanOrEqual(6);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never sends a value that is not an actor hash", async () => {
    for (const subject of ["", "203.0.113.7", "iph_XYZ", `${IP_HASH}0`]) {
      const response = await postSubject({ subject }, `ar_admin=${key}`);
      expect(response.status).toBe(303);
      expect(response.headers.get("location")).toBe("/settings/data?subject_export=invalid#subject");
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("posts the actor hash and streams the API's NDJSON through as an attachment", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"kind":"manifest"}\n'));
        controller.close();
      },
    });
    fetchMock.mockResolvedValue(new Response(body, { status: 200 }));
    const response = await postSubject({ subject: ` ${IP_HASH} ` }, `ar_admin=${key}`);
    expect(response.status).toBe(200);
    expect(response.body).toBe(body);
    expect(response.headers.get("content-type")).toBe("application/x-ndjson");
    expect(response.headers.get("content-disposition")).toBe('attachment; filename="airverse-subject.ndjson"');
    expect(response.headers.get("cache-control")).toBe("no-store");
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe("http://api.test:9999/v1/subjects/export");
    expect(JSON.parse(String(init?.body))).toEqual({ ip_hash: IP_HASH });
  });

  it("goes back with a notice on a refusal; a pending deletion shows Data controls' own notice", async () => {
    fetchMock.mockResolvedValue(refusal(500));
    let response = await postSubject({ subject: IP_HASH }, `ar_admin=${key}`);
    expect(response.status).toBe(303);
    // Never the actor hash in an address (review 18b, L2): the form keeps what was typed.
    expect(response.headers.get("location")).toBe("/settings/data?subject_export=failed#subject");
    fetchMock.mockResolvedValue(refusal(403, {}, PENDING_PROBLEM));
    response = await postSubject({ subject: IP_HASH }, `ar_admin=${key}`);
    expect(response.headers.get("location")).toBe("/settings/data?blocked=1");
    fetchMock.mockResolvedValue(refusal(401));
    response = await postSubject({ subject: IP_HASH }, `ar_admin=${key}`);
    expect(response.headers.get("location")).toBe("/sign-in?reason=expired");
  });
});
