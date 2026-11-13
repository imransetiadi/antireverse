import { generateVerificationToken } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { checkOwnership, createDnsResolver, type Fetcher, type Resolver } from "../src/prove/verify.ts";

const HOST = "shop.acme-shop.io";
const RECORD = `_airverse-challenge.${HOST}`;
const TOKEN = generateVerificationToken();

const dnsError = (code: string) => Object.assign(new Error(`queryTxt ${code}`), { code });

function fakeResolver(txt: Record<string, string[][] | Error>, addresses: Record<string, string[]> = {}) {
  const asked: string[] = [];
  const resolver: Resolver = {
    async txt(name) {
      asked.push(`txt ${name}`);
      const answer = txt[name];
      if (answer === undefined) throw dnsError("ENOTFOUND");
      if (answer instanceof Error) throw answer;
      return answer;
    },
    async addresses(host) {
      asked.push(`a ${host}`);
      const answer = addresses[host];
      if (answer === undefined) throw dnsError("ENOTFOUND");
      return answer;
    },
  };
  return Object.assign(resolver, { asked });
}

function fakeFetcher(outcome: Awaited<ReturnType<Fetcher>>) {
  const hosts: string[] = [];
  const fetcher: Fetcher = async (host) => {
    hosts.push(host);
    return outcome;
  };
  return Object.assign(fetcher, { hosts });
}

describe("checkOwnership: DNS first, then the file", () => {
  it("passes by DNS when a TXT record holds the value, and never fetches the file", async () => {
    const resolver = fakeResolver({ [RECORD]: [["v=spf1 -all"], [`airverse-verification=${TOKEN}`]] });
    const fetcher = fakeFetcher({ ok: true, body: TOKEN });
    expect(await checkOwnership(HOST, TOKEN, { resolver, fetcher })).toEqual({ verified: true, method: "dns" });
    expect(resolver.asked).toEqual([`txt ${RECORD}`]);
    expect(fetcher.hosts).toEqual([]);
  });

  it("joins the chunks of one TXT record", async () => {
    const resolver = fakeResolver({ [RECORD]: [["airverse-verification=", TOKEN.slice(0, 20), TOKEN.slice(20)]] });
    expect(
      await checkOwnership(HOST, TOKEN, { resolver, fetcher: fakeFetcher({ ok: false, reason: "status" }) }),
    ).toEqual({ verified: true, method: "dns" });
  });

  it("passes by the file when DNS has no record, and the file holds the token (whitespace ignored)", async () => {
    const resolver = fakeResolver({});
    const fetcher = fakeFetcher({ ok: true, body: `\n ${TOKEN}\r\n` });
    expect(await checkOwnership(HOST, TOKEN, { resolver, fetcher })).toEqual({ verified: true, method: "file" });
    expect(fetcher.hosts).toEqual([HOST]);
  });

  it("names why each method failed", async () => {
    const other = generateVerificationToken();
    expect(
      await checkOwnership(HOST, TOKEN, {
        resolver: fakeResolver({ [RECORD]: [[`airverse-verification=${other}`]] }),
        fetcher: fakeFetcher({ ok: true, body: other }),
      }),
    ).toEqual({ verified: false, dns: "mismatch", file: "mismatch" });
    expect(
      await checkOwnership(HOST, TOKEN, {
        resolver: fakeResolver({ [RECORD]: dnsError("ENODATA") }),
        fetcher: fakeFetcher({ ok: false, reason: "address_not_public" }),
      }),
    ).toEqual({ verified: false, dns: "no_record", file: "address_not_public" });
    expect(
      await checkOwnership(HOST, TOKEN, {
        resolver: fakeResolver({ [RECORD]: dnsError("ESERVFAIL") }),
        fetcher: fakeFetcher({ ok: false, reason: "timeout" }),
      }),
    ).toEqual({ verified: false, dns: "lookup_failed", file: "timeout" });
    expect(
      await checkOwnership(HOST, TOKEN, {
        resolver: fakeResolver({ [RECORD]: [] }),
        fetcher: fakeFetcher({ ok: false, reason: "redirect" }),
      }),
    ).toEqual({ verified: false, dns: "no_record", file: "redirect" });
  });

  it("does not accept the record of another name or the token in another form", async () => {
    const resolver = fakeResolver({
      [HOST]: [[`airverse-verification=${TOKEN}`]],
      [RECORD]: [[TOKEN], [`airverse-verification=${TOKEN} `], [`AIRVERSE-VERIFICATION=${TOKEN}`]],
    });
    expect(await checkOwnership(HOST, TOKEN, { resolver, fetcher: fakeFetcher({ ok: true, body: "" }) })).toEqual({
      verified: false,
      dns: "mismatch",
      file: "mismatch",
    });
  });

  it("treats a DNS lookup that never answers as failed once the bound passes", async () => {
    const resolver: Resolver = { txt: () => new Promise(() => {}), addresses: () => new Promise(() => {}) };
    const result = await checkOwnership(HOST, TOKEN, {
      resolver,
      fetcher: fakeFetcher({ ok: false, reason: "timeout" }),
      dnsTimeoutMs: 20,
    });
    expect(result).toEqual({ verified: false, dns: "lookup_failed", file: "timeout" });
  });

  it("refuses a host that is not normalised, without asking anyone", async () => {
    const resolver = fakeResolver({});
    const fetcher = fakeFetcher({ ok: true, body: TOKEN });
    await expect(checkOwnership("127.0.0.1", TOKEN, { resolver, fetcher })).rejects.toThrow(TypeError);
    expect(resolver.asked).toEqual([]);
    expect(fetcher.hosts).toEqual([]);
  });
});

describe("createDnsResolver: node:dns answers mapped to the seam", () => {
  const backend = (answers: { txt?: string[][] | Error; a?: string[] | Error; aaaa?: string[] | Error }) => ({
    resolveTxt: async () => {
      if (answers.txt instanceof Error) throw answers.txt;
      return answers.txt ?? [];
    },
    resolve4: async () => {
      if (answers.a instanceof Error) throw answers.a;
      return answers.a ?? [];
    },
    resolve6: async () => {
      if (answers.aaaa instanceof Error) throw answers.aaaa;
      return answers.aaaa ?? [];
    },
  });

  it("returns the A and AAAA addresses together", async () => {
    const resolver = createDnsResolver({ backend: backend({ a: ["93.184.216.34"], aaaa: ["2606:2800::1"] }) });
    expect(await resolver.addresses(HOST)).toEqual(["93.184.216.34", "2606:2800::1"]);
  });

  it("accepts one family missing (ENODATA) but not both", async () => {
    const one = createDnsResolver({ backend: backend({ a: ["93.184.216.34"], aaaa: dnsError("ENODATA") }) });
    expect(await one.addresses(HOST)).toEqual(["93.184.216.34"]);
    const none = createDnsResolver({ backend: backend({ a: dnsError("ENODATA"), aaaa: dnsError("ENODATA") }) });
    await expect(none.addresses(HOST)).rejects.toThrow();
  });

  it("fails when one family fails for another reason: no partial answer is ever checked", async () => {
    const resolver = createDnsResolver({ backend: backend({ a: ["93.184.216.34"], aaaa: dnsError("ESERVFAIL") }) });
    await expect(resolver.addresses(HOST)).rejects.toThrow();
  });

  it("passes TXT answers and errors through", async () => {
    expect(await createDnsResolver({ backend: backend({ txt: [["a", "b"]] }) }).txt(RECORD)).toEqual([["a", "b"]]);
    await expect(createDnsResolver({ backend: backend({ txt: dnsError("ENOTFOUND") }) }).txt(RECORD)).rejects.toThrow();
  });
});
