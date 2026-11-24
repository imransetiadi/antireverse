// A loopback npm registry for the install smoke test (slice 23, D-131). It serves the third-party packages of the
// packed closures — packed from the repository's own node_modules, which `npm ci` installed against the lockfile —
// and answers 404 for every other name. So `npm install` of the tarballs runs for real, with no network and no
// user cache, and a dependency that is not in the reviewed closure (or an @antireverse package asked from a
// registry) makes the install fail. Binds 127.0.0.1 on a port the operating system picks.
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import type { Closure } from "./closure.ts";
import { npmPack, type PackedTarball } from "./pack.ts";

export interface LoopbackRegistry {
  url: string;
  /** Every request, in order, with the status it got. */
  requests: Array<{ path: string; status: number }>;
  close(): Promise<void>;
}

interface Served {
  manifest: Record<string, unknown>;
  tarball: PackedTarball;
}

/** Packs every third-party package of the closures from node_modules into `destination`. */
export async function packThirdParty(
  closures: Readonly<Record<string, Closure>>,
  destination: string,
  work: string,
): Promise<Served[]> {
  const folders = new Map<string, string>();
  for (const closure of Object.values(closures)) {
    for (const entry of closure.entries) folders.set(entry.id, join(REPO_ROOT, entry.paths[0] as string));
  }
  const ids = [...folders.keys()].sort();
  const packed = await npmPack(
    ids.map((id) => folders.get(id) as string),
    destination,
    work,
  );
  return ids.map((id, index) => {
    const tarball = packed[index] as PackedTarball;
    if (`${tarball.name}@${tarball.version}` !== id)
      throw new Error(`packed ${tarball.name}@${tarball.version} where ${id} was expected`);
    const manifest = JSON.parse(readFileSync(join(folders.get(id) as string, "package.json"), "utf8")) as Record<
      string,
      unknown
    >;
    return { manifest, tarball };
  });
}

export async function startRegistry(served: readonly Served[]): Promise<LoopbackRegistry> {
  const requests: LoopbackRegistry["requests"] = [];
  const byName = new Map<string, Served[]>();
  const byFile = new Map<string, Served>();
  for (const item of served) {
    byName.set(item.tarball.name, [...(byName.get(item.tarball.name) ?? []), item]);
    byFile.set(item.tarball.file, item);
  }
  let origin = "";
  const server: Server = createServer((request, response) => {
    const path = decodeURIComponent(new URL(request.url ?? "/", "http://registry.invalid").pathname.slice(1));
    const answer = (status: number, type: string, body: Buffer | string): void => {
      requests.push({ path, status });
      response.writeHead(status, { "content-type": type });
      response.end(body);
    };
    if (request.method !== "GET") return answer(405, "application/json", '{"error":"read only"}');
    if (path.startsWith("-/tarballs/")) {
      const item = byFile.get(path.slice("-/tarballs/".length));
      return item
        ? answer(200, "application/octet-stream", readFileSync(item.tarball.path))
        : answer(404, "application/json", '{"error":"not found"}');
    }
    const versions = byName.get(path);
    if (!versions) return answer(404, "application/json", '{"error":"not found"}');
    const packument = {
      name: path,
      "dist-tags": { latest: (versions[versions.length - 1] as Served).tarball.version },
      versions: Object.fromEntries(
        versions.map((item) => [
          item.tarball.version,
          {
            ...item.manifest,
            dist: { tarball: `${origin}/-/tarballs/${item.tarball.file}`, integrity: item.tarball.integrity },
          },
        ]),
      ),
    };
    return answer(200, "application/json", JSON.stringify(packument));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url: `${origin}/`,
    requests,
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
}
