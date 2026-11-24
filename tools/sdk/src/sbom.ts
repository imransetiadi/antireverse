// A bill of materials per packed package (slice 23, D-133): CycloneDX 1.5 JSON, written here from the lockfile
// closure. It has no timestamp and no serial number, and everything is sorted, so the same lockfile and the same
// tarballs give the same bytes and its SHA-256 can stand in the signed manifest. It describes the packed runtime
// closure: what `npm install` of the tarball brings in, as the lockfile pins it today — a project that installs the
// tarball resolves the transitive ranges again and may get newer versions.
import type { Closure } from "./closure.ts";

interface Hash {
  alg: "SHA-256" | "SHA-512";
  content: string;
}

export interface SbomComponent {
  type: "library";
  "bom-ref": string;
  group?: string;
  name: string;
  version: string;
  purl: string;
  hashes?: Hash[];
  licenses?: Array<{ license: { id: string } } | { expression: string }>;
  externalReferences?: Array<{ type: "distribution"; url: string }>;
  properties?: Array<{ name: string; value: string }>;
  /** What the component carries inside itself: a vendored package. */
  components?: SbomComponent[];
}

export interface Sbom {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  version: 1;
  metadata: { component: SbomComponent; properties: Array<{ name: string; value: string }> };
  components: SbomComponent[];
  dependencies: Array<{ ref: string; dependsOn: string[] }>;
}

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** pkg:npm/%40scope/name@version */
export function purlOf(name: string, version: string): string {
  const [scope, rest] = name.startsWith("@") ? (name.split("/") as [string, string]) : [undefined, name];
  return `pkg:npm/${scope === undefined ? "" : `${encodeURIComponent(scope)}/`}${rest}@${version}`;
}

function component(name: string, version: string, rest: Partial<SbomComponent>): SbomComponent {
  const [scope, plain] = name.startsWith("@") ? (name.split("/") as [string, string]) : [undefined, name];
  const purl = purlOf(name, version);
  return {
    type: "library",
    "bom-ref": purl,
    ...(scope === undefined ? {} : { group: scope }),
    name: plain,
    version,
    purl,
    ...rest,
  };
}

const licenses = (license: string | undefined): Pick<SbomComponent, "licenses"> =>
  license === undefined
    ? {}
    : { licenses: [/^[A-Za-z0-9.+-]+$/.test(license) ? { license: { id: license } } : { expression: license }] };

/**
 * `tarballs`: the SHA-256 of each SDK package's own tarball, by package name. `vendored`: the SDK packages whose
 * compiled files the package carries; each is listed inside the subject with the digest of its own tarball, whose
 * dist files are the ones copied.
 */
export function sbomOf(
  name: string,
  version: string,
  closure: Closure,
  tarballs: Readonly<Record<string, string>>,
  vendored: ReadonlyArray<{ name: string; dir: string }> = [],
): Sbom {
  const own = (pkg: string): Pick<SbomComponent, "hashes"> => {
    const sha256 = tarballs[pkg];
    if (sha256 === undefined) throw new Error(`no tarball digest for ${pkg}`);
    return { hashes: [{ alg: "SHA-256", content: sha256 }] };
  };
  const refOf = new Map(closure.entries.map((entry) => [entry.id, purlOf(entry.name, entry.version)]));
  const ref = (id: string): string => {
    const found = refOf.get(id);
    if (found === undefined) throw new Error(`${id} is not in the closure`);
    return found;
  };
  const inside = vendored.map((item) =>
    component(item.name, version, {
      ...own(item.name),
      ...licenses("Apache-2.0"),
      properties: [{ name: "airverse:vendored", value: `compiled files copied into ${item.dir}` }],
    }),
  );
  const subject = component(name, version, {
    ...own(name),
    ...licenses("Apache-2.0"),
    ...(inside.length === 0 ? {} : { components: inside }),
  });
  const components = closure.entries
    .map((entry) =>
      component(entry.name, entry.version, {
        ...(entry.integrity?.startsWith("sha512-")
          ? {
              hashes: [
                { alg: "SHA-512" as const, content: Buffer.from(entry.integrity.slice(7), "base64").toString("hex") },
              ],
            }
          : {}),
        ...licenses(entry.license),
        ...(entry.resolved === undefined
          ? {}
          : { externalReferences: [{ type: "distribution" as const, url: entry.resolved }] }),
      }),
    )
    .sort((a, b) => byText(a["bom-ref"], b["bom-ref"]));
  const dependencies = [
    { ref: subject["bom-ref"], dependsOn: closure.direct.map(ref).sort(byText) },
    ...closure.entries.map((entry) => ({ ref: ref(entry.id), dependsOn: entry.dependsOn.map(ref).sort(byText) })),
  ];
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      component: subject,
      properties: [
        {
          name: "airverse:scope",
          value: "runtime dependency closure of the packed package, as package-lock.json pins it",
        },
        { name: "airverse:release", value: "none: built locally, not published" },
      ],
    },
    components,
    dependencies: [
      dependencies[0] as Sbom["dependencies"][number],
      ...dependencies.slice(1).sort((a, b) => byText(a.ref, b.ref)),
    ],
  };
}

export const serializeSbom = (sbom: Sbom): string => `${JSON.stringify(sbom, null, 2)}\n`;

/** The file name of a package's bill of materials, beside its tarball. */
export const sbomFileOf = (tarball: string): string => tarball.replace(/\.tgz$/, ".cdx.json");
