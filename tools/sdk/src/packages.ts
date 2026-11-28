// The four packages that are packed (slice 23): what a project installs — Shield, Guard, Harden — and the protocol.
// `@antireverse/prove` is not one of them: no project installs it. No packed package depends on another: the
// @antireverse scope was not registered on npm when this was decided (the owner holds it since 2026-11-28), and
// an install should not rest on who holds a scope (D-140). Harden, which uses the protocol at run time, carries a copy of the compiled protocol instead.

export interface SdkPackage {
  /** The npm name. */
  name: string;
  /** The folder under packages/, and the name of its build and staging folders. */
  short: "protocol" | "shield-node" | "guard" | "harden";
  /** `tsc`: compiled from TypeScript. `copy`: plain ES modules with a hand-written declaration file, copied. */
  kind: "tsc" | "copy";
  /** Export subpath → module name inside src (no extension). */
  entries: Record<string, string>;
  /** Command name → module name inside src. */
  bin?: Record<string, string>;
  /** The guide copied into the tarball as its README, relative to the repository root. */
  guide?: string;
  /** SDK packages whose compiled files are copied into this one (dist/_<short>), with its imports rewritten. */
  vendors?: readonly string[];
  /** Released to npm by the owner (slice 23b). The protocol is not: it stays private and unpublished. */
  released: boolean;
  /** Search words of the npm page of a released package. */
  keywords?: readonly string[];
  /** SECURITY SC-SUP-03: this package may have no runtime dependency at all. */
  zeroDependencies: boolean;
  description: string;
}

export const SDK_PACKAGES: readonly SdkPackage[] = [
  {
    name: "@antireverse/protocol",
    short: "protocol",
    kind: "tsc",
    entries: { ".": "index", "./server": "server" },
    released: false,
    zeroDependencies: false,
    description: "Airverse wire contract: schemas, constants and helpers shared by the SDK packages.",
  },
  {
    name: "@antireverse/shield-node",
    short: "shield-node",
    kind: "tsc",
    entries: { ".": "index" },
    guide: "docs/shield.md",
    released: true,
    keywords: ["airverse", "shield", "express", "middleware", "api-security", "rate-limit", "request-signing"],
    zeroDependencies: true,
    description: "Airverse Shield: middleware for Express and plain Node http servers.",
  },
  {
    name: "@antireverse/guard",
    short: "guard",
    kind: "copy",
    entries: { ".": "index" },
    guide: "docs/guard.md",
    released: true,
    keywords: ["airverse", "guard", "browser", "attestation", "request-signing", "tamper-detection"],
    zeroDependencies: true,
    description: "Airverse Guard: browser attestation and request signing, plain ES modules.",
  },
  {
    name: "@antireverse/harden",
    short: "harden",
    kind: "tsc",
    entries: { ".": "index" },
    bin: { antireverse: "cli" },
    vendors: ["@antireverse/protocol"],
    guide: "docs/harden.md",
    released: true,
    keywords: ["airverse", "harden", "obfuscation", "build", "bundle", "leak-scan", "cli"],
    zeroDependencies: false,
    description: "Airverse Harden: build-time protection of a web bundle you own, and the antireverse command.",
  },
];

export const SDK_NAMES: readonly string[] = SDK_PACKAGES.map((pkg) => pkg.name);

/**
 * The project's public repository: what a released package.json and README name. A release is refused when the
 * checkout's origin is another repository, so a fork or a mirror cannot put its own URL into a published package.
 */
export const PUBLIC_REPOSITORY = "https://github.com/imransetiadi/antireverse";

/** The packages the owner publishes: Shield, Guard and Harden. Never the protocol. */
export const RELEASED_PACKAGES: readonly SdkPackage[] = SDK_PACKAGES.filter((pkg) => pkg.released);

export function sdkPackage(name: string): SdkPackage {
  const found = SDK_PACKAGES.find((pkg) => pkg.name === name || pkg.short === name);
  if (!found) throw new Error(`not an SDK package: ${name}`);
  return found;
}
