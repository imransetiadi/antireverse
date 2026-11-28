// What a release build needs to know, and what it refuses (slice 23b). A release is built only from a clean working
// tree whose HEAD is the commit origin/main points at, as this clone last saw it: the remote-tracking ref is read,
// nothing is fetched. The public repository URL comes from the origin remote and is refused when it holds
// credentials (they would end up in a published package.json). Nothing here publishes.
import { exec } from "./exec.ts";
import { PUBLIC_REPOSITORY, SDK_PACKAGES } from "./packages.ts";

export interface ReleaseInfo {
  /** https://host/owner/name, without credentials and without `.git`. */
  repository: string;
  /** The full commit the release is built from. */
  commit: string;
  /**
   * The files of the packages' source folders that the commit tracks, relative to the repository
   * (packages/<name>/src/…). Only what is compiled or copied from one of these may ship.
   */
  tracked: readonly string[];
}

/** The folders a tarball's code comes from: the four packages' sources (Harden carries the protocol's). */
const SOURCE_FOLDERS: readonly string[] = SDK_PACKAGES.map((pkg) => `packages/${pkg.short}/src`);

/** The origin remote as a public https URL. Throws without repeating a credential. */
export function normaliseRemote(remote: string): string {
  const text = remote.trim();
  const scp = /^git@([A-Za-z0-9.-]+):([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/.exec(text);
  if (scp) return `https://${scp[1]}/${scp[2]}/${scp[3]}`;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new Error("the origin remote is not a repository URL");
  }
  if (url.protocol === "ssh:" && url.username === "git" && url.password === "") {
    url = new URL(`https://${url.host}${url.pathname}`);
  } else if (url.username !== "" || url.password !== "") {
    throw new Error(
      "the origin remote holds credentials: remove them from the remote URL (git remote set-url origin https://…) before a release",
    );
  }
  if (url.protocol !== "https:") throw new Error("the origin remote must be https (or git@host:owner/name)");
  const parts = url.pathname
    .replace(/\.git$/, "")
    .split("/")
    .filter(Boolean);
  if (
    parts.length !== 2 ||
    parts.some((part) => !/^[A-Za-z0-9_.-]+$/.test(part)) ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("the origin remote is not a repository URL of the form https://host/owner/name");
  }
  return `https://${url.host}/${parts[0]}/${parts[1]}`;
}

/** The state a release may be built from, read from the repository at `dir`; throws with the reason otherwise. */
export async function releaseState(dir: string): Promise<ReleaseInfo> {
  const git = (...args: string[]) => exec("git", args, { cwd: dir });
  const head = await git("rev-parse", "--verify", "HEAD^{commit}");
  if (head.code !== 0) throw new Error(`${dir} is not a git repository with a commit (no commit to release)`);
  const commit = head.stdout.trim();
  const status = await git("status", "--porcelain", "--untracked-files=all");
  if (status.code !== 0) throw new Error(`git status failed in ${dir}`);
  const changed = status.stdout.split("\n").filter((line) => line.trim() !== "");
  if (changed.length > 0) {
    const shown = changed.slice(0, 10).join("\n  ");
    throw new Error(
      `a release is built from a clean working tree; there are uncommitted changes (${changed.length}):\n  ${shown}${changed.length > 10 ? "\n  …" : ""}`,
    );
  }
  const main = await git("rev-parse", "--verify", "--quiet", "refs/remotes/origin/main^{commit}");
  if (main.code !== 0) {
    throw new Error("origin/main is not known here: run `git fetch origin` yourself, then build the release again");
  }
  if (main.stdout.trim() !== commit) {
    throw new Error(
      `HEAD ${commit.slice(0, 12)} is not origin/main (${main.stdout.trim().slice(0, 12)}, as this clone last fetched it): a release is built from the commit that is on origin/main`,
    );
  }
  // What `git status` does not show (review S2). An ignored file in a source folder would be compiled or copied
  // like any other; a file marked skip-worktree or assume-unchanged can differ from the commit unseen.
  const ignored = await git("ls-files", "--others", "--ignored", "--exclude-standard", "--", ...SOURCE_FOLDERS);
  if (ignored.code !== 0) throw new Error(`git ls-files failed in ${dir}`);
  const hidden = ignored.stdout.split("\n").filter((line) => line !== "");
  if (hidden.length > 0) {
    throw new Error(
      `a release is built from the packages' tracked sources only; git ignores these files in their source folders, and they would be built in (${hidden.length}):\n  ${hidden.slice(0, 10).join("\n  ")}`,
    );
  }
  const flags = await git("ls-files", "-v");
  if (flags.code !== 0) throw new Error(`git ls-files -v failed in ${dir}`);
  // `H` is an ordinary tracked file. `S` is skip-worktree; a lower-case letter is assume-unchanged.
  const unseen = flags.stdout.split("\n").filter((line) => line !== "" && !line.startsWith("H "));
  if (unseen.length > 0) {
    throw new Error(
      `git was told not to look at these files (skip-worktree or assume-unchanged), so they may differ from the commit unseen (${unseen.length}):\n  ${unseen
        .slice(0, 10)
        .map((line) => line.slice(2))
        .join(
          "\n  ",
        )}\n  Undo that (git update-index --no-skip-worktree --no-assume-unchanged <file>) before a release`,
    );
  }
  const tree = await git("ls-tree", "-r", "--name-only", "HEAD", "--", ...SOURCE_FOLDERS);
  if (tree.code !== 0) throw new Error(`git ls-tree failed in ${dir}`);
  const tracked = tree.stdout
    .split("\n")
    .filter((line) => line !== "")
    .sort();
  const remote = await git("remote", "get-url", "origin");
  if (remote.code !== 0) throw new Error("there is no origin remote to take the repository URL from");
  const repository = normaliseRemote(remote.stdout);
  if (repository !== PUBLIC_REPOSITORY) {
    throw new Error(
      `origin is ${repository}, not the project's repository (${PUBLIC_REPOSITORY}): a release names the project's own repository and is built from it`,
    );
  }
  return { repository, commit, tracked };
}
