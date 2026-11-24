# Harden

`antireverse harden` is a build-time step you run in your own CI over a web bundle you own. It makes reverse engineering costlier without changing behaviour, and the source never leaves the machine. Only a Build Manifest (hashes, paths, costs) is uploaded, and only when you pass `--register`.

Responsible use: Harden protects software you own. It is not for evading detection or protecting software you do not own.

## Running it

The `antireverse` command is the `@antireverse/harden` package, which is not published to npm yet. There are two ways to run it.

**Installed from its tarball** (`npm run sdk:pack` in the Airverse repository writes it; then, in your project, `npm install --save-dev --ignore-scripts <path>/antireverse-harden-<version>.tgz`): plain JavaScript, run as `npx antireverse …`. Babel 8, which Harden depends on, supports Node 22.18 and newer (not 23, and 24 from 24.11). On Node 22.12 npm warns when it installs Harden and the command was seen to work; with npm's `engine-strict` the install is refused. Shield and Guard need only Node 22.12. Where the commands below say `npx tsx packages/harden/src/cli.ts`, write `npx antireverse`.

**From a clone of the repository:** its entry point there, `packages/harden/src/cli.ts`, is a TypeScript file. On Node 22.23 or newer (tested on 22.23.4), the bin works:

```bash
npx antireverse --help
```

On Node 22.12, the bin fails at once with `ERR_UNKNOWN_FILE_EXTENSION`. Run it through `tsx` instead:

```bash
npx tsx packages/harden/src/cli.ts --help
```

or let Node strip the types (it prints an ExperimentalWarning):

```bash
node --experimental-strip-types node_modules/.bin/antireverse --help
```

Every command below uses the clone's `npx tsx` form, which works on both versions. `--help` prints the full list of options and exit codes.

## Harden a bundle

```bash
npx tsx packages/harden/src/cli.ts harden <bundle-dir> --profile balanced --out <out-dir> --test "npm test"
```

In order, Harden:

1. **Scans for leaks** before it changes anything: source maps, private keys, known secret-key formats, random-looking values assigned to secret-like names, internal URLs. A finding fails the run with exit 3; nothing is written or registered.
2. **Protects** each file according to the profile.
3. **Plants Canaries**: one decoy API key and two decoy internal routes. Shield watches for them once the Build is registered.
4. **Proves equivalence**: with `--test`, it runs your test command against the protected copy and fails if anything differs.

| Option | What it does |
|---|---|
| `--profile <p>` | `light` = identifier mangling; `balanced` (default) = mangling + string encryption bound at the use site; `maximum` = `balanced` for now. |
| `--out <dir>` | Writes the protected files. Without it Harden only reports and writes nothing. Use a folder other than `<bundle-dir>`: the same folder is overwritten. |
| `--test <command>` | Runs this command against the protected copy as the equivalence gate. The command runs inside a temporary copy of `<bundle-dir>` that holds the protected files, not in your project root: give a command that tests the files in its current directory (name your test script by absolute path), and do not `cd` back into the project, which would test the unprotected build. |
| `--seed <n>` | An integer seed for reproducible output (with `--register`, apart from the integrity marker's line, see below). |
| `--map <file.json>` | A JSON map of `"relative/path": "skip"` to emit a file unchanged. |
| `--integrity` | Wraps already-bundled (non-ESM) output in a tamper self-check. Refused on ESM input. |
| `--leak-allow <file>` | The leak allowlist. Default: `.antireverse/leak-allow.json` in the working directory. |
| `--json` | Prints a machine-readable report. |

A module is never shipped more than 35 % larger (gzip). If a transform would exceed that, the file falls back to mangle-only or is emitted unchanged, with the reason in the report.

To accept a reviewed leak finding, commit its fingerprint with a reason in `.antireverse/leak-allow.json`:

```json
{ "version": 1, "allow": [{ "fingerprint": "<32 hex>", "reason": "Public demo key, revoked" }] }
```

## Register the Build: `--register`

`--register` sends the Manifest to Airverse so the Build appears on the App's **Builds** page, and its Canaries are watched. It needs all five of these flags:

| Flag | Value |
|---|---|
| `--endpoint <url>` | The Airverse API, for example `http://127.0.0.1:8787`. It must not contain credentials. |
| `--key-env <VAR>` | The name of the environment variable that holds the admin key. The key is read only from there and never printed. |
| `--app <appId>` | The App ID, `app_` and 24 hex characters. |
| `--environment <env>` | `production`, `staging` or `development`: the App's Environment, as chosen when the App was created. A Build for another Environment does not complete the App's **Harden your build** set-up step. |
| `--build-version <v>` | The version of the app you are hardening, one line: for example its `package.json` version or its own commit, not a commit of this repository. |

```bash
export AR_ADMIN_KEY="<the admin key>"
```

```bash
npx tsx packages/harden/src/cli.ts harden dist --out dist-protected \
  --register --endpoint http://127.0.0.1:8787 --key-env AR_ADMIN_KEY \
  --app <appId> --environment production --build-version 1.4.0
```

More flags that work with `--register`:

- `--lockfile <path>`: the npm lockfile to read (default `./package-lock.json`). Package names and versions are sent with the Build for known-vulnerability Findings.
- `--fail-on <low|medium|high|critical>`: exit 4 when the registered Build has open Findings at or above that level.
- `--origin <origin>`: plants a Clone Beacon. Give each origin your bundle is served from (`https://host[:port]`), up to 20; a copy running anywhere else reports once.
- `--no-integrity-marker`: does not plant the integrity marker (see below).

```bash
npx tsx packages/harden/src/cli.ts harden dist --out dist-protected \
  --origin https://shop.example.com \
  --register --endpoint http://127.0.0.1:8787 --key-env AR_ADMIN_KEY \
  --app <appId> --environment production --build-version 1.4.0 \
  --lockfile package-lock.json --fail-on high
```

## Integrity marker

With `--register`, Harden plants one more statement beside the Canaries: the **integrity marker**. It lets Airverse notice when the files a browser received are not the files of the Build you registered.

- **What is planted.** One line, in the same file as the Canaries, that adds `{ b: <Build ID>, f: [<file paths>] }` to a list under `globalThis[Symbol.for("ar.build")]`. It holds identifiers only: the Build ID and up to 32 file paths, the planted file first and then the largest protected files. It never holds a hash, runs inside `try`/`catch`, and does nothing else.
- **What is registered.** The Manifest lists the same paths in the same order (`integrity.files`), and for every file its SHA-256 and size (`artifacts`). The hash is of the exact bytes Harden writes to `--out`.
- **How it is used.** An attestation may carry the hashes a browser observed for these files; the API compares them with the registered Build. [Guard](guard.md#tamper-detection) collects and sends these hashes from pages that run it; a page without Guard reports nothing. A Build is watched from its first fully matching report; after that, a file whose hash differs opens a High **Tampered Build** Incident that names the Build, the file and both hashes. A file that belongs to another recent Build of the same App Environment (a deploy in progress, a cache) is not counted. Recent means one of the newest 20 Builds of that App Environment, or a Build registered in the last 30 days. The report never changes the attestation, the verdict or what Shield does.
- **It never fails a build.** If the marker does not fit the size budget, Harden plants it with fewer files, or not at all. The report says so (`! Integrity marker: …`), `--json` has `integrity_marker` with the files and how many were left out, and the Manifest lists only the files that were planted.
- **Reproducible output.** The marker names the Build ID, which is new on every run. Two runs with the same `--seed` are byte-identical apart from that one line, and identical altogether with `--no-integrity-marker`.

> **Serve the files exactly as Harden wrote them.** The registered hashes are of the bytes in `--out`. A step that rewrites those files afterwards changes their hashes: a minifier or bundler run after Harden, a build step that appends a source-map comment or a banner, a server or CDN feature that injects or rewrites code (analytics snippets, "auto-minify", HTML or script rewriting, email obfuscation), a line-ending or encoding conversion in the deploy (CRLF, a byte order mark). Run Harden as the last step that touches the files. If a later step must change them, such a Build is never seen matching, so it is never watched and opens no Incident; turn the marker off with `--no-integrity-marker` to make that explicit.

The marker is not the `--integrity` option: `--integrity` wraps a script in a self-check inside the bundle; the integrity marker only names the Build so that the comparison happens on the server.

> **With `--integrity`, the Build is not watched.** `--integrity` puts the whole planted file, marker included, into a string inside its self-check wrapper. Guard finds a Build by the marker's text in the bytes it is served, and inside that string the text is escaped, so Guard does not find it and sends no report. The Build is registered as usual and its page works; it just never becomes watched and never opens a Tampered Build Incident. Harden says so: the report shows `! Integrity marker: with --integrity this Build is not watched for tampering (the self-check wrapper hides the marker from Guard)`, and `--json` has `"watched": false` in `integrity_marker`. Use one or the other for a Build: `--integrity` for a self-check inside the bundle, or the marker (without `--integrity`) for tamper detection by Guard.

## Reverse Assessment: `--routes`, `--logic`, `--assess`

These flags feed the [Reverse Assessment](reverse-assessment.md), which attacks the protected output and scores how well it resists.

- `--routes <file>`: your route inventory, a JSON array of `"METHOD /path"` with `:param` segments, at most 2,000. Objective Map is judged against it. It is sent beside the Manifest, never written to `--out`, and never shown to the assessing agent.

  ```json
  ["GET /api/products/:id", "POST /api/login", "GET /api/admin/reports"]
  ```

- `--logic <file>`: up to 5 protected functions with hidden test vectors, for Objective Logic. Each function has an `id`, a `description`, up to 2 public `examples` and 10 to 200 hidden `vectors` (`{ "input": [args], "output": value }`); the file is at most 1 MB. The agent sees the id, description and examples, never the vectors.

  ```json
  {
    "functions": [
      {
        "id": "price-with-tax",
        "description": "The price in cents including tax: price in cents and tax rate in percent, rounded to a cent.",
        "examples": [{ "input": [1000, 10], "output": 1100 }],
        "vectors": [{ "input": [0, 10], "output": 0 }, { "input": [999, 7], "output": 1069 }]
      }
    ]
  }
  ```

  (A real file needs at least 10 vectors per function.)

- `--assess <T1|T2|T3>`: after registration, uploads the protected output (at most 25 MB and 1,000 files) and queues an Assessment at that tier. It prints the Assessment id and a Console link. Needs `--register`.

```bash
npx tsx packages/harden/src/cli.ts harden dist --out dist-protected --integrity \
  --register --endpoint http://127.0.0.1:8787 --key-env AR_ADMIN_KEY \
  --app <appId> --environment production --build-version 1.4.0 \
  --routes routes.json --logic logic.json --assess T1
```

Without `--logic`, Logic is not assessed and the run is inconclusive. Without `--integrity`, the Build has no tamper check, so a small edit is enough for the attacker to achieve Tamper.

`--wait` and `--on-no-score` (below) need `--min-rrs`, and `--min-rrs` needs `--assess`.

## CI gate on the score

### In the same step: `--min-rrs`

Add `--min-rrs <0-100>` to a `harden --register --assess <tier>` run. Harden writes `--out` first, then waits for the Assessment and fails the step when the score is lower than your threshold.

```bash
npx tsx packages/harden/src/cli.ts harden dist --out dist-protected \
  --register --endpoint http://127.0.0.1:8787 --key-env AR_ADMIN_KEY \
  --app <appId> --environment production --build-version 1.4.0 \
  --routes routes.json --logic logic.json --assess T1 --min-rrs 60
```

- `--wait <s>`: how long to wait, 1 to 86,400 seconds. Default: the tier's time plus 300 seconds. Progress goes to stderr every minute.
- `--on-no-score <fail|pass>`: what to do when there is no score (inconclusive, failed, or the wait ran out). `fail` (default) exits 6; `pass` passes with a warning and reports the gate as skipped.

### In a later step: `antireverse gate`

When the Assessment was queued by an earlier step, gate on it by its id:

```bash
npx tsx packages/harden/src/cli.ts gate --assessment <asm_id> --min-rrs 60 \
  --endpoint http://127.0.0.1:8787 --key-env AR_ADMIN_KEY
```

```bash
npx tsx packages/harden/src/cli.ts gate --assessment <asm_id> --min-rrs 60 \
  --endpoint http://127.0.0.1:8787 --key-env AR_ADMIN_KEY \
  --wait 1200 --on-no-score pass --json
```

`gate` takes `--assessment`, `--min-rrs`, `--endpoint` and `--key-env` (all required), and `--wait`, `--on-no-score` and `--json`. Any other argument is a usage error.

Both forms print the score, the threshold, the status and the two weakest Objectives. With `--json` the report has a `gate` (in `antireverse gate`) or `rrs_gate` (in `harden`) object with `result`: `passed`, `failed`, `no_score` or `skipped`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Failure: a parse error, an equivalence failure, a budget even mangle-only cannot meet, a registration error, or a gate that could not be evaluated |
| 2 | Usage or input error, checked before any work |
| 3 | The leak scan found something; nothing was written or registered |
| 4 | Open Findings at or above `--fail-on` |
| 5 | The score is below `--min-rrs` |
| 6 | No score: inconclusive, failed, or the wait ran out (unless `--on-no-score pass`) |

When 4 and 5 or 6 both apply, 4 wins and both gates are reported.

## Honest limits

- Mangling and string encryption are obfuscation, not secrecy: the decoder ships in the bundle. Never put real secrets in client code.
- `--integrity` is a tamper signal for already-bundled code, not tamper-proofing.
- A file that calls `eval` is left unmangled. Public export names, imports and property keys are preserved by design.
- The leak scan matches patterns; multi-line or computed secrets and symlinked files are not caught.
- Canaries are only seen where Shield runs. A cloner who edits the bundle can remove the Clone Beacon.
- The integrity marker catches tampering that does not adapt to it. Someone who changes the files can also remove the marker, remove Guard, or report the registered hashes. An origin that was changed before it ever served the registered files is never seen matching, so it is never watched. A page of an older Build that is neither among the newest 20 Builds of its App Environment nor registered in the last 30 days, and is still served somewhere (a long-lived cache, a forgotten host), is reported as tampered when it loads a file of a newer Build: register Builds for what you serve, and take old deployments down. Anyone who knows the public App ID can report a false mismatch for a watched Build, and can also use up the limits so that real reports of the same hour are not recorded. The limits are per Build: 20 new file-and-hash pairs an hour and 50 in any 24 hours, one Detection per file and hash per hour, and 600 reports an hour that carry a mismatch. When a limit hid something, the Incident says so ("More distinct hashes were reported than are recorded."). Guard hashes only files the page loads from its own origin; see [Guard](guard.md#tamper-detection) for what it sends and its limits.

See also: [Reverse Assessment](reverse-assessment.md), [Getting started](getting-started.md).
