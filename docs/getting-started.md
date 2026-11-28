# Getting started

From nothing to your first protected request, then Guard in the browser and Harden in your build. Each step links to its own page for the details.

> Airverse is a local walking skeleton today: no user accounts, development storage, keep it on localhost. The [README](../README.md) lists what is deliberately missing.

## What you need

- Node.js 22.12 or newer, and npm. No Docker, no database to install.
- A clone of this repository. The packages (`@antireverse/shield-node`, `@antireverse/guard`, `@antireverse/harden`) are not published to npm yet; inside the repository they are workspace packages, linked by `npm install`.
- For a project of your own outside the repository, `npm run sdk:pack` in the clone writes installable tarballs (plain JavaScript) to `dist/sdk`; install them with `npm install --ignore-scripts <tarball>`. The README's "SDK packages" section says what comes with them. Using the clone's folders directly remains possible; keep the clone beside your project, not inside it.
- The `@antireverse` scope on npm belongs to the project owner (since 2026-11-28) and holds no package yet, so `npm install @antireverse/<name>` finds nothing: use the tarballs or the clone. Neither asks a registry for an `@antireverse` name (a test checks both).
- In the clone, Harden runs as `npx antireverse …` on Node 22.23 or newer. On Node 22.12 that fails with `ERR_UNKNOWN_FILE_EXTENSION`; use `npx tsx packages/harden/src/cli.ts …` instead, as the commands below do. Installed from its tarball, `npx antireverse …` works on every supported Node. See [Harden](harden.md#running-it).

## 1. Start Airverse

```bash
npm install
```

```bash
npm run dev
```

This starts the API on `http://127.0.0.1:8787` and the Console on `http://127.0.0.1:3000`.

## 2. Create an Organization

Open `http://127.0.0.1:3000`. Under **Create your organization**, enter an **Organization name** and press **Create organization**.

The Console shows **Admin key — shown once**. Save it now: you sign in with it (**Sign in with an admin key**), and Harden registers Builds with it. It cannot be shown again.

## 3. Create an App

Open **Apps** and press **New App**. Under **Create an App**, enter an **App name**, choose the **Environment** (Production, Staging or Development) and press **Create App**.

The Console shows **Shield key — shown once**. Save it now: it cannot be shown again. The key is tied to the Environment you chose; remember which one, because Harden must register Builds for the same Environment (step 8).

Below the key, the same screen shows the three set-up steps with your App's real values filled in: **Add Shield**, **Add Guard** and **Harden your build**. Each step has copyable code, the **Policy public key**, and a **Having trouble?** list of common causes. Press **Open the Set up page** to come back to these steps later: the App's **Set up** page shows the same steps (without the Shield key) and marks each one **Done** by itself, live, when Airverse sees it work. The **Apps** list shows **Set up: n of 3** for each App until all three are done.

The steps below follow the same order.

## 4. Add Shield to your server

Try it first on the reference target that ships with the repository. In a second terminal:

```bash
AR_SHIELD_KEY="<the Shield key>" AR_POLICY_PUBLIC_KEY="<the policy public key>" npm run dev:range
```

The startup line says whether Shield is active; neither key is ever printed.

To protect your own Express server instead, add the middleware before your routes:

```ts
import { createShield } from "@antireverse/shield-node";

const shield = createShield({
  key: process.env.AR_SHIELD_KEY,
  endpoint: "http://127.0.0.1:8787",
  policyPublicKey: process.env.AR_POLICY_PUBLIC_KEY, // without it Shield observes only
});
app.use(shield.express());
```

[Shield](shield.md) covers the options, the environment variables, and monitor and enforce.

## 5. See the first protected request

Keep the App's **Set up** page (or its **Live** page) open. It says "Waiting for the first event from <App>…" until Shield sends one. Then make a request:

```bash
curl http://127.0.0.1:4010/api/products/7
```

Within seconds the Set up page says **First protected request received**, without a reload, and the request appears in the live feed as `GET /api/products/:id`, Decision *Allowed*, mode *Monitor*. That is your first protected request: Shield sees it and would apply your Policy to it.

## 6. Block something

Open the App's **Policy** page. Under **Add a Rule**, enter a **Path pattern** such as `/api/admin/**` and press **Add Rule**. A new Rule starts in monitor mode: it marks matching requests and blocks nothing.

Press **Promote to enforce** and confirm. Shields with the policy public key apply the new version within 15 seconds:

```bash
curl -i http://127.0.0.1:4010/api/admin/reports
```

The answer is `403 {"error":"request_blocked"}`, and the request appears as *Blocked* in the feed. **Roll back** under **History** undoes it in one action.

## 7. Add Guard to your frontend

Guard is a small browser library that gets a short-lived Attestation Token and sends it with your API calls. Shield then records, for every request, whether a valid token came with it and what Guard's signals earned (**Trusted**, **Suspect**, **Hostile**, **No token**, **Invalid**, **Expired**). The **Client** column of the live feed shows it.

```html
<script type="module">
  import { createGuard } from "/guard/index.js";
  const guard = createGuard({ appId: "app_…", endpoint: "http://127.0.0.1:8787" });
  await guard.attest();
  await fetch("/api/orders", { headers: { ...guard.headers() } });
</script>
```

The **Add Guard** step turns done, with **First request with a Guard token received**, when Shield records a request carrying a Guard token it verified. [Guard](guard.md) covers serving the files, the options, and signed requests.

## 8. Harden your bundle

Harden is a build-time step for a web bundle you own. It scans for leaks, protects the code without changing its behaviour, and registers the Build with Airverse. Run it from the root of this repository.

First, try it without Airverse: print the options, then harden a bundle into a new folder. Nothing is sent anywhere.

```bash
npx tsx packages/harden/src/cli.ts --help
```

```bash
npx tsx packages/harden/src/cli.ts harden <bundle-dir> --out <out-dir>
```

Then register the Build. Set the admin key in the shell first:

```bash
export AR_ADMIN_KEY="<the admin key>"
```

```bash
npx tsx packages/harden/src/cli.ts harden <bundle-dir> --out <out-dir> \
  --register --endpoint http://127.0.0.1:8787 --key-env AR_ADMIN_KEY \
  --app <appId> --environment <environment> --build-version <app-version>
```

- `<environment>` is the App's Environment from step 3, in lower case: `production`, `staging` or `development`. It must match, or the **Harden your build** step never turns done.
- `<app-version>` is the version of the app you are hardening, for example its `package.json` version or its own commit (`git -C <your-app> rev-parse --short HEAD`), not a commit of this repository.

The Set up page then says **First Build registered**, and the Build appears on the App's **Builds** page. [Harden](harden.md) covers every option and the CI gate; [Reverse Assessment](reverse-assessment.md) explains the score you get with `--assess`.

## Next

- [Shield](shield.md): Express set-up, environment variables, monitor and enforce, the policy key.
- [Guard](guard.md): the script tag and its options.
- [Harden](harden.md): the commands, registration, the Reverse Assessment flags and the CI gate.
- [Reverse Assessment](reverse-assessment.md): what the score means and its honest limits.
