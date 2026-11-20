# Security policy

Airverse is a security product. Reports of weaknesses in it are welcome.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub: open this repository's **Security** tab and choose **Report a vulnerability**. Only the maintainers can read the report.

Please include:

- the component (`packages/shield-node`, `packages/guard`, `packages/harden`, `packages/prove`, `apps/api`, `apps/console`) and the commit you tested;
- what an attacker gains, and what they need to begin with;
- the steps to reproduce it, with a proof of concept where you have one.

## Scope

- **In scope:** the code in this repository.
- **Out of scope:** any deployed system you do not own. Test only against a copy you run yourself (`npm run dev`, see the [README](../README.md#quickstart)).

## Supported versions

Airverse is pre-release and has no published versions. Fixes are made on the `main` branch only.

## Known limits are not vulnerabilities

Each feature section of the [README](../README.md) states its limits (for example: Guard's signals can be forged by a scripted client; obfuscation is not secrecy). A report that restates a documented limit is useful only when it shows the limit is wider than written.

## Threat model

The product's security specification — the threats, the controls and what verifies each control — is [SECURITY.md](../SECURITY.md) at the root of the repository.
