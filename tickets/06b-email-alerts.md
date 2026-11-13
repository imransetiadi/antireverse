---
title: "Ticket 06b — Email alerts over SMTP"
aliases: [Ticket 06b]
project: anti-reverse
doc: TICKET
slice: 6
version: 0.1.0
status: done
updated: 2026-11-13
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[UIUX]]"
---

# 06b: Email alerts over SMTP

**What to build:** Incident alerts can go to email, completing slice 06 (Slack and webhook were done). Airverse sends through one SMTP account configured for the service; an Organization adds an email channel with up to five recipients, each of whom confirms by a link before any alert reaches them.

**Blocked by:** 06 (done). Owner chose generic SMTP on 2026-11-12 (D-068); design by Jev (0.94), D-072.

**Status:** done on 2026-11-13 — plan in [plans/2026-11-13-slice-06b-email-alerts.md](../plans/2026-11-13-slice-06b-email-alerts.md)

## Acceptance criteria

- [x] The API reads SMTP settings from its environment (host, port, TLS mode implicit or STARTTLS, user, password from a file or variable, sender address and name). Without them, email channels cannot be created and the Console says why. Secrets are never logged or returned.
- [x] A channel of kind email has 1–5 recipients. Each recipient gets one confirmation mail with a single-use link (valid 72 hours); only confirmed recipients receive alerts or test alerts. At most 3 confirmation mails per address per day.
- [x] When an Incident opens, each confirmed recipient gets a plain-text mail: the Incident title, severity, App, Environment, time, and a link to the Incident in the Console. No tenant-supplied text in any header.
- [x] Delivery uses an in-house SMTP client: STARTTLS required unless implicit TLS, certificate validation, AUTH PLAIN or LOGIN, timeouts, dot-stuffing, header injection impossible; retries as for webhooks; failures recorded on the channel.
- [x] The Console adds the email channel form, recipient status (pending, confirmed), resend confirmation, and the test alert — in the restyled design (D-053).
- [x] `npm run verify` passes; an end-to-end test runs a local SMTP server, confirms a recipient through the link, opens an Incident and sees exactly one alert mail delivered to the confirmed recipient and none to an unconfirmed one.

## Proof

| Criteria | Proven by |
|---|---|
| Settings, client, message, caps | `apps/api/test/mail-*.test.ts`, `smtp-client.test.ts` (local SMTP server: STARTTLS, implicit TLS, failures), `email-caps.test.ts`, `address-key.test.ts` |
| Channels, confirmation, delivery | `apps/api/test/email-channels.test.ts`, `notifier-email.test.ts`, `email-server.test.ts` |
| Console | `apps/console/test/email-alerts-*.test.*`; `tests/e2e/email-alerts.e2e.ts` (confirm by button, no token in the done URL) |
| Quality | `tests/e2e/email-alerts.http.test.ts` (13) · `npm run test` — 6,811 tests · `npm run e2e` — 18 journeys · bench within PB-01 |

An independent review reproduced 2 MEDIUM and 4 LOW findings (cap bypass by plus-addressing and Gmail dots, a confirmation flood crowding out alerts, the confirm budget used by malformed requests, re-sent confirmations after a timeout, cross-tenant inference); all fixed test-first. Jev verified 4 of 4 completion claims.

## Honest limits

Delivery to the inbox depends on the sender domain's SPF and DKIM, set by the owner; Airverse does not sign mail itself. Bounces are not processed. The recipient address a tenant typed appears in the To header. Caps: 20 confirmation mails per Organization and 500 for the service per day (`AR_SMTP_CONFIRMATIONS_PER_DAY`), 20 new email channels per Organization per day. The development server logs confirmation link URLs.

## Out of scope

Per-Organization SMTP accounts · HTML mail · bounce and complaint processing · digests.
