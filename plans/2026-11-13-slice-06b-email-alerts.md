---
title: "Plan — Slice 06b Email alerts over SMTP"
aliases: [Plan 06b]
project: anti-reverse
doc: PLAN
slice: 6
version: 0.1.0
status: done
updated: 2026-11-13
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[UIUX]]"
---

# Slice 06b — Email Alerts Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** Confirmed recipients get Incident alerts by email; Airverse can never be used to mail strangers.

**Architecture:** Protocol adds the `email` channel kind, recipients and their status. The API reads SMTP settings, sends through an in-house client behind a `Mailer` seam (a fake in tests, a local SMTP server in e2e), adds confirmation links and plugs into the existing notifier. The Console extends the alert channel pages. No new dependency.

**Spec:** [tickets/06b-email-alerts.md](../tickets/06b-email-alerts.md); D-068, D-072; slice 06 plan (notifier, retries, test alert, channel secrets); SECURITY (secrets never logged); D-053.

## Global Constraints (additions)

- **Settings:** `AR_SMTP_HOST`, `AR_SMTP_PORT` (default 587), `AR_SMTP_TLS` = `starttls` (default) | `implicit`, `AR_SMTP_USER`, `AR_SMTP_PASSWORD` or `AR_SMTP_PASSWORD_FILE`, `AR_SMTP_FROM` (address), `AR_SMTP_FROM_NAME` (default "Airverse"). All or none; a partial set is a start-up error naming the missing variable (never its value). Test-only option for a local server CA.
- **Channel:** kind `email`, name, recipients 1–5 (lower-cased, syntactically valid, ≤ 254 characters, unique). Recipient status `pending` | `confirmed`, `confirmed_at`, `last_sent_at`. Responses never include tokens.
- **Confirmation:** token 32 random bytes base64url, stored hashed (SHA-256), valid 72 h, single use; link `<console>/alerts/confirm?token=…` handled by a public API endpoint `POST /v1/alert-recipients/confirm { token }`; mails: at most 3 per address per day across all Organizations; resend from the Console counts toward it.
- **Mail:** plain text UTF-8 (quoted-printable), subject `[Airverse] <severity>: <title>` with the title stripped of CR/LF and other control characters and truncated (RFC 2047 encoding for non-ASCII); body lines: Incident title, severity, App, Environment, opened at (UTC), link; Message-ID and Date set; no tenant text elsewhere in headers.
- **SMTP client:** EHLO; STARTTLS required when `starttls` (refuse to authenticate without TLS); certificate validated for the host; AUTH PLAIN or LOGIN as offered; MAIL FROM, RCPT TO per confirmed recipient, DATA with dot-stuffing and CRLF normalisation; timeouts 10 s connect, 30 s per command, 60 s total; one connection per alert batch; response codes checked; failures recorded per channel as the webhook notifier does, with its retry schedule.
- **Console:** channel form kind Email with recipients one per line; channel row lists recipients with Pending/Confirmed chips and "Resend confirmation"; a confirmation page for the link (calls the public endpoint, shows confirmed or expired); a note when SMTP is not configured.

## Review Focus

1. **Abuse:** no mail to an unconfirmed address except the rate-limited confirmation; tokens unguessable, single use, hashed; enumeration of addresses or channels impossible through the public endpoint.
2. **Injection:** headers and SMTP commands cannot be broken by titles, names, addresses or recipients (CR, LF, NUL, Unicode line separators, long lines).
3. **TLS and secrets:** no AUTH without TLS; certificate validation; password never logged.
4. **Delivery:** retries, partial recipient failure, server errors, timeouts.

## Tasks

Order: Task 1 (protocol and API) → Task 2 (Console) → Task 3 (e2e) → Task 4 (review, docs).

## Amendments
- **A1 — Protocol and API as built (Jev: three_changes, 0.96).** Channel kind `email` (union on kind), recipients with ids `rcp_`, `smtp_configured` on the channel list; migration 0024 (recipients under RLS, token hashes, confirmation-mail counts the request role cannot read, two definer functions); `src/mail/` settings (all or none, names never values), an in-house SMTP client (STARTTLS required, response-injection check after STARTTLS, certificate validated before AUTH, PLAIN or LOGIN, per-message RSET, timeouts) and message building (a 500-case property test: no subject, name or body can add a header line); confirmation mails asynchronous; resend by recipient id; the confirm endpoint answers the same for unknown, used and expired tokens. Changed: address hashes for the daily cap are keyed with a server secret; permanent 5xx SMTP replies are not retried; the confirm endpoint limits 5 attempts per token plus 600 per minute overall, because the Console calls it server-side.
- **A2 — Console as built (Jev: button_and_redirect, 1.0).** Email kind in the channel form (recipients one per line, errors by line number; disabled with a note when SMTP is not set up); recipient chips Pending (hourglass, medium colour) and Confirmed (circled check, accent); Resend confirmation; test-alert refusals mapped; public pages without a session. The confirmation page never confirms on load (mail link scanners open links): a "Confirm email" button posts the token, then redirects to `/alerts/confirm/done?result=…` without the token; a done page opened by hand changes nothing on the server. Stub serves email channels and a manual-testing link endpoint.
- **A3 — Review fixes (to do, test first; Jev fix_set 0.77).** Reproduced (anyone can create an Organization without a key): F1 plus-addressing and dots bypassed the daily cap (103 mails to one inbox); F2 confirmation mails skipped the queue limits and could crowd out other tenants' alerts; F3 malformed requests used up the confirm budget; F4 a timeout after DATA re-sent a counted confirmation; F5 the tenant-typed address reaches the recipient in the To header; F6 the shared cap revealed other Organizations' use. Fix: addresses normalised for the cap (+tag dropped; dots dropped for Gmail); 20 confirmation mails per Organization per day, 500 for the service (setting), 20 email-channel creations per Organization per day; confirmations share the alert queue limits and a 4-connection SMTP pool; validation before the confirm limiter; a confirmation whose DATA was sent is not retried; F5 documented; the cap tenants see is per Organization and address, the global per-address cap stays silent (resend answers 202 and sends nothing).
- **A3 as built.** Counters (migration 0025, one definer function `take_mail_caps`, all-or-none, keys HMAC'd with `mail-hash-key.json`): told to the tenant (429 on resend, recipient left pending at creation) — 3 per Organization and normalised address, 20 per Organization; silent (resend answers 202 and sends nothing, the earlier link still works) — 3 per normalised address for all Organizations, and the service's 500 (`AR_SMTP_CONFIRMATIONS_PER_DAY`), so a tenant's answers never depend on another Organization's use; the told counters are charged even when a silent one refuses. Email-channel creations: 20 per Organization per day (429 `too-many-requests`, Retry-After to UTC midnight). Notifier: confirmations dropped like alerts when the Organization's or the service's queue is full; one SMTP pool of 4 connections, at most 2 for confirmations, waiting alerts served first. SMTP client: a message whose data went out before the session ended carries `dataSent`; a confirmation with it counts as sent (logged `outcome=unknown`), an alert is still retried. Confirm endpoint: body validated before the 600-a-minute limiter. F5 documented in `src/mail/message.ts`: the To header is the address the tenant typed (its local part reaches the recipient); subject and body of a confirmation carry no tenant text. App names now refuse control and format characters (C0, C1/NEL, DEL, zero-width, bidi, BOM, U+2028/2029, lone surrogates) at creation; names stored earlier stay as they are.
- **A4 — End to end and observations.** 12 HTTP tests and 1 browser journey (a fake STARTTLS server inside the e2e API process; Jev 0.68; every Playwright journey now sees SMTP configured). Observations accepted and documented: after the Confirm button the browser keeps the previous page's framework data (including the token) in memory, not in the URL or the reloaded page; `next dev` logs request URLs, so the token appears in development logs only. App names will refuse control characters like channel names (they accepted CR and LF).
