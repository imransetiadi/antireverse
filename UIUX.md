---
title: "Airverse — UI and UX"
aliases: [UIUX]
project: anti-reverse
doc: UIUX
version: 0.1.0
status: approved
updated: 2026-11-11
language: en
tags:
  - anti-reverse
  - spec/uiux
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[OPERATION]]"
  - "[[QASUITE]]"
  - "[[MEMORY]]"
---

# Airverse — UI and UX

The design of the Console, the developer experience of the SDKs and CLI, and the rules every screen must pass. This file is the **design-system master**: page-level decisions may override it only by recording the override here. Users and their needs are in [PRD.md §4](PRD.md); performance budgets in [PERFORMANCE.md](PERFORMANCE.md); checks in [QASUITE.md §13](QASUITE.md).

---

## 1. Design intent

Airverse is used in two moods: **calm** (setting up, reviewing trends, tuning rules) and **urgent** (an alert at 02:00). The interface serves both by being quiet until something needs a decision, then making that decision obvious and reversible.

| # | Principle | In practice |
|---|---|---|
| 1 | **Evidence first** | Every number, block and score opens the reason behind it in one click |
| 2 | **Calm by default** | Colour and motion are reserved for things that need attention; no scare copy |
| 3 | **Safe to act** | Monitor before enforce, blast radius shown before confirming, undo always visible |
| 4 | **Dense, not crowded** | Analysts get information density; hierarchy and alignment keep it scannable |
| 5 | **One vocabulary** | The same words for severity, decisions and posture everywhere (§10) |
| 6 | **Fast feels safe** | Budgets PB-19 and PB-20; pages arrive complete and layout never shifts (§11); live data never jumps under the cursor |
| 7 | **Everyone can operate it** | WCAG 2.2 AA; keyboard for every action; status never by colour alone |
| 8 | **Honest about limits** | Scores carry their scope; AI output is labeled; unknown is shown as unknown |

## 2. Usage contexts

| Context | Device and setting | Design consequence |
|---|---|---|
| Setup and tuning | Desktop, focused, daytime | Wide layouts, side-by-side editor and simulation |
| Monitoring | Large or secondary screen, glanceable, long sessions | Dark theme, stable layout, restrained motion |
| Incident triage | Laptop or phone, interrupted, tired | Few choices, large targets, containment first |
| Reporting | Shared screen or print | Light print stylesheet, executive summary, sourced numbers |

## 3. Design-system decision

Derived from the reasoning tables of the UI/UX reference in PRD §19 for the product type *Cybersecurity Platform* — its product, reasoning, colour, typography, style, chart and UX-guideline data were read directly; its search script was not run.

```text
PATTERN      Console:   Real-Time Monitoring + Heat Map
             Marketing: Trust & Authority + Real-Time
STYLE        Dark Mode (OLED) as the base
             Data-Dense Dashboard for analyst screens
             Executive Dashboard for reports
             Drill-Down Analytics for navigation (overview → incident → event)
COLOUR       Signal green + deep black + alert red, terminal feel
TYPOGRAPHY   Technical and clear: IBM Plex Sans (interface) + JetBrains Mono (data)
EFFECTS      Threat visualisation; restrained alert animation; one live indicator
MUST HAVE    Real-time monitoring; threat display
AVOID        Light mode as default; weak data visualisation; decorative effects;
             colour as the only carrier of status
DIALS        Variance 3 (calm) · Motion 3 (subtle) · Density 8 (dashboard)
```

**Deliberate deviations from the reference's first recommendation, with reasons:**

| Reference suggests | We do | Why |
|---|---|---|
| *Cyberpunk UI* as the primary style | Keep its palette, drop its effects (glitch, scan lines, heavy neon glow) | The same reference lists that style as unsuitable for corporate and enterprise products; our buyers include security teams answering to auditors. Effects also cost performance and accessibility |
| An all-monospace type pairing for security tools | Monospace for data only; a sans for interface text | People read this interface for hours; long text in monospace slows scanning |
| Pure neon green for large areas | Green is a **signal**: live state, protected posture, primary action, focus. Never wall paint; since 2026-11-11 a calmer `#33CC66` (60 % saturation) instead of `#00FF41` | Saturated green at scale is fatiguing and drains meaning from the "all good" signal |
| IBM Plex Sans + JetBrains Mono | Geist + Geist Mono, by the design skill below | One family pair for the whole interface, self-hosted through `next/font` |

### Design skill

**Owner decision 2026-11-11:** the Console follows the design skill *elayadesign/ai-design-skills* (MIT), adopted faithfully with the carve-outs below (Jev: faithful with carve-outs, confidence 0.81). Its landing-page parts (hero, marketing sections) do not apply to the Console; §15 keeps its own pattern.

| The skill asks | In the Console |
|---|---|
| Geist for the interface, Geist Mono only where monospace is needed | Geist Mono for identifiers, keys, hashes, CIDRs, routes, code and numeric data; labels and table headers are Geist (§4.3) |
| Tailwind type scale only, named text styles defined once | `heading-*`, `title-*`, `body-*`, `button-*`, `caption-*`, `code-*` in `globals.css`; components use nothing else (§4.3) |
| Spacing scale 0 · 2 · 4 · 8 · 12 · 16 · 24 · 32 · 40 · 48 · 64 · 80 · 96 px | Every padding, margin, gap, offset and control size; widths over 96 px are layout measures, not spacing (§4.4) |
| Flat surfaces from a fixed dark set; no gradients; no single-side borders on cards | §4.1. Table row dividers, tab indicators and the top-bar divider are dividers, not card borders: 1 px full-width lines (2 px under the current tab) |
| One accent below 80 % saturation | `--primary` `#33CC66`, hue 140 (§4.1) |
| Phosphor icons, one weight | Bold weight, path data inlined in `src/components/icons.tsx` with its MIT notice; no icon dependency (§4.2) |
| Base curve, 300 ms colour and opacity, 500 ms layout, nothing under 200 ms | §4.4 |
| Every interactive state; composed empty states; skeletons while loading | All states (§11, §14). **Carve-out:** no skeleton pages and no `loading.tsx` — pages are server-rendered complete so session guards can answer with a real 307; a skeleton only where data loads in the browser |
| Sentence case, calm copy, no hyphens in prose | §10. **Carve-out:** hyphens stay inside identifiers, codes, keys, ids, rule keys, CIDRs, dates, route patterns and data |

`apps/console/test/design-system.test.ts` checks the token sheet (surfaces, accent, every contrast pair of §4.1–§4.2, motion durations) and the source (spacing steps, named text styles only); `test/t.test.ts` checks the catalog for hyphenated prose words, exclamation marks and banned filler.

## 4. Design tokens

Two layers: core values on `:root`, then semantic role utilities (`bg-surface`, `text-fg-muted`, …). Components use the role utilities only; raw hex values never appear in component code, and Tailwind's default palette is removed. Contrast ratios below were computed with the WCAG relative-luminance formula, in the order `--bg` / `--surface` / `--surface-raised` / `--muted`, and are recomputed by the design-system test on every run.

### 4.1 Colour — core

Dark surfaces come only from the skill's set: `#000000`, `#181818`, `#1F1F1F`, `#272727`, `#313131`, `#131209` (the last one unused).

| Token | Value (was) | Use | Contrast |
|---|---|---|---|
| `--bg` | `#000000` (same) | Application background | — |
| `--surface` | `#181818` (`#0C130E`) | Cards, panels | — |
| `--surface-raised` | `#1F1F1F` (`#121A14`) | Popovers, drawers, confirmation steps | — |
| `--muted` | `#272727` (`#181818`) | Table stripes, inset areas, hover fills | — |
| `--border` | `#313131` (`#1F1F1F`) | Decorative separators only | 1.6 / 1.4 / 1.3 / 1.1 : 1 (not for meaning) |
| `--border-strong` | `#6B7280` (same) | Input and control boundaries | 4.3 / 3.7 / 3.4 / 3.1 : 1 |
| `--fg` | `#E0E0E0` (same) | Primary text | 15.9 / 13.5 / 12.5 / 11.3 : 1 |
| `--fg-muted` | `#94A3B8` (same) | Secondary text | 8.2 / 6.9 / 6.4 / 5.8 : 1 |
| `--fg-subtle` | `#8A95A3` (`#7B8794`) | Tertiary text, timestamps | 6.9 / 5.8 / 5.4 / 4.9 : 1 |
| `--primary` | `#33CC66` (`#00FF41`) | The one accent: primary action, live, protected | 10.0 / 8.4 / 7.8 / 7.1 : 1 — hsl(140, 60 %, 50 %) |
| `--brand` | `#C7FA62` (new) | The trace in the brand mark only, the lime of the landing page; never an action, a state or text | 17.3 : 1 on `--bg`; decorative |
| `--on-primary` | `#000000` (`#0F172A`) | Text on primary fills | 10.0 : 1 on `--primary` |
| `--link` | `#7CC4FF` (same) | Links (always underlined) | 11.2 / 9.5 / 8.8 / 8.0 : 1 |
| `--ring` | `--primary` | Focus ring, 2 px with 2 px offset | 10.0 / 8.4 / 7.8 / 7.1 : 1 |
| `--destructive` | `#EF4444` (same) | Destructive fills, with black text | 5.6 : 1 with `--on-destructive` `#000000` (white text fails at 3.8 : 1 — never use it) |

**Why `#33CC66`:** the skill allows one accent below 80 % saturation. Hue 140 keeps the "signal green" of §3; 60 % saturation at 50 % lightness is the calmest green that still reads as a signal next to the severity colours, keeps text contrast at 7.1 : 1 or more on every surface (4.5 : 1 needed) and the focus ring far above 3 : 1, and takes black text at 10.0 : 1.

### 4.2 Colour — meaning

Each meaning has a colour **and** an icon **and** a word. Icons are Phosphor, bold weight, 16 px, coloured by the text token, hidden from assistive technology because the word next to them carries the meaning; each scale uses distinct silhouettes so it reads in greyscale. Badges use the colour at 16 % over the surface with coloured text; badge contrast is given over `--bg` / `--surface` / `--surface-raised` (badges never sit on `--muted`).

| Scale | Token | Value | Icon (Phosphor) | Text contrast on surfaces | Badge text contrast |
|---|---|---|---|---|---|
| Severity | `--sev-critical` | `#FF3333` fill · `#FF6B6B` text (`--sev-critical-text`) | WarningOctagon | 7.6 / 6.4 / 5.9 / 5.4 : 1 | 6.4 / 5.1 / 4.7 : 1 |
| | `--sev-high` | `#FF8A1F` | Warning (triangle) | 8.9 / 7.5 / 7.0 / 6.3 : 1 | 7.4 / 5.8 / 5.3 : 1 |
| | `--sev-medium` | `#FFC53D` | WarningCircle | 13.3 / 11.3 / 10.4 / 9.5 : 1 | 10.2 / 7.8 / 7.1 : 1 |
| | `--sev-low` | `#4DA3FF` | Info | 8.0 / 6.8 / 6.3 / 5.7 : 1 | 6.7 / 5.3 / 4.8 : 1 |
| | `--sev-info` | `#94A3B8` | Circle (empty) | 8.2 / 6.9 / 6.4 / 5.8 : 1 | 6.8 / 5.3 / 4.9 : 1 |
| Decision | `--dec-allow` | `--fg-muted` | Check | as `--fg-muted` | 6.8 / 5.3 / 4.9 : 1 |
| | `--dec-monitor` | `--sev-low` | Eye, **dashed** outline | as `--sev-low` | as `--sev-low` |
| | `--dec-challenge` | `--sev-medium` | SealQuestion | as `--sev-medium` | as `--sev-medium` |
| | `--dec-throttle` | `--sev-high` | HourglassMedium | as `--sev-high` | as `--sev-high` |
| | `--dec-block` | `--sev-critical-text` | Prohibit | as `--sev-critical-text` | as `--sev-critical-text` |
| | `--dec-deceive` | `#C084FC` | MaskHappy | 7.9 / 6.7 / 6.2 / 5.7 : 1 | 6.6 / 5.2 / 4.8 : 1 |
| Block status | — | `--fg`, `--fg-subtle`, `--fg-muted` | Lock (active, solid) · Clock (expired, dotted) · LockOpen (lifted, dashed) | as the text tokens | — |
| Waiting, empty | — | `--fg-subtle` | CircleDashed | as `--fg-subtle` | — |
| Posture | `--pos-protected` | `--primary` | ShieldCheck | as `--primary` | 8.1 / 6.3 / 5.8 : 1 |
| | `--pos-learning` | `--sev-low` | ShieldChevron | — | — |
| | `--pos-exposed` | `--sev-critical` | ShieldWarning | — | — |
| | `--pos-unknown` | `--fg-subtle` | Shield (outline) | — | — |

Posture icons are inlined into the icons module when the first posture screen is built. Rules: *blocked* is drawn in red because it marks hostile traffic, while **posture** carries the reassurance — a screen full of red blocks under a green "Protected" header is the intended reading. A rule in **monitor** mode is always dashed or hollow; **enforce** is always solid.

### 4.3 Typography

**Families:** Geist for the interface; Geist Mono only where monospace is functionally needed — identifiers, keys, hashes, CIDRs, routes, code and numeric data (tabular figures). Both are self-hosted through `next/font` with metric-matched fallbacks, so text does not shift when fonts load. Upright only: no italics anywhere. Weights 400, 500 and 600; never bolder than 700.

**Named text styles** are defined once in `globals.css` as utilities and are the only way a component sets type; sizes come from the Tailwind type scale (off-scale sizes snap down). Headings balance their lines (`text-wrap: balance`), body text uses `text-wrap: pretty`. Minimum 12 px.

| Style | Family | Size / line height | Weight | Was (role) |
|---|---|---|---|---|
| `heading-1` | Geist | 30 / 36 | 600 | — |
| `heading-2` | Geist | 24 / 32 | 600 | Page title (24 / 32) |
| `heading-3` | Geist | 20 / 28 | 600 | — |
| `heading-4` | Geist | 18 / 28 | 600 | Section title (18 / 28) |
| `heading-5` | Geist | 16 / 24 | 600 | Sub-section title |
| `heading-6` | Geist | 14 / 20 | 600 | Brand, current tab, confirmation question |
| `title-1` … `title-5` | Geist | 20 / 28 · 18 / 28 · 16 / 24 · 14 / 20 · 12 / 16 | 500 | `title-4`: field labels, other tabs |
| `body-1` … `body-3` | Geist | 20 / 28 · 18 / 28 · 16 / 24 | 400 | `body-3`: body on touch layouts (16 / 24) |
| `body-4` | Geist | 14 / 20 | 400 | Body (14 / 22, snapped to the scale) |
| `body-5` | Geist | 12 / 16 | 400 | Dense table, help and notes (13 / 20, snapped down) |
| `button-md` · `button-sm` | Geist | 14 / 20 · 12 / 16 | 600 | Buttons |
| `caption-1` · `caption-2` | Geist | 12 / 16 | 500 · 400 | Label, eyebrow, table header, tags (was mono caps 12 / 16; now sentence case, no tracking) |
| `code-1` | Geist Mono | 16 / 24, tabular | 400 | Identifier fields on touch layouts |
| `code-2` | Geist Mono | 14 / 20, tabular | 400 | Identifier fields: keys, CIDRs, path patterns |
| `code-3` | Geist Mono | 12 / 16, tabular | 400 | Data, identifiers, code (13 / 20, snapped down) |

Key figures (32–48 px) use `heading-1` until a screen needs them; a figure style is added here first.

### 4.4 Space, shape, depth, motion

| Token group | Values |
|---|---|
| Spacing | 0 · 2 · 4 · 8 · 12 · 16 · 24 · 32 · 40 · 48 · 64 · 80 · 96 px, nothing else — padding, margin, gap, offsets and control sizes |
| Layout | Sidebar 240 px · top bar 48 px · context bar 48 px · grid gap 8 px · card padding 12 px · table row 40 px · page gutter 16 px · section gap 24 px |
| Control height | Buttons and fields: 8 px vertical and 12 px horizontal padding around a 20 px line plus the border (38 px) on pointer layouts; 48 px on touch layouts; tabs and segments 32 px; never under a 24 × 24 px target |
| Radius | Tailwind values only: 4 px controls (`sm`) · 6 px cards (`md`) · full for status dots. Nested radius = outer − gap when the gap is under 32 px and the result is over 2 px; with today's 12 px card padding no nested radius applies |
| Surfaces | Flat fills; no gradients; borders all around a card or none. Dividers (table rows, tab rail, top bar) are 1 px full-width lines |
| Depth | Borders and surface steps instead of shadows; one overlay scrim |
| Layering | 10 sticky · 20 dropdown · 30 drawer · 50 modal · 60 toast |
| Motion | Base curve `cubic-bezier(0.22, 1, 0.36, 1)` (`--ease-base`); 300 ms for colour and opacity, such as hover (`--motion-hover`); 500 ms for layout and position (`--motion-layout`); nothing under 200 ms; only transform and opacity animate |
| Press feedback | Every button, tab and segment settles to `scale(0.98)` while pressed (`press` utility); hover changes opacity over 300 ms |
| Reduced motion | Only opacity changes: no scale, no movement; durations stay as they are |
| Live indicator | 2 s soft pulse on the base curve; static dot with the word "Live" under reduced motion |
| Alert | New Critical item pulses three cycles, then rests |

At most two animated elements per view. Every animation is cancellable and never required for state to be correct.

## 5. Information architecture

```text
Top bar     Organization ▾ · App ▾ · Environment tag · Search / command palette · Safe-mode state · Notifications · Account
Sidebar     Overview
            Live
            Incidents
            Apps ── Builds · Policies · Surfaces
            Prove ── Campaigns · Findings · Targets
            Reports
            Integrations
            Settings ── Organization · Members · Access · Billing and usage · Data controls · Audit log
```

- The **Environment tag** is always visible and colour-coded; production actions say "production" in the confirmation.
- Every list is deep-linkable with its filters; browser back always works.
- Breadcrumbs appear from the second level; drill-down keeps the time range and filters.
- Command palette (`Ctrl/⌘ K`) reaches every screen and action. Shortcuts: `g o` Overview, `g l` Live, `g i` Incidents, `j` / `k` move, `e` open evidence, `?` help.

## 6. Key journeys

| # | Journey | Steps | Success measure |
|---|---|---|---|
| J1 | First protection | Sign up → create App → copy Shield snippet → first event appears → add Guard → add Harden to CI | ≤ 15 min to first protected request |
| J2 | From learning to enforcing | Review "would have blocked" → simulate → promote at 10 % → watch → 100 % | No false-positive rollback |
| J3 | Triage at night | Alert → Incident → read summary and evidence → contain Actor for 1 h → note → back to sleep | ≤ 3 interactions from alert to containment |
| J4 | Fix a weak Build | CI gate fails → Build page → Objective achieved at T1 → evidence → fix suggestion → rebuild → score recovers | Developer needs no security expert |
| J5 | Authorized test | Verify target → sign Rules of Engagement → schedule Campaign → review Findings → retest | No test without verified ownership |
| J6 | Prove it to others | Reports → pick period and framework → export | Shareable in under 2 minutes |

## 7. Screens

| ID | Screen | Primary job | Key elements |
|---|---|---|---|
| SCR-01 | Onboarding | Reach first protected request | Three-step checklist, framework picker, copyable snippets, live "waiting for first event" state |
| SCR-02 | Overview | Is everything all right? | Posture line, four key figures, live traffic chart, needs-attention list, techniques, hour × day heat map |
| SCR-03 | Live | What is happening now? | Virtualised event stream, pause on scroll, filters, evidence drawer |
| SCR-04 | Incidents | What needs me? | List newest first by last seen with severity on every row (word + icon), status, assignee, saved filters |
| SCR-05 | Incident detail | Understand and contain | Summary, timeline, Actor card, evidence, containment actions, notes |
| SCR-06 | App detail | Posture per Surface and Environment | Surface cards, SDK versions, enforcement coverage |
| SCR-07 | Build detail | How resistant is this Build? | RRS with threshold, Objective rows with evidence, protection report, compare with previous |
| SCR-08 | Policies | Change behaviour safely | Rule list with mode and rollout, editor, simulation, history, rollback |
| SCR-09 | Campaigns and Targets | Run authorized tests | Target verification state, Rules of Engagement, schedule, live status, kill switch |
| SCR-10 | Findings | Fix weaknesses | Severity, status, reproduction, fix suggestion, retest |
| SCR-11 | Reports | Show the trend | Executive summary, framework mapping, export |
| SCR-12 | Integrations | Connect tools | Alert channels, webhooks, API keys |
| SCR-13 | Settings | Govern | Members and roles, access, billing and usage, data controls, audit log |

**SCR-02 Overview**

```text
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│ Airverse   Acme ▾   shop-web ▾   [PRODUCTION]      Search  Ctrl K     ● Live    (2)   NS │
├───────────┬────────────────────────────────────────────────────────────────────────────────┤
│ Overview  │ ● PROTECTED · 12 of 15 rules enforced · RRS 78 (+4) · SDKs current               │
│ Live      │ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐              │
│ Incidents │ │ REQUESTS 24H │ │ BLOCKED      │ │ CHALLENGED   │ │ OPEN         │              │
│ Apps      │ │ 4.82M        │ │ 12,904 0.27% │ │ 3,118        │ │ 2 high 5 med │              │
│ Prove     │ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘              │
│ Reports   │ ┌─ TRAFFIC AND DECISIONS ─────────────── live ─┐ ┌─ NEEDS ATTENTION ───────────┐ │
│ Integr.   │ │ streaming area: allowed · challenged · blocked│ │ ▲ High  Credential stuffing │ │
│ Settings  │ │                                               │ │         POST /api/login     │ │
│           │ └───────────────────────────────────────────────┘ │ ▲ High  Canary used         │ │
│           │ ┌─ TOP TECHNIQUES ──────┐ ┌─ WHEN (HOUR × DAY) ──┐ │ ■ Med   Clone detected      │ │
│           │ │ horizontal bars       │ │ heat map             │ │         View all incidents  │ │
│           │ └───────────────────────┘ └──────────────────────┘ └─────────────────────────────┘ │
└───────────┴────────────────────────────────────────────────────────────────────────────────┘
```

**SCR-05 Incident detail**

```text
Incidents / INC-2041                                                    Status: Open ▾   Assign ▾
▲ HIGH   Credential stuffing against POST /api/login                    Started 02:14 · ongoing
┌─ SUMMARY (AI summary — verify against evidence) ────────┐ ┌─ CONTAIN ────────────────────────┐
│ 1,912 failed sign-ins from 3 networks in 9 minutes,     │ │ [ Block actor 1 h ]              │
│ 412 distinct accounts, no valid attestation.            │ │ [ Challenge 24 h ]  [ More ▾ ]   │
└─────────────────────────────────────────────────────────┘ │ Affects 0.4 % of last hour's     │
┌─ TIMELINE ──────────────────────────────────────────────┐ │ actors · expires automatically   │
│ 02:14 ● Detection: credential stuffing (rule managed)   │ └──────────────────────────────────┘
│ 02:15 ● Playbook: throttle applied to 3 network prefixes│ ┌─ ACTOR ──────────────────────────┐
│ 02:19 ○ 412 accounts targeted · 0 successful sign-ins   │ │ Risk 91 · automation · no Guard  │
└─────────────────────────────────────────────────────────┘ │ Top factors ▸                    │
┌─ EVIDENCE ──────────────────────────────── 1,912 events ┐ └──────────────────────────────────┘
│ time      decision    route            signals    rule  │ ┌─ NOTES ──────────────────────────┐
│ 02:23:05  Throttled   POST /api/login  webdriver  …     │ │ Add a note…                      │
└─────────────────────────────────────────────────────────┘ └──────────────────────────────────┘
```

**SCR-07 Build detail**

```text
Apps / shop-web / Builds / 1.14.0 (bld_2x8Q)                    Profile: balanced · 6 Nov 2026
RRS  78  ████████████████████▌───│──────   threshold 70   ▲ +4 vs 1.13.2        Gate: PASSED
     Scored by agent config rc-2026.11 · tiers T1+T2 · comparable only within this configuration
┌─ OBJECTIVES ──────────────────────────────────────────────────────────────────────────────┐
│ Map         weight 15   ◐ achieved at T2      Evidence ▸   Fix: move admin routes to lazy… │
│ Secrets     weight 20   ● not achieved        Evidence ▸                                   │
│ Logic       weight 25   ● not achieved        Evidence ▸                                   │
│ Tamper      weight 20   ◐ achieved at T3      Evidence ▸   Fix: raise checkout to maximum  │
│ Replay      weight 20   ● not achieved        Evidence ▸                                   │
└───────────────────────────────────────────────────────────────────────────────────────────┘
┌─ PROTECTION REPORT ───────────────┐ ┌─ COST ───────────────────┐ ┌─ MARKERS ───────────────┐
│ 214 modules · 31 at maximum       │ │ Size +28 % · Run +9 %    │ │ 6 Canaries · Watermark ✓│
└───────────────────────────────────┘ └──────────────────────────┘ └─────────────────────────┘
```

**SCR-08 Policy editor with simulation**

```text
Policies / production / Require attestation on API                    Mode: ◌ Monitor   v42 draft
┌─ RULE ─────────────────────────────────────┐ ┌─ SIMULATION · last 24 h ──────────────────────┐
│ When    attestation verdict is not trusted │ │ Would block      3,902 requests   0.08 %       │
│ On      /api/**  except /api/public/**     │ │ Actors affected  211                           │
│ Then    Block                              │ │ Known-good hit   0   ✓                         │
│ If Airverse errors   ( ) Open (•) Close│ │ Top routes ▸     Sample events ▸               │
└────────────────────────────────────────────┘ └────────────────────────────────────────────────┘
Rollout   ○ 10 %   ○ 50 %   ○ 100 %                         [ Save draft ]  [ Promote to enforce ]
History   v41 enforced 3 Nov by N. Sari ▸        Promoting affects production. Undo is one click.
```

**SCR-01 Onboarding**

```text
Set up shop-web                                                        Step 1 of 3 · about 5 min
● 1 Add Shield          ○ 2 Add Guard          ○ 3 Harden your build
Framework  [ Next.js ▾ ]
┌──────────────────────────────────────────────────────────────────────────────── Copy ┐
│ npm install @antireverse/shield-node                                                 │
│ …three lines of middleware set-up…                                                   │
└──────────────────────────────────────────────────────────────────────────────────────┘
Shield starts in monitor mode — it observes and cannot block anything yet.
◌ Waiting for the first event from shop-web…                          Having trouble? ▸
```

## 8. Components

| Component | Rules |
|---|---|
| Severity badge | Icon + word + colour; never colour alone; one size in tables |
| Decision chip | Solid for enforced outcomes; dashed and hollow for "would have" in monitor mode |
| Posture line | One sentence at the top of Overview and App detail; the only place the large shield appears |
| Key-figure card | Label in `caption-1`, figure in Geist Mono, delta with direction word; four to six per row at most |
| Live indicator | One per screen; shows connection state: Live · Reconnecting · Paused |
| Event row | Fixed columns, Geist Mono data, truncation with full value on focus and hover |
| Evidence drawer | Opens from any decision, Detection or score; shows rule, signals, policy version, Build, raw event; copy as JSON |
| Timeline | Vertical, newest last, system and human actions distinguished by marker |
| Containment bar | Primary containment action first; always states blast radius and expiry |
| Rule row | Mode, rollout, last change; reorder by drag **and** by move up/down buttons |
| Rollout control | Discrete steps; shows the current share of matching traffic |
| RRS meter | Bullet chart with threshold marker, delta, scope line beneath |
| Objective row | State icon, tier, evidence link, fix suggestion |
| Confirmation dialog | Names the object and environment, states the effect in numbers, offers undo information; destructive button uses black text on `--destructive` |
| Safe-mode banner | Persistent, full width, explains what is suspended and who enabled it |
| AI label | "AI summary — verify against evidence" on every model-written block |
| Empty state | A composed getting-started view: an icon, what will appear here and the one action that makes it appear; bordered all around |
| Toast | 5 s, polite live region, never the only record of an event |

## 9. Data visualisation

| Question | Chart | Notes |
|---|---|---|
| What is happening now? | Streaming area chart | Stacked by decision; redraws at most once per second |
| How is it trending? | Line chart | RRS per Build, incidents per week |
| Where is the spike? | Line chart with highlighted anomalies | Annotations link to Incidents |
| Which techniques dominate? | Horizontal bar chart | Up to 15 categories; a donut only for five or fewer |
| When does it happen? | Heat map, hour × day | Sequential single-hue scale with a legend |
| Where from? | Choropleth or bubble map | Always paired with a sortable table |
| How does a request become a decision? | Sankey: route → rule → decision | For policy review |
| Are we above the bar? | Bullet chart | RRS against threshold |
| How are Actors connected? | Network graph | With an adjacency list alternative |
| How do Objectives compare across Builds? | Grouped bars | Chosen over a radar chart for readability |

Rules for every chart: a title that states the finding or the question; direct labels where possible and a legend otherwise; tooltips on hover **and** focus; a data-table alternative and a one-sentence text summary; shapes or patterns in addition to colour; no dual axes; time axis in the user's zone with UTC available.

## 10. Content and voice

**Voice:** calm, precise, plain. State what happened, how much, and what can be done.

| Instead of | Write |
|---|---|
| "ATTACK DETECTED!" | "Credential stuffing on POST /api/login — 1,912 attempts blocked" |
| "Your app is vulnerable" | "Map objective achieved at tier T2 — 14 routes recovered" |
| "Error occurred" | "Could not publish the policy: rule 4 references a list that was deleted" |
| "Are you sure?" | "Promote to enforce in production? About 0.08 % of yesterday's requests would be blocked" |
| "Unhackable", "military-grade" | Never |

**Copy rules:** sentence case for headings and buttons (glossary terms keep their capital); calm and specific; no exclamation marks; never an invented number; none of the filler words *revolutionize, supercharge, cutting edge, effortless, transform your workflow, take it to the next level, harness the power, world class*. No hyphenated words in prose ("never block list", "sign in attempts"); hyphens stay inside identifiers, codes, keys, ids, rule keys, CIDRs, dates, route patterns and data (`SHA-256`, `AR-Signature`, `--register`).

**Fixed vocabulary**

| Scale | Words |
|---|---|
| Severity | Critical · High · Medium · Low · Info |
| Decision | Allowed · Monitored · Challenged · Throttled · Blocked · Deceived |
| Posture | Protected · Learning · Exposed · Unknown |
| Rule mode | Monitor · Enforce |
| Finding status | New · Unverified · Confirmed · Fixed · Retest passed · Accepted risk |

**Language and locale.** English is the default. All strings live in message catalogs with plural and gender rules; no text is baked into images; layouts tolerate 35 % longer strings; dates and numbers follow the locale, with a UTC toggle for analysts. Bahasa Indonesia is the proposed second locale. Layout uses logical properties so a right-to-left locale needs no rework.

## 11. States

| State | Behaviour |
|---|---|
| Loading | Pages are server-rendered complete: no skeleton pages and no `loading.tsx`, so a session guard can answer with a real 307. A skeleton with final dimensions only where data loads in the browser; no spinner-only screens; buttons show progress and disable while pending |
| Empty, first run | A getting-started view: icon, what will appear and the step that produces it |
| Empty, filtered | States the filters and offers to clear them |
| Error | Says what failed, why, and what to do; inline next to the cause; never silent |
| Partial data | Labels the missing part ("events delayed 3 min") rather than showing stale data as current |
| Disconnected | Live indicator switches to Reconnecting; last-updated time shown |
| No permission | Explains which role is needed; no dead buttons |
| Inconclusive | An Assessment without a score says why; never shows a number |
| Safe mode | Banner plus dashed decision chips everywhere |

## 12. Accessibility

- **Target:** WCAG 2.2 AA.
- **Contrast:** text ≥ 4.5 : 1, large text and control boundaries ≥ 3 : 1 — verified per token pair in §4.
- **Colour independence:** severity, decision, posture and block status always carry an icon and a word.
- **Keyboard:** every action reachable; visible focus ring on every control; logical order; no traps; focus is never hidden under sticky bars; shortcuts are discoverable and remappable.
- **Targets:** at least 24 × 24 px; 44 px or more on touch layouts (controls are 48 px there).
- **Dragging:** always has a button alternative.
- **Live content:** new Incidents are announced politely and batched ("3 new high-severity incidents"); the event stream itself is not a live region.
- **Motion:** honours reduced-motion; no information depends on animation.
- **Forms:** visible labels, errors below the field and linked to it, error summary that receives focus after a failed submit.
- **Charts:** table alternative and text summary (§9).
- **Zoom and reflow:** usable at 200 % text size and 320 px width without two-dimensional scrolling, tables excepted.
- **Icons:** Phosphor vector icons (bold weight); an icon-only control has an accessible name; icons next to a word are hidden from assistive technology; no emoji as icons.

## 13. Responsive behaviour

| Width | Layout | Scope |
|---|---|---|
| ≥ 1440 px | Sidebar + main + optional evidence drawer side by side | Everything |
| 1024–1439 px | Sidebar collapsible; drawer overlays | Everything |
| 768–1023 px | Icon sidebar; single column with stacked cards | Everything; editors simplified |
| 375–767 px | Bottom navigation with five items: Overview, Live, Incidents, Prove, More | Triage complete: Overview, Incidents, Incident detail, containment, safe mode. Policy editing is view-only with a prompt to continue on a larger screen |

No horizontal page scroll at any width. Tables scroll inside their container with a sticky first column.

**Themes.** Dark is the default and the only interactive theme in MVP. Reports, exports and print use a light print stylesheet. A high-contrast variant follows the system preference.

## 14. Pre-delivery checklist

Every new screen passes this list before merge (QASUITE.md gate G2).

**Visual and tokens**
- [ ] Only semantic tokens; no raw colour values in components.
- [ ] Monitor vs enforce is distinguishable in greyscale.
- [ ] Phosphor icons only, bold weight, 16 px beside text; colour from tokens.
- [ ] Named text styles only; spacing on the scale of §4.4; Geist Mono only for identifiers and data.
- [ ] Flat surfaces; no gradients; no single-side borders on cards.
- [ ] Layout holds with 35 % longer text and with long unbroken identifiers.

**Interaction**
- [ ] Every control has hover, focus, active, disabled or pending, and error states.
- [ ] Destructive or wide-impact actions confirm with the effect stated in numbers.
- [ ] Nothing important is hover-only.
- [ ] Back, deep links and filters in the address all work.

**Feedback and states**
- [ ] Loading, empty, error, partial, disconnected and no-permission states designed.
- [ ] No layout shift when data arrives.
- [ ] Errors say what, why and what next.

**Accessibility**
- [ ] Contrast verified; focus visible; keyboard-complete; names on icon buttons.
- [ ] Reduced motion respected (opacity only); nothing under 200 ms; at most two animated elements.
- [ ] Charts have a table alternative and a text summary.
- [ ] Target sizes met at every breakpoint.

**Content**
- [ ] Fixed vocabulary used; no scare copy; numbers have units; sentence case; no hyphenated prose words.
- [ ] AI-written content is labeled.
- [ ] Strings are in the catalog; nothing concatenated.

**Performance**
- [ ] Route meets PB-19 and PB-20 in the lab check.
- [ ] Long lists are virtualised; live updates are batched.

## 15. Marketing site and documentation

- **Pattern:** Trust & Authority + Real-Time. Sections: what it protects, the closed loop, a real Build's RRS evidence, how the rollout stays safe, security and privacy facts, pricing, documentation.
- **Proof, not adjectives.** Only real, sourced figures; demo data is labeled as demo; limits are stated (SECURITY.md §2).
- **Same tokens** as the Console, with more space and larger type.
- **Documentation** is task-first: quickstart per framework, then concepts, then reference. Every page has a copyable example and names the plan and role it needs.

## 16. Developer experience

The CLI, SDKs and error messages are interfaces too.

| Surface | Rules |
|---|---|
| CLI output | Short by default; `--json` for machines; colour optional and off when not a terminal; documented exit codes; never prints secrets |
| CLI errors | Cause, fix and a documentation link in three lines |
| SDK set-up | Three lines to a working monitor-mode install; safe defaults; one obvious way to turn it off |
| SDK logs | Quiet at default level; one line when a bundle loads, when fail-open triggers and when the cloud is unreachable |
| Build report | States what was protected and what it cost in size and speed |

```text
$ antireverse harden ./dist --profile balanced
✓ 214 modules protected (31 at maximum)      size +28 %   run +9 %
✓ leak scan clean                            6 Canaries planted
✓ equivalence check passed (312 tests)
→ Build bld_2x8Q registered · assessment queued · https://console.antireverse.example/b/bld_2x8Q
```

## 17. Open design questions

1. Product name styling: "Airverse", "AntiReverse" or "anti·reverse"; logo and mark.
2. Whether a light interactive theme is needed for a specific customer segment.
3. Map visual: choropleth vs bubble map as the default for origin data.
4. How much of the Console the first additional locale must cover at launch.
