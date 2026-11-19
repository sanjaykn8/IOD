# UI design system (web-ui)

Status: adopted 2026-11-19 for the redesign of every route. Implementation: `web-ui/src/styles.css` (tokens and
component classes) and `web-ui/src/components/command/core.tsx` (shared primitives). No new UI framework was
added; the existing React, TanStack Router, Tailwind and Radix stack is unchanged.

The dashboard is a research tool for one operator. It should read like an instrument panel: calm, dense where
data is dense, and explicit about what is real, simulated or deferred. Every value on screen comes from the
backend; nothing is invented to fill space.

## 1. Principles

1. **Layout first.** Each page answers one question. The page header says what the page is for in one sentence;
   the primary action sits in the first section; supporting data follows; technical depth is behind a
   disclosure.
2. **One accent.** Colour follows a 60-30-10 split: 60 % neutral canvas and surfaces, 30 % secondary surfaces,
   borders and secondary text, 10 % accent (primary buttons, active navigation, focus, selected rows).
   Success, warning and danger colours are used **only** for status, never for decoration.
3. **Readable type.** Inter for the interface; JetBrains Mono only where character-level reading matters:
   identifiers, hashes, fingerprints, hex, byte counts in tables, code. Sentence case everywhere. No
   letter-spaced uppercase micro-labels.
4. **Say it once.** A drone id, a suite id or an explanation appears once per view. Role labels describe the role
   (`Initiator`, `Verifier`, `From`, `To`, `Sender`, `Receiver`) and the selected id is the value — never
   `D1 / Initiator` or `Source / D1`.
5. **Honest status.** Status badges reflect backend state. Simulated parts are labelled `Simulated`, deferred
   parts `Deferred`; nothing is shown as "online", "streaming" or "operational" unless the backend says so.

## 2. Tokens

Defined as CSS custom properties on `:root` (dark, default) and `.light-theme`; components never use raw colours.

| Token | Role | Dark | Light |
|---|---|---|---|
| `--background` | canvas (60 %) | `oklch(0.17 0.01 255)` | `oklch(0.985 0.002 255)` |
| `--card` | primary surface (60 %) | `oklch(0.205 0.012 255)` | `oklch(1 0 0)` |
| `--surface-2` | secondary surface, table headers, inputs (30 %) | `oklch(0.235 0.013 255)` | `oklch(0.965 0.004 255)` |
| `--border` | dividers (30 %) | `oklch(0.3 0.012 255)` | `oklch(0.9 0.005 255)` |
| `--foreground` | primary text | `oklch(0.96 0.004 255)` | `oklch(0.22 0.015 255)` |
| `--muted-foreground` | secondary text (≥ 4.5 : 1 on `--card`) | `oklch(0.74 0.012 255)` | `oklch(0.47 0.015 255)` |
| `--primary` | accent (10 %) | `oklch(0.72 0.12 245)` | `oklch(0.52 0.15 250)` |
| `--success` / `--warning` / `--destructive` | status only | green / amber / red | darker variants |

Spacing uses an 8-point scale (4 for tight inline gaps): `--space-1` 4 px, `--space-2` 8, `--space-3` 12,
`--space-4` 16, `--space-5` 24, `--space-6` 32, `--space-7` 48. Radius: 6 px (controls), 8 px (surfaces).
Elevation: borders, not shadows; one subtle shadow for overlays only.

### Type scale

| Use | Size / line height | Weight |
|---|---|---|
| Page title | 22 / 28 | 600 |
| Section title | 15 / 22 | 600 |
| Body, controls | 14 / 20 | 400 |
| Table cell, secondary text | 13 / 18 | 400 |
| Label, caption | 12 / 16 | 500 |
| Metric value | 26 / 32 | 600 (tabular numbers) |
| Mono (ids, hashes) | 12.5 / 18 | 400–500 |

## 3. Layout

* App shell: 240 px sidebar (64 px collapsed; off-canvas below 900 px) + a 56 px top bar + content area with a
  maximum width of 1320 px and 32 px side padding (16 px below 768 px).
* Grids: `.grid-2`, `.grid-3`, `.grid-4` collapse to fewer columns at 1200, 900 and 600 px. Forms use `.form-row`
  (fields side by side, action aligned to the field baseline).
* Verified viewports: 1440, 1024, 768 and 390 px wide (screenshots in `docs/screenshots/ui/`).

## 4. Navigation

Grouped, sentence case, one icon per entry:

```
Overview
Fleet          Drones · Groups
Protocols      Authentication · Secure communication
Analysis       Steganography lab · Knowledge base
Audit          Trace manager · Event log
System
```

The top bar shows live counts from `GET /api/state` (events, groups, drones) and the theme toggle; the page title
appears there only when the sidebar is off-canvas (below 900 px), because the page header already names the page.
A connection badge appears only when the gateway is unreachable.

## 5. Components (`core.tsx`)

| Component | Use | Rules |
|---|---|---|
| `PageHeader` | title, one-sentence description, actions | no eyebrow labels; group name appears in the navigation only |
| `Panel` | titled section | title in sentence case; `meta` for one status badge or count |
| `Metric` | one number with a label | value from the backend or `—`; optional one-line detail |
| `Status` | state badge | tone from data; sentence-case text (`Active`, `Revoked`, `Verified`) |
| `DataTable` | tabular data | sticky header, horizontal scroll inside the panel on small screens |
| `KeyValues` | definition list | label above value; mono only for ids/hashes |
| `Disclosure` | advanced/technical details | native `<details>`; closed by default; summary says what is inside |
| `Field` | form control with label and hint | label in sentence case, hint only when it adds information |
| `Notice` / `ErrorNotice` | contextual message | info / warning / danger; one per concern |
| `Empty` | empty state | says what to do next |
| `TechnicalId` | id, hash, fingerprint | mono, truncated with full value in the tooltip |
| `Flow` / `Timeline` | ordered protocol stages | compact; labels are the protocol names (M1–M8, K1–K4) |

## 6. Page patterns

| Page | Primary question | Primary content | In disclosures |
|---|---|---|---|
| Overview | Is the simulation healthy and what exists? | metrics, fleet table, groups | — |
| Drones | Which drones exist and with which keys? | provisioning forms, fleet table with suite and both fingerprints | Merkle root per drone |
| Groups | Which membership groups exist? | create form, group cards | full root hash |
| Authentication | Did M1–M8 succeed between two drones? | Initiator → Verifier selector, decision, compact M1–M8 timeline | per-check evidence, event details |
| Secure communication | Can two drones exchange an encrypted message? | From → To, K1–K3 key establishment, message round trip | transport details |
| Steganography lab | How was a message carried in an image? | send/preview, result, patch overlay | generation diagnostics, per-patch retrieval, bootstrap, timings |
| Knowledge base | Why is an algorithm chosen? | entries, risk table, policy | evidence notes, BM25 statistics |
| Trace manager | Who requested an identity trace and why? | flag and request forms, audit tables | — |
| Event log | What happened, in order? | filters, event stream | — |
| System | What is the active configuration? | suite, sizes, conformance, PUF status, policy, services, reset | library details |

## 7. Accessibility

Text contrast ≥ 4.5 : 1 in both themes, visible focus ring (2 px accent), targets ≥ 36 px, tables are
labelled regions, status is never conveyed by colour alone (badge text), `prefers-reduced-motion` disables
transitions.

## 8. Things that are not allowed

* Uppercase letter-spaced labels, decorative grid backgrounds, glows, or gradients behind content.
* Duplicated aliases (`D1 / Initiator`, `Source / D1`), repeated explanations, or a second description under
  the page description.
* Placeholder or decorative status (`Event bus standby`, `Research mode`), invented numbers, or a badge that is
  not derived from data.
* Mono for prose or labels.
