# GUI Design — Case File Theme

A redesign spec for the four-tab web UI (`frontend/`), written for whoever implements it. It
replaces the default daisyUI look with a **case-file / verification-dossier** aesthetic: this is a
forensic instrument that stamps a verdict, not a SaaS dashboard. See `.impeccable.md` for the
audience and tone this design answers to.

Anti-goal, stated once so no one re-introduces it during implementation: no neon cyan-on-black
hacker-terminal look, no Matrix rain, no glitch text, no glowing borders. The subject matter is
steganography; the *tone* is an official report, not a thriller.

## 1. Typographic system

Three faces, each with one job. Do not use any of them outside that job.

| Face | Job | Where |
| --- | --- | --- |
| **Big Shoulders Condensed** (700/900) | Stamped labels: tab names, verdict word, section headers, the app title | Never for body paragraphs or data |
| **Public Sans** (400/500/600) | All prose: instructions, help text, form labels, buttons | The default face for everything not covered by the other two |
| **Martian Mono** (400/500) | Byte-level exhibit data only: hashes, hex dumps, start offsets, nonces, signatures, bit counts | Never for prose, never for decoration |

Load via Google Fonts (`@import` in `index.css`, weights above only — don't pull the full family).

Fixed `rem` scale (app UI, not marketing — no fluid `clamp()` here):

| Token | Size | Line-height | Use |
| --- | --- | --- | --- |
| `--text-stamp` | 2.25rem | 1.0 | Verdict word ("AUTHENTIC", "TAMPERED") |
| `--text-h1` | 1.5rem | 1.15 | Tab/page title |
| `--text-h2` | 1.125rem | 1.25 | Section header ("EXHIBIT · PAYLOAD", "STEP 2 — START LOCATION") |
| `--text-body` | 0.9375rem | 1.5 | Prose, form labels, buttons |
| `--text-small` | 0.8125rem | 1.4 | Captions, hints, timestamps |
| `--text-mono` | 0.8125rem | 1.6 | Hash/hex/offset exhibit data (tabular, `font-variant-numeric: tabular-nums`) |

Ratio between steps is ≥1.2×; five sizes total, used consistently. Headings use Big Shoulders in
uppercase with `letter-spacing: 0.02em` (condensed faces need slight opening at small sizes, not
tight tracking). Body text is sentence case — reserve caps for the stamped labels.

## 2. Color system (OKLCH)

Dark, ink/slate base tinted toward a cold blue-slate hue (`h ≈ 250`), not pure black. One signal
accent for primary actions. Each verdict gets its own coded hue so it reads by color alone.

```css
:root {
  /* ink/slate neutrals, tinted h≈250 */
  --ink-950: oklch(0.16 0.014 250);   /* page background */
  --ink-900: oklch(0.20 0.016 250);   /* section surface */
  --ink-850: oklch(0.25 0.018 250);   /* raised surface (inputs, exhibit blocks) */
  --ink-700: oklch(0.36 0.018 250);   /* borders, dividers */
  --ink-500: oklch(0.55 0.014 250);   /* muted text */
  --ink-200: oklch(0.88 0.008 250);   /* body text on dark */
  --ink-50:  oklch(0.97 0.004 250);   /* high-emphasis text */

  /* signal accent — stamp-ink amber, used sparingly (primary actions, active tab) */
  --signal-500: oklch(0.72 0.16 55);
  --signal-400: oklch(0.80 0.14 55);
  --signal-950: oklch(0.24 0.05 55);  /* accent-tinted surface, e.g. active tab bg */

  /* verdict semantics */
  --verdict-authentic: oklch(0.72 0.15 150);   /* green */
  --verdict-tampered:  oklch(0.63 0.19 25);    /* red */
  --verdict-siginvalid:oklch(0.63 0.19 25);    /* red — same family as tampered, distinguished by label */
  --verdict-missing:   oklch(0.78 0.15 80);    /* amber */
  --verdict-wrongstart:oklch(0.78 0.15 80);    /* amber */
  --verdict-cannot:    oklch(0.60 0.01 250);   /* neutral gray */
}
```

Rules:
- Neutrals are the 60%, `--ink-700` borders/dividers are the 30%, `--signal-500` is the 10% —
  and it only appears on primary buttons, the active tab underline, and focus rings. It does not
  decorate headings or icons.
- Verdict colors are used as **solid fills on the stamp**, not as text-on-dark accents alone —
  see §4. Never render verdict text in gray with a colored dot; the word itself is filled.
- No gradients anywhere, including text. No `box-shadow` glow effects.
- Light-mode is out of scope for this pass (dark-only tool per `.impeccable.md`); if a light
  variant is ever needed, invert `--ink-*` and reduce chroma on the verdict hues by ~30%.

## 3. Layout shell

Replace the daisyUI `tabs` component with a **case-file folder-tab** header:

```
┌─────────────────────────────────────────────────────────────┐
│  STEGO/CASE          01 PROTECT  02 VERIFY  03 KEYS  04 ATTACK │  ← Big Shoulders, uppercase
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   (page content, max-width 72rem, left-aligned, not centered) │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

- Tabs are numbered (`01`–`04`) like case-file section dividers, not rounded pills. Active tab:
  `--signal-500` bottom border (2px) + `--ink-50` text; inactive: `--ink-500` text, no border.
  No background pill, no rounded-full active state.
- Page content is **left-aligned**, not centered — a report reads left-to-right from a fixed
  margin, not floating in the middle of the viewport. Max content width `72rem` with a left
  gutter of `--space-2xl` (see §6), so it doesn't sprawl on wide monitors during the demo.
- No outer "card" wrapping the whole page. Sections are separated by a `--ink-700` 1px rule and
  vertical spacing, not by nested bordered boxes.

## 4. The verdict stamp (replaces `VerdictBadge`)

This is the single most important visual moment in the app — the thing a marker looks for. Design
it as a **stamp**, not a badge chip.

```
┌───────────────────────┐
│  ▣ AUTHENTIC          │   Big Shoulders 900, --text-stamp, uppercase
│  hash + signature      │   Public Sans, --text-small, --ink-500
│  match. Verified       │
│  2026-09-12 14:02:31   │   Martian Mono, --text-small (the timestamp only)
└───────────────────────┘
```

- Rendered as a filled rectangle in the verdict's semantic color at ~15% opacity background
  (`color-mix(in oklch, var(--verdict-authentic) 15%, var(--ink-900))`) with **solid** (100%)
  verdict-color text and a 1px border in the same solid color. No left-border stripe — the whole
  block is tinted, so the color reads as a stamp, not a sidebar accent.
- The glyph before the word (▣ / ✕ / ⚠ / ?) is a single fixed Unicode/SVG glyph per verdict,
  never an illustrative icon set — keep it typographic, consistent with the stamp metaphor.
- Below the stamp: one sentence of plain-language explanation (Public Sans), then the supporting
  exhibit data (media hash, signature status, timestamp) in the monospace exhibit block from §5.
- Six verdicts, six fixed copy strings (see `docs/design/verdict-table.md` for the trigger logic
  this must match exactly):

  | Verdict | Glyph | Sentence |
  | --- | --- | --- |
  | Authentic | ▣ | "Hash and signature match. Nothing has changed since protection." |
  | Tampered | ✕ | "Signature is valid, but the media no longer matches its recorded hash." |
  | Signature Invalid | ✕ | "Payload found, but the signature does not verify against this public key." |
  | Payload Missing | ∅ | "No embedded payload found anywhere in this file." |
  | Wrong Start Location | ⌖ | "A payload exists, but not at the location this key/offset derives." |
  | Cannot Verify | ? | "This file or key could not be processed — see the detail below." |

## 5. Exhibit data blocks (hashes, hex, offsets)

Any byte-level value gets rendered the same way everywhere in the app — a labeled, monospace,
tabular block, styled like an evidence tag, not an inline `<code>` snippet:

```css
.exhibit {
  background: var(--ink-850);
  border: 1px solid var(--ink-700);
  border-radius: 2px;           /* sharp, document-like — not the soft 8-12px card radius elsewhere */
  padding: var(--space-sm) var(--space-md);
  font-family: "Martian Mono", monospace;
  font-size: var(--text-mono);
  color: var(--ink-50);
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.01em;
}
.exhibit__label {
  font-family: "Public Sans", sans-serif;
  font-size: var(--text-small);
  color: var(--ink-500);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: var(--space-xs);
}
```

A label ("MEDIA HASH (SHA-256)", "START OFFSET", "SIGNATURE") always sits above the value, never
inline as `Hash: abc123` prose. Long hashes wrap with a monospace-safe `word-break: break-all`,
never truncate-with-ellipsis (a marker needs the full value to compare across screens).

This directly replaces the ad hoc "hash chip" mentioned in `TECH_STACK.md` — one `.exhibit`
component used for every hash/hex/offset display, including the `lib/hash.ts` before/after hash
shown in the Protect/Verify flow.

## 6. Spacing

4pt scale, semantic tokens, used for `gap` on flex/grid containers rather than margins:

```css
--space-2xs: 4px;  --space-xs: 8px;   --space-sm: 12px;  --space-md: 16px;
--space-lg: 24px;  --space-xl: 32px;  --space-2xl: 48px; --space-3xl: 64px;
```

Rhythm rule for this app specifically: a stamped section header (`--text-h2`) gets `--space-xl`
above it and `--space-sm` below, so sections visually separate even without borders. Form fields
within one step use `--space-sm` between them; steps within a page use `--space-lg`.

## 7. Per-tab layout

### 01 · Protect

Vertical numbered steps (reuse daisyUI's `steps` primitive for structure, restyle to match: square
step markers with Big Shoulders numerals, not circular dots):

1. **Cover object** — `FilePicker`, restyled as a drop-zone with a dashed `--ink-700` border and
   Public Sans instructions; once a file lands, show its name + size in an `.exhibit` block plus
   the pre-embed hash.
2. **Payload** — preset selector (short / large / custom-encrypted) as three toggleable segmented
   buttons (not radio circles), `PayloadPreview` below rendering by MIME as already speced in
   `TECH_STACK.md`.
3. **LSB count** — `LsbSelector` as a stepped range 1–8 with tick marks and the current value shown
   as a large Big Shoulders numeral to its right (`--text-h1`), not a tiny daisyUI thumb label.
4. **Start location** — `StartLocationPanel`: explicit-offset vs. passphrase-derived as two tabs
   within the step (not the outer nav tabs — visually subordinate, plain underline style).
5. **Capacity** — `CapacityMeter` as a horizontal bar, `--ink-700` track, `--signal-500` fill, with
   the numeric bits-used/bits-available pair in `.exhibit` mono to the right of the bar, not baked
   into the bar as text.
6. **Result** — `ImageCompare`/`AudioCompare` side by side (grid, `auto-fit minmax(280px, 1fr)` so
   it reflows to one column narrow), then `DownloadButton` as the page's one primary
   (`--signal-500` filled) button — every other button on the page is a plain text/ghost button so
   the primary action stays singular.

### 02 · Verify

Mirrors Protect's step structure (upload → key/passphrase → result), collapsing to the verdict
stamp (§4) as the final step, full-width, impossible to miss. Exhibit blocks below the stamp show:
recomputed hash, expected hash (side by side, monospace, so a mismatch is visually scannable
character-by-character), signature status, resolved start offset.

### 03 · Keys

Simplest tab: keypair generation/upload as a two-column layout (private-key controls left, public
distribution right), each key's fingerprint shown in an `.exhibit` block. A visible reminder
("private key never leaves this machine") styled as plain small-caps text, not an alert box —
this app doesn't need daisyUI `alert` banners for routine reminders, only for actual errors.

### 04 · Attack Lab

A grid of attack cards (`flip_bits`, `crop`, `lsb_scrub`, `reencode`, `corrupt_payload`, `replay`)
— this is the one place a card grid is appropriate, since each is a genuinely parallel, equal-
weight action. Each card: attack name (Public Sans, medium weight), one-line description, a plain
"Run" button. Running one attacks a copy of the current stego file and re-runs Verify inline below
the grid, showing the resulting verdict stamp and, in small Public Sans, whether it matched
`attacks.EXPECTED` — this is the team's own confirmation UI, so make the match/mismatch state
plain text, not another badge system layered on top of the verdict stamp.

## 8. Motion

Minimal, purposeful only:
- Verdict stamp entrance: 200ms opacity + `translateY(4px)→0` on result, `ease-out-quart`. This is
  the one moment worth a flourish; everything else is instant.
- Step transitions (Protect/Verify): height animated via `grid-template-rows` (0fr→1fr), not
  `height`, per the interaction reference — avoids layout jank when a step's content varies.
- No hover-triggered reveals for anything needed to operate the tool (this is used live, often via
  trackpad on a shared lab PC) — all controls are always visible, never hidden behind `:hover`.

## 9. What this replaces

| Old (default daisyUI) | New |
| --- | --- |
| Rounded `tabs` with pill active state | Numbered folder-tab header, underline active state |
| `badge` verdict chip | Full-width verdict stamp (§4) |
| Inline `<code>` / small hash chips | `.exhibit` block, used everywhere (§5) |
| `card` wrapping every section | Spacing + rules; cards reserved for Attack Lab only |
| `alert` for routine reminders | Plain small-caps text; `alert` kept only for real errors |
| Circular `steps` dots | Square Big Shoulders numeral step markers |
| Generic sans (Inter-adjacent default) | Big Shoulders (stamps) + Public Sans (body) + Martian Mono (data) |
