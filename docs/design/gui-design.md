# GUI Design — Case File Theme

A redesign spec for the five-tab web UI (`frontend/`), written for whoever implements it. It
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
| **Big Shoulders** (700/900, display optical size) | Stamped labels: tab names, verdict word, section headers, the app title | Never for body paragraphs or data |
| **Public Sans** (400/500/600) | All prose: instructions, help text, form labels, buttons | The default face for everything not covered by the other two |
| **Martian Mono** (400/500) | Byte-level exhibit data only: hashes, hex dumps, start offsets, nonces, signatures, bit counts | Never for prose, never for decoration |

Self-hosted, never fetched: latin-subset `woff2` files in `frontend/src/assets/fonts/`, loaded by
`@font-face` rules at the top of `index.css` (that folder's `README.md` lists the axes and the OFL
licence). There is no Google Fonts `@import` and no CDN, so the type renders on a lab PC with no
internet. The family is **Big Shoulders**: "Big Shoulders Condensed" is not a Google Fonts family,
so the original request returned 400 and every heading silently fell back to the system sans. The
condensed, stamped cut is Big Shoulders at its display optical size, pinned with
`font-variation-settings: 'opsz' 72` on `.font-stamp`; left on auto, small labels would get the
wide text cut.

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

Implementation: these values are the daisyUI theme `casefile` (`@plugin 'daisyui/theme'` in
`index.css`), and `index.html` must set `data-theme="casefile"` on `<html>`. It used to say
`data-theme="dark"`, which selected daisyUI's built-in dark theme over ours, so every primary
button and the active tab rendered in daisyUI's indigo instead of the amber signal accent.

## 3. Layout shell

Replace the daisyUI `tabs` component with a **case-file folder-tab** header:

```
┌──────────────────────────────────────────────────────────────────────┐
│  STEGO / CASE FILE                                                   │  ← Big Shoulders, uppercase
│  01 PROTECT  02 VERIFY  03 KEYS  04 ATTACK LAB  05 STEGANALYSIS      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   (page content, max-width 72rem, left-aligned, not centered)        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

- Tabs are numbered (`01`–`05`) like case-file section dividers, not rounded pills. Active tab:
  `--signal-500` bottom border (2px) + `--ink-50` text; inactive: `--ink-500` text, no border.
  No background pill, no rounded-full active state.
- Page content is **left-aligned**, not centered — a report reads left-to-right from a fixed
  margin, not floating in the middle of the viewport. Max content width `72rem` with a left
  gutter of `--space-2xl` (see §6), so it doesn't sprawl on wide monitors during the demo.
- No outer "card" wrapping the whole page. Sections are separated by a `--ink-700` 1px rule and
  vertical spacing, not by nested bordered boxes.
- All five pages stay mounted; inactive ones are only `hidden` (`App.tsx`). Switching tabs
  mid-demo never throws away a verdict, a report or a half-filled form. The shell also carries
  the hand-offs between tabs (§7).

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

This directly replaces the ad hoc "hash chip" in the original `TECH_STACK.md` plan — one `.exhibit`
component (`Exhibit.tsx`) used for every hash/hex/offset display, including the `lib/hash.ts` before/after hash
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

Around those steps:
- **Media ID** is prefilled with the cover's file name as soon as a cover is chosen, instead of
  hiding the default in a placeholder. It is signed into the payload, so party B has to type the
  same value.
- **Seal the frame** is an opt-in checkbox inside the start-location panel, labelled "advanced
  start-location security", with one paragraph on what it hides and its cost (a wrong passphrase then reads as
  Payload Missing, not Wrong Start Location). See `docs/design/start-location.md` §7.
- **Disabled buttons say why.** Once a cover is chosen, whatever still blocks Protect ("Enter a
  media ID.", "Choose the private key that signs the payload.", "Enter the shared passphrase: …")
  sits in small text under the disabled button. Verify does the same.
- A payload that does not fit is reported as an error block titled **"Blocked before embedding:
  the payload does not fit"**, so the required capacity case reads as a deliberate refusal, not
  a crash.
- On success the result column ends with the hand-off card (below).

### 02 · Verify

Mirrors Protect's step structure (upload → key/passphrase → result), collapsing to the verdict
stamp (§4) as the final step, full-width, impossible to miss. Exhibit blocks below the stamp show:
recomputed hash, expected hash (side by side, monospace, so a mismatch is visually scannable
character-by-character), signature status, resolved start offset.

Implemented aids for party B:
- **Team public keys** picker (`GET /api/keys/public`), each option showing the file name and
  the first 12 hex digits of its fingerprint. The full fingerprint of whichever key is in use
  sits in an `.exhibit` block under the key inputs.
- **SHA-256 party A read out** (optional). When filled in, one stamped line compares it with the
  received file: "✓ Same bytes as party A sent" in the Authentic green, or "✕ Different bytes —
  the file changed in transit" in the Tampered red.
- **Media ID guessed from the file name.** Protect names its output `<cover>.stego.png` and the
  Attack Lab appends `.<attack>`, so Verify strips the `.stego…` part and gets back the cover
  name Protect used as its default media ID, with the help text "Guessed from the file name". The
  old default was the stego file's own name. Since the media ID salts the passphrase, a default
  Protect → Verify round trip in derived mode reported Wrong Start Location.
- **What to check.** Under any non-Authentic verdict, a short plain list of the likely causes
  for that verdict (LSB count and copies, passphrase and media ID, the sealed-frame case,
  transfer damage). It is a list, not an `alert`.
- The checks table gains a **Frame sealed** row whenever the report's `sealed` is not null.

### Demo-sample loader (Verify)

A "Load a demo sample" select sits above step 1, filled from `GET /api/samples` and grouped as
Image (PNG), Audio (WAV) and Video (AVI). Each option reads "label → expected verdict". One choice
fetches the file and fills the media ID, LSB count, copies, start mode, explicit offset,
passphrase and committed public key. This is the demo's fallback path, so nobody types settings
on stage. A banner "Loaded from Sample · `<file>`" shows the expected verdict as a small chip and
the case note (for example why Signature Invalid uses a different key). After Verify, one line of
small text says whether the verdict matched the expected one. The same banner is used for
hand-offs from Protect and the Attack Lab.

### Hand-off card (Protect → party B)

`HandoffCard.tsx`, titled "Hand-off to party B", is the "sent from party A to party B" moment in
one bordered block. It holds everything party B must enter on Verify, as `.exhibit` blocks so it
can be read out character by character:

| Exhibit | Content |
| --- | --- |
| Media ID | The media ID that was signed |
| Read with | LSB count · number of copies |
| Start location | "derived from the shared passphrase", or "explicit offset N" |
| Frame | "sealed (needs the passphrase)" or "plaintext header" |
| Stego file SHA-256 (compare after download) | Full hash, never truncated (§5) |
| Signer public key fingerprint | `signer_fingerprint` from the Protect result |

Buttons: **Verify this file →**, **Attack this file →** and **Download public key**
(`signer.pub.pem`, from `signer_public_key_pem`). The passphrase is deliberately not on the card,
because it travels out of band. "Verify this file" opens Verify with the file, media ID, LSB
count, copies, start mode and offset, the signer's public key and the expected SHA-256 filled in,
and a note asking for the passphrase whenever it is needed. "Attack this file" makes the file
the Attack Lab's target, with its LSB count, offset, copies, media ID, seal flag and key.

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

The robust-embedding attack `lsb_noise` sits in the same grid. After an attack, **Verify the
damaged file →** sends the output to Verify with the original media ID, LSB count, copies, public
key and start offset in **explicit** start mode, because a crop or replay changes the cover size
and a derived start would move. The predicted verdict travels with it. A "Target has a sealed
frame" checkbox (set automatically when the target comes from Protect) sends `sealed`, so
`corrupt_payload` and `replay` work from the offset instead of the encrypted header.

### 05 · Steganalysis

The attacker's view: no key, no passphrase, no settings. The layout is two columns like Verify.
The left column has "File to analyse" (a sample-file select, the file picker, window size as three
segmented buttons 1,024 / 4,096 / 16,384 with 4,096 the default, and Analyse) and "Method" (the
report's method text, crediting Ke Ying). The right column has:

- A result block in the stamp layout, but not one of the six verification verdicts: ▲ in the
  amber `--verdict-missing` hue when suspicious, ○ in the neutral gray otherwise, with the
  backend's plain-language summary. This is a statistical call, not a verdict on authenticity.
- Exhibit blocks: file, elements analysed, windows flagged (n of N), suspected region, strongest
  byte-phase p, whole-file chi-square p and, when suspicious, the rough LSB-count guess.
- The evidence chart, then the flagged-window table.

#### Evidence chart (`EvidenceStrip.tsx`)

- **One series.** One column per window, in file order from "element 0" to the element count.
  Height is −log₁₀(byte-phase p), so more evidence reads as taller. Chi-square is not plotted:
  the reported region is decided by the byte-phase test alone, and chi-square is informational
  (`limitations-and-ai-use.md`). It appears in the tooltip and the table only.
- **Capped at 20.** The axis ticks are 0, 5, 10, 15 and "≥20". A p of 0 draws at the cap. The
  tooltip and the table keep the true p.
- **Threshold line** at p = 1e-6 (height 6), labelled "threshold p = 1e-6". This is
  `stego_core.steganalysis.PHASE_ALPHA`.
- **Flagged columns** (p below the threshold) are filled in the warning hue (`--color-warning`,
  the same amber as Payload Missing and Wrong Start Location, not the signal accent). Other
  columns use muted body text colour. Flagging never depends on colour alone: the tooltip says
  "▲ flagged" and the table lists every flagged window.
- **Per-bar tooltip** on hover or keyboard focus shows p, the element range, chi-square p and
  flagged / below threshold. The hit target is the whole slot at full plot height, and each slot
  is focusable with an `aria-label`.
- **Table view.** A "Flagged windows (n)" disclosure lists elements, byte-phase p and chi-square p
  in mono. It is open by default when there are 6 rows or fewer.
- Bars are at most 24px wide with a 2px gap when there is room, rounded at the data end and
  square at the baseline. When the backend has merged windows (more than 400), a caption says
  how many windows each column merges (strongest evidence kept).

### Video covers: why the AVI plays as audio

Chrome, Edge and Firefox do not play AVI, so a `<video>` element would stay blank. The payload
lives in the AVI's PCM audio track anyway, and the video frames are byte-identical before and
after embedding. `VideoCompare` (Protect) and the received-file preview (Verify) therefore ask
`POST /api/preview/audio-track` for each clip's track as a WAV (`lib/useAviAudioTrack.ts`) and
play it with native `<audio controls>`, like `AudioCompare`. A line of small text says why;
`VideoCompare` also says to download the AVI to watch it in VLC. The preview is display only. The
demo cover `samples/video/original/cover.avi` is built by `scripts/make_video_cover.py` from the
team's `samples/audio/original/cover.wav`.

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
