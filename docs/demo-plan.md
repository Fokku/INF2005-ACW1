# Demo plan

> **Status: running order, settings and presenter slots drafted.** Slots are proposed from the FR
> ownership table in the README (each member presents what they built); confirm or swap them at the
> first rehearsal. Due **one day before the demo**, uploaded to xSite together with the signed
> Declaration of Originality and the contribution statement.

**Hard limits:** 25 minutes total. Every member must have speaking time. Absence scores zero.
Total below is 24 minutes, leaving a 1-minute buffer for transitions/questions.

## Running order

Everything — settings, filenames, exact clicks — is drafted against what is actually implemented,
so nobody improvises on stage. Rows 4–7 each have a **fallback** that needs no typing: the Verify
tab's **Load a demo sample** list loads a curated file with its media ID, LSB count, start mode,
passphrase and public key already filled in (row 6 also has the recorded SMTP round trip). The
curated samples are single-copy, unsealed PNG and WAV files only, so the video part of row 5 and
rows 8–9 have no sample to switch to. Their fallback is the committed GUI screenshots in
`evidence/screenshots/gui/`: `40-protect-video` / `41-verify-video` (video), `60-robust-*` (row 8),
and `70`–`73` plus `80-steganalysis-image-stego` (row 9). All of these flows are rehearsed
automatically by `scripts/capture_screenshots.py` (38 GUI scenes, see
`evidence/screenshots/gui/README.md`).

| # | Min | Who | What they show | Rubric |
| --- | --- | --- | --- | --- |
| 1 | 1.5 | Kai Yuan | Problem/scenario: why a verification payload is hidden, signed and checked; the architecture in one breath (browser for display only, all bit work in `stego_core`); a 10-second tour of the five tabs | — |
| 2 | 3 | Wen Xuan | **FR3/FR4** — Keys tab: generate a live key pair (label `demo`), download both halves, read out the fingerprint. Protect tab: explain the payload fields (media ID, timestamp, hash, nonce, metadata), AES-256-GCM for the custom message, and that the payload is signed before embedding. **Use this key pair for every live Protect below.** | 1, 4 |
| 3 | 3 | Ridwan | **FR7/FR8** — Start-location panel: explicit vs. derived-from-passphrase, how party B re-derives the same offset (scrypt → HKDF → HMAC), bounded extraction and why a wrong offset is distinguishable from no payload | 1 |
| 4 | 3.5 | Zong Han | **FR1/FR5** — Image: Protect `samples/image/original/cover.png`, media ID `P6-8-live-image`, derived start, passphrase `acw1-demo-passphrase-2026`; move the LSB slider 1 → 8 and show the amplified LSB plane; embed; **Verify this file →**, type the passphrase → **Authentic**. Fallback: Verify → Load a demo sample → *Image · Short message* → **Authentic** | 2 |
| 5 | 3.5 | Ke Ying | **FR2/FR6** — Audio: same flow with `samples/audio/original/cover.wav`, play cover vs. stego side by side, verify → **Authentic**. Then 20 s on the video cover: `samples/video/original/cover.avi` embeds into its PCM audio track. Fallback: *Audio · Short message* sample → **Authentic**; video: screenshots `40-protect-video`, `41-verify-video` | 3 |
| 6 | 3 | Kai Yuan (party A) · Kannan (party B) | **FR11/FR12** — Party A → B: Kai Yuan protects `cover.png` with the custom encrypted message (media ID `P6-8-transfer`, 2 LSBs, derived, the passphrase), reads out the hand-off card (SHA-256 + key fingerprint), attaches the stego file to a real email. Kannan downloads it on the second machine, pastes party A's SHA-256 (**✓ Same bytes**), verifies with the public key and passphrase → **Authentic**, message decrypts. Fallback: the recorded SMTP round trip in `evidence/transfer.md` and the pre-downloaded file | 2, 3 |
| 7 | 3 | Kannan | **FR9/FR10/FR11** — Attack Lab from the hand-off: `flip_bits` → **Verify the damaged file →** → **Tampered**; then samples: *Signature Invalid (wrong public key)*, *Payload Missing (never protected)*, *Wrong Start Location (wrong passphrase)*; finally Protect a 20 KB message into `samples/image/original/cover-empty.png` → **Blocked before embedding** (capacity check). Fallback for the `flip_bits` step: *Image · Tampered (high-bit flip)* sample → **Tampered** | 2, 3, 4 |
| 8 | 1.5 | Wen Xuan | **FR13 — robust embedding**: protect with 3 copies, Attack Lab `lsb_noise` → still **Authentic**; with 1 copy → **Tampered**. Trade-off: 3× the capacity. Fallback (no sample exists): screenshots `60-robust-1-copies`, `60-robust-3-copies` | 5 |
| 9 | 2 | Kai Yuan · Ke Ying | **Optional challenges — sealed frame + steganalysis**: Kai Yuan protects with **Seal the frame**, verifies → **Authentic** ("Frame sealed ✓"), then a wrong passphrase → **Cannot Verify**: without the passphrase the payload is not even findable. Ke Ying runs Steganalysis on `image-large.stego.png` (**Signs of LSB embedding**, elements 0–8,192) and on the sealed file (no byte pattern) — and states the honest limit: chi-square still detects *that* something was embedded on natural covers. Close with one limitation and the AI-use disclosure (rubric 7). Fallback (no sealed sample exists): screenshots `70-protect-sealed` to `73-steganalysis-sealed`, `80-steganalysis-image-stego` | 1, 5, 7 |

Each member's time: Kai Yuan rows 1, 6, 9 · Wen Xuan rows 2, 8 · Ridwan row 3 · Zong Han row 4 ·
Ke Ying rows 5, 9 · Kannan rows 6, 7.

## Before the demo

- [ ] `scripts/demo.sh` (Windows: `scripts\demo.ps1`) runs on the **lab PC**, not just on a laptop
- [ ] `PYTHONPATH=backend python scripts/capture_screenshots.py --out <tmp>` passes 38/38 on the
      machine you will present from (it drives the real GUI through every row below)
- [ ] Built UI served from one process, never the Vite dev server
- [ ] `samples/` present as committed. Do **not** re-run `scripts/make_samples.py` on the lab PC
      unless the team private key is there: without it the script re-signs every sample with a new
      key (see README "Keys")
- [ ] `keys/public/team_ed25519.pub.pem` present (the sample loader verifies against it); live
      protects use the key pair generated in row 2, never shown on screen beyond its fingerprint
- [ ] Browser tabs pre-opened: Protect, Verify, Keys, Attack Lab, plus the email client logged in
      on both the "party A" and "party B" windows/machines
- [ ] Passphrase (`acw1-demo-passphrase-2026`, or your team's real one) and every media ID
      (`P6-8-live-image`, `P6-8-live-audio`, `P6-8-transfer`, and `P6-8-transfer-audio` if the audio
      file goes in the same email) written down off-screen; do not improvise them. The committed
      transfer evidence used `P-transfer-image` / `P-transfer-audio`: those IDs are only for
      re-verifying those recorded files (see `evidence/transfer.md`), never for a live protect
- [ ] `evidence/screenshots/gui/` open in an image viewer or browser tab: it is the fallback for
      the rows with no demo sample (video in row 5, rows 8 and 9)
- [ ] Two full rehearsals with a timer, out loud, on the actual lab PC if possible

## Contingencies

- **Live embed/verify fails or hangs on stage**: don't debug live. For rows 4–7, choose the row's
  fallback under **Load a demo sample** on the Verify tab (file and settings load in one click) and
  continue. Robust embedding, sealed frames and video have no demo sample, so for the video part of
  row 5 and for rows 8–9 open the row's committed screenshot in `evidence/screenshots/gui/` and
  narrate it. Rehearse this switch, not just the happy path.
- **Email attachment gets stripped or delayed by the mail provider**: have `samples/image/stego/`
  and `samples/audio/stego/` files already sitting in party B's downloads folder as a backup, and
  narrate "here's what would have arrived" rather than stalling on a spinner.
- **Lab PC has no network / email is unreachable**: demonstrate the transfer via a USB stick or a
  local shared folder instead, and say so explicitly — the point being verified (SHA-256 matches,
  signature holds after transfer) doesn't require the internet specifically, just "the bytes moved
  and weren't altered."
- **A verdict comes out wrong live** (e.g. `Cannot Verify` instead of `Authentic`): the most likely
  causes are a typo'd passphrase/media ID or a mismatched `n_lsb` / copies between Protect and
  Verify — the Verify tab's "What to check" list names them. Recheck those fields out loud as part of
  the narrative ("this is exactly the kind of mismatch the system is designed to catch"). Using
  **Verify this file →** on the hand-off card, or **Verify the damaged file →** in the Attack Lab,
  carries every setting across except a live Protect's passphrase, which never travels. For a
  derived start, or to read an encrypted message, type it on the Verify tab. For a sealed file,
  Verify keeps **Extract and verify** disabled until it is typed, because without it the sealed
  frame cannot be found at all.
- **Browser truly breaks**: the `stego` CLI (`keygen`/`capacity`/`protect`/`verify`/`tamper`, see
  `backend/stego_core/cli.py`, tested in `backend/tests/test_cli.py`) is now a real fallback — e.g.
  `python -m stego_core.cli verify --stego samples/image/stego/image-short.stego.png --pub keys/public/team_ed25519.pub.pem --lsb 2 --media-id P6-8-image-short --start 128`
  prints the verdict as JSON and exits non-zero for anything but Authentic. The pre-generated files
  in `samples/` (already verified to their correct verdicts in `evidence/logs/sample-manifest.json`)
  remain the fastest fallback since they need no typing on stage; the CLI is the next resort if a
  fresh cover/message needs to be run through the pipeline without the GUI.
