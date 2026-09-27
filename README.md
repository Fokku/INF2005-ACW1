# ACW1 — Steganographic Image and Audio Integrity Verification

INF2005 ACW1 team project (Singapore Institute of Technology, Trimester 1 2026).
A GUI-based **LSB-replacement steganography** tool that protects a PNG image and a WAV audio file by embedding a **signed verification payload** inside them, and later verifies whether a file is authentic using **hashing** and **digital-signature** checks.

> **Status: demo-ready.** The web UI, the API and the full protect → verify round trip (LSB
> embed/extract, hashing, Ed25519 signing, start-location derivation, all six verdicts) work end to
> end for image, audio and video covers — **938 backend tests green** (`./scripts/check.sh`). Every
> scenario the demo needs is also exercised in the real GUI by a Playwright run that asserts each
> verdict: **38/38 scenes pass**, screenshots in [`evidence/screenshots/gui/`](evidence/screenshots/gui/README.md).
> Optional challenges done: video cover, attack simulation, robust embedding, steganalysis, and the
> sealed frame (advanced start-location security). Party A → party B transfer evidence:
> [`evidence/transfer.md`](evidence/transfer.md).
>
> **Left for the team before submission** (none of it can be done by one person alone): the live
> two-machine email transfer and its screenshots, the six signatures on the declaration, the agreed
> percentages on the contribution statement, confirming the demo-plan slots, and two timed
> rehearsals on the lab PC. See [TODO.md](TODO.md) workstream I.

## Team

Team number: `P6-8` — the ID `scripts/make_samples.py` signs into every sample (`TEAM_ID`); confirm it
matches xSite before submission.

| Member |
| --- |
| Ang Ke Ying |
| Chng Zong Han |
| Kannan s/o Rajamohan |
| Loh Wen Xuan |
| Muhammad Ridwan Putra Jasni |
| Yeo Kai Yuan |

Task ownership by functional requirement. The **Allocated** column is copied from the team's
task-allocation document (cross-checked against the per-workstream owners recorded in
[TODO.md](TODO.md)). The **Added later** column and the last two rows are **not** from that
document: they were added afterwards from the work recorded in TODO.md and the contribution
statement, and the team confirms them together with the contribution percentages.

| FR | Allocated (task-allocation document) | Added later (to be confirmed by the team) |
| --- | --- | --- |
| FR1 – Image input | Ke Ying | |
| FR2 – Audio input | Ke Ying | |
| FR3 – Payload generation | Wen Xuan | |
| FR4 – Digital signature | Wen Xuan | |
| FR5 – Image steganographic embedding | Zong Han | |
| FR6 – Audio steganographic embedding | Zong Han | |
| FR7 – Variable start location | Ridwan / Zong Han | |
| FR8 – Extraction and decoding | Ridwan / Zong Han | |
| FR9 – Hash verification | Ridwan / Zong Han | |
| FR10 – Verdict generation | Zong Han | |
| FR11 – Positive and negative cases | Kannan / Zong Han | Kai Yuan (party A → B transfer evidence) |
| FR12 – Evidence and reproducibility | All | Wen Xuan (samples), Kannan (FR11 evidence), Kai Yuan (GUI screenshots, transfer evidence) |
| FR13 – Innovation | Zong Han (start location), Kannan (attack lab) | Wen Xuan (robust embedding), Kai Yuan (sealed frame) |
| Project architecture and scaffold (web UI, API, module structure, team plan) | — | Kai Yuan |
| Optional challenges (spec Section 8) | — | Ke Ying (video cover, steganalysis), Kannan (attack simulation), Wen Xuan (robust embedding), Kai Yuan (advanced start-location security: sealed frame) |

The full per-member breakdown, with the files each person wrote, is in
[docs/contribution-distribution-statement.md](docs/contribution-distribution-statement.md).

## What the tool does

**Protect (party A)**

1. Choose a cover object: PNG image, WAV/PCM audio, or an AVI video with a PCM audio track (the payload rides in the audio track).
2. The system hashes a stable representation of the cover (SHA-256) and builds a compact payload: media ID, timestamp, hash, nonce and team-defined metadata, plus the hidden message (short, large, or a custom confidentiality-protected message).
3. The payload is digitally signed with the team's private key (Ed25519).
4. The user picks the number of LSBs to use (1–8), how many copies to embed (robust embedding), and a start location (explicit, or derived from a passphrase so the verifier can re-derive it). Optionally the whole frame is **sealed** (encrypted, magic marker included) so it cannot even be found without the passphrase. The payload and signature are embedded by LSB replacement starting at that location.
5. The stego file is downloaded and sent to party B (e.g. as an email attachment). A hand-off card lists what party B needs: media ID, LSB count, copies, start mode, the file's SHA-256 and the signer's key fingerprint.

**Verify (party B)**

1. Upload the received stego file (its SHA-256 is checked against the one party A read out), supply the public key and the passphrase / start location.
2. The system recovers the start location, extracts the payload and signature, verifies the signature with the public key, and recomputes the media hash.
3. It returns a verdict with an explanation:

| Verdict | Meaning |
| --- | --- |
| **Authentic** | Payload found, signature valid, hash matches. |
| **Tampered** | Payload found and signed, but the media hash (or payload integrity) no longer matches. |
| **Signature Invalid** | Payload found, but the signature does not verify (wrong key or altered payload). |
| **Payload Missing** | No embedded payload found anywhere (never protected, or LSB plane destroyed by re-encoding). |
| **Wrong Start Location** | A payload exists but not at the location derived from the supplied key/offset. |
| **Cannot Verify** | Unsupported file, missing/invalid public key, or an internal error. |

The GUI shows the cover and stego objects side by side (image, with an amplified LSB plane) and plays cover, stego and payload audio (for AVI, the audio track that carries the payload), before and after encoding and decoding. Two more tabs complete it: the **Attack Lab** manufactures the negative cases and hands each damaged file straight to Verify, and **Steganalysis** shows what an analyst with no key can infer (chi-square and byte-phase tests, per-window evidence chart).

## Repository layout

```
ACW1/
├── README.md            this file
├── TECH_STACK.md        technologies, versions, commands, rules
├── TODO.md              task inventory with owners
├── docs/
│   ├── spec/            assignment specification (md + pdf)
│   ├── design/          design notes: payload format, start location, verdict table, threat model, innovation, limitations & AI use
│   ├── demo-plan.md     25-minute demo sequence (slots proposed by FR ownership; confirm at rehearsal)
│   ├── declaration-of-originality.md          needs all six signatures
│   └── contribution-distribution-statement.md responsibilities filled in; needs agreed percentages
├── keys/
│   ├── public/          team public key(s) — tracked
│   └── private/         demo-only private key — gitignored, never committed
├── samples/
│   ├── image/           original/ stego/ tampered/
│   ├── audio/           original/ stego/ tampered/
│   ├── video/           original/cover.avi (built by scripts/make_video_cover.py)
│   └── payloads/        short (a Learning Outcome), large (Project Overview paragraph), custom (encrypted)
├── evidence/            screenshots/ (gui/ = Playwright run, section-f/), logs/, fr10-fr11/, transfer/, steganalysis/
├── backend/
│   ├── stego_core/      the marked logic: LSB, hashing, signing, start location, verdicts
│   ├── app/             FastAPI routers and the API contract (schemas.py)
│   └── tests/           pytest suite; test_verdicts.py is the gate
├── frontend/            React + TypeScript + Tailwind CSS web UI (five tabs, fonts bundled — works offline)
└── scripts/             setup / dev / demo / check / package_submission, plus the evidence generators:
                         make_samples, make_video_cover, transfer_demo, capture_screenshots,
                         generate_verification_evidence, steganalysis
```

## Getting started

Requirements: Python 3.12–3.14, Node 25 + pnpm 10 (only needed to build the UI), git.

```bash
git clone https://github.com/Fokku/INF2005-ACW1 ACW1 && cd ACW1
./scripts/setup.sh          # venv, dependencies, UI build   (Windows: scripts\setup.ps1)
```

Then pick one:

```bash
./scripts/dev.sh            # development: API on :8000 + Vite on :5173 with hot reload
./scripts/demo.sh           # demo/marker mode: one process on http://127.0.0.1:8000   (Windows: scripts\demo.ps1)
./scripts/check.sh          # pytest + ruff + typecheck + lint
```

Interactive API docs are at http://127.0.0.1:8000/docs — useful for testing the backend before
the UI needs it.

### Regenerating the evidence

All from the repo root with the venv active:

```bash
PYTHONPATH=backend python scripts/make_samples.py                  # samples/ + evidence/logs/sample-manifest.json (team key holder only, see "Keys")
PYTHONPATH=backend python scripts/make_video_cover.py              # samples/video/original/cover.avi
PYTHONPATH=backend python scripts/transfer_demo.py --out evidence/transfer   # party A -> B email round trip
PYTHONPATH=backend python scripts/generate_verification_evidence.py --output /tmp/fr10-fr11-rerun   # FR10/FR11 cases
# GUI screenshots (needs the UI built and, once: pip install -e "backend[evidence]" && python -m playwright install chromium)
PYTHONPATH=backend python scripts/capture_screenshots.py           # evidence/screenshots/gui/, asserts every verdict
```

`generate_verification_evidence.py` requires `--output` and refuses a folder that already exists,
so it never overwrites the committed `evidence/fr10-fr11/`. Give it a new folder, then compare its
`manifest.json` with `evidence/fr10-fr11/manifest.json`: all 18 cases should give the same verdict
(or, for the two oversized cases, the same capacity refusal). The stego bytes, keys and hashes
differ on every run (fresh nonce, timestamp and key pair), and the oversized cases now report a
smaller `max_message_bytes`, because `/api/capacity` counts exactly what Protect embeds (see
`docs/design/api-contract.md`, "Capacity accuracy").
`transfer_demo.py` replaces its generated files in `--out` only after every check passes, and
`capture_screenshots.py --only NAME…` runs a subset into a temporary folder, never into the
committed evidence.

### Expected outputs

Every file under `samples/` is produced by one command, run from the repo root with the venv active:

```bash
PYTHONPATH=backend python scripts/make_samples.py     # Windows: set PYTHONPATH=backend
```

This (re)creates `samples/image/original/cover.png` (512×512 RGB) and `samples/audio/original/cover.wav`
(16-bit mono PCM, 5 s) the first time it runs, generates a demo Ed25519 key pair under `keys/` if one
is not already there, protects both covers with every case below, and writes
`evidence/logs/sample-manifest.json` — the same settings and verdicts as the table below, freshly
re-verified. The cover files and key pair are reused (not regenerated) on later runs, so only the
stego/tampered files change between runs — see the script's docstring for why byte-identical stego
output is neither possible nor desirable (the signed payload includes a fresh nonce and timestamp
every time by design).

All cases below use `n_lsb=2` and the demo key pair at `keys/public/team_ed25519.pub.pem`
(private half gitignored under `keys/private/`; see "Keys" below for who may regenerate it).
To reproduce a case through the **GUI**: open the Verify tab, choose it under **Load a demo sample**
(file, media ID, LSB count, start mode, passphrase and public key are filled in), and press
**Extract and verify**. The media IDs are `P6-8-image-short`, `P6-8-audio-large` and so on — the
loader reads them from `evidence/logs/sample-manifest.json`, and
`backend/tests/test_samples_api.py` checks that every listed case produces its verdict.

| Case | File | Cover / message | Settings | Expected verdict |
| --- | --- | --- | --- | --- |
| Short message | `samples/image/stego/image-short.stego.png` | image, Learning Outcome 1 (105 B) | explicit start 128 | **Authentic** |
| Short message | `samples/audio/stego/audio-short.stego.wav` | audio, Learning Outcome 1 (105 B) | explicit start 128 | **Authentic** |
| Large message | `samples/image/stego/image-large.stego.png` | image, Project Overview paragraph (675 B) | explicit start 128 | **Authentic** |
| Large message | `samples/audio/stego/audio-large.stego.wav` | audio, Project Overview paragraph (675 B) | explicit start 128 | **Authentic** |
| Custom encrypted message | `samples/image/stego/image-custom.stego.png` | image, team release-note message, AES-256-GCM encrypted | explicit start 128, passphrase `acw1-demo-passphrase-2026` | **Authentic** (message decrypts) |
| Custom encrypted message | `samples/audio/stego/audio-custom.stego.wav` | audio, same custom message | explicit start 128, passphrase `acw1-demo-passphrase-2026` | **Authentic** |
| Tampered | `samples/image/tampered/image-flip_bits.png` | `image-short.stego.png` with a high-bit flip attack applied | explicit start 128 | **Tampered** |
| Tampered | `samples/audio/tampered/audio-flip_bits.wav` | `audio-short.stego.wav`, same attack | explicit start 128 | **Tampered** |
| Signature Invalid | `image-short.stego.png` / `audio-short.stego.wav` (reused) | verified with a mismatched public key | explicit start 128 | **Signature Invalid** |
| Payload Missing | `samples/image/original/cover-empty.png` | a small (32×32) untouched cover, never protected | explicit start 128 | **Payload Missing** |
| Payload Missing | `samples/audio/original/cover-empty.wav` | a small (0.5 s) untouched cover | explicit start 128 | **Payload Missing** |
| Wrong Start Location | `samples/image/stego/image-derived-start.stego.png` | protected with a **derived** start (correct passphrase `acw1-demo-passphrase-2026`) | verified with the **wrong** passphrase | **Wrong Start Location** |
| Wrong Start Location | `samples/audio/stego/audio-derived-start.stego.wav` | same, audio | verified with the wrong passphrase | **Wrong Start Location** |
| Capacity check | — (`image-oversized`, `audio-oversized`) | a 10 MB message against either cover at `n_lsb=2` | protect is attempted | Blocked before embedding: `CapacityError` — "payload does not fit: the frame needs 13,333,808 bytes ... but this cover only has capacity for 196,608 bytes" (image); analogous for audio |

`Cannot Verify` is demonstrated separately (not regenerated by this script, since it needs a large
cover): verifying the full 512×512 `cover.png` unprotected reports `Cannot Verify` — "the remaining
locations were not searched, so payload absence cannot be confirmed" — because an exhaustive
LSB-magic scan over that many candidate offsets exceeds `location.MAX_SCAN_POSITIONS`. See
`backend/tests/test_attacks.py::test_large_cover_attack_reports_incomplete_search` for the
automated proof of this case, and `docs/design/attack-lab.md` / `evidence/section-f.md` for six more
attack-driven negative cases (`crop`, `lsb_scrub`, `reencode`, `corrupt_payload`, `replay`) with
screenshots.

Beyond the curated files, the GUI run in [`evidence/screenshots/gui/`](evidence/screenshots/gui/README.md)
verifies the curated files through **Load a demo sample** (all six verdicts for image, five for
audio: Cannot Verify is image-only) and records (and asserts) the live flows: protect → download →
verify in a second browser session with the SHA-256 compared, the capacity block for image and
audio, the AVI video cover, Attack Lab → Verify, robust embedding (1 copy + `lsb_noise` → Tampered;
3 copies → Authentic), and the sealed frame (right passphrase → Authentic; wrong passphrase → Cannot
Verify on the 512×512 cover, because a sealed frame cannot be found without the passphrase;
steganalysis finds no byte pattern in it).

**Party A → party B transfer:** [`evidence/transfer.md`](evidence/transfer.md) records a real
RFC 5322 email with both stego files as base64 MIME attachments, delivered over SMTP to a Maildir on
this machine, then extracted and verified (SHA-256 identical before and after, both Authentic, the
message decrypts; a wrong passphrase and a one-bit tamper are caught). The same flow over a real mail
provider between two machines is done live in the demo (row 6 of the demo plan); its screenshots are
added after rehearsal — checklist in `evidence/transfer.md`.

## Keys

- The team's **public key** lives in `keys/public/` and is what a verifier (and the marker) uses.
- The **private key** used for the demo is generated only for this assignment, kept in `keys/private/`, and is gitignored. `scripts/make_samples.py` generates the pair automatically the first time it runs (via `stego_core.signing.generate_keypair`) if `keys/private/team_ed25519.pem` doesn't already exist. Anyone cloning the repository can delete `keys/private/` and re-run the script for a fresh pair; the samples under `samples/` then regenerate and verify against the new public key. For a personal key pair on the command line, use `stego keygen --out keys --label <yourname>` (see `backend/stego_core/cli.py`). Never use the default label `team` for that: `keygen` refuses to overwrite an existing key file, either half, unless given `--force`, and forcing it over the committed `team_ed25519.pub.pem` makes every curated sample report Signature Invalid.
- **Only the holder of `keys/private/team_ed25519.pem` should re-run `make_samples.py`.** On a machine without it, the script creates a *new* pair and re-signs every sample, so `samples/` and the committed public key change together (consistent, but a large diff). For live demos, generate a key pair on the Keys tab and use it for Protect; the curated samples keep verifying against `team_ed25519.pub.pem`, which the Verify tab's sample loader selects automatically.
- `keys/public/section-f-demo.pub.pem` (Attack Lab evidence) and `keys/public/transfer-demo.pub.pem` (email transfer evidence) are separate demo keys; the sample loader uses the Section F key as the deliberately *wrong* key for the Signature Invalid case. It did not sign the short-message samples those cases pair it with (the team key did); it signed only the Section F replay files (`samples/audio/stego/section-f-replay-source.wav`, replayed into `samples/audio/tampered/section-f-replay.wav`), which are not sample-loader cases.

## Deadlines

| When | What |
| --- | --- |
| One day before the demo | Demo plan (≤ 25 min, every member's air time), signed Declaration of Originality, agreed contribution/distribution statement — uploaded to xSite |
| Week 5, Tues/Thurs lab | Live team demo (≤ 25 min, all members present and presenting; zero marks for absence) |
| Week 5, Friday | Source code, README, sample files, test evidence, public key + key instructions |

Exact dates: to be confirmed by the team once the lab schedule is published.

## Documents

- [TECH_STACK.md](TECH_STACK.md) — stack, versions, layout, commands, non-negotiable engineering rules
- [TODO.md](TODO.md) — every section and feature that has to be done, with spec references
- [docs/spec/INF2005-ACW1-spec-v5.md](docs/spec/INF2005-ACW1-spec-v5.md) — the assignment specification
- `docs/design/` — payload format, start location, extraction, hash verification, verdict table, threat model, attack lab, limitations and AI use
- [docs/demo-plan.md](docs/demo-plan.md) — running order, with slots proposed by FR ownership
- [docs/declaration-of-originality.md](docs/declaration-of-originality.md) — needs all six signatures
- [docs/contribution-distribution-statement.md](docs/contribution-distribution-statement.md) — responsibilities per member; needs agreed percentages
- [evidence/screenshots/gui/README.md](evidence/screenshots/gui/README.md) — 38 GUI scenes with expected and observed verdicts
- [evidence/transfer.md](evidence/transfer.md) — party A → party B email round trip

## Use of generative AI

The assignment requires AI use to be disclosed in the Declaration of Originality and reflected on in the demo (rubric criterion 7). The team records how AI tools were used and how their output was checked in `docs/design/limitations-and-ai-use.md`.

## Working conventions

- Branch per feature, pull request into `main`, at least one other member reviews.
- Run the checks before pushing: `./scripts/check.sh` (pytest, ruff check + format, tsc, oxlint).
- Never commit private keys, `.venv/`, `node_modules/` or `out/` (already gitignored).
- Keep `samples/` and `evidence/` curated: only files that are used in the demo or submission.
