# ACW1 — Steganographic Image and Audio Integrity Verification

INF2005 ACW1 team project (Singapore Institute of Technology, Trimester 1 2026).
A GUI-based **LSB-replacement steganography** tool that protects a PNG image and a WAV audio file by embedding a **signed verification payload** inside them, and later verifies whether a file is authentic using **hashing** and **digital-signature** checks.

> **Status: core pipeline working.** The web UI, the API, and the full protect → verify round trip
> (LSB embed/extract, hashing, Ed25519 signing, start-location derivation, all six verdicts) work
> end to end for image, audio, and video covers — 629/629 backend tests green. The Attack Lab
> implements six PNG/WAV attacks, plus five AVI audio-track attacks (AVI crop is unsupported).
> See [the Attack Lab design and demo guide](docs/design/attack-lab.md) for verdict conditions.
> The curated `samples/` set and `scripts/make_samples.py` are done — see "Expected outputs" below.
> What's left is the `stego` CLI (a rescue path if the web UI misbehaves; not required, since the GUI
> and `scripts/make_samples.py` already cover every FR1–11 case), the party A → B email evidence,
> and the submission admin (demo plan, declaration, contribution statement).
> See [TODO.md](TODO.md) for the nine workstreams and [TECH_STACK.md](TECH_STACK.md) for the stack.
>
> Find your work with: `grep -rn "TODO(team)" backend frontend scripts`

## Team

Team number: `Px-x` (fill in).

| Member |
| --- |
| Yeo Kai Yuan |
| Wen Xuan Loh |
| Ang Ke Ying |
| Wan |
| Zong Han |
| Kannon |

Task ownership is not assigned yet. [TODO.md](TODO.md) lists every section and feature; the team will allocate them together.

## What the tool does

**Protect (party A)**

1. Choose a cover object: PNG image or WAV/PCM audio.
2. The system hashes a stable representation of the cover (SHA-256) and builds a compact payload: media ID, timestamp, hash, nonce and team-defined metadata, plus the hidden message (short, large, or a custom confidentiality-protected message).
3. The payload is digitally signed with the team's private key (Ed25519).
4. The user picks the number of LSBs to use (1–8) and a start location (explicit, or derived from a passphrase so the verifier can re-derive it). The payload and signature are embedded by LSB replacement starting at that location.
5. The stego file is downloaded and sent to party B (e.g. as an email attachment).

**Verify (party B)**

1. Upload the received stego file, supply the public key and the passphrase / start location.
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

The GUI shows the cover and stego objects side by side (image) and plays cover, stego and payload audio, before and after encoding and decoding.

## Repository layout

```
ACW1/
├── README.md            this file
├── TECH_STACK.md        technologies, versions, commands, rules
├── TODO.md              task inventory (unassigned)
├── docs/
│   ├── spec/            assignment specification (md + pdf)
│   ├── design/          design notes: payload format, start location, verdict table, threat model, innovation, limitations & AI use
│   └── demo-plan.md     25-minute demo sequence (to be written)
├── keys/
│   ├── public/          team public key(s) — tracked
│   └── private/         demo-only private key — gitignored, never committed
├── samples/
│   ├── image/           original/ stego/ tampered/
│   ├── audio/           original/ stego/ tampered/
│   └── payloads/        short (a Learning Outcome), large (Project Overview paragraph), custom (encrypted)
├── evidence/            screenshots/ and logs/ of verification results and test runs
├── backend/
│   ├── stego_core/      the marked logic: LSB, hashing, signing, start location, verdicts
│   ├── app/             FastAPI routers and the API contract (schemas.py)
│   └── tests/           pytest suite; test_verdicts.py is the gate
├── frontend/            React + TypeScript + Tailwind CSS web UI (four tabs)
└── scripts/             setup / dev / demo / check / make_samples
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
./scripts/demo.sh           # demo/marker mode: one process on http://127.0.0.1:8000
./scripts/check.sh          # pytest + ruff + typecheck + lint
```

Interactive API docs are at http://127.0.0.1:8000/docs — useful for testing the backend before
the UI needs it.

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
(private half gitignored under `keys/private/`, regenerated locally by the script above).
To reproduce a case through the **GUI** instead of pytest/`pipeline` calls directly: open the
Verify tab, upload the file, paste the public key PEM, and fill in the settings column.

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

**Still outstanding** (spec FR11/FR12 — see [TODO.md](TODO.md) workstreams H and I): the actual
party A → party B email transfer with before/after SHA-256 screenshots has not been performed yet;
everything above is reproducible locally but has not been demonstrated over a real transfer.

## Keys

- The team's **public key** lives in `keys/public/` and is what a verifier (and the marker) uses.
- The **private key** used for the demo is generated only for this assignment, kept in `keys/private/`, and is gitignored. `scripts/make_samples.py` generates the pair automatically the first time it runs (via `stego_core.signing.generate_keypair`) if `keys/private/team_ed25519.pem` doesn't already exist. Anyone cloning the repository can delete `keys/private/` and re-run the script for a fresh pair; the samples under `samples/` then regenerate and verify against the new public key. (`stego keygen` will do the same once the CLI is implemented — see `TODO.md` workstream E.)

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

## Use of generative AI

The assignment requires AI use to be disclosed in the Declaration of Originality and reflected on in the demo (rubric criterion 7). The team records how AI tools were used and how their output was checked in `docs/design/limitations-and-ai-use.md`.

## Working conventions

- Branch per feature, pull request into `main`, at least one other member reviews.
- Run the checks before pushing: `pytest`, `ruff`, `biome check`, `tsc --noEmit` (see TECH_STACK.md).
- Never commit private keys, `.venv/`, `node_modules/` or `out/` (already gitignored).
- Keep `samples/` and `evidence/` curated: only files that are used in the demo or submission.
