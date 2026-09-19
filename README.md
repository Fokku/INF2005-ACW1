# ACW1 — Steganographic Image and Audio Integrity Verification

INF2005 ACW1 team project (Singapore Institute of Technology, Trimester 1 2026).
A GUI-based **LSB-replacement steganography** tool that protects a PNG image and a WAV audio file by embedding a **signed verification payload** inside them, and later verifies whether a file is authentic using **hashing** and **digital-signature** checks.

> **Status: core pipeline working.** The web UI, the API, and the full protect → verify round trip
> (LSB embed/extract, hashing, Ed25519 signing, start-location derivation, all six verdicts) work
> end to end for image, audio, and video covers — 393/393 backend tests green. What's left is the
> Attack Lab backend (`stego_core/attacks.py`, `/api/attack` still answers `501`), the `stego` CLI
> commands, the remaining team-wide `docs/design/` files, and `scripts/make_samples.py` / `evidence/`.
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

Filled in once the implementation exists. This section must eventually list, for every file under `samples/`, the exact `stego verify` command (or GUI steps), the passphrase / start location used, and the expected verdict, so the marker can reproduce every demonstrated case (spec FR12).

## Keys

- The team's **public key** lives in `keys/public/` and is what a verifier (and the marker) uses.
- The **private key** used for the demo is generated only for this assignment with `stego keygen`, kept in `keys/private/`, and is gitignored. Anyone cloning the repository can generate a fresh pair; samples regenerated with `scripts/make_samples.py` then verify against the new public key.

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
- `docs/design/` — FR7/FR8 notes are complete; remaining team-wide design notes are still required

## Use of generative AI

The assignment requires AI use to be disclosed in the Declaration of Originality and reflected on in the demo (rubric criterion 7). The team records how AI tools were used and how their output was checked in `docs/design/limitations-and-ai-use.md`.

## Working conventions

- Branch per feature, pull request into `main`, at least one other member reviews.
- Run the checks before pushing: `pytest`, `ruff`, `biome check`, `tsc --noEmit` (see TECH_STACK.md).
- Never commit private keys, `.venv/`, `node_modules/` or `out/` (already gitignored).
- Keep `samples/` and `evidence/` curated: only files that are used in the demo or submission.
