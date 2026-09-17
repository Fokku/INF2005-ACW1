# TODO

Work is grouped into **9 workstreams**. Each one is a self-contained chunk with its own files,
sized so a person or a pair can own it. Nothing is assigned yet — put names in the `Owner` blanks
when the team divides the work.

**How to find your work:** every stub in the codebase is marked `TODO(team)`. Run this to list them:

```bash
grep -rn "TODO(team)" backend frontend scripts
```

Each stub has a docstring explaining what it must do, a sketch of the implementation, and the
traps to avoid. Read the docstring before writing code.

**Build order matters.** A → B → C → D can proceed in parallel after A lands. G (docs) and
I (admin) can start immediately and run alongside everything.

| Rubric criterion | Marks | Workstreams |
| --- | --- | --- |
| 1 Security design and problem framing | 5 | C, D, G |
| 2 Image embedding, extraction, demo | 9 | A, B |
| 3 Audio embedding, extraction, demo | 10 | A, B |
| 4 Hashing, signatures, failed verification | 5 | C, E |
| 5 Innovation | 4 | F |
| 6 Individual technical explanation | 5 | everyone |
| 7 Limitations, ethics, AI use | 2 | G |

---

## A · Bit engine — `backend/stego_core/lsb.py`

Owner: Zong Han (done)

Everything else depends on this. Do it first.

- [x] `bytes_to_bits` and `bits_to_bytes`
- [x] `embed_bits` — replace the low N bits of consecutive elements, starting at an offset
- [x] `extract_bits` — the exact inverse
- [x] Make `tests/test_lsb_roundtrip.py` pass for every LSB count 1–8 (remove the `pytest.skip` lines)
      — 25/25 green, verified end-to-end through both `image_codec` (PNG) and `audio_codec` (WAV).

Watch out: keep the array dtype, and never do bit operations on `int16`.

## B · Cover codecs — `image_codec.py`, `audio_codec.py`

Owner: ______  ·  Owner: ______  (split image / audio between two people)

- [x] `load_png` / `save_png` — lossless round-trip, normalise odd modes to RGB/RGBA
- [x] `load_wav` / `save_wav` — 8/16-bit PCM, mono and stereo, WAV header and params preserved
- [x] Round-trip tests for both: `tests/test_image_codec.py` and `tests/test_audio_codec.py`
      (13 tests, all passing) — pixel/sample-identical round-trip, odd-mode normalisation
      (P/L → RGB), unsupported-format rejection, and the `lsb_plane_png` nice-to-have
- [x] `lsb_plane_png` — amplified LSB view for the side-by-side comparison (nice-to-have)

Watch out: 16-bit WAV needs a `uint16` view. Never write JPEG.

## C · Crypto — `hashing.py`, `kdf.py`, `signing.py`, `payload.py`

Owner: ______

- [ ] `stable_media_hash` — SHA-256 over samples with the low N bits masked, plus the format fields
- [ ] `derive_keys` — passphrase → scrypt → HKDF → `K_loc`, `K_enc`
- [x] `generate_keypair`, `sign`, `verify`, `fingerprint` (Ed25519, PEM files) — FR4, see `tests/test_signing.py`
- [x] `Payload` serialize / deserialize — canonical JSON, byte-identical on both sides — FR3, see `tests/test_payload.py`
- [x] `encrypt_message` / `decrypt_message` — AES-256-GCM for the confidential custom payload

Watch out: hash a stable representation, not the file bytes. `verify` returns `False` for a bad
signature; it only raises for a bad key.

## D · Frame, start location, verdicts — `container.py`, `location.py`, `verdict.py`

Owner: ______

This workstream is where most of rubric criterion 1 lives.

- [ ] `build_frame` / `parse_frame` / `parse_header` — magic, version, lengths, CRC32
- [ ] `derive_start` — keyed HMAC start offset that the verifier can re-derive
- [ ] `scan_for_magic` — bounded search that separates *Wrong Start Location* from *Payload Missing*
- [ ] `decide` — the verdict decision table, one branch per category
- [ ] Make `tests/test_verdicts.py` pass, all six verdicts

Watch out: never derive the start from the media hash, the payload nonce, or the cover shape.
The module docstring explains why each one breaks a verdict.

## E · End-to-end pipeline and API — `pipeline.py`, `app/routers/*`, `cli.py`

Owner: ______

Do this after A–D. It is mostly plumbing.

- [ ] `pipeline.protect` — hash, build payload, sign, frame, capacity check, choose start, embed
- [ ] `pipeline.verify` — resolve start, parse, check signature, recompute hash, decide
- [ ] Fill in the four router stubs: `capacity`, `protect`, `verify`, `attack`
- [ ] Fill in the `stego` CLI commands: `keygen`, `capacity`, `protect`, `verify`, `tamper`
- [ ] Make `tests/test_api.py::test_protect_then_verify_roundtrip` pass for image and audio

The frontend needs no changes — it already calls all of these correctly.

## F · Attack lab and innovation — `attacks.py`

Owner: ______

The Attack Lab UI and the backend route already exist. Only the six functions are missing.

- [ ] `flip_bits`, `crop`, `lsb_scrub`, `reencode`, `corrupt_payload`, `replay`
- [ ] Confirm each one produces the verdict `attacks.EXPECTED` predicts
- [ ] Write up the innovation claim: what it is, why it is useful, what it does not solve

Innovation candidates (pick one and justify it): the keyed start-location derivation, the attack
simulation module, an encrypted payload, or something from spec Section 8. **Do not start this
until `test_verdicts.py` is green** — criteria 2 and 3 are worth 19 marks, this one is worth 4.

## G · Design documents — `docs/design/`

Owner: ______

Can start now. These are what the demo explanation is read from.

- [ ] `payload-format.md` — payload fields, the frame layout, the exact hash formula
- [ ] `start-location.md` — how the start is chosen, how the verifier finds it, how it is protected
- [ ] `verdict-table.md` — each verdict, its trigger condition, and the test that proves it
- [ ] `threat-model.md` — what the design defends against, and what it does not
- [ ] `limitations-and-ai-use.md` — honest limits (magic bytes are scannable, LSB is fragile and
      detectable by steganalysis) plus how the team used and checked AI tools

## H · Samples, evidence and test cases — `samples/`, `evidence/`, `scripts/make_samples.py`

Owner: ______

The spec needs **at least 2 positive and 3 negative cases**, with at least one of each per cover
object. Suggested set:

| # | Cover | Case | Expected |
| --- | --- | --- | --- |
| 1 | image | protect → verify with the right key and passphrase | Authentic |
| 2 | audio | protect → verify with the right key and passphrase | Authentic |
| 3 | image | edit pixels after protecting | Tampered |
| 4 | audio | verify with a different public key | Signature Invalid |
| 5 | audio | verify an untouched cover | Payload Missing |
| 6 | image | verify with the wrong passphrase | Wrong Start Location |
| 7 | image | payload larger than the cover | capacity error, blocked before embedding |

- [ ] Source one PNG (512×512 or larger) and one 16-bit PCM WAV (5 s or longer)
- [ ] Three payload sizes: a Learning Outcome (short), the Project Overview paragraph (large),
      and the team's custom encrypted message — all three are preset in the Protect tab
- [ ] Produce the original, stego and tampered files for both cover types
- [ ] `scripts/make_samples.py` so every sample regenerates deterministically
- [ ] Screenshots of each verdict, plus `pytest` output, into `evidence/`
- [ ] The party A → party B run: email the stego file **as an attachment**, download it, verify it,
      and show the SHA-256 matching on both sides

## I · Submission and demo — `README.md`, `docs/demo-plan.md`

Owner: ______

Can start now.

- [ ] Fill in the team number (`Px-x`) and the exact Week 5 dates
- [ ] Demo plan: ≤ 25 minutes, a slot for **every** member, who shows what and in what order
- [ ] Declaration of Originality, signed by all six
- [ ] Contribution/distribution statement with percentages, agreed by all six
- [ ] Complete the README's "Expected outputs" section — every sample, its command, its verdict
- [ ] Commit `keys/public/*.pem`; confirm no private key is in git history
- [ ] Ship `frontend/dist` in the submission so the marker needs only Python
- [ ] Rehearse twice on the actual lab PC, including the email round trip

**Deadlines:** demo plan + declaration + contribution statement are due **one day before the demo**.
Code, README, samples, evidence and keys are due **Week 5 Friday**.

---

## J · Optional challenges (bonus, spec Section 8)

Owner: ______

These are the five official optional challenges. None are required for the core rubric — attempt
after A–H are green. Pick one or two and go deep rather than spreading thin across all five.

- [x] **Video cover object** — `video_codec.load_avi` / `save_avi` (audio-track embedding, AVI
      container), `CoverKind.video` / `VideoInfo` in `schemas.py`, `.avi` MIME in `storage.py`, and
      the Protect/Verify/Attack Lab pages + `VideoCompare.tsx` all done; `tests/test_video_codec.py`
      is green (5/5).
  - [ ] Wire it through `pipeline.protect` / `pipeline.verify` once those are implemented
        (workstream E) — the docstrings mention `video_codec` but the pipeline body itself still
        raises `NotImplementedError`.
- [ ] **Robust embedding** — improve payload survival under compression, noise, resampling or
      mild transformation, using redundancy, error correction (e.g. repetition or Hamming codes)
      or spread-spectrum techniques. Document the trade-off against raw capacity.
- [ ] **Attack simulation module** — overlaps workstream F. Extend `attacks.py` beyond the six
      required functions to also simulate wrong-key verification, payload corruption, wrong
      start-location extraction, and replay/substitution attempts, each asserting the verdict
      `attacks.EXPECTED` predicts.
- [ ] **Advanced start-location security** — overlaps workstream D. Derive the start location from
      a keyed pseudo-random function, an encrypted header, or a seed phrase (beyond the baseline
      keyed HMAC in `derive_start`), and write up its limitations in `docs/design/start-location.md`.
- [ ] **Steganalysis** — using a known algorithm or methodology (e.g. chi-square attack, RS
      analysis, LSB histogram analysis), analyse one of the project's own stego samples and
      convincingly infer whether the cover shows signs of a hidden payload. Write up the method
      and result, ideally as a script under `scripts/` plus a short section in
      `docs/design/limitations-and-ai-use.md`.

---

## Definition of done

A workstream is finished when its tests pass, `grep -rn "TODO(team)"` finds nothing in its files,
and the person who wrote it can explain it without notes — rubric criterion 6 is 5 individual marks
for exactly that.
