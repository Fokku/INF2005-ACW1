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

Owner: Ke Ying (done — image and audio codecs)

- [x] `load_png` / `save_png` — lossless round-trip, normalise odd modes to RGB/RGBA
- [x] `load_wav` / `save_wav` — 8/16-bit PCM, mono and stereo, WAV header and params preserved
- [x] Round-trip tests for both: `tests/test_image_codec.py` and `tests/test_audio_codec.py`
      (13 tests, all passing) — pixel/sample-identical round-trip, odd-mode normalisation
      (P/L → RGB), unsupported-format rejection, and the `lsb_plane_png` nice-to-have
- [x] `lsb_plane_png` — amplified LSB view for the side-by-side comparison (nice-to-have)

Watch out: 16-bit WAV needs a `uint16` view. Never write JPEG.

## C · Crypto — `hashing.py`, `kdf.py`, `signing.py`, `payload.py`

Owner: Zong Han (done)

- [x] `stable_media_hash` — SHA-256 over samples with the low N bits masked, plus the format fields
- [x] `derive_keys` — passphrase → scrypt → HKDF → `K_loc`, `K_enc`
- [x] `generate_keypair`, `sign`, `verify`, `fingerprint` (Ed25519, PEM files) — FR4, see `tests/test_signing.py`
- [x] `Payload` serialize / deserialize — canonical JSON, byte-identical on both sides — FR3, see `tests/test_payload.py`
- [x] `encrypt_message` / `decrypt_message` — AES-256-GCM for the confidential custom payload

Watch out: hash a stable representation, not the file bytes. `verify` returns `False` for a bad
signature; it only raises for a bad key.

## D · Frame, start location, verdicts — `container.py`, `location.py`, `verdict.py`

Owner: Zong Han (done)

This workstream is where most of rubric criterion 1 lives.

- [x] `build_frame` / `parse_frame` / `parse_header` — magic, version, lengths, CRC32
- [x] `derive_start` — keyed HMAC start offset that the verifier can re-derive
- [x] `scan_for_magic` — bounded search that separates *Wrong Start Location* from *Payload Missing*
- [x] `decide` — the verdict decision table, one branch per category
- [x] Make `tests/test_verdicts.py` pass, all six verdicts — 12/12 green (one per verdict per cover type)

Watch out: never derive the start from the media hash, the payload nonce, or the cover shape.
The module docstring explains why each one breaks a verdict. Note a related subtlety worth writing
into `docs/design/start-location.md`: `derive_start`'s modulus (`span = n_elements - needed`) is
still indirectly shape-sensitive even though shape itself isn't hashed into the HMAC message —
cropping a derived-mode file shifts `n_elements`, hence the offset, same failure story as deriving
from shape directly.

## E · End-to-end pipeline and API — `pipeline.py`, `app/routers/*`, `cli.py`

Owner: Zong Han (pipeline + capacity/protect/verify routers done); Kannon (attack router done). CLI still open.

Do this after A–D. It is mostly plumbing.

- [x] `pipeline.protect` — hash, build payload, sign, frame, capacity check, choose start, embed
      (image, audio, and video covers)
- [x] `pipeline.verify` — resolve start, parse, check signature, recompute hash, decide
      (image, audio, and video covers)
- [x] `capacity`, `protect`, `verify`, `keys` routers wired to the real pipeline/`signing` functions
- [x] `attack` router / `attacks.py` — Kannon, see workstream F
- [ ] Fill in the `stego` CLI commands: `keygen`, `capacity`, `protect`, `verify`, `tamper`
      (`stego_core/cli.py` — every command still `raise NotImplementedError`)
- [x] Make `tests/test_api.py::test_protect_then_verify_roundtrip` pass for image and audio

Full backend suite is 629/629 green after FR11 evidence (`cd backend && python -m pytest -q`).
The Attack Lab route now produces downloadable altered files; its UI explains conditional
verdict predictions and the original verification settings to use.

### FR7/FR8 assigned contribution — Ridwan (done)

This contribution extends workstreams D and E without claiming the original frame, verdict, crypto,
codec, or pipeline implementations.

- [x] FR7 explicit/derived start validation and actual-frame trailing-capacity checks
- [x] FR7 element-aligned bounded recovery and incomplete-scan handling
- [x] FR8 bounded frame extraction, strict payload decoding, and pipeline integration
- [x] Focused image/audio tests: 315; full backend regression suite: 393
- [x] `docs/design/start-location.md`, `docs/design/extraction.md`, and the scoped contribution record

See `docs/design/fr7-fr8-contributions.md` for the exact ownership boundary and reproducible test
commands. Screenshots, samples, manual demo evidence, and the final team contribution statement
remain in workstreams H and I.

### FR9 supporting contribution — Ridwan (done; final owner to be confirmed)

The work-split document leaves FR9's owner cell blank. Zong Han contributed the original
`stable_media_hash` implementation and pipeline comparison; the work below tests and hardens that
foundation without claiming FR10.

- [x] Stable SHA-256 unit coverage for image/audio dtypes and LSB depths 1-8
- [x] Image/audio protect-to-verify comparison tests in explicit and derived modes
- [x] Canonical 64-character lowercase digest validation at payload decoding
- [x] API checks for separate embedded/recomputed hashes and `hash_match`
- [x] `docs/design/hash-verification.md` with algorithm, scope, tests, and security limitations

FR9-focused additions contribute 66 tests; screenshots, samples, transfer evidence, FR10, and the
final team ownership statement remain outside this contribution.

## F · Attack lab and innovation — `attacks.py`

Owner: Kannon (done — `kannan_features`)

Implemented on top of Ridwan's merged FR7–FR9 work, using the shared bounded frame extractor.

- [x] `flip_bits`, `crop`, `lsb_scrub`, `reencode`, `corrupt_payload`, `replay` for PNG/WAV
- [x] Wire `/api/attack`, validate inputs and return named downloads; update GUI guidance
- [x] Confirm `attacks.EXPECTED` under documented demo conditions — 139 Section F tests,
      including real verification and API downloads; full backend suite 597/597 green
- [x] Write up innovation, demo steps, limitations and AI-use record in `docs/design/attack-lab.md`
- [x] Archive 14 manual PNG/WAV result screenshots and an independent-target WAV replay
      API check, with public key, reproducible samples and logs in `evidence/section-f.md`

The innovation is the reproducible attack simulation workflow. Cropping/re-encoding have
conditional outcomes, explained in the GUI and design note (including Cannot Verify after an incomplete large-cover search). AVI supports the five equal-length
PCM transformations; cropping AVI is explicitly rejected. Section F evidence is saved;
team-wide sample curation, the email transfer, timed rehearsal and final contribution
declaration remain with H/I. CLI commands remain with E.

## G · Design documents — `docs/design/`

Owner: Kannon (remaining system design documents); Ridwan (FR7–FR9 documents)

Technical documents are complete. Personal AI-use confirmations remain a team action before submission.

- [x] `payload-format.md` — payload fields, the frame layout, the exact hash formula
- [x] `start-location.md` — FR7 selection, recovery, validation, and security limits (Ridwan)
- [x] `extraction.md` — FR8 bounded extraction, decoding, failure mapping, and limits (Ridwan)
- [x] `fr7-fr8-contributions.md` — scoped ownership, test record, and AI-use note (Ridwan)
- [x] `hash-verification.md` — FR9 formula, workflow, test record, and limitations (Ridwan support)
- [x] `verdict-table.md` — each verdict, its trigger condition, and the test that proves it
- [x] `threat-model.md` — what the design defends against, and what it does not
- [x] `limitations-and-ai-use.md` — honest limits (magic bytes are scannable, LSB is fragile and
      detectable by steganalysis) plus recorded AI assistance and checks (Kannon)
- [ ] Each member confirms their AI-use disclosure and reconciles it with the final declaration;
      see the confirmation checklist in `limitations-and-ai-use.md`

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

### FR11 testing, demonstration and evidence — Kannon (transfer pending)

Builds on the team's implementation, including Zong Han's FR10 verdict logic.

- [x] PNG/WAV checks for all six verdicts, with short, large and encrypted custom messages
- [x] Exact message recovery, wrong/missing passphrase checks and oversized-payload rejection
- [x] 18 automated API cases passing; samples, public keys and reports in `evidence/fr10-fr11/`
- [x] Reproduction script: `scripts/generate_verification_evidence.py`
- [x] Fix explicit-mode passphrase entry, decryption status and readable downloads;
      32 regression cases and PNG/WAV browser checks passed (629 backend tests total)
- [ ] Party A → Party B attachment transfer, received-file verification and screenshots
- [ ] Confirm the proposed custom demo message with the team

See `evidence/fr10-fr11/manifest.json` for case results and verification settings.

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

- [x] **Video cover object** (Ke Ying) — `video_codec.load_avi` / `save_avi` (audio-track embedding, AVI
      container), `CoverKind.video` / `VideoInfo` in `schemas.py`, `.avi` MIME in `storage.py`, and
      the Protect/Verify/Attack Lab pages + `VideoCompare.tsx` all done; `tests/test_video_codec.py`
      is green (5/5).
  - [x] Wired through `pipeline.protect` / `pipeline.verify` (workstream E) — `cover_kind == "video"`
        is handled alongside image/audio in both directions.
- [x] **Robust embedding** — `ecc.py` implements a repetition code: `pipeline.ProtectOptions
      .redundancy` (default 1, off) embeds the frame's header and body as two separate blocks of
      `redundancy` back-to-back copies each, and `extraction.extract_frame` majority-votes each
      block back to one copy before handing it to the unmodified `container.parse_header`/
      `parse_frame`. Redundancy=1 is byte-for-byte identical to before this existed — zero risk to
      the rest of the pipeline. `tests/test_robust_embedding.py` proves the actual claim: a
      localized attack that breaks verification at redundancy=1 is fully recovered at redundancy=3
      (2 of 3 body copies survive), while wiping 2 of 3 copies, or a wrong redundancy guess in
      either direction, correctly still fails. Trade-off: capacity cost is linear in `redundancy`
      (3x frame size at redundancy=3). Not wired into the API/CLI/GUI yet — usable today via
      `pipeline.protect`/`verify` and proven by pytest; exposing it as a Protect-tab option is a
      natural follow-up.
- [x] **Attack simulation module** — covered by workstream F (Kannon): tampering, payload
      corruption, LSB scrub, re-encode, crop and replay/substitution in `attacks.py`, with wrong key
      and wrong start location shown through Verify. Overlaps workstream F. Extend `attacks.py` beyond the six
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
