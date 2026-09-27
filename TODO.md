# TODO

Work is grouped into **9 workstreams** (plus K, demo readiness). Each one is a self-contained chunk
with its own files and an `Owner` line.

**Status (2026-09-27):** every implementation stub is done (`grep -rn "TODO(team)" backend frontend
scripts` finds nothing), 938 backend tests pass, and a Playwright run asserts 38 GUI scenes. What is
still open is team-only: the live email transfer screenshots, signatures, agreed percentages,
AI-use confirmations and rehearsals — see the unticked boxes in G, H and I.

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

Owner: Zong Han (`hashing.py`, `kdf.py`, done); Wen Xuan (`signing.py`, `payload.py` — FR3/FR4, done)

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

Owner: Zong Han (pipeline + capacity/protect/verify routers done); Kannon (attack router done); CLI done.

Do this after A–D. It is mostly plumbing.

- [x] `pipeline.protect` — hash, build payload, sign, frame, capacity check, choose start, embed
      (image, audio, and video covers)
- [x] `pipeline.verify` — resolve start, parse, check signature, recompute hash, decide
      (image, audio, and video covers)
- [x] `capacity`, `protect`, `verify`, `keys` routers wired to the real pipeline/`signing` functions
- [x] `attack` router / `attacks.py` — Kannon, see workstream F
- [x] `stego` CLI commands: `keygen`, `capacity`, `protect`, `verify`, `tamper`
      (`stego_core/cli.py`; `tests/test_cli.py` — 16/16 green, exercises real PNG/WAV covers;
      `keygen` refuses to overwrite an existing key file without `--force`)
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
      see the confirmation checklist in `limitations-and-ai-use.md` (Kai Yuan's entry is recorded;
      every member still confirms their own)

## H · Samples, evidence and test cases — `samples/`, `evidence/`, `scripts/make_samples.py`

Owner: Wen Xuan (script + samples done; screenshots and the email round trip still open)

The spec needs **at least 2 positive and 3 negative cases**, with at least one of each per cover
object. `scripts/make_samples.py` now produces all 7 (plus `Cannot Verify`, proven separately in
`test_attacks.py` — see README):

| # | Cover | Case | Expected |
| --- | --- | --- | --- |
| 1 | image | protect → verify with the right key and passphrase | Authentic |
| 2 | audio | protect → verify with the right key and passphrase | Authentic |
| 3 | image | edit pixels after protecting | Tampered |
| 4 | audio | verify with a different public key | Signature Invalid |
| 5 | audio | verify an untouched cover | Payload Missing |
| 6 | image | verify with the wrong passphrase | Wrong Start Location |
| 7 | image | payload larger than the cover | capacity error, blocked before embedding |

- [x] Source one PNG (512×512 or larger) and one 16-bit PCM WAV (5 s or longer) — generated
      deterministically by `scripts/make_samples.py` (fixed RNG seed), not hand-sourced
- [x] Three payload sizes: a Learning Outcome (short), the Project Overview paragraph (large),
      and the team's custom encrypted message — all three under `samples/payloads/`, embedded for
      both cover types
- [x] Produce the original, stego and tampered files for both cover types — 18 files under `samples/`
- [x] `scripts/make_samples.py` so every sample regenerates deterministically — the cover files and
      demo key pair are fixed across runs; every case re-verifies to the same verdict on every run
      (nonce/timestamp inside the signed payload vary by design, so stego bytes are not literally
      byte-identical — see the script's docstring)
- [x] README's "Expected outputs" table — every sample file, its settings, and its verdict
- [x] Screenshots of each verdict — Kai Yuan: `scripts/capture_screenshots.py` drives the real GUI
      (Playwright) through all six verdicts for image and five for audio (Cannot Verify is
      image-only: there is no audio Cannot Verify sample) plus the capacity, transfer, attack,
      robust, sealed, steganalysis and video flows, asserting each one — 38/38 in
      `evidence/screenshots/gui/` (index: its `README.md`)
- [x] The party A → party B run, recorded — Kai Yuan: `scripts/transfer_demo.py` sends a real
      RFC 5322 email with both stego files as MIME attachments over SMTP to a Maildir, party B
      extracts and verifies them; SHA-256 identical, Authentic, message decrypts; wrong passphrase
      and a one-bit tamper caught (`evidence/transfer.md`); the GUI run repeats it across two
      browser sessions with the SHA-256 compared on screen
- [ ] The same run live between two machines over a real mail provider, with screenshots — at
      rehearsal (checklist in `evidence/transfer.md`)

### FR11 testing, demonstration and evidence — Kannon (transfer pending)

Builds on the team's implementation, including Zong Han's FR10 verdict logic.

- [x] PNG/WAV checks for all six verdicts, with short, large and encrypted custom messages
- [x] Exact message recovery, wrong/missing passphrase checks and oversized-payload rejection
- [x] 18 automated API cases passing; samples, public keys and reports in `evidence/fr10-fr11/`
- [x] Reproduction script: `scripts/generate_verification_evidence.py`
- [x] Fix explicit-mode passphrase entry, decryption status and readable downloads;
      32 regression cases and PNG/WAV browser checks passed (629 backend tests total)
- [x] Party A → Party B attachment transfer and received-file verification, recorded locally
      (with Kai Yuan — `evidence/transfer.md`)
- [ ] The live two-machine transfer screenshots (demo row 6, at rehearsal)
- [ ] Confirm the proposed custom demo message with the team

See `evidence/fr10-fr11/manifest.json` for case results and verification settings.

## I · Submission and demo — `README.md`, `docs/demo-plan.md`

Owner: Wen Xuan (README "Expected outputs" and `docs/demo-plan.md` running order done; the rest —
team number, declaration, contribution statement, rehearsal — is a whole-team action, not one owner)

Can start now.

- [x] Team number filled in as `P6-8` (the `TEAM_ID` in `scripts/make_samples.py`) — confirm on xSite
- [ ] Fill in the exact Week 5 dates once the schedule is published
- [x] Demo plan: ≤ 25 minutes (24 planned), a slot for every member, proposed from FR ownership in
      `docs/demo-plan.md` — Kai Yuan
- [ ] Confirm or swap the demo-plan slots at the first rehearsal
- [ ] Declaration of Originality, signed by all six (`docs/declaration-of-originality.md` is ready)
- [ ] Contribution/distribution statement: responsibilities are filled in per member
      (`docs/contribution-distribution-statement.md`, Kai Yuan); the **percentages still need
      agreeing** and every member acknowledges
- [x] Complete the README's "Expected outputs" section — every sample, its command, its verdict
- [x] `keys/public/*.pem` committed; no private key anywhere in git history (checked for Ed25519
      PKCS#8 key material across every revision; `scripts/package_submission.sh` re-checks)
- [x] Ship `frontend/dist` in the submission: `./scripts/package_submission.sh` builds the UI and
      zips it with the committed tree into `dist/P6-8-ACW1-submission.zip`
- [ ] Rehearse twice on the actual lab PC, including the email round trip
      (`scripts/capture_screenshots.py` is the automated dry run to do first)

**Deadlines:** demo plan + declaration + contribution statement are due **one day before the demo**.
Code, README, samples, evidence and keys are due **Week 5 Friday**.

---

## J · Optional challenges (bonus, spec Section 8)

Owner: Ke Ying (video cover object, done; steganalysis, done); Wen Xuan (robust embedding, done);
Kai Yuan (advanced start-location security, done)

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
      (3x frame size at redundancy=3). In the GUI: a "Copies embedded" selector (1/3/5) on Protect
      and Verify, the capacity meter counts every copy, and the Attack Lab's `lsb_noise` attack
      flips 0.1% of the hidden low bits. Demo: 1 copy + `lsb_noise` gives Tampered, 3 or 5 copies
      + `lsb_noise` still gives Authentic (`tests/test_robust_embedding_api.py`). `corrupt_payload`
      and `replay` are told the copy count (`redundancy` on `POST /api/attack`, `--copies` on
      `stego tamper`, the Attack Lab's Copies field) and change or carry every copy, so they still
      give Tampered on a 3- or 5-copy file, sealed or not (`tests/test_attack_redundancy.py`).
      Honest limit: JPEG re-encoding or audio resampling defeats every copy, since they rewrite all
      low bits.
- [x] **Attack simulation module** — covered by workstream F (Kannon): tampering, payload
      corruption, LSB scrub, re-encode, crop and replay/substitution in `attacks.py`, with wrong key
      and wrong start location shown through Verify. Overlaps workstream F. Extend `attacks.py` beyond the six
      required functions to also simulate wrong-key verification, payload corruption, wrong
      start-location extraction, and replay/substitution attempts, each asserting the verdict
      `attacks.EXPECTED` predicts.
- [x] **Advanced start-location security** (Kai Yuan) — the **sealed frame**: on top of the keyed
      HMAC start, the whole embedded frame (magic, header, payload, signature, CRC) is encrypted with
      AES-256-CTR under a third passphrase-derived key and a fresh 12-byte nonce, so nothing in the
      LSB plane can be scanned for or read without the passphrase; Verify detects it automatically.
      `stego_core/sealing.py`, `tests/test_sealed_frame*.py`, `tests/test_attack_sealed_api.py`;
      GUI option "Seal the frame"; limitations evaluated in `docs/design/start-location.md` §7
      (wrong passphrase now reads as Payload Missing / Cannot Verify; CTR is malleable so integrity
      still rests on the CRC + signature; chi-square steganalysis still sees *that* data is there).
- [x] **Steganalysis** (Ke Ying) — using a known algorithm or methodology (e.g. chi-square attack, RS
      analysis, LSB histogram analysis), analyse one of the project's own stego samples and
      convincingly infer whether the cover shows signs of a hidden payload. Write up the method
      and result, ideally as a script under `scripts/` plus a short section in
      `docs/design/limitations-and-ai-use.md`. Done: `scripts/steganalysis.py`, `evidence/logs/steganalysis-demo.txt`.

## K · Demo readiness — GUI, evidence tooling, admin

Owner: Kai Yuan (done)

A click-through of the real app found issues that would have broken the live demo; all fixed and
covered by the Playwright run:

- [x] Default protect → download → verify reported **Wrong Start Location** for a correct file:
      Protect defaulted the media ID to the cover's name, Verify to the downloaded file's name
      (`*.stego.png`). Protect now shows the media ID, Verify guesses it from the file name, and the
      hand-off card / **Verify this file →** carries the exact settings across
- [x] The team's `casefile` theme was overridden by `data-theme="dark"` (amber accent rendered
      indigo); "Big Shoulders Condensed" is not a Google Fonts family (headings fell back to the
      system font). Theme fixed; all three fonts now bundled — no CDN, works offline on the lab PC
- [x] Browsers cannot play AVI: the video cover's players stayed blank. The payload-carrying audio
      track is now played instead (`POST /api/preview/audio-track`); demo AVI cover built by
      `scripts/make_video_cover.py`
- [x] `POST /api/keys/inspect` took a query parameter while the UI sent a form (422) — fixed; the
      Keys tab now checks fingerprints and lists the committed public keys
- [x] Capacity meter could say a message fits when Protect then refused it: `/api/capacity` now
      measures the signed JSON (real media ID and metadata), encryption, every copy and the start
      offset the way Protect pays them, so its largest message protects and one byte more does not
      (`tests/test_capacity_accuracy.py`)
- [x] Steganalysis (Ke Ying's method) exposed as `POST /api/steganalysis` and a fifth GUI tab with
      a per-window evidence chart
- [x] Demo speed: one-click **Load a demo sample** on Verify (settings from the sample manifest,
      `GET /api/samples`, every case asserted by `tests/test_samples_api.py`), committed-key picker,
      SHA-256 "same bytes" check, "What to check" hints, Attack Lab → **Verify the damaged file**
- [x] `scripts/demo.ps1` for Windows lab PCs; `scripts/package_submission.sh` for the final archive

---

## Definition of done

A workstream is finished when its tests pass, `grep -rn "TODO(team)"` finds nothing in its files,
and the person who wrote it can explain it without notes — rubric criterion 6 is 5 individual marks
for exactly that.
