# Contribution and distribution statement

**INF2005 ACW1 · Team P6-8** (confirm the team number against xSite before submission)

> **Status: responsibilities filled in, percentages NOT yet agreed.** Spec Section 9 requires an
> "agreed statement signed or acknowledged by all members showing each member's responsibilities and
> percentage contribution", due **one day before the demo**. The responsibilities below are compiled
> from the team's task allocation (README "Task ownership"), the owners recorded in `TODO.md`, and
> the git history. The percentage column is a starting point for discussion only — the team fills in
> the agreed figures together, and each member then acknowledges the whole table.

## Responsibilities

| Member | Responsibilities | Main evidence in the repository |
| --- | --- | --- |
| **Ang Ke Ying** | FR1 image input and FR2 audio input (PNG/WAV codecs); the web GUI's case-file visual design; optional challenges: **video cover object** (AVI audio-track embedding) and **steganalysis** (chi-square + byte-phase method); the `stego` command-line interface | `backend/stego_core/image_codec.py`, `audio_codec.py`, `video_codec.py`, `cli.py`, `steganalysis.py` (method); `scripts/steganalysis.py`; `.impeccable.md`; `backend/tests/test_image_codec.py`, `test_audio_codec.py`, `test_video_codec.py`, `test_cli.py` |
| **Chng Zong Han** | FR5/FR6 LSB embedding engine; stable media hash and passphrase KDF; frame container; FR7 start-location derivation; FR10 verdict decision table; the end-to-end protect/verify pipeline and the capacity/protect/verify API routes; FR13 start-location design | `backend/stego_core/lsb.py`, `hashing.py`, `kdf.py`, `container.py`, `location.py`, `verdict.py`, `pipeline.py`; `backend/app/routers/capacity.py`, `protect.py`, `verify.py`; `backend/tests/test_lsb_roundtrip.py`, `test_verdicts.py`, `test_api.py` |
| **Kannan s/o Rajamohan** | Section F Attack Lab (six attacks, the attack API and GUI guidance) and its evidence; FR11 positive/negative verification tests and evidence; Section G design documents; the encrypted-message verification fix | `backend/stego_core/attacks.py`, `backend/app/routers/attack.py`, `backend/tests/test_attacks.py`, `test_message_decryption.py`; `scripts/generate_verification_evidence.py`; `evidence/section-f.md`, `evidence/fr10-fr11/`; `docs/design/attack-lab.md`, `threat-model.md`, `verdict-table.md`, `payload-format.md`, `limitations-and-ai-use.md` |
| **Loh Wen Xuan** | FR3 payload structure, canonical serialization and AES-256-GCM message encryption; FR4 Ed25519 digital signature; FR12 curated samples, the sample generator and the README "Expected outputs"; the demo-plan running order; optional challenge: **robust embedding** (repetition code) | `backend/stego_core/payload.py`, `signing.py`, `ecc.py`; `backend/tests/test_payload.py`, `test_signing.py`, `test_ecc.py`, `test_robust_embedding*.py`; `scripts/make_samples.py`; `samples/`; `evidence/logs/sample-manifest.json`; `docs/demo-plan.md` |
| **Muhammad Ridwan Putra Jasni** | FR7 explicit/derived start validation and bounded recovery; FR8 bounded frame extraction and strict payload decoding; FR9 hash-verification tests and hardening; the FR7–FR9 design documents | `backend/stego_core/extraction.py`, `location.py` (validation/recovery); `backend/tests/test_extraction*.py`, `test_start_location_workflows.py`, `test_location*.py`, `test_hashing.py`, `test_hash_verification_workflows.py`; `docs/design/start-location.md`, `extraction.md`, `hash-verification.md`, `fr7-fr8-contributions.md` |
| **Yeo Kai Yuan** | Project architecture and scaffold (web UI shell, FastAPI API contract, `stego_core` module structure with specified stubs, setup/dev/demo/check scripts, `TECH_STACK.md` and the workstream plan in `TODO.md`); optional challenge: **advanced start-location security** (the sealed frame); FR11/FR12 party A → party B transfer evidence (with Kannan) and the GUI screenshot evidence; demo-readiness GUI work (hand-off card, demo-sample loader, steganalysis tab, AVI playback, theme/font and media-ID fixes); submission admin (this statement, the declaration, demo-plan slots) | commit `c66d412` (scaffold); `backend/stego_core/sealing.py`, `backend/tests/test_sealed_frame*.py`, `test_attack_sealed_api.py`, `docs/design/start-location.md` §7; `backend/app/routers/samples.py`, `preview.py`, `keys.py` (public-key list, inspect fix); `frontend/src/components/HandoffCard.tsx`, `pages/SteganalysisPage.tsx`, `components/EvidenceStrip.tsx`; `scripts/transfer_demo.py`, `evidence/transfer.md`; `scripts/capture_screenshots.py`, `evidence/screenshots/gui/`; `scripts/make_video_cover.py` |

FR12 (evidence and reproducibility) is shared by all six members, as the task allocation says.

## Percentage contribution

Percentages must add up to 100 %. The "starting point" column is an equal split, not a claim by
anyone; replace it with the figures the team agrees.

| Member | Starting point | Agreed % | Acknowledged (signature or initials, date) |
| --- | --- | --- | --- |
| Ang Ke Ying | 16.67 % | | |
| Chng Zong Han | 16.67 % | | |
| Kannan s/o Rajamohan | 16.67 % | | |
| Loh Wen Xuan | 16.67 % | | |
| Muhammad Ridwan Putra Jasni | 16.67 % | | |
| Yeo Kai Yuan | 16.67 % | | |
| **Total** | 100 % | 100 % | |

## Acknowledgement

By signing or initialling above, each member confirms that the responsibilities listed for them
are accurate, that they can explain their own technical contribution in the demo (rubric
criterion 6), and that they agree with the percentage distribution.
