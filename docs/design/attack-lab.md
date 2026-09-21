# Section F: Attack Lab and innovation

Owner: Kannon (`kannan_features`). Built on the core pipeline and Ridwan's merged
FR7–FR9 extraction and hash-verification work. This contribution implements the
six media transformations, `/api/attack`, input validation, verification tests,
and the Attack Lab's explanation of conditional predictions.

## Innovation claim

The Attack Lab makes the assignment's negative cases reproducible in the GUI.
A user chooses a protected object and an attack, downloads the altered copy,
and independently verifies it with the existing Verify workflow. The predicted
verdict is shown before verification so the user can compare prediction with
observation and explain which check detected the change.

This is an educational attack simulation module (spec Section 8), not a new
cryptographic algorithm. It demonstrates the difference between damage to the
carrier, destruction of hidden data, and transplantation of a valid signature.
The API does not sign or authenticate its output and does not label the prediction
as an observed verification result.

## Transformations and expected results

`attacks.EXPECTED` describes the demo conditions below, not a guarantee for every
input. Use the original public key, media ID and LSB count when verifying.

| Action | Transformation | Demo prediction and conditions |
| --- | --- | --- |
| `flip_bits` | XOR the highest bit in the first 10% of carrier elements; core callers may supply a half-open region | **Tampered**: the frame survives but the masked media hash changes. For 8-bit carriers, select 1–7 LSBs; the API rejects 8 because no high bit remains outside the payload plane. 16-bit PCM supports 1–8. |
| `crop` | Retain the first 90% of image rows or PCM frames | **Tampered** when the embedded frame survives: shape and hash differ. Use the original explicit start. Removing the frame may instead produce **Payload Missing**; truncating it may produce **Tampered**; an out-of-range supplied offset produces **Cannot Verify**. Derived mode can produce **Wrong Start Location** because cover length changed. |
| `lsb_scrub` | Clear the selected low bits throughout the carrier | **Payload Missing** with matching settings after a complete search; **Cannot Verify** when the cover exceeds the search budget and no magic is found in the searched prefix. More LSBs cleared can mean obvious visual/audio degradation. |
| `reencode` | PNG → JPEG (quality 65) → PNG; for PCM, retain every second sample per channel and linearly interpolate back to the original length | **Payload Missing** on the small test covers; **Cannot Verify** on the large test covers after an incomplete search. Lossy transformations may preserve some or all hidden data on other inputs, so other verdicts are possible. The algorithm does not secretly scrub bits to force a result. RGBA becomes RGB in the JPEG round trip. |
| `corrupt_payload` | Extract a valid frame, flip one bit in its payload, retain the original header and CRC | **Tampered**: CRC fails before signature verification. Incorrect LSB count/offset or an already damaged frame is rejected instead of modifying arbitrary bits. |
| `replay` | Embed the source frame, including its unchanged signature, into another cover at the supplied offset | **Tampered** when the target differs in hashed content or signed shape/format. Use the original explicit offset and media ID. An equivalent target is rejected because that would not demonstrate tampering. An undersized target is rejected before embedding. |

All six actions support PNG and WAV. Five also operate on AVI's PCM track while
preserving container and video bytes. AVI cropping is explicitly unsupported
(HTTP 415): the existing AVI writer only patches equal-length audio chunks and
cannot safely rebuild the container/index after removing samples.

## Reproducing the demo

1. In Keys, generate a throwaway key pair. Keep both downloads.
2. In Protect, select a sufficiently large PNG or WAV, a short message, 2 LSBs,
   a media ID, and explicit start 0. Download the protected object.
3. Verify that object using the matching public key, media ID, 2 LSBs and offset 0.
   It should be **Authentic** before any attack.
4. In Attack Lab, upload the protected object and copy those LSB/offset values.
   Select an attack and download its output.
5. Verify the output with the same parameters and compare the observed verdict
   and reasons with the prediction. For crop, keep the frame inside the retained
   leading rows/frames. For replay, supply a different cover of the same kind
   with enough space after offset 0; use 1–7 LSBs for an 8-bit carrier.
6. Repeat for the other media type. Section F's screenshots and replay samples
   are indexed in [the evidence record](../../evidence/section-f.md).
   Team-wide submission samples remain with H. Runtime downloads are stored under `out/`.

The user's original upload is never overwritten. Every successful API call saves
a separate file named with the attack (for example `demo.stego.flip_bits.png`).
Invalid options receive a 400/422 response; unsupported media receives 415.

## Evidence and checks

`backend/tests/test_attacks.py` contains 139 cases. It exercises real
protect → attack → verify flows and API downloads across RGB/RGBA PNG,
8/16-bit PCM, stereo PCM and synthetic AVI. It checks all 1–8 LSB counts for
payload corruption and scrubbing, unchanged signatures during replay, CRC
failure, crop loss/derived offsets, AVI byte preservation, invalid settings,
missing/mismatched replay targets and insufficient capacity. Four regression cases cover scrub/re-encode on 512×512 RGBA images and five-second 44.1 kHz WAV files; they assert Cannot Verify with no signature/hash result when the search is incomplete.

```bash
cd backend
python -m pytest -q tests/test_attacks.py
python -m pytest -q
python -m ruff check .
python -m ruff format --check stego_core/attacks.py app/routers/attack.py tests/test_attacks.py tests/test_api.py
```

The complete suite passes 597 tests: the inherited 459, minus the obsolete test
expecting `/api/attack` to return 501, plus 139 attack cases. Backend lint and
formatting of changed Python files pass. Four inherited files still fail the
repository-wide formatter check (`audio_codec.py`, `lsb.py`, `payload.py`,
`test_video_codec.py`); this contribution does not reformat teammates' code.
The frontend production build (`pnpm build`, including TypeScript) and `pnpm lint`
also pass. Kannon's PNG/WAV manual tests and the independent-target replay check
are recorded in [the evidence record](../../evidence/section-f.md).
The full team's timed demo rehearsal remains with I.

## Limits and AI-use record

The masked media hash excludes selected low bits. At 8 LSBs on an 8-bit carrier,
it excludes all sample content; this is why a high-bit demo is rejected and why
same-shape replay can be indistinguishable to the hash. A copied authentic file
also remains authentic: a random nonce and timestamp alone do not provide replay
prevention without a verifier-side freshness policy or record of prior messages.

Keyed placement is not encryption. Frame magic is searchable, CRC is an error
check rather than a security boundary, and re-encoding can destroy the payload.
AVI verification covers its PCM track and associated signed parameters, not the
video imagery. Test fixtures establish behavior for covered cases; they are not
a guarantee for every photograph, audio signal or AVI container.

Codex assisted Kannon with implementation, tests, code inspection and this
write-up. Checks exposed the need to describe crop and re-encode predictions as
conditional, reject high-bit edits when all 8 bits carry data, and use Ridwan's
bounded extraction routine. Kannon should review the code, rehearse the GUI demo,
and align this record with the team's final AI-use and contribution declarations.
The manual tests below cover Section F; no full team rehearsal or independent
code review is claimed here.

## Manual-test follow-up

The PNG screenshots supplied by Kannon show Authentic for the protected original,
Tampered for flip_bits, crop and replay, and Tampered with a CRC mismatch for
corrupt_payload. Scrub and re-encode returned Cannot Verify: the verifier searched
only the first 200,000 candidate starts. A 512×512 RGBA cover has 1,048,576 carrier
elements, so that search cannot establish absence throughout the file. This is
Ridwan's deliberate bounded-search behavior and is preserved. Attack predictions
are conditional, and the GUI now explicitly explains this outcome.

The Tampered summary now covers both damaged payloads and signed-media mismatches.
It no longer claims a valid signature when CRC failure prevented signature
verification. The detailed checks remain the authority on which checks ran.
Kannon subsequently completed the WAV baseline and all six attack runs with the
same pattern of outcomes. All 14 PNG/WAV result screenshots are archived in
`evidence/screenshots/section-f/`. The WAV replay screenshot used an already
protected target; a separate automated API replay with an independently generated
unprotected WAV confirms the stronger case. See
[the evidence index and reproduction steps](../../evidence/section-f.md).
