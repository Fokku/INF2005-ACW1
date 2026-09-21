# Section F verification evidence

Kannon manually exercised the original and all six attacks for PNG and WAV on
20 September 2026. The attached screenshots were archived unchanged during the
handoff on 21 September. Results below describe those files and settings, not a
guarantee for every possible carrier.

Common settings: 2 LSBs, explicit start 0, and the public key now saved at
`keys/public/section-f-demo.pub.pem`. PNG media ID: `kannan-test`.
WAV media ID: `kannan-audio-test`.

| Case | PNG screenshot/result | WAV screenshot/result |
| --- | --- | --- |
| Original protected file | [Authentic](screenshots/section-f/png-authentic.png) | [Authentic](screenshots/section-f/wav-authentic.png) |
| High-bit change | [Tampered; signature valid, hash differs](screenshots/section-f/png-flip-bits.png) | [Tampered; signature valid, hash differs](screenshots/section-f/wav-flip-bits.png) |
| Crop/truncate | [Tampered; hash and shape differ](screenshots/section-f/png-crop.png) | [Tampered; hash and shape differ](screenshots/section-f/wav-crop.png) |
| LSB scrub | [Cannot Verify; incomplete search](screenshots/section-f/png-lsb-scrub.png) | [Cannot Verify; incomplete search](screenshots/section-f/wav-lsb-scrub.png) |
| Re-encode | [Cannot Verify; incomplete search](screenshots/section-f/png-reencode.png) | [Cannot Verify; incomplete search](screenshots/section-f/wav-reencode.png) |
| Corrupt payload | [Tampered; CRC mismatch](screenshots/section-f/png-corrupt-payload-before-summary-fix.png) | [Tampered; CRC mismatch](screenshots/section-f/wav-corrupt-payload.png) |
| Replay | [Tampered; signature valid, hash differs](screenshots/section-f/png-replay.png) | [Tampered; existing-payload target, see caveat below](screenshots/section-f/wav-replay-existing-payload-target.png) |

## Findings and corrections

The large covers exceeded the verifier's 200,000-candidate recovery search.
Scrub and re-encode therefore correctly returned Cannot Verify when no marker
was found within that prefix. Attack guidance now explains this, and four new
large-cover regression cases preserve that behavior.

The PNG CRC screenshot predates the summary-text fix: its old sentence wrongly
claimed that the signature was valid. The detailed checks correctly show that
signature/hash verification did not run. The later WAV CRC screenshot confirms
the corrected summary. Historical screenshots were not altered.

## Stronger WAV replay evidence

The manual WAV replay used the earlier flip-bits output as its target. That file
already held the same payload; the identical output hash means it is weak evidence
of transplantation by itself.

The follow-up [automated API replay report](logs/section-f-replay.json) closes that
gap. It identifies the user's protected source by its exact screenshot SHA-256,
checks that source as Authentic, and generates an independent 660 Hz, five-second,
44.1 kHz, mono 16-bit PCM target. The target has no frame at offset 0. The real
`/api/attack` route transplants the frame; its download verifies as Tampered with
a valid signature and differing hash. The extracted signed frame is unchanged.
This is an automated follow-up, not an additional manual GUI screenshot.

Reproduce it in the GUI:

1. In Attack Lab, upload
   [the protected source](../samples/audio/stego/section-f-replay-source.wav).
2. Select [the unprotected target](../samples/audio/original/section-f-replay-target.wav)
   as the second cover; use 2 LSBs and offset 0, then run replay.
3. Verify the downloaded result with
   [the public key](../keys/public/section-f-demo.pub.pem),
   media ID `kannan-audio-test`, 2 LSBs and explicit offset 0.
4. Expect Tampered with a valid signature and mismatched media hash. The saved
   [replay output](../samples/audio/tampered/section-f-replay.wav) gives the same
   case without regenerating it. The JSON report records SHA-256 for all files.

The source audio was downloaded by Kannon from Example Files' five-second PCM
tone listing: https://examplefiles.org/example-audio-files/sample-wav-files.
The target tone was generated locally for this demonstration. No private key
is included. The PNG screenshot images were supplied by Kannon; they document
the interface and do not establish redistribution rights for the underlying art.

## Automated checks

- [Backend regression log](logs/section-f-pytest.txt): 597 tests passed, including
  139 attack tests.
- [Lint/build log](logs/section-f-checks.txt): backend lint, formatting of changed
  Python files, frontend TypeScript/production build and frontend lint.
- The four inherited formatter differences recorded in
  [the design note](../docs/design/attack-lab.md) remain outside this contribution.

This evidence completes the Section F handoff. Team-wide samples, the email
transfer demonstration, contribution agreement and timed lab rehearsal still
belong to workstreams H/I.
