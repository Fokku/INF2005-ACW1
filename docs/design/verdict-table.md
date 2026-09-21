# Verification verdicts

The source of truth is [pipeline.verify](../../backend/stego_core/pipeline.py)
together with [verdict.decide](../../backend/stego_core/verdict.py). Verification
stops when a stage fails; later checks shown as a dash were not completed.

## Decision order

| Priority | Verdict | Trigger |
| --- | --- | --- |
| 1 | Cannot Verify | Unsupported cover, unusable key when checked, invalid start/settings, unexpected processing error, or an incomplete search with no magic found |
| 2 | Wrong Start Location | No magic at the supplied/derived start, but magic found elsewhere in the bounded search |
| 3 | Payload Missing | No magic at the expected start and none in a complete search of candidate starts at the selected LSB count |
| 4 | Tampered | Magic present, but frame/header/length/CRC or payload decoding fails |
| 5 | Signature Invalid | Frame and payload decode, but the signature fails against a usable supplied public key |
| 6 | Tampered | Signature valid, but the stable media hash or signed parameters do not match |
| 7 | Authentic | Frame, payload, signature, media hash and signed parameters all pass |

Priority describes the decision record, not a promise that every input is checked
before an earlier stage returns. For example, an absent payload returns before
the public key is parsed. A wrong usable public key gives Signature Invalid only
after valid extraction; malformed key material gives Cannot Verify at that stage.
CRC failures give Tampered before any signature or media-hash conclusion.

## What the results establish

**Authentic** means the selected representation matches a payload signed by the
supplied key. Trust in the key's owner must be established separately. It does not
prove every file byte is unchanged, that a message is fresh, or that encrypted
content was decrypted successfully. Decryption is best effort for display and
does not change the verdict.

**Wrong Start Location** is a diagnostic hint: the search recognizes magic, not
a fully authenticated alternate frame. It does not automatically extract or trust
the bytes found elsewhere.

**Payload Missing** applies to the chosen LSB count and element-aligned frame
format. It does not prove there is no hidden data under another encoding.

The fallback scans at most **200,000 candidate start positions**. If more
positions exist and no magic was found in the searched prefix, the answer is
**Cannot Verify**, not Payload Missing. This explains the PNG/WAV scrub and
re-encode screenshots in [Section F evidence](../../evidence/section-f.md).

**Tampered** includes malformed/corrupt data and authenticated-content mismatch;
it does not identify an attacker or prove malicious intent. A false magic match
can also lead to an invalid-frame result.

## Tests and demonstrations

All six categories have pure decision tests in
[test_verdicts.py](../../backend/tests/test_verdicts.py):
`test_authentic`, `test_tampered`, `test_signature_invalid`,
`test_payload_missing`, `test_wrong_start_location`, `test_cannot_verify`.
These exercise outcome records; they are not all manual demonstrations.

| Behaviour | Additional test evidence |
| --- | --- |
| Authentic round trip | [test_api.py](../../backend/tests/test_api.py): `test_protect_then_verify_roundtrip` |
| Changed media with valid signature | [test_hash_verification_workflows.py](../../backend/tests/test_hash_verification_workflows.py): `test_content_change_above_lsb_plane_causes_hash_mismatch_after_valid_extraction` |
| Wrong usable key versus malformed key | [test_signing.py](../../backend/tests/test_signing.py): `test_verify_fails_for_wrong_key`, `test_verify_raises_for_malformed_key`, combined with the decision tests above |
| Wrong offset/passphrase | [test_start_location_workflows.py](../../backend/tests/test_start_location_workflows.py): `test_wrong_explicit_offset_finds_non_byte_aligned_frame`, `test_wrong_passphrase_finds_frame_without_revealing_payload` |
| Complete versus incomplete absent-magic search | Same workflow file: `test_absent_payload_distinguishes_complete_and_incomplete_scan`, `test_scan_limit_does_not_claim_a_later_payload_is_missing` |
| Damaged frame and attack outcomes | [test_attacks.py](../../backend/tests/test_attacks.py): `test_attack_verdict`, `test_large_cover_attack_reports_incomplete_search`, `test_replay_preserves_signature_and_frame` |

The [Attack Lab guide](attack-lab.md) records settings and conditional predictions.
Crop can preserve or destroy the frame; re-encoding can destroy magic or leave
damaged framing. Therefore one attack name does not guarantee one verdict for all
inputs. The saved Section F screenshots demonstrate Authentic, Tampered and
Cannot Verify; they are not evidence of a manual run of every verdict category.
