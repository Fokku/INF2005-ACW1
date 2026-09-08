# Verdict decision table

> **Status: to be written** — workstream G, alongside `stego_core/verdict.py`.
> Keep this table and the `decide()` function in step with each other.

| # | Condition | Verdict | Test that proves it |
| --- | --- | --- | --- |
| 1 | Unsupported file, or missing/invalid public key | Cannot Verify | `test_cannot_verify` |
| 2 | No magic at the expected start, but found elsewhere | Wrong Start Location | `test_wrong_start_location` |
| 3 | No magic anywhere in the cover | Payload Missing | `test_payload_missing` |
| 4 | Magic found but CRC fails or the frame will not parse | Tampered | `test_tampered` |
| 5 | Signature does not verify | Signature Invalid | `test_signature_invalid` |
| 6 | Signature valid but the media hash or bound parameters differ | Tampered | `test_tampered` |
| 7 | Every check passes | Authentic | `test_authentic` |

The order matters: the checks are evaluated top to bottom, and the first match wins.

TODO(team): after implementing `decide()`, add a column mapping each row to the Attack Lab action
that produces it, and to the sample file in `samples/*/tampered/`.
