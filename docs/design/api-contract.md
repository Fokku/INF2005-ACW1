# Message decryption in verification responses

`PayloadInfo` in `backend/app/schemas.py` and `frontend/src/types.ts` separates
signed encryption metadata from the result of the current verification request:

| Field | Meaning |
| --- | --- |
| `message_encrypted` | The signed message was encrypted by the sender |
| `message_decrypted` | This request successfully decrypted that message; defaults to false |
| `decryption_error` | Missing/wrong-passphrase guidance, or null |
| `message_text` | Readable text only; null while encrypted content is locked |
| `message_file` | Download of readable message bytes; null while locked |

An Authentic verdict covers signature/media integrity, independently of decryption.
Explicit-offset requests may verify authenticity without a passphrase, but cannot
return plaintext until the correct passphrase is supplied. Derived-mode requests
also need the passphrase to locate the frame. Protect responses have not performed
decryption and leave `message_decrypted` false.

The GUI exposes Message passphrase in explicit mode and displays “Decrypted” only
when `message_decrypted` is true. Missing/wrong passphrases show a locked message
and no download. Successful text decryption produces both a readable preview and
an exact plaintext download. The embedded frame and cryptographic formats are
unchanged; existing stego attachments and public keys can be reused.

`backend/tests/test_message_decryption.py` covers PNG/WAV, explicit/derived starts,
plaintext/encrypted messages, absent/wrong/correct passphrases and text/binary
downloads (32 cases). The full suite passed 629 tests after this change.
Chrome checks also exercised the saved FR11 PNG/WAV attachments with absent,
wrong and correct passphrases and compared the actual text downloads byte-for-byte.
These local checks do not replace the teammate's pending transfer retest.

The earlier API evidence supplied a passphrase directly and did not exercise the
hidden GUI input or misleading encrypted/decrypted badge. It was insufficient to
establish that the GUI decryption workflow worked. The older archived manifest
records that historical API run; it is not regenerated or presented as post-fix evidence.

# Robust embedding (number of copies)

`/api/capacity`, `/api/protect` and `/api/verify` accept an optional `redundancy`
form field: how many copies of the frame are embedded (see `stego_core/ecc.py`).
It must be an odd number from 1 to 9 (400 otherwise) and defaults to 1, which is
the original single-copy behaviour. Like the LSB count, party B must send the same
value party A used.

| Response | Field | Meaning |
| --- | --- | --- |
| `CapacityReport` | `redundancy` | Copies counted; `fits` and `max_message_bytes` assume that many copies |
| `ProtectResult` | `redundancy` | Copies that were embedded |
| `VerifyReport` | `redundancy` | Copies the verifier expected |

The GUI shows a "Copies embedded" selector (1/3/5) on Protect and Verify. The Attack
Lab's `lsb_noise` attack flips 0.1% of the hidden low bits without changing the
visible content: a 1-copy file then verifies as Tampered, a 3- or 5-copy file still
verifies as Authentic. `backend/tests/test_robust_embedding_api.py` covers this flow.
