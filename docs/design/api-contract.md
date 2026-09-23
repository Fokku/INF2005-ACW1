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
