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

# Sealed frame (advanced start-location security)

Optional challenge, owner Yeo Kai Yuan. Design, verdict trade-offs and limits are in
[start-location.md §7](start-location.md#7-advanced-start-location-security-sealed-frames-optional-challenge-owner-yeo-kai-yuan);
the primitives are in `stego_core/sealing.py`.

| Endpoint | Field | Meaning |
| --- | --- | --- |
| `POST /api/protect` | `seal_frame` (form, bool, default false) | Encrypt the whole frame with AES-256-CTR under `K_seal` and a random 12-byte nonce, so no plaintext magic or header is embedded. Needs a passphrase in both start modes (400 otherwise) |
| `POST /api/capacity` | `seal_frame` (form, bool, default false) | Adds the 12-byte nonce per copy to `frame_overhead_bytes`, `max_message_bytes` and `fits` |
| `POST /api/attack` | `sealed` (form, bool, default false) | `corrupt_payload` and `replay` run their key-less variants from `start_offset`. Without it they return 400 on a sealed file, since they cannot read its encrypted header |

| Response | Field | Meaning |
| --- | --- | --- |
| `ProtectResult` | `sealed` | The frame was sealed; `frame_bytes` includes the nonce |
| `VerifyReport` | `sealed` | `true`: a sealed frame was opened. `false`: a plaintext frame was found. `null`: no frame was located. With a sealed file, a wrong passphrase or media ID also gives `null` (Payload Missing, or Cannot Verify on a cover too large to scan fully) |

Verify takes no new input: it tries the plaintext magic first, then the seal when a
passphrase was supplied. Tests: `backend/tests/test_sealed_frame_api.py`,
`backend/tests/test_attack_sealed_api.py`.

# Signer public key in Protect results

`ProtectResult` also returns the public half of the private key that signed, so the
GUI can hand it to party B without a separate key file:

| Field | Meaning |
| --- | --- |
| `signer_public_key_pem` | SPKI PEM of the signing key, in the same form `signing.generate_keypair` writes |
| `signer_fingerprint` | SHA-256 hex of its DER SubjectPublicKeyInfo, the same value as `KeyInfo.fingerprint` |

Both are required fields. The private key itself is never returned.

# Capacity boundary

`CapacityReport.max_message_bytes` now rounds the room left after the frame overhead
down to whole base64 groups (4 encoded bytes carry 3 raw bytes) before converting it.
The earlier formula could advertise up to 2 bytes more than fit, so a message of
exactly `max_message_bytes` could be reported with `fits: false`. A message of that size
now fits and one byte more does not
(`test_capacity_max_message_bytes_agrees_with_fits_at_the_boundary`).

# Demo samples

Read-only endpoints for the curated files under `samples/` (`backend/app/routers/samples.py`):

| Endpoint | Returns |
| --- | --- |
| `GET /api/samples` | A list of `SampleCase`: every verifiable case in `evidence/logs/sample-manifest.json`, plus an image Cannot Verify case (the full-size unprotected cover). Cases whose file is missing are left out; no manifest gives an empty list |
| `GET /api/samples/file/{path}` | The sample file, served inline with its PNG/WAV/AVI MIME type |

`SampleCase` carries everything needed to reproduce the verdict: `id`, `label`, `kind`,
`file`, `url`, `expected_verdict`, `media_id`, `n_lsb`, `start_mode`, `explicit_start`,
`passphrase`, `public_key` (a file name under `keys/public/`), `redundancy` and `note`.
The Signature Invalid cases reuse the short-message stego file with
`section-f-demo.pub.pem`, a committed key that never signed `samples/`. With the
committed manifest the list has 15 cases: seven image, seven audio and the Cannot
Verify case.

The file route resolves the path and returns 404 unless it stays inside `samples/`
and ends in `.png`, `.wav` or `.avi`, so `../` traversal and non-media files are
refused. Tests: `backend/tests/test_samples_api.py`, which also verifies every listed
case against its advertised verdict.

# Public keys and key inspection

| Endpoint | Change |
| --- | --- |
| `GET /api/keys/public` | New. Lists the committed `keys/public/*.pem` as `PublicKeyFile` (`name`, `fingerprint`, `public_key_pem`, `url`). Unparseable files are skipped; `keys/private/` is never read |
| `GET /api/keys/public/{name}` | New. Downloads one of those files. Only the base name is used, and anything that is not an existing `.pem` in `keys/public/` is 404 |
| `POST /api/keys/inspect` | `public_key_pem` is now a **form** field. It was declared as a query parameter, so the frontend's form request got 422. A PEM that is not a usable Ed25519 public key returns 400 with a "not a usable public key" detail |

Tests: `test_public_keys_are_listed_with_fingerprints_and_no_private_keys`,
`test_public_key_route_refuses_traversal` and
`test_inspect_accepts_form_pem_and_rejects_garbage` in `backend/tests/test_samples_api.py`.

# Steganalysis

`POST /api/steganalysis` (`backend/app/routers/steganalysis.py`) judges a PNG, WAV or
AVI without any key, passphrase or settings. The method is Ke Ying's; the analysis moved
from `scripts/steganalysis.py` into `stego_core/steganalysis.py`, which the script now
imports. See [Steganalysis of our own output](limitations-and-ai-use.md#steganalysis-of-our-own-output).

| Input | Meaning |
| --- | --- |
| `file` | PNG, WAV or AVI (an AVI is analysed through its PCM audio track). Anything else is 415 |
| `window` (form, default 4096, minimum 256) | Elements per window; below the minimum is 422. A file shorter than the window (but with at least 256 elements) is analysed as one window |

`SteganalysisReport` (defined in the router, since no other endpoint uses it):

| Field | Meaning |
| --- | --- |
| `suspicious`, `verdict`, `summary` | Overall call and its plain-language explanation |
| `elements`, `window`, `kind`, `filename` | What was analysed and at which window size |
| `chi_square_p` | Whole-file pairs-of-values p-value |
| `phase_p` | Smallest per-window byte-phase p-value |
| `phase_n_lsb_guess` | Rough LSB-count guess (1, 2 or 4), null unless suspicious |
| `suspected_region` | `start`/`end` of the flagged run, or null |
| `windows` | Per-window `start`, `end`, `chi_square_p`, `phase_p`, `flagged` (byte-phase p below 1e-6) |
| `windows_total`, `windows_flagged` | Counts at full resolution |
| `windows_merged` | Windows per `windows` entry. Above 400 windows, neighbours are merged for the chart, keeping the most suspicious values and flagged if any member was; the counts and region stay exact |
| `method` | Description of the tests used |

The analysis runs in a worker thread. Tests: `backend/tests/test_steganalysis_api.py`.

# AVI audio-track preview

`POST /api/preview/audio-track` (`backend/app/routers/preview.py`) takes an AVI as
`file` and returns a `FileRef` to its PCM audio track re-wrapped as a WAV
(`<name>.audio-track.wav`). Browsers cannot play AVI, and the payload lives in that
track, so the GUI plays it for the cover-versus-stego comparison. It is display only:
the WAV is never used for embedding or verification. A file that is not a readable AVI
is 415. Tests: `backend/tests/test_preview_api.py`.
