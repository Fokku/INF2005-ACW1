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

`/api/capacity`, `/api/protect`, `/api/verify` and `/api/attack` accept an optional
`redundancy` form field: how many copies of the frame are embedded (see
`stego_core/ecc.py`). It must be an odd number from 1 to 9 (400 otherwise) and
defaults to 1, which is the original single-copy behaviour. Like the LSB count,
party B must send the same value party A used.

| Response | Field | Meaning |
| --- | --- | --- |
| `CapacityReport` | `redundancy` | Copies counted; `fits` and `max_message_bytes` assume that many copies |
| `ProtectResult` | `redundancy` | Copies that were embedded |
| `VerifyReport` | `redundancy` | Copies the verifier expected |

On `POST /api/attack`, `redundancy` is the copy count the target was protected
with. It is validated for every attack kind, but only `corrupt_payload` and `replay`
read the frame and use it. Unsealed, `corrupt_payload` flips the same payload bit in
every body copy, so the majority vote keeps the change, and `replay` carries the whole
multi-copy region, every header and body copy, into the other cover. Both then give
Tampered, as `expected_verdict` says. Sent with the wrong count (or left out on a
multi-copy file), the plaintext variants return 400 with a detail naming the copy
count the file was embedded with, for example "... embedded as 3 copies parses
there; rerun corrupt_payload with redundancy 3 (CLI: --copies 3)". For the sealed
variants see "Sealed frame" below.

The GUI shows a "Copies embedded" selector (1/3/5) on Protect and Verify, and a
Copies field in the Attack Lab, filled in from the target it was handed. The Attack
Lab's `lsb_noise` attack flips 0.1% of the hidden low bits without changing the
visible content: a 1-copy file then verifies as Tampered, a 3- or 5-copy file still
verifies as Authentic (the GUI overrides the backend's single-copy prediction for
this one attack). `backend/tests/test_robust_embedding_api.py` covers this flow, and
`backend/tests/test_attack_redundancy.py` covers `corrupt_payload` and `replay` at
3 and 5 copies, sealed and unsealed.

# Sealed frame (advanced start-location security)

Optional challenge, owner Yeo Kai Yuan. Design, verdict trade-offs and limits are in
[start-location.md §7](start-location.md#7-advanced-start-location-security-sealed-frames-optional-challenge-owner-yeo-kai-yuan);
the primitives are in `stego_core/sealing.py`.

| Endpoint | Field | Meaning |
| --- | --- | --- |
| `POST /api/protect` | `seal_frame` (form, bool, default false) | Encrypt the whole frame with AES-256-CTR under `K_seal` and a random 12-byte nonce, so no plaintext magic or header is embedded. Needs a passphrase in both start modes (400 otherwise) |
| `POST /api/capacity` | `seal_frame` (form, bool, default false) | Counts the 12-byte nonce in every copy for `frame_overhead_bytes`, `max_message_bytes` and `fits` |
| `POST /api/attack` | `sealed` (form, bool, default false) | `corrupt_payload` and `replay` run their key-less variants from `start_offset`, which must be the real start (they cannot find or check the frame). Without it they return 400 on a sealed file, since they cannot read its encrypted header. With `redundancy` > 1, the sealed `corrupt_payload` flips the encrypted version byte in every 25-byte header-block copy (the body copies' spacing is unreadable without the key), and the sealed `replay` carries every copy; both still give Tampered |

| Response | Field | Meaning |
| --- | --- | --- |
| `ProtectResult` | `sealed` | The frame was sealed; `frame_bytes` includes the nonce |
| `VerifyReport` | `sealed` | `true`: a sealed frame was opened. `false`: a plaintext frame was found. `null`: no frame was located. With a sealed file, a wrong passphrase or media ID also gives `null` (Payload Missing, or Cannot Verify on a cover too large to scan fully) |

Verify takes no new input: it tries the plaintext magic first, then the seal when a
passphrase was supplied. In the GUI, a sealed file handed to Verify from Protect or
the Attack Lab arrives without the passphrase of a live Protect, so Verify disables
**Extract and verify** until the passphrase is typed. Tests:
`backend/tests/test_sealed_frame_api.py`, `backend/tests/test_attack_sealed_api.py`,
`backend/tests/test_attack_redundancy.py`.

# Signer public key in Protect results

`ProtectResult` also returns the public half of the private key that signed, so the
GUI can hand it to party B without a separate key file:

| Field | Meaning |
| --- | --- |
| `signer_public_key_pem` | SPKI PEM of the signing key, in the same form `signing.generate_keypair` writes |
| `signer_fingerprint` | SHA-256 hex of its DER SubjectPublicKeyInfo, the same value as `KeyInfo.fingerprint` |

Both are required fields. The private key itself is never returned.

# Capacity accuracy

`POST /api/capacity` used to add a flat 300-byte allowance for the signed JSON and
ignore the start offset and encryption, so the meter could show a message as fitting
that `/api/protect` then refused. It now takes the same form fields as Protect for
everything that changes the frame's size or where it starts, and counts each cost the
way `pipeline.protect` pays it (`backend/app/routers/capacity.py`):

| Field (form) | Default | Meaning |
| --- | --- | --- |
| `payload_bytes` | none | Size of the message; with it the report fills in `fits`. Negative is 422 |
| `redundancy`, `seal_frame` | 1, false | As on Protect (see the sections above) |
| `media_id` | none | The media ID Protect will sign. Omitted, a 128-byte one is assumed |
| `metadata_json` | none | The metadata Protect will sign, as JSON. Omitted, 256 bytes beyond `{}` are assumed. Not valid JSON is 400, as on Protect |
| `message_mime` | `text/plain` | The message MIME type Protect will sign |
| `encrypt_message` | false | The message will be AES-GCM encrypted (28 more bytes before base64) |
| `start_mode` | `derived` | `explicit` or `derived` |
| `explicit_start` | none | Element offset in explicit mode. Missing or negative in explicit mode is 400, as on Protect |

The fixed cost is the length of a real `payload.serialize` output for an empty message
with the caller's media ID, metadata, cover shape, LSB count, MIME type and encryption
flag, plus the frame header, signature and CRC, and the seal nonce when sealed. The
message then adds its base64 length (after AES-GCM when encrypted). The report inverts
Protect's element count exactly, including the two separately rounded blocks at
redundancy > 1, and subtracts the start: the explicit one, or in derived mode the
latest offset `location.derive_start` can pick on this cover, so the answer holds for
any passphrase.

The guarantee, tested in `backend/tests/test_capacity_accuracy.py`:

- **Explicit start:** a message of exactly `max_message_bytes` protects and one byte
  more is refused. The tests cover image, audio and video covers, LSB counts from 1 to
  7, 1, 3 and 5 copies, sealed and encrypted frames, and a media ID and metadata with
  non-ASCII and escaped characters. `fits` agrees with Protect on both sides of that boundary.
- **Derived start:** `max_message_bytes` protects whatever the passphrase, and equals the
  explicit limit at the latest derivable start, so it is as large as that promise
  allows. A particular passphrase may leave room for more.
- **Media ID or metadata omitted:** the answer is still safe for a media ID of up to
  128 bytes and metadata of up to 256 bytes beyond `{}`; nothing bounds larger ones. The
  GUI always sends both, so this allowance never applies to it.

`frame_overhead_bytes` is every byte of one copy's share of the cover that the message
cannot use: the fixed frame, this message's base64 and encryption growth, and the copy's
share of the cover before the start offset and lost to element rounding. The GUI meter's
`(payload_bytes + frame_overhead_bytes) × redundancy ≤ capacity_bytes` is therefore
exactly `fits`, though the meter now takes `fits` from the report. An explicit start past
the end of the cover gives `max_message_bytes` 0 and `fits: false`.

`start_reserve_bytes` is the part of `frame_overhead_bytes` that comes from the start offset
and element rounding (the worst case when the start is derived). The GUI shows it as its own
row, "Before the start offset", and shows `frame_overhead_bytes - start_reserve_bytes` as
"Frame overhead", so a small message does not appear to carry a large frame.

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
`section-f-demo.pub.pem`, a committed key that did not sign the short-message samples
those cases pair it with (the team key did). It signed only the Section F replay files
(`samples/audio/stego/section-f-replay-source.wav`, replayed into
`samples/audio/tampered/section-f-replay.wav`), and neither is a sample case. With the
committed manifest the list has 15 cases: seven image, seven audio and the Cannot
Verify case. That is all six verdicts for image and five for audio: there is no audio
Cannot Verify case.

The file route serves only a file that some listed case names; the GUI only ever
requests `SampleCase.url`. Everything else is 404 with the detail "not a sample file".
The path is checked as a string first, before anything touches the filesystem. An empty
path, a NUL byte, a backslash, a POSIX-absolute path, a Windows drive, UNC or root anchor,
or any `..` step is refused whatever the host OS, so a hostile path can neither raise a
500 nor, on the Windows demo host, open a network share. Only then is the path resolved,
and the result must still lie inside `samples/` and end in `.png`, `.wav` or `.avi`, so
a symlink cannot lead out either. A listed case whose file is missing gives 404 "sample
not found — run scripts/make_samples.py". Tests: `backend/tests/test_samples_api.py`,
which also verifies every listed case against its advertised verdict.

# Public keys and key inspection

| Endpoint | Change |
| --- | --- |
| `GET /api/keys/public` | New. Lists the committed `keys/public/*.pem` as `PublicKeyFile` (`name`, `fingerprint`, `public_key_pem`, `url`). A file is listed only if it resolves to a file directly inside `keys/public/` (a symlink cannot lead out), holds a usable Ed25519 public key, and contains no `PRIVATE KEY` block. `cryptography` reads only the first PEM block, so a public-then-private bundle would otherwise parse as a public key. Anything else is skipped, not a 500; `keys/private/` is never read |
| `GET /api/keys/public/{name}` | New. Downloads exactly the files the listing shows. `name` must be a plain `.pem` file name: no directory part, drive, backslash or NUL, checked as a string before anything touches the filesystem. Anything else is 404 "public key not found" |
| `POST /api/keys/inspect` | `public_key_pem` is now a **form** field. It was declared as a query parameter, so the frontend's form request got 422. A PEM that is not a usable Ed25519 public key, including a key of an algorithm `cryptography` cannot load, returns 400 with a "not a usable public key" detail |

Tests: `test_public_keys_are_listed_with_fingerprints_and_no_private_keys`,
`test_public_key_route_refuses_traversal` (parametrized over hostile names),
`test_public_key_listing_and_download_skip_unusable_and_private_files`,
`test_inspect_accepts_form_pem_and_rejects_garbage` and
`test_inspect_rejects_a_key_with_an_unsupported_algorithm` in
`backend/tests/test_samples_api.py`, and the unsupported-algorithm key loaders in
`backend/tests/test_malformed_headers.py`.

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
is 415. That includes an AVI whose audio header is impossible: 0 or more than 8
channels, a sample rate of 0, or a byte rate that overflows the WAV header's 32-bit
field. `video_codec.load_avi` now rejects those, so `/api/capacity`, `/api/protect`,
`/api/verify` and `/api/steganalysis` refuse them too (415, or Cannot Verify on
Verify) instead of accepting them. A WAV writer failure is also mapped to 415 as a
backstop. Tests: `backend/tests/test_preview_api.py`,
`backend/tests/test_malformed_headers.py`.
