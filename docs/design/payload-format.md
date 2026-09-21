# Payload and frame format

This document describes the implemented version 1 format. Sources:
[payload.py](../../backend/stego_core/payload.py),
[container.py](../../backend/stego_core/container.py),
[extraction.py](../../backend/stego_core/extraction.py) and
[pipeline.py](../../backend/stego_core/pipeline.py).

## Signed payload

The sender serializes these fields into UTF-8 JSON and signs the exact bytes with
Ed25519. The receiver verifies the extracted bytes directly; it does not rebuild
JSON before checking the signature.

| JSON field | Representation and meaning |
| --- | --- |
| `version` | Integer `1` |
| `media_id` | Sender's identifier; receiver supplies the expected identifier |
| `timestamp` | Sender-generated UTC ISO timestamp; not a trusted timestamp service |
| `media_hash` | 64 lowercase hexadecimal characters: stable SHA-256 digest below |
| `nonce` | 16 random bytes encoded as 32 hex characters, making payloads distinct |
| `cover_kind` | `image`, `audio` or `video` |
| `n_lsb` | Integer 1–8 |
| `shape` | Image: [height, width, channels]; audio/video PCM: [frames, channels] |
| `message_mime` | Message content type, such as `text/plain` |
| `message_b64` | Base64 of message bytes, or of the encrypted message envelope |
| `encrypted` | Boolean indicating message encryption |
| `metadata` | String-to-string map, such as team and purpose |

Canonical serialization is
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.
The in-memory `message` bytes become `message_b64` in JSON. Base64 provides
encoding, not secrecy. Strict extraction validates field types, version, digest
syntax, shape and agreement with the frame. Timestamp and nonce strings are not
checked against a freshness policy or a database of previously received messages.

## Binary frame

All multibyte header integers use big-endian order. Offsets are bytes from the
start of the extracted frame; N is the serialized payload length and S the signature length.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | Magic: ASCII `ACW1` |
| 4 | 1 | Frame version: 1 |
| 5 | 1 | Flags: bit 0 means encrypted; remaining bits reserved |
| 6 | 1 | LSB count, 1–8 |
| 7 | 4 | Payload length N, unsigned |
| 11 | 2 | Signature length S, unsigned |
| 13 | N | Exact signed JSON bytes |
| 13 + N | S | Signature; the extraction workflow requires Ed25519's 64 bytes |
| 13 + N + S | 4 | CRC32 of all preceding frame bytes |

The header is 13 bytes and the total is N + S + 17 bytes, or **N + 81**
with Ed25519. CRC32 detects accidental/corrupted framing; it is not authentication
and can be recomputed by an attacker. Ed25519 signs the payload, not the outer
header. Header/payload consistency checks prevent contradictory LSB and encryption
claims from being accepted.

Extraction validates the fixed header before reading the advertised body. Invalid
magic/version/flags, invalid or empty lengths, an unexpected signature length,
insufficient trailing capacity, CRC mismatch, and extra/truncated frame bytes
are rejected. See [bounded extraction](extraction.md).

## Capacity and encryption

For E carrier elements, start index s and n LSBs, available frame bytes are
`floor((E - s) * n / 8)`. A frame of F bytes needs `ceil(8 * F / n)`
elements. The actual frame must fit after its selected start; total cover capacity
alone is insufficient.

Base64 uses `4 * ceil(B / 3)` characters for B message bytes. JSON fields and
metadata add variable overhead. AES-256-GCM adds a 12-byte random IV and 16-byte
tag before Base64 encoding: `IV || ciphertext || tag`. Its associated data is
the UTF-8 media ID. Only the message is encrypted; identifiers, hash, metadata,
timestamp and signature remain visible to someone who extracts the frame.

The passphrase is processed by scrypt (N=32768, r=8, p=1, output 32 bytes), salted
with SHA-256 of the UTF-8 media ID. HKDF-Expand with SHA-256 separates the location
and encryption keys using `acw1-loc` and `acw1-enc`. See
[kdf.py](../../backend/stego_core/kdf.py) and [start location](start-location.md).
The final protect operation checks the actual frame size; the GUI capacity
estimate is not a guarantee for every metadata/message combination.

## Exact media hash

For unsigned carrier array A and LSB count n:

```text
mask = (~((1 << n) - 1)) restricted to A's dtype bit width
masked = A & mask
H = SHA256(
    json.dumps(format_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    || masked.tobytes()
).hexdigest()
```

Image format fields are `kind, height, width, channels`. Audio/video PCM fields
are `kind, rate, channels, width`, where width is bytes per sample. Images use
decoded RGB/RGBA channel bytes; 16-bit PCM uses an unsigned view of the samples.
The implementation uses the array's byte representation, without a separate
cross-platform endian normalization step.

Masking makes the digest stable across embedding. It also excludes the selected
low bits throughout the carrier, including unused areas. At 8 LSBs on uint8,
all sample values disappear from the hash. AVI hashing covers the PCM track,
not video imagery. The GUI's separate file SHA-256 hashes all file bytes and is
useful for comparing a sent attachment with its downloaded copy.

After signature verification the receiver compares this digest and the signed
media ID, kind, shape and LSB count with the supplied/actual values. Transplanting
a frame to different authenticated content is detected, but resending the same
authentic file is not prevented. See [hash verification](hash-verification.md)
and [threat model](threat-model.md).

## Checks

[Payload tests](../../backend/tests/test_payload.py) cover canonical serialization,
round trips, malformed input and AES-GCM wrong-key/data/associated-data failures.
[Signing tests](../../backend/tests/test_signing.py) cover valid signatures,
altered messages and wrong/malformed keys.
[Extraction tests](../../backend/tests/test_extraction.py) cover bounded reads,
frame damage and strict decoding.
[Hash tests](../../backend/tests/test_hashing.py) cover masking and format fields.
