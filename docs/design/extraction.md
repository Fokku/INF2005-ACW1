# FR8: Extraction and decoding

Status: the FR8 extraction helper, pipeline integration, focused tests, and this explanation are
complete. Assigned owner: Ridwan. The existing frame format, bit engine, payload serialization,
signing, hashing, encryption, and verdict table remain their original contributors' work. See the
[FR7/FR8 contribution and test record](fr7-fr8-contributions.md).

## 1. Responsibility and output

`stego_core.extraction.extract_frame(elements, start, n_lsb)` reads the frame at an FR7 location.
On success it returns an `ExtractedFrame` containing the exact serialized payload bytes, the
signature, the frame LSB depth, and the encrypted flag. Extraction by itself does not establish
authenticity; the pipeline subsequently validates the payload, signature, stable media hash, and
signed parameters.

`decode_payload` deserializes those exact payload bytes and validates field types and supported
values without reserializing them. The signature is checked against the original extracted bytes,
so harmless-looking JSON normalization cannot change what was signed.

## 2. Frame layout

All integer lengths use big-endian byte order.

| Byte offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | Magic `ACW1` |
| 4 | 1 | Frame version |
| 5 | 1 | Flags; bit 0 records message encryption |
| 6 | 1 | LSB depth, 1 through 8 |
| 7 | 4 | Serialized payload length |
| 11 | 2 | Signature length |
| 13 | variable | Canonical JSON payload bytes |
| after payload | variable | Ed25519 signature |
| final 4 | 4 | CRC32 over all preceding frame bytes |

The fixed header is 13 bytes. Ed25519 signatures are 64 bytes, so the current frame adds 81 bytes
around the serialized payload: 13 header bytes, 64 signature bytes, and four CRC bytes. This is
not the overhead relative to the user's original message because the JSON fields, base64 encoding,
and optional AES-GCM nonce/tag also consume space.

## 3. Bounded two-stage extraction

Extraction follows these steps:

1. Validate that the selected start can hold the fixed 13-byte header.
2. Extract exactly 104 bits and parse the header.
3. Reject bad magic, unsupported frame versions or flags, impossible LSB depths, empty payloads or
   signatures, an LSB mismatch with the selected extraction setting, and a signature length other
   than the expected 64 bytes.
4. Calculate the exact total frame size from the checked length fields.
5. Validate that this complete frame fits in the remaining cover before allocating or extracting.
6. Re-extract exactly the complete frame from the original start and verify its strict length and
   CRC32 before separating payload bytes and signature.

The complete frame is intentionally re-read from the original start. A header can finish part-way
through an element. For example, at three LSBs per element, a 104-bit header occupies 35 elements,
but only one bit in the final element belongs to the next section. Advancing by 35 whole elements
would discard that bit and corrupt the payload. Re-reading the exact total avoids this alignment
error for every LSB depth.

The bit engine reads the selected low bits from consecutive flattened elements, preserving the
same most-significant-bit-first order used during embedding. Padding bits in the last element are
not included because extraction returns exactly the requested bit count.

## 4. Payload validation

After strict JSON and base64 decoding, `decode_payload` enforces:

- payload version 1;
- string values for media ID, timestamp, media hash, nonce, cover kind, and message MIME type;
- a supported `image`, `audio`, or optional `video` cover kind;
- integer LSB depth from 1 through 8, equal to the frame header value;
- a Boolean encrypted flag equal to the frame header flag;
- positive integer dimensions with three values for images and two for audio/video;
- metadata whose keys and values are strings.

The pipeline then checks the Ed25519 signature over the extracted payload bytes, recomputes the
stable media hash, and compares the signed media ID, cover kind, LSB depth, and shape with the
actual verification inputs and decoded cover.

## 5. Message decryption

If the payload says the custom message is encrypted and a passphrase is supplied, the pipeline
derives `K_enc` and makes a best-effort AES-256-GCM decryption for display. The media ID is the
additional authenticated data. Successful signature and cover verification do not by themselves
prove that message decryption succeeded: an absent or incorrect decryption passphrase can leave an
otherwise authentic result displaying ciphertext. The current decryption failure is deliberately
display-only and does not alter the six existing verdict rules.

This distinction should be stated during the demo; a generic authenticity badge must not be
described as proof that encrypted content was decrypted.

## 6. Failure mapping and limitations

| Extraction observation | Existing pipeline result |
| --- | --- |
| Magic absent at expected start but found elsewhere | `Wrong Start Location` |
| Magic absent after a complete bounded search | `Payload Missing` |
| Search limit reached without finding magic | `Cannot Verify` |
| Magic present but header, length, CRC, or payload validation fails | `Tampered` |
| Frame and payload parse, but signature fails | `Signature Invalid` |
| Signature passes, but media hash or signed parameters differ | `Tampered` |
| All checks pass | `Authentic` |

These mappings reuse the team's existing verdict decision table; FR8 does not redefine FR9/FR10.
Unsupported frame or payload versions are currently reported as `Tampered` once valid magic has
been found. If the magic is destroyed, a complete scan cannot distinguish a damaged frame from a
cover that never contained one. The verifier also does not auto-detect an unknown LSB depth.

## 7. Verification scope

Focused tests cover image and audio extraction at LSB depths 1 through 8, explicit and derived
starts, exact-fit boundaries, malformed fields, impossible lengths and flags, LSB mismatches,
truncated frames, CRC failures, encrypted payloads, and all six workflow verdicts. Test commands
and current counts are recorded in the
[FR7/FR8 contribution and test record](fr7-fr8-contributions.md). Screenshots and the final manual
party-A/party-B demonstration remain with the owners of evidence and submission work.
