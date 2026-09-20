# Payload and frame format

> **Status: to be written** — workstream G. Fill this in as workstreams C and D are implemented.
> This document plus `start-location.md` and `verdict-table.md` are what rubric criterion 1
> (5 marks: "payload structure, start-location design, start-location security") is marked on.

## 1. The verification payload

Required by spec FR3: media ID, timestamp, hash, nonce and team-defined metadata.

| Field | Type | Purpose |
| --- | --- | --- |
| `version` | int | payload format version |
| `media_id` | string | identifies this media item; also salts the key derivation |
| `timestamp` | ISO-8601 UTC | when it was signed |
| `media_hash` | hex | SHA-256 of the stable representation (section 3) |
| `nonce` | hex, 16 bytes | freshness; evidence against replay |
| `cover_kind` | "image" \| "audio" | bound so a frame cannot move between media types |
| `n_lsb` | 1–8 | bound so the parameter cannot be swapped |
| `shape` | int list | `[h, w, c]` or `[frames, channels]`; bound so crops are detected |
| `message_mime` | string | how the GUI should display or play the message |
| `message` | bytes | the hidden message, plaintext or AES-256-GCM ciphertext |
| `encrypted` | bool | whether `message` is ciphertext |
| `metadata` | string map | team-defined, e.g. team number, author, purpose |

Confirmed against `stego_core/payload.py` (see `Payload`, `serialize`, `deserialize`). The table
above matches the dataclass fields exactly, with one encoding detail: `message` (raw bytes) is
carried in the JSON object under the key `message_b64`, base64-encoded, so the whole structure is
UTF-8 JSON-safe.

Canonical serialisation, byte for byte:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

`sort_keys=True` makes field order irrelevant; `separators=(",", ":")` removes the whitespace
Python's default encoder would otherwise insert; `ensure_ascii=False` keeps UTF-8 metadata (e.g. a
non-ASCII author name) as UTF-8 rather than `\uXXXX` escapes — either side would produce the same
bytes as long as both use this exact call, but pinning it removes any ambiguity. Both signer and
verifier must produce identical bytes from the same field values, or the Ed25519 signature will
not verify (`signing.py`, spec FR4) — this is why `test_payload_and_signing.py` asserts
`serialize(p) == serialize(p)` and a `serialize -> deserialize` round trip.

Malformed input (bad JSON, a missing field, a corrupt base64 blob) raises `FrameError` from
`deserialize`, which the pipeline turns into a verdict instead of crashing.

## 2. The embedded frame

TODO(team): copy the layout table from the `container.py` docstring, and state the total overhead
in bytes so the capacity numbers in the UI can be explained.

## 3. What exactly is hashed

FR9 hashes a stable representation rather than the encoded file bytes:

```text
SHA-256(canonical_json(actual_format_fields) || masked_element_bytes)
```

The low `n_lsb` carrier bits are cleared before hashing so valid embedding does not invalidate the
digest. The full algorithm, verification sequence, tests, and important masking limitations are in
[FR9: Hash verification](hash-verification.md).

## 4. Why the parameters are signed

TODO(team): explain the parameter-substitution and replay attacks that binding `n_lsb`, `shape`,
`cover_kind` and `media_id` into the signed payload prevents, and point at the Attack Lab's
`replay` case as the demonstration.
