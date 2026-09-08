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

TODO(team): confirm this table against `stego_core/payload.py` once implemented, and record the
canonical serialisation exactly: `json.dumps(obj, sort_keys=True, separators=(",", ":"))`, UTF-8,
message base64-encoded. Both signer and verifier must produce identical bytes or nothing verifies.

## 2. The embedded frame

TODO(team): copy the layout table from the `container.py` docstring, and state the total overhead
in bytes so the capacity numbers in the UI can be explained.

## 3. What exactly is hashed

TODO(team): write out the stable-representation formula and explain **why** it is not the file
bytes. This is the single most likely question a marker will ask.

## 4. Why the parameters are signed

TODO(team): explain the parameter-substitution and replay attacks that binding `n_lsb`, `shape`,
`cover_kind` and `media_id` into the signed payload prevents, and point at the Attack Lab's
`replay` case as the demonstration.
