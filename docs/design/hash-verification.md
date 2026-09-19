# FR9: Hash verification

Status: FR9 has dedicated unit/workflow coverage, canonical digest validation, and this design
explanation. The work-split document leaves the FR9 owner cell blank. Zong Han contributed the
original stable-media-hash implementation and pipeline comparison; Ridwan added the focused tests,
hash-format boundary check, API-report verification, and documentation. The team should confirm
the final ownership wording before submission.

## 1. What FR9 verifies

FR9 answers one narrow question: does a SHA-256 digest recomputed from the received media's stable
representation equal the digest stored in the signed verification payload?

It does not decide the final user-facing verdict by itself. FR10 combines this Boolean comparison
with frame extraction, CRC, signature, and parameter checks. It also does not identify the signer;
Ed25519 signature verification provides that authentication.

## 2. Stable representation and exact formula

Hashing the PNG or WAV file bytes directly would not work. Protect necessarily changes carrier
bits, and lossless encoders may also produce different container bytes while preserving decoded
content. A raw hash of the original cover would therefore disagree with every valid stego file.

Instead, the system hashes decoded elements after clearing the exact low-bit plane reserved for
embedding:

```text
low_mask = (1 << n_lsb) - 1
masked_elements = elements AND NOT low_mask       (within the element dtype)
format_bytes = UTF8(JSON(header_fields, sorted keys, no spaces))

media_hash = lowercase_hex(
    SHA-256(format_bytes || masked_elements.tobytes())
)
```

The canonical JSON call is:

```python
json.dumps(header_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

The actual format fields are:

| Cover | Fields included before the masked elements |
| --- | --- |
| PNG image | `kind`, `height`, `width`, `channels` |
| PCM WAV audio | `kind`, `rate`, `channels`, `width` |
| Optional AVI path | `kind`, `rate`, `channels`, `width` for its PCM audio carrier |

PNG elements are flattened unsigned 8-bit channel values. Supported WAV elements are unsigned
8-bit samples or unsigned 16-bit views of signed PCM samples. Masking and hashing preserve the
array's dtype; neither operation mutates the input.

## 3. Protect and verify sequence

### Protect

1. Decode the original cover into elements and actual format fields.
2. Calculate the stable media hash using the selected `n_lsb`.
3. Store the 64-character lowercase digest in the payload's `media_hash` field.
4. Canonically serialize and sign the entire payload, including `media_hash`, `n_lsb`, cover kind,
   shape, and media ID.
5. Embed the signed frame. Only bits removed by the stable mask are intentionally changed.

### Verify

1. Decode the received stego object and retain its actual format fields.
2. Extract and strictly decode the signed payload.
3. Reject `media_hash` unless it is exactly 64 lowercase hexadecimal characters.
4. Verify the Ed25519 signature over the exact extracted payload bytes.
5. Recompute the stable hash over the received elements using the signed `n_lsb` and the actual
   decoded format fields.
6. Compare the embedded and recomputed digests and expose both values plus `hash_match` in the API
   report.

Using the signed LSB depth prevents an attacker from choosing a more permissive mask after
extraction. Using actual decoded header fields rather than trusting copies from the payload makes
format changes affect the recomputed digest. The pipeline separately compares signed shape, media
ID, cover kind, and LSB depth with the current verification context.

## 4. FR9 versus the other integrity mechanisms

| Mechanism | Purpose | Security boundary |
| --- | --- | --- |
| Stable SHA-256 media hash | Detect changes to unmasked media content and included format fields | FR9 |
| Ed25519 signature | Authenticate the exact serialized payload, including its stored hash | FR4 |
| Frame CRC32 | Detect accidental frame corruption before payload/signature processing | Frame extraction; not cryptographic |
| Raw-file SHA-256 | Show that the same stego attachment arrived byte-for-byte after transfer | FR11 evidence; not the stable cover comparison |

The raw-file hash should compare the sent stego file with the downloaded stego file. It should not
compare the original cover with the stego output because embedding intentionally makes those files
different.

## 5. Result passed to FR10

When extraction, payload decoding, and signature verification reach FR9, the pipeline records:

```text
hash_match = recomputed_media_hash == signed_payload.media_hash
```

A false result is evidence that authenticated expectations no longer match the received cover.
The existing FR10 decision table maps that state to `Tampered`. Missing payloads, invalid
signatures, wrong starts, and unsupported inputs are classified by their own earlier checks; FR9
does not redefine those categories.

## 6. Honest limitations

- Changes confined to the selected low `n_lsb` bits are invisible to the stable media hash. This
  is necessary for legitimate embedding, but it also means an attacker can alter unused carrier
  bits outside the frame without changing FR9's result.
- Carrier-bit changes inside the embedded frame will normally be caught by the frame CRC or
  signature, even though the stable media hash masks them.
- For an 8-bit PNG using `n_lsb=8`, every pixel-channel bit is masked. The media-content portion is
  therefore all zeroes and the digest authenticates only the included format fields. At
  `n_lsb=7`, only the highest bit of each image channel remains covered by the media hash. The GUI
  must retain 1-8 selectability, so this trade-off should be explained rather than hidden.
- SHA-256 alone does not prove who created a digest. Authenticity depends on the Ed25519 signature
  over the payload containing that digest.
- Enforcing lowercase 64-character hexadecimal syntax rejects malformed values, but it does not
  make an unsigned digest trustworthy.
- A lossy conversion or LSB scrub may destroy the magic/frame before FR9 can run, producing a
  missing/wrong-location outcome instead of a hash mismatch.
- `masked_elements.tobytes()` follows the NumPy array's dtype byte representation. The supported
  codecs produce consistent arrays on the current deployment platform, but cross-endian exchange
  is not explicitly normalized by the hash format.

## 7. Automated verification

The dedicated FR9 suites cover:

| Test file | Current tests | Coverage |
| --- | ---: | --- |
| `backend/tests/test_hashing.py` | 51 | Known digest, image/audio dtypes, LSB depths 1-8, content/header sensitivity, canonical digest validation, and non-mutation |
| `backend/tests/test_hash_verification_workflows.py` | 12 | Image/audio, explicit/derived starts, matching and mismatching hashes, API fields, and malformed signed hashes |
| Shared cases in `backend/tests/test_extraction.py` | 3 | Short, uppercase, and non-hex embedded media hashes |
| **FR9-focused additions** | **66** | Dedicated and shared boundary cases |

Run from the repository root:

```bash
.venv/bin/python -m pytest -q \
  backend/tests/test_hashing.py \
  backend/tests/test_hash_verification_workflows.py

.venv/bin/python -m pytest -q backend/tests/test_extraction.py
.venv/bin/python -m pytest -q backend/tests
.venv/bin/python -m ruff check backend
```

The current branch has 459 backend tests. Screenshots, manual email-transfer evidence, samples,
FR10 ownership, and the final team contribution statement remain outside this FR9 documentation
phase.

## 8. AI-use record for team review

Codex assisted with repository/specification inspection, test generation, boundary-hardening
suggestions, automated checks, and drafting this explanation. Ridwan should review the diff,
understand the stable-hash trade-offs above, and align this factual note with the team's final
Declaration of Originality and AI-use statement.
