# FR7: Start-location design and security

Status: the FR7 implementation, focused tests, and this explanation are complete for the current
design, subject to the security limitations below. Assigned owner: Ridwan. The original keyed
derivation and scanner were contributed by Zong Han; Ridwan added validation, compatibility checks,
and alignment-correct bounded recovery. See the
[FR7/FR8 contribution and test record](fr7-fr8-contributions.md).

Section 7 is the optional "advanced start-location security" challenge (spec Section 8): an
opt-in **sealed frame** that encrypts the whole embedded frame. Owner: Yeo Kai Yuan.

## 1. What the offset means

The start offset is a zero-based index into the cover's flattened decoded elements. It is not a
byte offset in the PNG or WAV file:

- PNG: one element is one colour-channel value, for `height × width × channels` elements.
- WAV: one element is one interleaved sample-channel value, for `frames × channels` elements.
- AVI: the current optional video path embeds into its decoded PCM audio elements.

For a frame containing `B` bits and an LSB depth of `n`, the frame needs `ceil(B / n)` elements. A
start is valid only when:

```text
0 <= start <= element_count - ceil(frame_bits / n_lsb)
```

`location.validate_start` is the shared boundary check. Protect validates the complete frame at
the chosen offset before embedding; verify first validates that the four-byte magic can be read,
then the extraction layer validates the fixed header and complete frame. Offset zero remains a
valid compatibility and boundary-test value, but the FR7 demonstration should use a visible
non-zero offset, such as 137.

## 2. The two modes

### Explicit mode

Party A selects an offset and communicates it to party B out of band. Both Protect and Verify
require the offset when explicit mode is selected. This mode is useful for demonstrating both a
successful non-zero start and the `Wrong Start Location` verdict.

An explicit offset is not a secret cryptographic key. Anyone who learns or scans for it can read
the frame, and changing only the location is not independently authenticated.

### Derived mode

Both parties supply the same passphrase, media ID, cover kind, and LSB depth. The passphrase is
processed by scrypt (`N=32768`, `r=8`, `p=1`) using `SHA-256(media_id)` as the reproducible salt.
HKDF-Expand then produces separate 32-byte keys labelled `acw1-loc` and `acw1-enc`. `K_loc` is used
for location derivation; `K_enc` is used only when message encryption is enabled.

The current derivation is:

```text
capacity_bits = element_count * n_lsb
reserved_bits = capacity_bits - floor(capacity_bits / 10)
needed_elements = ceil(reserved_bits / n_lsb)
span = element_count - needed_elements

input = "start" || media_id || cover_kind || one_byte(n_lsb) || uint32_be(0)
start = HMAC-SHA256(K_loc, input) mod span
```

The 90% reservation is computable before reading the embedded header, so protect and verify can
derive the same location. It confines the start to approximately the first 10% of the cover and
leaves at least the reservation after it. Protect still checks the actual frame because a very
large frame can exceed that reservation.

For compatibility with existing stego files, positive spans retain the original modulus. This
means the last otherwise fitting reservation position is excluded in derived mode. If the
reservation exactly fills the cover, zero is the only possible start. Explicit mode can still use
the last fitting offset.

Example: with 12,000 elements and two LSBs per element, raw capacity is 24,000 bits. The reserved
size is 21,600 bits, requiring 10,800 elements, so the legacy derived span is 1,200 candidate
offsets: 0 through 1,199.

## 3. What party B needs

For derived mode, party B needs the unchanged media ID, the same LSB depth and cover kind, and the
shared passphrase. For explicit mode, party B needs the same LSB depth and the offset. In both
modes, party B also needs the public key to authenticate the signed payload. If the message itself
was encrypted, the passphrase is additionally needed to display its plaintext.

The media ID is application data agreed out of band; it is not inferred from a filename. The start
is not stored as a frame field, although Protect returns it so the interface can display and share
it for the demonstration.

## 4. Inputs deliberately excluded from derivation

- **Media hash:** tampering changes the hash. Using it would move the expected start and mislabel
  tampering as `Wrong Start Location`.
- **Payload nonce:** the verifier cannot read the nonce until it already knows the start, creating
  a circular dependency.
- **Signed payload fields:** these are also unavailable before extraction.

The formula does use the decoded element count to calculate its modulus. Therefore, cropping a
derived-mode cover can change the expected start before the verifier reaches the later signed-shape
check. This is an honest limitation of the existing design, not a claim that shape changes are
always classified as `Tampered` in derived mode. Explicit mode keeps its supplied start stable and
allows the signed shape/hash checks to handle such changes when the frame survives.

## 5. Bounded diagnostic recovery

If magic is absent at the expected start, verify performs a diagnostic search at the selected LSB
depth. `scan_for_magic` tests every **element-aligned** candidate, including locations whose bit
positions are not byte-aligned, by checking the required shifted bit streams. It searches at most
200,000 candidate starts (offsets 0 through 199,999) and reads enough trailing elements to test a
complete four-byte marker at the last candidate.

The result is interpreted as follows:

- magic found elsewhere: `Wrong Start Location`;
- no magic after a complete search of a small cover: `Payload Missing`;
- no magic within a truncated 200,000-position search: `Cannot Verify`, because absence was not
  established over the unsearched remainder.

This scan is a location diagnostic only. It does not automatically switch to the discovered
offset, return a payload, authenticate a candidate, or search other LSB depths. The actual frame
must still pass bounded extraction, CRC, payload validation, signature verification, and media
checks at the user-selected or derived start.

## 6. Security limitations

- The frame begins with plaintext `ACW1`, so a determined analyst can scan the LSB plane. A hidden
  start frustrates a naive fixed-offset reader; it does not provide confidentiality. The optional
  sealed frame (section 7) removes this marker, at the costs listed in section 7.8.
- Different keys can map to the same finite offset. Finding magic at the expected position is not
  proof that the passphrase is correct.
- Explicit mode provides no key-based protection for the location.
- The mode and offset are not signed fields. Relocating an otherwise intact frame within the same
  compatible cover is not independently detected if the verifier is told the new offset.
- Optional AES-256-GCM protects message confidentiality. Ed25519 authenticates the serialized
  payload. CRC32 detects accidental frame corruption but is not an authentication mechanism.
- If an attack destroys the magic itself, the verifier cannot distinguish that damaged payload
  from a cover that never contained one after a complete scan.

The extraction steps that consume this location are documented in
[FR8: Extraction and decoding](extraction.md).

## 7. Advanced start-location security: sealed frames (optional challenge, owner: Yeo Kai Yuan)

Code: `backend/stego_core/sealing.py` (primitives), `extraction.sealed_frame_at` /
`extraction.extract_sealed_frame` (bounded reading), `pipeline.protect` / `pipeline.verify`
(wiring). Tests: `backend/tests/test_sealed_frame.py`, `backend/tests/test_sealed_frame_api.py`.

### 7.1 Threat addressed

Sections 2 and 6 hide *where* the frame starts, not *what* it looks like. The frame opens with
the plaintext magic `ACW1`, a plaintext header (flags, LSB count, lengths) and canonical JSON
(media ID, timestamp, media hash, metadata, and the message unless it is encrypted).
`location.scan_for_magic` finds that at any element alignment in milliseconds, and anyone can
then read every field. The derived start only defeats a reader who assumes a fixed offset.

Goal of the sealed frame: without the passphrase and media ID, an analyst can neither locate the
frame by its structure nor read any field. They cannot even confirm that a frame is there by
parsing one. The only remaining evidence is statistical (section 7.8).

### 7.2 Construction

```text
frame  = container.build_frame(...)       # unchanged: MAGIC, header, payload, signature, CRC
K_seal = HKDF-Expand(scrypt(passphrase, SHA-256(media_id)), info = "acw1-seal", 32 bytes)
sealed = nonce (12 random bytes) || AES-256-CTR(K_seal, counter block = nonce || 00000000, frame)
```

The sealed bytes are embedded at the same derived or explicit start an unsealed frame would use.
The inner frame is byte-for-byte the normal one, so the CRC, signature, media hash and
parameter checks after decryption are the existing code paths. Sealing is opt-in: `seal_frame`
on `POST /api/protect` and `POST /api/capacity`, and `stego protect --seal` on the command line.
It requires a passphrase in both start modes.

| Visible in the LSB plane without the key | Unsealed frame | Sealed frame |
|---|---|---|
| Magic `ACW1` at the start | yes | no (`scan_for_magic` finds nothing) |
| Header: flags, LSB count, payload and signature lengths | yes | encrypted |
| Payload JSON: media ID, timestamp, hash, metadata | yes | encrypted |
| Message | yes, unless AES-GCM encrypted | encrypted (AES-GCM may also be used inside) |
| Byte structure used by the steganalysis phase test | yes | no |

Overhead: 12 bytes per copy. The capacity check and its error message include the nonce
("... that includes the 12-byte seal nonce a sealed frame adds to every copy"), and `/api/capacity` with
`seal_frame=true` counts those 12 bytes in every copy for `frame_overhead_bytes`, `max_message_bytes`
and `fits`.
`ProtectResult.frame_bytes` counts what is actually embedded per copy, nonce included.

**Robust embedding (redundancy 3/5/7/9) works unchanged.** An unsealed frame with redundancy is
embedded as a header block (13 bytes × r) followed by a body block (rest × r), so the verifier can
majority-vote the header before it knows any lengths. A sealed frame uses the same split, with the
header block being the nonce plus the first 13 ciphertext bytes (25 bytes × r). This is safe
because CTR decrypts any prefix on its own. Repeating ciphertext copies reveals nothing new: the
copies are identical, which is also true of the unsealed layout.

### 7.3 Why AES-CTR and not an AEAD such as AES-GCM

1. **The header has to open before the length is known.** The verifier reads the 25-byte header
   block, decrypts it, and only then learns how many more bits to read. CTR is a stream cipher,
   so decrypting a prefix is exact. An AEAD releases no plaintext until it has checked a tag over
   the whole ciphertext, whose length it does not yet know.
2. **The verdict table would collapse.** With an AEAD, one flipped LSB and a wrong passphrase
   both show up as "authentication failed". With CTR, a damaged body still has an openable
   header, so the CRC reports **Tampered** exactly as it does for an unsealed frame.

Integrity was never the seal's job. The CRC detects accidents and Ed25519 detects deliberate
changes (section 7.8, first point).

### 7.4 Why a random nonce for every embed

`K_seal` is a pure function of (passphrase, media ID), and teams reuse both. Examples are several
covers protected under one media ID, or the same cover protected again after a mistake. With a
fixed or derived IV, two frames sealed under one key would share a keystream. XOR of the two
embedded regions cancels it and gives `frame_a XOR frame_b`, and the predictable
magic/header/JSON skeleton then exposes both. A fresh 96-bit nonce from `os.urandom` makes a
repeat negligible (birthday bound about 2^48 embeds per key). The nonce does not need to be
secret, only unique, so it is stored in the clear in front of the ciphertext.
`test_every_seal_draws_a_fresh_nonce` checks that the same key and frame seal differently each
time. The low 32 counter bits give 2^32 blocks (64 GiB) before a carry could reach the nonce. The
frame's uint32 payload length keeps it far below that.

### 7.5 Why `K_seal` is a separate key

`kdf.derive_keys` now returns three HKDF-Expand outputs from one scrypt result, with labels
`acw1-loc`, `acw1-enc` and `acw1-seal`.

- `K_enc` drives AES-256-GCM, which runs CTR internally with its own counter blocks
  (`nonce || 1`, `nonce || 2`, ...). Reusing it for sealing (`nonce || 0`, `nonce || 1`, ...)
  could make the two modes produce the same keystream block. Separate keys rule this out without
  any reasoning about counters.
- `K_loc` is an HMAC key for the location PRF. Using one key in two different primitives is
  poor practice even when no attack is known.
- **Backwards compatibility.** HKDF-Expand with a new label is a new, independent output, so
  `K_loc` and `K_enc` stay byte-identical. `test_adding_k_seal_leaves_k_loc_and_k_enc_byte_identical`
  pins values computed before the change. `test_committed_samples_still_verify_after_adding_k_seal`
  shows that the committed derived-start samples (which depend on `K_loc`) and encrypted samples
  (which depend on `K_enc`) still verify Authentic and still decrypt.

### 7.6 How the verifier detects a sealed frame automatically

There is no new input on Verify. At the resolved start (derived or explicit):

1. If the plaintext magic is there, continue exactly as before. The report has `sealed: false`.
2. Otherwise, if a passphrase was supplied, read the 25-byte header block (majority-voted when
   redundancy > 1), decrypt it with `K_seal`, and compare the first four bytes with `ACW1`
   (`extraction.sealed_frame_at`). A match is treated like "magic at the expected start" in the
   unchanged `verdict.decide` table. With a wrong key those bytes are uniformly random, so a false
   match has probability 2^-32, and the header, CRC and signature checks would still catch it.
3. `extraction.extract_sealed_frame` then reads the rest the same way as `extract_frame`. It
   parses the decrypted header, checks the LSB count and signature length, and runs
   `location.validate_start` on the complete sealed length before extracting a single body bit.
   Lengths from the header are never trusted for allocation. It then decrypts and calls
   `container.parse_frame` (CRC). Signature, hash, parameter checks and the verdict follow as
   usual, and the report has `sealed: true`.
4. If neither works, the existing `scan_for_magic` logic runs unchanged. A sealed frame never
   contains a plaintext magic, so the scan finds nothing, and the result is **Payload Missing**
   (or **Cannot Verify** for covers larger than the 200,000-position scan limit). The report has
   `sealed: null`. When a passphrase was supplied, one extra reason is added: *"If this file was
   protected with a sealed frame, a wrong passphrase or media ID is indistinguishable from no
   payload."* Without a passphrase, the extra reason says the sender's passphrase is needed.

scrypt runs at most once per verification (the derived keys are cached). When an unsealed file
has no magic at the start, derived mode pays for one extra 25-byte decrypt. Explicit mode also
pays for one scrypt run (about 100 ms), which it previously skipped when the message was not
encrypted.

### 7.7 Verdict consequences (a deliberate trade-off)

Measured with the pipeline on a 64×64 RGB cover at 2 LSBs:

| Situation | Unsealed | Sealed |
|---|---|---|
| Right passphrase, media ID, key; file intact | Authentic | Authentic |
| Wrong public key | Signature Invalid | Signature Invalid |
| High-bit pixel/sample change (`flip_bits`) | Tampered | Tampered |
| One bit flipped inside the frame | Tampered (CRC) | Tampered (CRC) |
| Derived start, wrong passphrase or media ID | Wrong Start Location | Payload Missing |
| Explicit start, wrong passphrase | Authentic (passphrase unused) | Payload Missing |
| Explicit start, no passphrase | Authentic | Payload Missing (+ "passphrase needed") |
| Explicit start, wrong media ID | Tampered (signed media ID differs) | Payload Missing |
| Explicit start, wrong offset | Wrong Start Location | Payload Missing |
| Crop, derived start | Wrong Start Location | Payload Missing |
| Crop, verified at the original explicit offset | Tampered | Tampered |

**Wrong Start Location cannot occur for a sealed file.** That diagnostic depends on finding the
magic somewhere else, and removing that marker is the point of sealing. Every wrong secret now
gives the same answer as an untouched cover. That is the security property: the file does not
reveal whether a payload exists, even to someone holding the public key. The cost is a less
helpful diagnosis for honest users, which the extra reason line partly offsets. No existing verdict
changed for unsealed files. The only visible change for them is that extra reason line on
not-found verdicts.

### 7.8 Limitations (evaluation)

1. **CTR provides confidentiality, not integrity, and it is malleable.** Flipping ciphertext
   bit i flips plaintext bit i. CRC32 is affine, so an attacker who knows the frame layout but
   not the key can edit the payload and patch the encrypted CRC to match.
   `test_ctr_is_malleable_so_the_signature_not_the_crc_catches_a_forged_edit` does this: it
   changes metadata `ACW1` to `ACW0` and fixes the CRC. The CRC then passes, and the result is
   **Signature Invalid** because Ed25519 still covers the payload. This is no weaker than the
   baseline, where anyone can recompute a plaintext CRC. Integrity has always come from the CRC
   (accidents) and Ed25519 (authenticity), never from the seal.
2. **Steganalysis still detects that something was embedded.** Measured with
   `stego_core.steganalysis.analyze_elements` (the engine behind `scripts/steganalysis.py`) at
   16,384-element windows: `pipeline.protect` with a 20,000-byte message, `encrypt_message=True`
   (AES-GCM), explicit start 20,000, and 1 or 2 LSBs, sealed and unsealed. Re-measured with the
   current frame format over twenty runs, each with a fresh key pair, message and nonces. The
   flagged-window counts were the same in every run. The chi-square p-values vary with the random
   ciphertext, and the ranges below cover all twenty runs.
   - *Photo-like 8-bit image (`natural_cover()`, 512×512 RGB, 48 windows):* sealing removes the
     byte-phase signal. Flagged windows drop from 14/48 to 0/48 at 1 LSB and from 7/48 to 0/48 at
     2 LSBs. Unsealed, every window that overlaps the frame is flagged. However, the
     Westfeld-Pfitzmann chi-square pairs test gets **stronger**. Every window wholly inside the
     sealed region scores p above about 0.97 (typically above 0.99; the exact value varies with the
     random ciphertext), against p ≤ 7.0e-61 in every window outside it. That holds at
     2 LSBs too, where the unsealed frame's non-uniform bits kept chi-square below about 1e-19
     inside the region (missed). The two edge windows, which mix frame and cover, score in between.
     Ciphertext is uniformly random, which is exactly the model chi-square assumes. The region,
     and so its approximate start and length, can still be found at window resolution.
     (`evidence/logs/steganalysis-demo.txt` shows 11/48 and 6/48 for the unsealed frame on the
     same cover. That run's message is the 15,395-byte spec file, since the script's `[:20000]`
     slice keeps the whole file, so its frame is shorter and overlaps fewer windows.)
   - *16-bit audio (8 s of 44.1 kHz mono: 440, 660 and 1,320 Hz tones at amplitudes 6,000, 3,000
     and 1,500, plus Gaussian noise with σ = 300; 21 windows):* neither test separates a sealed
     region. The phase test flags 0/21 windows at either LSB count, against 14/21 (1 LSB) and 7/21
     (2 LSBs) for the unsealed frame. Chi-square p is 0.7-1.0 inside the sealed region and
     0.97-1.0 outside it, so it cannot tell them apart. The natural low bits of 16-bit audio are
     already noise-like.

   LSB *replacement* statistics do not depend on the content, so encryption cannot hide that an
   embedding exists. Hiding that would need a different embedding method (for example ±1
   matching or content-adaptive embedding), which is out of scope. Sealing does not pad, so the
   length of the detectable region also reveals roughly how big the message is.
3. **The passphrase sets the ceiling.** `K_loc`, `K_enc` and `K_seal` all come from one
   passphrase. For an offline guess, the attacker runs scrypt (N = 2^15, r = 8, p = 1, about
   100 ms, as intended), decrypts 25 bytes and checks for `ACW1`. Everything after scrypt is
   cheap, so scrypt's cost is the only brake. A dictionary word will still fall. The salt is
   SHA-256(media ID), which is public and repeats for every file with the same media ID, so
   work can be precomputed per media ID.
4. **Crop in derived mode.** The derived start depends on the element count (section 4). After
   a crop the verifier looks somewhere else, and a sealed frame cannot be scanned for. The
   result is therefore Payload Missing (or Cannot Verify), not Tampered or Wrong Start Location.
   With the original explicit offset the frame is found and the signed shape gives Tampered
   (`test_crop_moves_a_derived_start_so_a_sealed_frame_is_not_found`).
5. **The nonce is all-or-nothing.** One flipped bit in the 12 nonce bytes changes the whole
   keystream, and the frame then reads as absent (Payload Missing) rather than Tampered.
   Redundancy 3+ repairs this like any other bit (`test_redundancy_lets_a_sealed_frame_survive_lsb_noise`).
6. **Attack Lab.** `flip_bits`, `crop`, `lsb_scrub`, `reencode` and `lsb_noise` do not read the
   frame and work on sealed files unchanged. `corrupt_payload` and `replay` locate the payload
   through the plaintext header, and without the key a sealed frame cannot be told apart from an
   empty cover, so they cannot detect one automatically. Both accept `sealed=True` (CLI:
   `stego tamper --attack corrupt_payload|replay --sealed --start N [--copies r]`) for a key-less
   variant. The variant cannot find or check the frame, so it must be given the real start offset
   (the CLI refuses `--sealed` without `--start`) and the copy count the file was protected with
   (`redundancy` form field on `POST /api/attack`, `--copies` on the CLI, default 1):
   - `corrupt_payload` with 1 copy flips the top ciphertext bit of the first payload byte. CTR
     flips the same plaintext bit, the header still opens, and the CRC reports the change:
     Tampered. With 3 or more copies one flipped body copy would be outvoted, and the body copies
     are one encrypted frame length apart, which cannot be read without the key. So it flips the
     top bit of the encrypted version byte in every header-block copy instead, since those copies
     are a fixed 25 bytes apart. The vote keeps the flip, the magic still decrypts, and the opened
     header is rejected as an unsupported version: Tampered.
   - `replay` copies every hidden bit from the start offset to the end of the shorter cover, which
     carries every copy of the sealed frame when it fits: Tampered at the original explicit offset
     and copy count. It refuses a start that leaves no room for the sealed header block's copies.

   Without the flag they refuse with an error that explains sealed frames are opaque to them.
   The web Attack Lab passes the flag through its "Target has a sealed frame" checkbox (ticked
   automatically when the target comes from a sealed Protect result; `sealed` form field on
   `POST /api/attack`), and the copy count through its Copies field, filled in from the target.
   Unticked, those two attacks return HTTP 400 with that explanation
   (`backend/tests/test_attack_sealed_api.py`, `backend/tests/test_attack_redundancy.py`). When a
   sealed result is sent on to Verify, a live Protect's passphrase does not travel with it, so
   Verify keeps **Extract and verify** disabled until the passphrase is typed. Without it the
   sealed frame could not be found, and the result would be Payload Missing or Cannot Verify
   instead of the predicted Tampered.

### 7.9 Test and demo commands

```bash
cd backend
../.venv/bin/python -m pytest -q tests/test_sealed_frame.py tests/test_sealed_frame_api.py
../.venv/bin/python -m pytest -q                       # full suite: existing tests unchanged

# CLI round trip with a throwaway key pair generated locally, outside the repository. Never use
# the team key here: keys/private/team_ed25519.pem is not on most machines, and forcing a new "team"
# pair (keygen refuses without --force) would replace the committed public key every curated
# sample verifies against.
../.venv/bin/python -m stego_core.cli keygen --out /tmp/sealed-demo-keys --label sealed-demo
../.venv/bin/python -m stego_core.cli protect --cover ../samples/image/original/cover.png \
    --message ../samples/payloads/short.txt --lsb 2 --media-id sealed-demo \
    --key /tmp/sealed-demo-keys/private/sealed-demo_ed25519.pem \
    --passphrase "demo passphrase" --seal --out /tmp/sealed.png    # prints "start offset: N"
../.venv/bin/python -m stego_core.cli verify --stego /tmp/sealed.png \
    --pub /tmp/sealed-demo-keys/public/sealed-demo_ed25519.pub.pem --lsb 2 --media-id sealed-demo \
    --passphrase "demo passphrase"                     # Authentic, "sealed": true
../.venv/bin/python -m stego_core.cli verify --stego /tmp/sealed.png \
    --pub /tmp/sealed-demo-keys/public/sealed-demo_ed25519.pub.pem --lsb 2 --media-id sealed-demo \
    --passphrase "wrong"      # "sealed": null; Cannot Verify on this 512x512 cover (too big to
                              # scan fully), Payload Missing on a cover under 200,000 elements

# Key-less sealed attack: N is the start offset protect printed (--sealed refuses to run without it)
../.venv/bin/python -m stego_core.cli tamper --stego /tmp/sealed.png --attack corrupt_payload \
    --sealed --start N --lsb 2 --out /tmp/sealed-corrupt.png
../.venv/bin/python -m stego_core.cli verify --stego /tmp/sealed-corrupt.png \
    --pub /tmp/sealed-demo-keys/public/sealed-demo_ed25519.pub.pem --lsb 2 --media-id sealed-demo \
    --passphrase "demo passphrase" --start N           # Tampered, "sealed": true
# For the 3-copy variant add --copies 3 to protect, tamper and every verify. The right passphrase
# still gives Authentic before the attack and Tampered after it.
```

`keygen` refuses to overwrite an existing key file unless given `--force`, so running the block a
second time needs a fresh `--out` folder (or `rm -r /tmp/sealed-demo-keys` first).
