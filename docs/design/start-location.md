# FR7: Start-location design and security

Status: the FR7 implementation, focused tests, and this explanation are complete for the current
design, subject to the security limitations below. Assigned owner: Ridwan. The original keyed
derivation and scanner were contributed by Zong Han; Ridwan added validation, compatibility checks,
and alignment-correct bounded recovery. See the
[FR7/FR8 contribution and test record](fr7-fr8-contributions.md).

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
  start frustrates a naive fixed-offset reader; it does not provide confidentiality.
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
