# Limitations, ethics and AI use

## Steganalysis of our own output

_Author: Ke Ying (optional challenge). Script drafted with Claude Code assistance; the byte-phase test is our own design, not a published algorithm._

`scripts/steganalysis.py demo` (log: `evidence/logs/steganalysis-demo.txt`, files:
`evidence/steganalysis/`) audits stego objects made by `pipeline.protect` on
synthetic, real-photo, real-audio and video covers, using 16384-element windows and no key,
start offset or n_lsb knowledge. Two blind tests are combined:

1. **Chi-square pairs-of-values** (Westfeld-Pfitzmann). LSB replacement equalises
   the counts of (2k, 2k+1); a natural cover keeps them unequal.
2. **Byte-phase test** (our own). The frame is byte-aligned ASCII/base64 JSON, so
   the embedded bit-plane repeats with period 8/n_lsb elements and some phases are
   biased (ASCII top bit is always 0). A homogeneity chi-square across phases is
   uniform on a cover and collapses inside an embedded region.

Results (`evidence/logs/steganalysis-demo.txt`, run with `--photo` and `--wav`; the real
photo is a Windows wallpaper JPEG cropped to 640x480 and the real audio is a Windows
system WAV, both used locally and not committed; the video cover is that same PCM
inside an AVI, since the AVI cover embeds only in its PCM track): every unmodified
cover raises 0 windows, and every stego file (n_lsb 1 and 2, plain and AES-encrypted)
raises one contiguous run of windows that brackets the true embedded span, e.g.
n_lsb=1 flagged 16384-196608 against a true 20000-187479, on synthetic photo, real
photo, real audio and video. The bundled white-noise samples also work with the phase
test (cover 0 windows, stego flags window 0, which holds the start-128 payload).

The analysis itself now lives in `backend/stego_core/steganalysis.py`. The script imports it,
and the GUI's Steganalysis tab calls it through `POST /api/steganalysis`, so the command line
and the GUI share one implementation.

- Textbook chi-square alone was **not** enough: our frame bits are not 50/50, so it
  missed n_lsb=2 on images. On 16-bit audio it is useless, because natural 16-bit
  audio LSBs are already random, so covers give p near 1. The reported region is
  therefore decided by the byte-phase test only; chi-square is informational.
- Constant bit-planes (silence, saturation) are skipped, otherwise silent audio
  looked like an embedded region.
- AES-GCM only encrypts the message, not the JSON/signature wrapper, so encryption
  did not remove the structure the phase test exploits. This is a real weakness: the
  wrapper's byte structure is visible to a blind attacker.
- **Sealed frames remove that structure, not the detection.** The optional sealed
  frame (Yeo Kai Yuan's advanced start-location option) encrypts the whole frame,
  wrapper included, with AES-256-CTR. Measured with `analyze_elements` at
  16,384-element windows and a 20,000-byte encrypted message at explicit start
  20,000, over twenty runs with the same window counts each time (exact setup in
  [start-location.md §7.8](start-location.md#78-limitations-evaluation)):
  - On a photo-like 8-bit image (`natural_cover()`) the byte-phase signal is gone:
    flagged windows drop from 14/48 to 0/48 at 1 LSB and from 7/48 to 0/48 at
    2 LSBs. (The demo log above shows 11/48 and 6/48 unsealed because its message
    is the shorter 15,395-byte spec file.) Chi-square gets stronger instead.
    Every window wholly inside the sealed region scores p above about 0.97
    (typically above 0.99; the exact value varies with the random ciphertext),
    against p ≤ 7.0e-61 in every window outside it, so the region and its
    approximate start and length are still found at window resolution.
  - On 16-bit synthetic audio (tones plus noise) neither test separates a sealed
    region (0/21 phase windows, against 14/21 at 1 LSB and 7/21 at 2 LSBs unsealed),
    because natural 16-bit low bits already look like noise.

  LSB replacement statistics do not depend on the content, so no encryption can hide
  *that* something was embedded. Sealing does not pad either, so the region's length
  hints at the message size. Our own tool's call ("Signs of LSB embedding") is decided
  by the byte-phase test only, so it reports "No evidence of LSB embedding" for a
  sealed file (GUI evidence scene 73). The per-window chi-square values it shows
  alongside would still expose the region on a natural cover. That scene's cover is the
  bundled noise image, whose low bits are already random, so there chi-square cannot
  separate the region either.
- Limits of the evidence: one photo and one clip, not a corpus, so no false-positive
  rate is claimed. Tampering to the embedded region was not separately analysed (the
  verdict pipeline catches it).

## Technical limits

- **Fragile embedding:** cropping, resampling, lossy compression and LSB scrubbing
  can remove or corrupt the frame. The optional redundancy (an odd number of copies
  up to 9, with a per-bit majority vote; `stego_core/ecc.py`) repairs scattered
  low-bit flips such as the Attack Lab's `lsb_noise`. It is a repetition code, not a
  robust watermark: those operations damage every copy.
- **Detectability:** public magic and contiguous LSB embedding are searchable.
  Keyed placement does not provide confidentiality or resistance to steganalysis.
  A sealed frame removes the public magic and readable header, but the embedded
  region stays statistically detectable. See "Steganalysis of our own output" above
  for what we measured.
- **Partial integrity:** the stable hash omits all selected low bits, including
  outside the payload. Eight LSBs on uint8 exclude all sample content. Authentic
  does not imply identical file bytes.
- **Limited format scope:** covers are normalized RGB/RGBA PNG, 8/16-bit PCM WAV,
  or supported AVI with PCM audio. JPEG covers, high-bit-depth PNG, 24-bit/float
  WAV and compressed audio are outside this implementation. These require
  different sample handling or are incompatible with this lossless LSB workflow.
  PNG mode conversion can discard palette/mode information and some transparency;
  the signed representation is the decoded normalized carrier.
- **AVI scope:** only the PCM track and associated parameters are authenticated;
  video imagery is not. AVI crop is unsupported in the Attack Lab.
- **Bounded recovery:** fallback search checks at most 200,000 candidate starts.
  An incomplete unsuccessful scan gives Cannot Verify. Crop can change a
  derived start because the available span changes; retain the original explicit
  offset when demonstrating a surviving cropped frame.
- **Capacity and perception:** larger payloads, metadata and Base64/encryption
  overhead consume capacity. Higher LSB counts reduce image/audio fidelity and
  the content retained by the hash. The final actual frame must fit after the
  start offset. `/api/capacity` and the GUI's meter count every byte Protect
  embeds, with the typed media ID and metadata. With an explicit start, the
  largest message they report protects and one byte more does not. With a
  derived start they assume the latest offset any passphrase can produce (about
  a tenth of the cover in), so they can understate the room for a particular
  passphrase. The CLI's `stego capacity` still uses a rough fixed allowance.
- **Keys and freshness:** public-key identity needs an external trust process.
  There is no key revocation or replay cache. Nonces/timestamps alone do not
  reject a repeated authentic file.
- **Encryption scope:** unless the frame is sealed, only message bytes are
  encrypted. Passphrase strength matters; media ID provides a deterministic salt,
  not a secret. Successful verification and successful decryption are separate
  outcomes.
- **Sealed frame trade-offs** ([start-location.md §7.7-7.8](start-location.md#77-verdict-consequences-a-deliberate-trade-off)):
  a wrong passphrase, media ID or offset gives Payload Missing (Cannot Verify on a
  cover too large to scan fully), never Wrong Start Location, so that diagnosis is
  lost. AES-CTR gives confidentiality only and is malleable: an attacker can patch the
  encrypted CRC, so integrity rests on the Ed25519 signature, as it always did. One flipped nonce bit makes the frame read as
  absent unless redundancy is 3 or more. An offline guess costs one scrypt run, so
  the passphrase sets the ceiling.
- **Portability and deployment:** sample hashing uses NumPy's array bytes, without
  an independent endian normalization layer. Local-demo tests do not establish
  compatibility with every platform/container. The service receives secrets
  during processing and has not been hardened or audited for public hosting.

See the [threat model](threat-model.md), [payload format](payload-format.md) and
[verdict table](verdict-table.md) for the precise boundaries.

## Responsible use

The intended use is coursework demonstrating hidden verification records and
integrity checks for media shared with permission. Use owned or appropriately
licensed samples, obtain consent for recordings, and avoid placing personal or
confidential information in public evidence.

The same concealment technique can hide unauthorized data transfers. It should
not be used to bypass monitoring, conceal prohibited content or imply that
hidden data cannot be discovered. Attack Lab examples deliberately alter test
copies to show failure handling. A failed verdict does not prove malicious
intent, and an Authentic verdict does not establish ownership or truth of the
media's contents.

Keep private keys and passphrases out of commits, screenshots and submitted logs.
A demo public key can be shared; its identity still needs verification by the
receiver.

## Recorded AI assistance

This is a factual working record, not a signed team declaration. It records
assistance documented in this repository and the Section G work; it does not
invent individual disclosures or claim unassisted authorship.

| Contribution | Tool and recorded use | Checks, corrections and evidence |
| --- | --- | --- |
| Ridwan's FR7/FR8 contribution | Codex: repository inspection, implementation suggestions, test generation, automated checks and explanation drafts | The [contribution record](fr7-fr8-contributions.md) identifies scope and reproducible checks. Ridwan must confirm the final personal disclosure and understanding. |
| Kannon's Section F | Codex: implementation, tests, code inspection and documentation | Checks led to conditional crop/re-encode predictions, rejection of uint8 high-bit attacks at 8 LSBs, and reuse of shared bounded extraction. Kannon supplied manual PNG/WAV screenshots; an independent-target WAV replay was checked through the API. See [Attack Lab](attack-lab.md) and [saved evidence](../../evidence/section-f.md). |
| Kannon's Section G documentation | Codex: drafts of payload/frame format, verdict table, threat model and this limitations/AI-use record | Drafts were compared with implementation, named tests and saved evidence. They explicitly distinguish incomplete scans from Payload Missing, freshness from nonce uniqueness, and signature verification from decryption. Earlier placeholder wording suggesting automatic replay prevention or secrecy from placement was corrected. |
| Yeo Kai Yuan's contributions | Claude Code (Anthropic) was used for: the initial project scaffold (web UI, API, module structure and team plan, commit c66d412); the sealed-frame advanced start-location option (sealing.py, its tests and design section); the demo-readiness GUI work (hand-off card, sample loader, steganalysis tab, AVI audio preview, theme/font fixes, media-ID bug fix); the Playwright GUI evidence script and screenshots; the local email transfer evidence script; and drafts of the contribution statement, declaration template and demo-plan names. | Checks: the full backend test suite, frontend type-check/lint, and the Playwright run asserting 38 GUI scenarios; Kai Yuan must review every change and confirm they can explain it before submission. |

The Section F evidence records 597 passing backend tests, plus frontend build/lint
checks. That is the recorded validation at that stage, not a claim that every
scenario has been tested or that Section G ran a new full regression suite.
AI-generated code and tests can share mistakes; human explanation, source review
and independent manual observations remain necessary.

Kannon's supplied screenshots document the manual demonstrations. They do not
establish that all source code was written without AI. Other members' tools,
usage scope, rejected suggestions and independently authored work are not fully
recorded here.

## Team confirmation required before submission

- Each member confirms their tools, where assistance was used, what was changed
  or rejected, how correctness was checked, and what they personally authored.
- Kannon, Ridwan and Yeo Kai Yuan review the recorded entries and confirm they can
  explain their contributions; the other members add their own factual disclosures.
- The team reconciles this record with its signed Declaration of Originality
  and agreed contribution statement in workstream I.

These confirmations remain open. No statement of “no AI use” or wholly human
authorship is inferred from a missing entry.
