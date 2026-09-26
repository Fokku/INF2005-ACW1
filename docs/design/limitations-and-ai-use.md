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

- Textbook chi-square alone was **not** enough: our frame bits are not 50/50, so it
  missed n_lsb=2 on images. On 16-bit audio it is useless, because natural 16-bit
  audio LSBs are already random, so covers give p near 1. The reported region is
  therefore decided by the byte-phase test only; chi-square is informational.
- Constant bit-planes (silence, saturation) are skipped, otherwise silent audio
  looked like an embedded region.
- AES-GCM only encrypts the message, not the JSON/signature wrapper, so encryption
  did not remove the structure the phase test exploits. This is a real weakness: the
  wrapper's byte structure is visible to a blind attacker.
- Limits of the evidence: one photo and one clip, not a corpus, so no false-positive
  rate is claimed. Tampering to the embedded region was not separately analysed (the
  verdict pipeline catches it).

## Technical limits

- **Fragile embedding:** cropping, resampling, lossy compression and LSB scrubbing
  can remove or corrupt the frame. There is no error-correcting or robust
  embedding scheme.
- **Detectability:** public magic and contiguous LSB embedding are searchable.
  Keyed placement does not provide confidentiality or resistance to steganalysis.
  See "Steganalysis of our own output" below for what we measured.
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
  start offset; the UI estimate is approximate.
- **Keys and freshness:** public-key identity needs an external trust process.
  There is no key revocation or replay cache. Nonces/timestamps alone do not
  reject a repeated authentic file.
- **Encryption scope:** only message bytes are encrypted. Passphrase strength
  matters; media ID provides a deterministic salt, not a secret. Successful
  verification and successful decryption are separate outcomes.
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
- Kannon and Ridwan review the recorded entries and confirm they can explain
  their contributions; the other members add their own factual disclosures.
- The team reconciles this record with its signed Declaration of Originality
  and agreed contribution statement in workstream I.

These confirmations remain open. No statement of “no AI use” or wholly human
authorship is inferred from a missing entry.
