# Threat model

## Purpose, assets and trust

The project lets a sender hide a signed verification record in supported media,
then lets a receiver check the record and the authenticated media representation.
Assets are the private signing key, optional message plaintext/passphrase,
signed payload and integrity of the covered image/audio samples.

The receiver must obtain the sender's public key through a trusted channel.
A supplied PEM file proves no identity by itself; replacing both media and the
public key can make an attacker's own signature appear valid. The expected media
ID and extraction settings also need agreement between sender and receiver.

The demo assumes trusted sender/receiver machines and a locally operated service.
Private signing keys and passphrases reach the backend during relevant requests.
The browser/backend path is therefore inside the trust boundary; this is not a
hardware-isolated signing service or a hardened multi-user public deployment.

## Attacker capabilities and boundaries

An attacker can inspect, modify, delete, replace or resend media; search its low
bits; learn the format and media ID; and recompute CRC32. The attacker is assumed
not to possess the legitimate private signing key or encryption passphrase.

| Attempt | Implemented response | Boundary |
| --- | --- | --- |
| Edit authenticated pixels/samples | Recomputed stable SHA-256 differs after valid extraction: Tampered | Selected low bits are excluded everywhere |
| Alter signed fields/message | Ed25519 rejects altered signed bytes if parsing and CRC pass | Broken framing may stop earlier with Tampered |
| Crop/substitute media | Actual shape/format/hash compared with signed data | Crop can destroy or relocate the frame, preventing comparison |
| Transplant a valid frame | Signature may remain valid, but a different authenticated target hash/shape is rejected | Equivalent masked content is indistinguishable |
| Resend an unchanged authentic file | Still Authentic | No replay cache, expiry check or trusted timestamp |
| Search for the message | Magic and contiguous embedding can be located | Keyed placement is not encryption |
| Read an encrypted message | AES-256-GCM protects message bytes under the derived key | Metadata stays visible; weak passphrases permit offline guessing |
| Destroy embedded bits or withhold the file | Receiver cannot establish authenticity | No recovery redundancy or availability guarantee |
| Supply malformed lengths/fields | Bounded extraction and strict decoding reject invalid frames | Does not establish comprehensive denial-of-service protection |

The nonce makes payload instances distinct but is not replay prevention on its
own. A timestamp is a signed claim by the sender, not proof of freshness. The
current verifier neither remembers prior nonces nor enforces a time window.

## Scope of integrity

The signed stable hash masks the selected LSB plane across the full carrier.
Changes confined to unused low bits can go undetected. With n=8 on an 8-bit
carrier no pixel/sample value remains in the media hash. PNG file metadata and
encoding details are outside the normalized pixel representation. AVI verification
covers PCM audio and associated parameters, not the visual frames or whole container.
See [the exact formula](payload-format.md) and [FR9 analysis](hash-verification.md).

The file SHA-256 shown separately in the UI supports an attachment transfer check,
provided sender and receiver compare it through a trusted channel. An attacker
able to replace both the file and an unauthenticated advertised hash defeats that
comparison.

## Secrets and failure handling

A stolen private signing key allows forged signed records; message encryption
does not repair that trust failure. A leaked passphrase exposes encrypted messages
and derived placement, but does not by itself grant signing authority. The project
has no key revocation, key rotation protocol or certificate infrastructure.

CRC32 is a corruption check, not a cryptographic defense. The finite magic search
is diagnostic: a match elsewhere is only a location hint, and an incomplete search
cannot establish absence. Successful signature verification also does not ensure
that optional decryption succeeded.

Use the [verdict table](verdict-table.md) to interpret failed checks and the
[Attack Lab](attack-lab.md) to demonstrate covered threats. Those tests support
specific behaviours; no claim of undetectable steganography, compression
resilience, comprehensive security audit or universal attack resistance is made.
