# Party A → party B transfer evidence

Spec Section 5 asks the team to show "the stego object being sent from party A
to party B (eg, via email), party B downloads to his/her folder and extracts
the hidden message with proof of the message integrity, signature
verification" (FR11/FR12). Owner: Yeo Kai Yuan, with Kannan s/o Rajamohan.

This file records a **local simulation** of that transfer, generated on
27 September 2026 by `scripts/transfer_demo.py`. The same email is built and
sent that a mail client would send, but it travels over SMTP to a receiver on
this machine, not through a third-party provider. The real two-machine email
transfer happens live in the demo. Its screenshots are still to be added (see
[the checklist](#live-demo-screenshots-to-add-after-rehearsal)).

## What the script does

1. **Party A protects both covers.** `samples/image/original/cover.png` and
   `samples/audio/original/cover.wav` are protected with `pipeline.protect`,
   using the custom message from `samples/payloads/custom.txt` (257 bytes).
   The message is encrypted with AES-256-GCM before it is signed. The stego
   files are saved to `party-a/outbox/`, and party A checks each one as
   Authentic before sending it.
2. **Party A composes a real email.** `email.message.EmailMessage` builds an
   RFC 5322 message from `party-a@acw1.local` to `party-b@acw1.local`. It
   carries both files as base64 MIME attachments (`image/png`, `audio/wav`).
   The body gives the media ID, LSB count, start mode, size and SHA-256 of
   each file. It says that the passphrase and public-key fingerprint were
   shared out of band. The script checks that neither appears in the email.
   The raw message is saved as `party-a/sent.eml`.
3. **The email crosses SMTP.** `smtplib` delivers it to a minimal SMTP
   receiver on `127.0.0.1` (ephemeral port, background thread). The receiver
   was written with `socketserver`, because `smtpd` is no longer in the
   standard library. It handles EHLO/HELO, MAIL FROM, RCPT TO, DATA with
   dot-unstuffing, RSET, NOOP and QUIT. It refuses unknown mailboxes, adds
   `Return-Path`/`Received` trace headers, and files the message into party
   B's Maildir with `mailbox.Maildir`.
4. **Party B downloads and verifies.** Party B opens the Maildir, parses the
   email and saves the attachments to `party-b/downloads/`. Each SHA-256 is
   compared with party A's pre-send value and with the value in the email.
   Party B then runs `pipeline.verify` with party A's **public** key, the
   settings read from the email body, and the out-of-band passphrase. The
   decrypted messages are saved to `party-b/extracted/`.
5. **Negative controls.** Party B verifies each download with a wrong
   passphrase. A copy of each download with one high bit flipped is saved to
   `party-b/tampered/` and verified too.

The script records 45 checks and exits non-zero if any fails. It needs only
the Python standard library and the project's `stego_core`.

## Command

From the repository root:

```bash
PYTHONPATH=backend .venv/bin/python scripts/transfer_demo.py --out evidence/transfer
```

Re-running replaces everything under `evidence/transfer/`. Each payload
carries a fresh nonce and timestamp by design, so stego bytes and SHA-256
values change on every run. Every check must still pass. The values below
come from the run at 2026-09-27T13:28:08Z:
[report](transfer/transfer-report.json), [log](transfer/transfer-log.txt).

## Settings

| Setting | Image | Audio |
| --- | --- | --- |
| Cover | `samples/image/original/cover.png` (788,092 bytes) | `samples/audio/original/cover.wav` (441,044 bytes) |
| Media ID | `P-transfer-image` | `P-transfer-audio` |
| LSB count | 2 | 2 |
| Start mode | derived from passphrase (offset 50,002) | derived from passphrase (offset 19,931) |
| Frame / capacity | 917 / 196,608 bytes | 916 / 55,125 bytes |
| Message | `samples/payloads/custom.txt`, encrypted | same |

Passphrase (demo-only, out of band): `acw1-demo-passphrase-2026`.
Public key: [`keys/public/transfer-demo.pub.pem`](../keys/public/transfer-demo.pub.pem),
fingerprint `50f4a321588e3e25401a9a9ebd5636d1841196a8b549545e1e46007930a4830e`.

This is a dedicated transfer key pair, not the team key. The team's private
key is not on this machine. Regenerating `team_ed25519` would have made every
committed sample report Signature Invalid. The private half is at
`keys/private/transfer-demo_ed25519.pem`, which is gitignored and never
copied into `evidence/`. If only one half of the pair is present, the script
refuses to run. With `--regenerate-key` it creates a new pair. Commit the new
public key together with the regenerated evidence.

## Results

| File | SHA-256, party A before sending | SHA-256, party B after download | Match | Verdict | Signature | Media hash | Message recovered |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `transfer-image.stego.png` (788,084 bytes) | `e680fbbd331c525cddbb297300a3bdd743057fb264a509a65f99fe1e30823120` | `e680fbbd331c525cddbb297300a3bdd743057fb264a509a65f99fe1e30823120` | yes, byte-identical | **Authentic** | valid | matches | yes, equals `custom.txt` |
| `transfer-audio.stego.wav` (441,044 bytes) | `22d95718609d81ce62f523b9cb8c0bf54258238f659af6b877e25b477a9fee39` | `22d95718609d81ce62f523b9cb8c0bf54258238f659af6b877e25b477a9fee39` | yes, byte-identical | **Authentic** | valid | matches | yes, equals `custom.txt` |

Both SHA-256 values also equal the ones in the email body, which is what party
B compares against in practice. Party B found each frame at party A's
derived offset. Party B never saw that offset: it was re-derived from the
passphrase and media ID.

The receiver's record of the SMTP session:

```text
S: 220 mx.acw1.local ESMTP ACW1 local receiver (simulation)
C: ehlo party-a.acw1.local
S: 250-mx.acw1.local greets party-a.acw1.local
S: 250-SIZE 33554432
S: 250-8BITMIME
S: 250 HELP
C: mail from:<party-a@acw1.local> size=1683903
S: 250 2.1.0 Sender OK
C: rcpt to:<party-b@acw1.local>
S: 250 2.1.5 Recipient OK
C: data
S: 354 End data with <CR><LF>.<CR><LF>
C: [message data: 1,683,903 bytes in 21,622 lines; 0 dot-stuffed line(s) restored]
C: .
S: 250 2.0.0 OK: queued as FFF1CB2C25A1
C: QUIT
S: 221 2.0.0 mx.acw1.local closing connection
```

(Lowercase commands are how `smtplib` writes them. SMTP verbs are
case-insensitive.)

## Negative controls

| Control | File | Verdict | Signature | Media hash | File SHA-256 vs party A |
| --- | --- | --- | --- | --- | --- |
| Wrong passphrase, image | `party-b/downloads/transfer-image.stego.png` | **Wrong Start Location** | not reached | not reached | matches (file unchanged) |
| Wrong passphrase, audio | `party-b/downloads/transfer-audio.stego.wav` | **Wrong Start Location** | not reached | not reached | matches (file unchanged) |
| High bit flipped, image: pixel (256, 256), red, bit 7, 190 → 62 | `party-b/tampered/transfer-image.high-bit-flipped.png` | **Tampered** | valid | differs | differs (`d81fc9f0…`) |
| High bit flipped, audio: sample 110,250, bit 15 | `party-b/tampered/transfer-audio.high-bit-flipped.wav` | **Tampered** | valid | differs | differs (`adc363c2…`) |

**Wrong passphrase.** In derived mode the passphrase decides where the frame
is read. A wrong one looks at offset 64,734 (image) and 3,058 (audio) instead
of 50,002 and 19,931. It finds no frame marker there, and the bounded scan
finds one elsewhere, so the verdict is Wrong Start Location. The message is not
decrypted. Holding the file is not enough; the out-of-band secret is needed
too.

**One flipped high bit.** This simulates a change in transit. Two separate
checks catch it:

- The file SHA-256 no longer matches the value party A sent.
- The verifier reports Tampered. The flipped bit is outside the 2-bit LSB
  plane, so the embedded frame and its signature are intact (signature
  valid). But the recomputed media hash differs from the one party A signed.

The encrypted message still decrypts on the tampered copies, because
decryption is for display only and never changes the verdict. The verdict,
not decryptability, is the integrity signal. Say this during the demo if
someone asks.

## Files

- `transfer/party-a/outbox/`: the two stego files as party A sent them
- `transfer/party-a/sent.eml`: the raw RFC 5322 message (1,683,903 bytes); opens in any mail client
- `transfer/party-b/Maildir/new/…`: the same message as delivered, with trace headers
- `transfer/party-b/downloads/`: the attachments party B saved
- `transfer/party-b/extracted/`: the decrypted messages recovered by party B
- `transfer/party-b/tampered/`: the high-bit-flipped copies
- `transfer/transfer-report.json`: every value above, plus timestamps, nonces and all 45 checks
- `transfer/transfer-log.txt`: the readable transcript, including the email body party B reads

No private key material is under `evidence/`. The script checks this and fails
if it finds any.

## Reproduce in the GUI

These are the settings the live walkthrough should mirror.

1. Protect: upload the cover, message = contents of `samples/payloads/custom.txt`,
   encrypt on, 2 LSBs, start **Derived from passphrase**, passphrase
   `acw1-demo-passphrase-2026`, media ID `P-transfer-image` (or
   `P-transfer-audio`). Sign with the transfer or team private key, whichever
   is on the demo machine.
2. Verify: upload `transfer/party-b/downloads/transfer-image.stego.png`, public
   key `keys/public/transfer-demo.pub.pem`, media ID `P-transfer-image`,
   2 LSBs, Derived from passphrase, the passphrase above. Expect Authentic and
   the decrypted message. Compare the file's SHA-256 chip with the table above.
3. Repeat with `transfer/party-b/tampered/transfer-image.high-bit-flipped.png`
   (expect Tampered) and with a wrong passphrase (expect Wrong Start Location).

A live demo that signs with a different private key must verify with that
key's public half. Files protected live will have different SHA-256 values
from this table.

## Scope

This is a local SMTP and Maildir round trip on one machine. It uses the same
MIME base64 attachment encoding that a real mail provider carries, and a real
SMTP conversation. It also shows that the bytes party B saves are identical to
the bytes party A sent. It does **not** involve a third-party mail provider,
two machines, a webmail download button, or any provider-side processing such
as virus scanning, size limits or attachment rewriting. It is reproducible
evidence for the marker, not a replacement for the demo.

The real two-machine email transfer is performed live during the demo
([docs/demo-plan.md](../docs/demo-plan.md) row 6). That run should use a real
email account on each side. Party A attaches the stego file. Party B downloads
it to their own folder, compares SHA-256 and verifies.

## Live demo screenshots to add after rehearsal

Save to `evidence/screenshots/transfer/` and link them here. Do not show the
private key or type the passphrase into the email.

- [ ] Party A: Protect result for the image, showing media ID, 2 LSBs, derived start and the stego SHA-256
- [ ] Party A: the same for the audio file
- [ ] Party A: the composed email with both attachments, before sending (recipient visible, body shows SHA-256)
- [ ] Party B: the received email in the inbox on the second machine or account, attachments listed
- [ ] Party B: the downloaded files in party B's downloads folder
- [ ] Party B: SHA-256 of each downloaded file (GUI chip or `sha256sum`), matching party A's
- [ ] Party B: Verify result for the image, Authentic with decrypted message
- [ ] Party B: Verify result for the audio, Authentic with decrypted message
- [ ] Party B: one negative on the received file (wrong passphrase, or a tampered copy), not Authentic
- [ ] Note which mail provider was used and the date of the rehearsal run

## Automated checks

[`backend/tests/test_transfer_demo.py`](../backend/tests/test_transfer_demo.py)
runs the whole round trip into a temporary folder with a throwaway key pair,
in about 1 second. Its 8 tests cover:

- SHA-256 match on both sides
- base64 attachments and no passphrase in the email
- independent re-verification of the downloads as Authentic, with the exact
  message recovered
- the high-bit flip giving Tampered and the wrong passphrase giving a
  non-Authentic verdict
- no private key in the output
- SMTP dot-unstuffing and refusal of unknown mailboxes
- refusal to replace a public key whose private half is missing
