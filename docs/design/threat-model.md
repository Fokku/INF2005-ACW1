# Threat model

> **Status: to be written** — workstream G.

## What the design defends against

TODO(team): fill in, with the mechanism next to each.

- Altering the media after it was signed → the stable media hash no longer matches
- Forging a payload without the private key → signature verification fails
- Moving a valid frame into a different cover → bound `media_id`/`shape`/`cover_kind` disagree
- Reading the hidden message without the passphrase → AES-256-GCM
- Extracting the payload without the passphrase → the start location is keyed

## What it does NOT defend against

TODO(team): be honest here; criterion 7 rewards it.

- Anyone who re-encodes the file destroys the payload — availability, not confidentiality
- The frame magic is scannable, so the presence of a payload is detectable
- LSB replacement is detectable by chi-square and RS steganalysis
- A leaked passphrase or private key breaks everything
- Nothing here proves the *content* is true, only that it has not changed since signing

## Assumptions

TODO(team): the public key reaches party B authentically (fingerprint read out of band); the
passphrase is shared over a separate channel; the demo keys are throwaway.
