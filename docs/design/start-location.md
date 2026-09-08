# Start-location design and security

> **Status: to be written** — workstream G, alongside `stego_core/location.py`.
> Spec FR7 and learning outcome 6 both ask for this, and the spec explicitly requires a start
> location **other than the top-left corner**.

## 1. The two modes

TODO(team): describe both, and say which one the demo uses for which case.

- **Explicit** — the user picks an element offset and shares it out of band.
- **Derived** — the offset comes from a keyed HMAC over the passphrase and cover-invariant facts.

## 2. How the offset is derived

TODO(team): write out the formula from `location.py`:
`start = HMAC-SHA256(K_loc, "start" ‖ media_id ‖ cover_kind ‖ n_lsb ‖ counter) mod span`,
where `K_loc` comes from `scrypt(passphrase) → HKDF-Expand`.

## 3. How the verifier finds it again

TODO(team): explain that party B re-derives the same number from the same passphrase, so nothing
about the location travels with the file.

## 4. What it is NOT derived from, and why

TODO(team): this section is the interesting one. Each of these looks reasonable and each breaks a
verdict — the reasoning is in the `location.py` module docstring:

- not the media hash (every tamper would report *Wrong Start Location*)
- not the payload nonce (circular: you cannot read it before you know where to look)
- not the cover shape (a crop would report *Wrong Start Location* instead of *Tampered*)

## 5. Honest limitations

TODO(team): the frame begins with a plaintext magic value, so an analyst can scan the LSB plane
and find it. A secret start defeats a naive fixed-offset reader, not a determined attacker.
Confidentiality comes from AES-GCM; authenticity comes from the signature. Say this plainly —
rubric criterion 7 rewards honesty about limits.
