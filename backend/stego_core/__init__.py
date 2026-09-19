"""stego_core — all steganography and cryptography logic for ACW1.

This package is PURE: it must never import fastapi, pydantic or anything from
`app/`. That keeps it testable with pytest, drivable from the `stego` CLI, and
readable by the marker. `tests/test_architecture.py` enforces it.

Module map (see TODO.md for who does what):

    lsb.py          bit-level LSB replacement + capacity maths
    image_codec.py  PNG  <-> numpy array
    audio_codec.py  WAV  <-> numpy array
    hashing.py      SHA-256 over the stable representation
    kdf.py          passphrase -> K_loc, K_enc
    signing.py      Ed25519 keygen / sign / verify
    payload.py      the verification payload (media ID, timestamp, hash, nonce, metadata)
    container.py    the byte frame that is actually embedded
    location.py     where the payload starts, and how the verifier finds it again
    extraction.py   bounded frame extraction and strict payload decoding
    verdict.py      the six verdict categories and the decision table
    pipeline.py     protect() and verify() — glues everything together
    attacks.py      tamper simulations for the negative test cases
    cli.py          `stego keygen|capacity|protect|verify|tamper|serve`
"""

__version__ = "0.1.0"
