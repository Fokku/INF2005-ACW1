"""Turning one human passphrase into three independent keys.

The user types one secret in the GUI. From it we need:
    K_loc  — keys the start-location PRF (`location.py`)
    K_enc  — encrypts the confidential custom payload (`payload.py`)
    K_seal — encrypts the whole embedded frame when it is sealed (`sealing.py`)

>>> Passphrases are LOW entropy, so run a slow password KDF (scrypt) FIRST,
>>> then split its output with HKDF-Expand using different labels. Feeding a
>>> passphrase straight into HKDF is wrong: HKDF assumes a high-entropy input.
>>>
>>> Adding K_seal did NOT change K_loc or K_enc. Each label is a separate
>>> HKDF-Expand call over the same scrypt output, so a new label is a new,
>>> independent output and the old two stay byte-identical. That matters:
>>> every existing stego file's derived start and encrypted message depend on
>>> them (tests/test_sealed_frame.py pins their values). Never rename a label.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


@dataclass(frozen=True)
class DerivedKeys:
    k_loc: bytes  # 32 bytes, for HMAC start-location derivation
    k_enc: bytes  # 32 bytes, for AES-256-GCM
    k_seal: bytes  # 32 bytes, for AES-256-CTR over the whole frame (sealing.py)


def derive_keys(passphrase: str, salt: bytes) -> DerivedKeys:
    """passphrase + salt -> (K_loc, K_enc, K_seal).

    Args:
        salt: must be reproducible by the verifier from something it can see
              WITHOUT extracting the payload first. Use SHA-256(media_id) where
              media_id is agreed out of band, or a fixed per-team salt.
              Do NOT use a random salt you only store inside the payload — the
              verifier needs the keys before it can read the payload. (Circular.)

    Note the cost: scrypt at n=2**15 takes ~100 ms. That is intentional (it
    slows passphrase guessing) but call it once per request, not per bit.
    """
    master = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        passphrase.encode("utf-8")
    )
    k_loc = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"acw1-loc").derive(master)
    k_enc = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"acw1-enc").derive(master)
    k_seal = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"acw1-seal").derive(master)
    return DerivedKeys(k_loc=k_loc, k_enc=k_enc, k_seal=k_seal)
