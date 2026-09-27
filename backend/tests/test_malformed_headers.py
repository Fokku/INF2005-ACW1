"""Well-formed files with header fields the core cannot use.

Each of these parses as far as the container or PEM layer, then carries a value
a library below the core refuses with its own exception type. The core must turn
that into one of its own errors (UnsupportedCoverError -> 415, KeyError_ -> 400
or Cannot Verify) so no endpoint answers with an unhandled 500.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from stego_core import signing, video_codec
from stego_core.errors import KeyError_, UnsupportedCoverError

COVER_AVI = Path(__file__).resolve().parents[2] / "samples" / "video" / "original" / "cover.avi"

# PEMs whose AlgorithmIdentifier OID (1.2.3.4) `cryptography` does not know. It
# raises UnsupportedAlgorithm for them, which is not a ValueError.
UNKNOWN_ALGORITHM_PUBLIC_PEM = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"MCowBQYDKgMEAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    b"-----END PUBLIC KEY-----\n"
)
UNKNOWN_ALGORITHM_PRIVATE_PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"MC4CAQAwBQYDKgMEBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    b"-----END PRIVATE KEY-----\n"
)


def test_public_key_with_unknown_algorithm_is_a_key_error() -> None:
    with pytest.raises(KeyError_, match="malformed public key"):
        signing.fingerprint(UNKNOWN_ALGORITHM_PUBLIC_PEM)
    with pytest.raises(KeyError_):
        signing.verify(UNKNOWN_ALGORITHM_PUBLIC_PEM, b"message", bytes(signing.SIGNATURE_BYTES))


def test_private_key_with_unknown_algorithm_is_a_key_error() -> None:
    with pytest.raises(KeyError_, match="malformed private key"):
        signing.sign(UNKNOWN_ALGORITHM_PRIVATE_PEM, b"message")


def _cover_with_audio_format(*, channels: int | None = None, sample_rate: int | None = None) -> bytes:
    """The demo cover.avi (mono, 44.1 kHz, 16-bit) with its WAVEFORMATEX edited."""
    avi = bytearray(COVER_AVI.read_bytes())
    fmt = avi.index(b"strf", avi.index(b"auds")) + 8  # wFormatTag, nChannels, nSamplesPerSec, ...
    if channels is not None:
        struct.pack_into("<H", avi, fmt + 2, channels)
    if sample_rate is not None:
        struct.pack_into("<I", avi, fmt + 4, sample_rate)
    return bytes(avi)


@pytest.mark.parametrize("channels", [0, 9, 65535])
def test_load_avi_rejects_an_impossible_channel_count(channels: int) -> None:
    with pytest.raises(UnsupportedCoverError, match="channels"):
        video_codec.load_avi(_cover_with_audio_format(channels=channels))


@pytest.mark.parametrize("sample_rate", [0, 0xFFFFFFFF])
def test_load_avi_rejects_an_impossible_sample_rate(sample_rate: int) -> None:
    with pytest.raises(UnsupportedCoverError, match="sample rate"):
        video_codec.load_avi(_cover_with_audio_format(sample_rate=sample_rate))


def test_load_avi_still_accepts_the_largest_plausible_header() -> None:
    """7.1 surround at 768 kHz is unusual but real, so it must still load."""
    cover = video_codec.load_avi(_cover_with_audio_format(channels=8, sample_rate=768_000))
    assert (cover.channels, cover.sample_rate) == (8, 768_000)
    assert cover.frames == len(cover.elements) // 8
