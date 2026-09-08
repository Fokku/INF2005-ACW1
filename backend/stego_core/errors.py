"""Exception types shared by the whole core.

Complete — no TODO here. Raise these from your module and the API layer will
map them to the right HTTP status and verdict automatically.
"""

from __future__ import annotations


class StegoError(Exception):
    """Base class for every error this package raises."""

    code = "internal"


class UnsupportedCoverError(StegoError):
    """Cover file is a format we deliberately do not support.

    Examples: 24-bit or float WAV, compressed WAV, JPEG cover, 16-bit PNG.
    The API turns this into the verdict `Cannot Verify`.
    """

    code = "unsupported_cover"


class CapacityError(StegoError):
    """The payload does not fit in the cover at the chosen LSB count / start."""

    code = "capacity_exceeded"


class FrameError(StegoError):
    """The embedded frame is absent or malformed (bad magic, bad length, bad CRC)."""

    code = "bad_frame"


class KeyError_(StegoError):
    """A key is missing, malformed, or of the wrong type."""

    code = "bad_key"
