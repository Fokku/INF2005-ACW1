"""API contract between the FastAPI backend and the React frontend.

This file is the single source of truth for request/response shapes.
`frontend/src/types.ts` mirrors these models by hand. If you change anything
here, update `types.ts` and `docs/design/api-contract.md` in the same commit.

These models are complete (not TODO): they describe *what* the system reports.
The behaviour behind them lives in `stego_core/` and is marked with TODO there.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class CoverKind(str, Enum):
    image = "image"  # PNG, 8-bit RGB/RGBA
    audio = "audio"  # WAV/PCM, 8- or 16-bit, mono/stereo


class StartMode(str, Enum):
    """How the payload start location is chosen and later recovered."""

    derived = "derived"  # start = keyed PRF(passphrase, cover-invariant properties); verifier re-derives it
    explicit = "explicit"  # user picks an element offset; shared with the verifier out of band


class Verdict(str, Enum):
    """The six verdict categories required by spec FR10 / Section 7."""

    AUTHENTIC = "Authentic"
    TAMPERED = "Tampered"
    SIGNATURE_INVALID = "Signature Invalid"
    PAYLOAD_MISSING = "Payload Missing"
    WRONG_START_LOCATION = "Wrong Start Location"
    CANNOT_VERIFY = "Cannot Verify"


class AttackKind(str, Enum):
    """Tamper simulations offered by the Attack Lab (innovation / negative cases)."""

    flip_bits = "flip_bits"  # flip high bits in a region          -> Tampered
    crop = "crop"  # crop image / truncate audio                    -> Tampered
    lsb_scrub = "lsb_scrub"  # zero the LSB plane                   -> Payload Missing
    reencode = "reencode"  # PNG->JPEG->PNG or WAV resample         -> Payload Missing
    corrupt_payload = "corrupt_payload"  # flip bits inside the embedded frame -> Tampered / Signature Invalid
    replay = "replay"  # transplant the frame into another cover    -> Tampered


# --------------------------------------------------------------------------- #
# Cover / file descriptions
# --------------------------------------------------------------------------- #


class ImageInfo(BaseModel):
    width: int
    height: int
    channels: int  # 3 (RGB) or 4 (RGBA) after normalisation
    mode: str  # Pillow mode of the original file, e.g. "RGB", "RGBA", "P"


class AudioInfo(BaseModel):
    sample_rate: int
    channels: int
    sample_width_bytes: int  # 1 (8-bit unsigned) or 2 (16-bit signed LE)
    frames: int
    duration_seconds: float


class CoverInfo(BaseModel):
    kind: CoverKind
    filename: str
    size_bytes: int
    sha256: str = Field(
        description="SHA-256 of the raw file bytes (for the 'hash before send / after download' check)"
    )
    image: ImageInfo | None = None
    audio: AudioInfo | None = None


class FileRef(BaseModel):
    """A file the backend has written to `out/` and can serve back."""

    file_id: str
    filename: str
    mime: str
    size_bytes: int
    sha256: str
    url: str = Field(description="Inline URL for <img>/<audio> src, e.g. /api/files/{id}")
    download_url: str = Field(
        description="Same file with Content-Disposition: attachment, e.g. /api/files/{id}?download=1"
    )


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #


class CapacityReport(BaseModel):
    cover: CoverInfo
    n_lsb: int = Field(ge=1, le=8)
    total_elements: int = Field(description="pixels*channels for images, frames*channels for audio")
    capacity_bits: int = Field(description="total_elements * n_lsb")
    capacity_bytes: int
    frame_overhead_bytes: int = Field(
        description="header + signature + CRC, i.e. bytes not available for the message"
    )
    max_message_bytes: int
    payload_bytes: int | None = Field(
        default=None, description="size of the message the user wants to embed, if given"
    )
    fits: bool | None = Field(default=None, description="payload_bytes + overhead <= capacity_bytes")


# --------------------------------------------------------------------------- #
# Payload (what is embedded)
# --------------------------------------------------------------------------- #


class PayloadInfo(BaseModel):
    """Decoded view of the embedded verification payload (spec FR3)."""

    version: int
    media_id: str
    timestamp: str  # ISO-8601 UTC
    cover_kind: CoverKind
    n_lsb: int
    shape: list[int] = Field(
        description="[height, width, channels] or [frames, channels]; signed so crops are detected"
    )
    media_hash: str = Field(description="SHA-256 of the stable representation of the cover (LSBs masked)")
    nonce: str = Field(description="hex, 16 random bytes")
    metadata: dict[str, str] = Field(
        default_factory=dict, description="team-defined metadata, e.g. team, author, purpose"
    )
    message_mime: str
    message_encrypted: bool
    message_text: str | None = Field(
        default=None, description="present when the message is text and readable"
    )
    message_file: FileRef | None = Field(
        default=None, description="the extracted message as a file, so the GUI can display/play it"
    )


# --------------------------------------------------------------------------- #
# Protect / verify / attack results
# --------------------------------------------------------------------------- #


class ProtectResult(BaseModel):
    stego: FileRef
    cover: CoverInfo
    n_lsb: int
    start_mode: StartMode
    start_offset: int = Field(
        description="element index where the frame begins (revealed for the demo explanation)"
    )
    payload: PayloadInfo
    signature_b64: str
    frame_bytes: int
    capacity_bytes: int
    diff: FileRef | None = Field(
        default=None, description="amplified LSB-plane difference image (image covers only)"
    )
    changed_elements: int | None = None
    psnr_db: float | None = None


class VerifyReport(BaseModel):
    verdict: Verdict
    reasons: list[str] = Field(description="human-readable explanation lines shown in the GUI")
    stego: CoverInfo
    n_lsb: int
    start_mode: StartMode
    start_offset_used: int | None = None
    payload_found: bool
    signature_valid: bool | None = None
    media_hash_embedded: str | None = None
    media_hash_recomputed: str | None = None
    hash_match: bool | None = None
    payload: PayloadInfo | None = None


class AttackResult(BaseModel):
    attack: AttackKind
    description: str
    expected_verdict: Verdict
    output: FileRef


# --------------------------------------------------------------------------- #
# Keys
# --------------------------------------------------------------------------- #


class KeyInfo(BaseModel):
    key_id: str
    label: str
    algorithm: str = "Ed25519"
    public_key_pem: str
    fingerprint: str = Field(description="SHA-256 of the DER-encoded SubjectPublicKeyInfo, hex")
    created_at: str | None = None


class KeyPairResult(BaseModel):
    key: KeyInfo
    public_key_file: FileRef
    private_key_file: FileRef = Field(description="download once and keep outside git; demo-only key")


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #


class HealthResponse(BaseModel):
    status: str
    version: str
    frontend_built: bool


class ErrorResponse(BaseModel):
    error: str = Field(
        description="machine-readable code: not_implemented | unsupported_cover | capacity_exceeded | bad_request | internal"
    )
    detail: str | None = None
    todo: str | None = Field(
        default=None, description="for not_implemented: the stego_core function a teammate must implement"
    )
