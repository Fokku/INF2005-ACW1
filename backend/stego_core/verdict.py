"""The six verdict categories and the decision table (spec FR10).

Keep this module PURE: no file I/O, no numpy, no crypto. It takes a record of
what happened during extraction and returns a verdict plus the reasons the GUI
displays. That makes it trivially unit-testable, and `tests/test_verdicts.py`
(one test per verdict per cover type) is the gate before any innovation work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    AUTHENTIC = "Authentic"
    TAMPERED = "Tampered"
    SIGNATURE_INVALID = "Signature Invalid"
    PAYLOAD_MISSING = "Payload Missing"
    WRONG_START_LOCATION = "Wrong Start Location"
    CANNOT_VERIFY = "Cannot Verify"


@dataclass
class ExtractionOutcome:
    """Everything `pipeline.verify` learned, with nothing interpreted yet."""

    cover_supported: bool = True
    public_key_usable: bool = True
    magic_at_expected_start: bool = False
    magic_found_elsewhere: bool = False
    frame_parsed: bool = False  # header + lengths + CRC all good
    crc_ok: bool | None = None
    payload_parsed: bool | None = None
    signature_valid: bool | None = None
    hash_match: bool | None = None
    params_match: bool | None = None  # frame n_lsb / shape / kind == signed values
    error: str | None = None


def decide(outcome: ExtractionOutcome) -> tuple[Verdict, list[str]]:
    """Map an ExtractionOutcome to (verdict, reasons).

    The order of these checks IS the design — the same table is written into
    docs/design/verdict-table.md.

      1. not cover_supported, or not public_key_usable, or an unexpected error
                                                        -> CANNOT_VERIFY
      2. no magic at the expected start, but found elsewhere
                                                        -> WRONG_START_LOCATION
      3. no magic anywhere                              -> PAYLOAD_MISSING
      4. magic found but CRC fails / frame or payload will not parse
                                                        -> TAMPERED
      5. signature does not verify                      -> SIGNATURE_INVALID
      6. signature fine but recomputed media hash differs, or the frame's
         parameters disagree with the signed ones       -> TAMPERED
      7. everything checks out                          -> AUTHENTIC
    """
    if not outcome.cover_supported:
        return Verdict.CANNOT_VERIFY, [outcome.error or "cover file format is not supported"]
    if not outcome.public_key_usable:
        return Verdict.CANNOT_VERIFY, [outcome.error or "public key is missing or malformed"]
    if outcome.error:
        return Verdict.CANNOT_VERIFY, [outcome.error]

    if not outcome.magic_at_expected_start:
        if outcome.magic_found_elsewhere:
            return Verdict.WRONG_START_LOCATION, [
                (
                    "payload magic was not found at the expected start location, but was found "
                    "elsewhere in the cover — check the passphrase / explicit start offset"
                )
            ]
        return Verdict.PAYLOAD_MISSING, [
            (
                "no embedded payload could be found anywhere in this cover — it may never have "
                "been protected, or the LSB plane was destroyed by re-encoding"
            )
        ]

    if not outcome.frame_parsed or outcome.crc_ok is False or not outcome.payload_parsed:
        return Verdict.TAMPERED, [
            outcome.error
            or (
                "the embedded frame failed its CRC check or would not parse — the stego file "
                "was altered after protection"
            )
        ]

    if outcome.signature_valid is False:
        return Verdict.SIGNATURE_INVALID, [
            (
                "the digital signature does not verify against the supplied public key — wrong "
                "key, or the signed payload was altered"
            )
        ]

    reasons: list[str] = []
    tampered = False
    if outcome.hash_match is False:
        tampered = True
        reasons.append("the recomputed media hash does not match the hash signed into the payload")
    if outcome.params_match is False:
        tampered = True
        reasons.append(
            "the cover's actual parameters (n_lsb / shape / cover kind / media ID) do not "
            "match the signed payload"
        )
    if tampered:
        return Verdict.TAMPERED, reasons

    return Verdict.AUTHENTIC, ["signature valid, media hash matches, parameters match the signed payload"]


@dataclass
class VerdictExplanation:
    """Optional richer explanation for the report panel."""

    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
