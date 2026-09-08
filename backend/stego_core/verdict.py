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

    TODO(team): implement. The order of these checks IS the design — write the
    same table into docs/design/verdict-table.md.

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

    Always return at least one reason string. The GUI shows them verbatim, and
    the demo is far more convincing when the tool says WHY.
    """
    raise NotImplementedError("TODO(team): decide — see docstring")


@dataclass
class VerdictExplanation:
    """Optional richer explanation for the report panel."""

    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
