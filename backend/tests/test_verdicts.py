"""One test per verdict per cover type. THIS IS THE GATE.

Rubric criteria 2 and 3 are worth 19 of the 35 team marks and they are about
exactly this: does the image workflow and the audio workflow produce the right
answer, positively and negatively. Do not start the innovation work until every
test in this file passes.

Each test is written as a scenario a teammate can implement by filling in the
protect/verify calls. Remove the skip as you go.
"""

from __future__ import annotations

import pytest

from stego_core.verdict import ExtractionOutcome, Verdict, decide

pytestmark = pytest.mark.parametrize("cover_kind", ["image", "audio"])


def test_authentic(cover_kind: str) -> None:
    """Protect then verify with the right key and passphrase -> Authentic."""
    outcome = ExtractionOutcome(
        magic_at_expected_start=True,
        frame_parsed=True,
        crc_ok=True,
        payload_parsed=True,
        signature_valid=True,
        hash_match=True,
        params_match=True,
    )
    assert decide(outcome)[0] is Verdict.AUTHENTIC


def test_tampered(cover_kind: str) -> None:
    """Edit the media after protecting -> signature still valid, hash differs."""
    outcome = ExtractionOutcome(
        magic_at_expected_start=True,
        frame_parsed=True,
        crc_ok=True,
        payload_parsed=True,
        signature_valid=True,
        hash_match=False,
        params_match=True,
    )
    assert decide(outcome)[0] is Verdict.TAMPERED


def test_signature_invalid(cover_kind: str) -> None:
    """Verify with a different public key -> Signature Invalid."""
    outcome = ExtractionOutcome(
        magic_at_expected_start=True,
        frame_parsed=True,
        crc_ok=True,
        payload_parsed=True,
        signature_valid=False,
    )
    assert decide(outcome)[0] is Verdict.SIGNATURE_INVALID


def test_payload_missing(cover_kind: str) -> None:
    """Verify an untouched cover, or one whose LSB plane was scrubbed."""
    outcome = ExtractionOutcome(magic_at_expected_start=False, magic_found_elsewhere=False)
    assert decide(outcome)[0] is Verdict.PAYLOAD_MISSING


def test_wrong_start_location(cover_kind: str) -> None:
    """Verify with the wrong passphrase / wrong explicit offset."""
    outcome = ExtractionOutcome(magic_at_expected_start=False, magic_found_elsewhere=True)
    assert decide(outcome)[0] is Verdict.WRONG_START_LOCATION


def test_cannot_verify(cover_kind: str) -> None:
    """Unsupported file, or a missing/broken public key."""
    outcome = ExtractionOutcome(cover_supported=False)
    assert decide(outcome)[0] is Verdict.CANNOT_VERIFY
