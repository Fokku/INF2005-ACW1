"""API smoke tests.

The first two pass today and guard the scaffold. The rest are the end-to-end
tests to enable as the core lands.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_attack_kinds_listed() -> None:
    r = client.get("/api/attack/kinds")
    assert r.status_code == 200
    kinds = {k["kind"] for k in r.json()}
    assert {"flip_bits", "lsb_scrub", "replay"} <= kinds


def test_unimplemented_endpoints_say_so(png_rgb: bytes) -> None:
    """Until the core exists, every feature endpoint returns a helpful 501."""
    r = client.post(
        "/api/capacity",
        files={"cover": ("t.png", png_rgb, "image/png")},
        data={"n_lsb": "1"},
    )
    assert r.status_code == 501
    assert r.json()["error"] == "not_implemented"


@pytest.mark.parametrize("kind", ["image", "audio"])
def test_protect_then_verify_roundtrip(kind: str) -> None:
    """The headline test: protect a cover through the API, download the stego
    file, verify it, and expect Authentic.

    TODO(team): implement once pipeline.protect and pipeline.verify work.
    Steps: POST /api/protect -> GET the returned download_url -> POST /api/verify
    with the same media_id, n_lsb and passphrase -> assert verdict == "Authentic".
    """
    pytest.skip("TODO(team): enable once pipeline.protect and pipeline.verify exist")
