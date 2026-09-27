"""The one-click demo samples (GET /api/samples) and committed public keys.

The Verify tab loads a sample's file, settings and public key in one click, so
every listed case must actually produce the verdict it advertises when those
exact settings go through /api/verify — this is what a presenter relies on
when the live embed misbehaves on stage (docs/demo-plan.md, "Contingencies").
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import samples as samples_router

client = TestClient(app)

ALL_VERDICTS = {
    "Authentic",
    "Tampered",
    "Signature Invalid",
    "Payload Missing",
    "Wrong Start Location",
    "Cannot Verify",
}


def _cases() -> list[dict]:
    r = client.get("/api/samples")
    assert r.status_code == 200
    return r.json()


def test_samples_cover_all_six_verdicts_for_image() -> None:
    image_verdicts = {c["expected_verdict"] for c in _cases() if c["kind"] == "image"}
    assert image_verdicts == ALL_VERDICTS


def test_samples_cover_five_verdicts_for_audio() -> None:
    audio_verdicts = {c["expected_verdict"] for c in _cases() if c["kind"] == "audio"}
    assert audio_verdicts == ALL_VERDICTS - {"Cannot Verify"}


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["id"])
def test_each_sample_produces_its_advertised_verdict(case: dict) -> None:
    file_response = client.get(case["url"])
    assert file_response.status_code == 200
    key_response = client.get(f"/api/keys/public/{case['public_key']}")
    assert key_response.status_code == 200

    data = {
        "media_id": case["media_id"],
        "n_lsb": str(case["n_lsb"]),
        "start_mode": case["start_mode"],
        "redundancy": str(case["redundancy"]),
    }
    if case["explicit_start"] is not None:
        data["explicit_start"] = str(case["explicit_start"])
    if case["passphrase"]:
        data["passphrase"] = case["passphrase"]
    r = client.post(
        "/api/verify",
        files={
            "stego": (case["file"].rsplit("/", 1)[-1], file_response.content),
            "public_key_pem": (case["public_key"], key_response.content),
        },
        data=data,
    )
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == case["expected_verdict"], r.json()["reasons"]


def test_sample_file_route_refuses_paths_outside_samples() -> None:
    assert client.get("/api/samples/file/../keys/public/team_ed25519.pub.pem").status_code == 404
    assert client.get("/api/samples/file/..%2F..%2FREADME.md").status_code == 404
    assert client.get("/api/samples/file/payloads/short.txt").status_code == 404


def test_missing_manifest_yields_empty_list(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(samples_router, "MANIFEST", tmp_path / "absent.json")
    assert client.get("/api/samples").json() == []


def test_public_keys_are_listed_with_fingerprints_and_no_private_keys() -> None:
    keys = client.get("/api/keys/public").json()
    names = {k["name"] for k in keys}
    assert "team_ed25519.pub.pem" in names
    for key in keys:
        assert "PRIVATE" not in key["public_key_pem"]
        assert len(key["fingerprint"]) == 64


def test_public_key_route_refuses_traversal() -> None:
    assert client.get("/api/keys/public/..%2F..%2FREADME.md").status_code == 404
    assert client.get("/api/keys/public/nope.pem").status_code == 404


def test_inspect_accepts_form_pem_and_rejects_garbage() -> None:
    pem = client.get("/api/keys/public/team_ed25519.pub.pem").text
    r = client.post("/api/keys/inspect", data={"public_key_pem": pem})
    assert r.status_code == 200
    listed = {k["name"]: k["fingerprint"] for k in client.get("/api/keys/public").json()}
    assert r.json()["fingerprint"] == listed["team_ed25519.pub.pem"]

    bad = client.post("/api/keys/inspect", data={"public_key_pem": "not a key"})
    assert bad.status_code in (400, 422)


@pytest.mark.parametrize("n_lsb,redundancy", [(1, 1), (2, 1), (3, 3), (8, 5)])
def test_capacity_max_message_bytes_agrees_with_fits_at_the_boundary(
    png_rgb: bytes, n_lsb: int, redundancy: int
) -> None:
    """The largest message the meter advertises must be reported as fitting,
    and one byte more must not (regression: they rounded in opposite ways)."""
    base = {"n_lsb": str(n_lsb), "redundancy": str(redundancy)}
    largest = client.post("/api/capacity", files={"cover": ("c.png", png_rgb)}, data=base).json()[
        "max_message_bytes"
    ]
    at = client.post(
        "/api/capacity", files={"cover": ("c.png", png_rgb)}, data={**base, "payload_bytes": str(largest)}
    )
    assert at.json()["fits"] is True
    over = client.post(
        "/api/capacity", files={"cover": ("c.png", png_rgb)}, data={**base, "payload_bytes": str(largest + 1)}
    )
    assert over.json()["fits"] is False
