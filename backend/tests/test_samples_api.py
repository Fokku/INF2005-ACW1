"""The one-click demo samples (GET /api/samples) and committed public keys.

The Verify tab loads a sample's file, settings and public key in one click, so
every listed case must actually produce the verdict it advertises when those
exact settings go through /api/verify — this is what a presenter relies on
when the live embed misbehaves on stage (docs/demo-plan.md, "Contingencies").
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote, unquote

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import keys as keys_router
from app.routers import samples as samples_router
from stego_core import signing

client = TestClient(app)
ROOT = Path(__file__).resolve().parents[2]

# The handlers' own 404 bodies. Asserting the body, not just the status, proves
# a request reached the handler: a path the router cannot match gets a plain
# {"detail": "Not Found"} without any containment check ever running.
NOT_A_SAMPLE = {"detail": "not a sample file"}
NO_SUCH_KEY = {"detail": "public key not found"}

# A well-formed SubjectPublicKeyInfo whose algorithm OID (1.2.3.4) `cryptography`
# does not know: it raises UnsupportedAlgorithm, which is not a ValueError.
UNKNOWN_ALGORITHM_PUBLIC_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDKgMEAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    "-----END PUBLIC KEY-----\n"
)

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
    """Every request reaches the handler and names a real PNG/WAV outside
    samples/ with a servable suffix, so only the containment checks stand
    between it and a 200 (the suffix whitelist alone would let it through)."""
    for rel in ("evidence/fr10-fr11/image-custom.stego.png", "evidence/fr10-fr11/original.wav"):
        assert (ROOT / rel).is_file()  # the target exists, so a 404 means it was refused
    absolute = quote((ROOT / "evidence/fr10-fr11/original.wav").as_posix(), safe="")
    for path in (
        "..%2Fevidence%2Ffr10-fr11%2Fimage-custom.stego.png",
        "image/stego/..%2F..%2F..%2Fevidence%2Ffr10-fr11%2Foriginal.wav",
        absolute,
    ):
        r = client.get(f"/api/samples/file/{path}")
        assert (r.status_code, r.json()) == (404, NOT_A_SAMPLE), path
    # Inside samples/ but not media.
    assert client.get("/api/samples/file/payloads/short.txt").json() == NOT_A_SAMPLE


def test_sample_file_route_serves_only_files_a_case_names() -> None:
    """Real media inside samples/ that no listed case names is refused too: the
    route serves the demo cases, not the whole folder."""
    listed = {case["file"] for case in _cases()}
    for rel in (
        "audio/original/cover.wav",
        "video/original/cover.avi",
        "audio/stego/section-f-replay-source.wav",
    ):
        assert (ROOT / "samples" / rel).is_file() and f"samples/{rel}" not in listed
        assert client.get(f"/api/samples/file/{rel}").json() == NOT_A_SAMPLE, rel


def _spy_on_filesystem(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every path Path.resolve() and Path.is_file() are called on."""
    seen: list[str] = []
    real_resolve, real_is_file = Path.resolve, Path.is_file

    def spy_resolve(self: Path, *args, **kwargs):
        seen.append(str(self))
        return real_resolve(self, *args, **kwargs)

    def spy_is_file(self: Path, *args, **kwargs):
        seen.append(str(self))
        return real_is_file(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", spy_resolve)
    monkeypatch.setattr(Path, "is_file", spy_is_file)
    return seen


def _use_manifest(monkeypatch: pytest.MonkeyPatch, root: Path, files: list[str]) -> None:
    """Point the samples router at `root`, with a manifest listing one case per file."""
    settings = {"media_id": "m", "n_lsb": 1}
    cases = [
        {"case": f"image-case{i}-authentic", "file": file, "settings": settings}
        for i, file in enumerate(files)
    ]
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    monkeypatch.setattr(samples_router, "ROOT", root)
    monkeypatch.setattr(samples_router, "SAMPLES_DIR", root / "samples")
    monkeypatch.setattr(samples_router, "MANIFEST", manifest)


@pytest.mark.parametrize(
    "path",
    [
        "%00",
        "image/stego/image-short.stego.png%00.png",
        "%2F%2Fevil.example%2Fshare%2Fx.png",  # UNC path spelt with forward slashes
        "%5C%5Cevil.example%5Cshare%5Cx.png",  # UNC path
        "C:%2Fsamples%2Fx.png",
        "C:x.png",
        "image%5Cstego%5Cimage-short.stego.png",
    ],
)
def test_sample_file_route_refuses_hostile_paths_before_touching_the_filesystem(
    path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A NUL byte used to make resolve() raise (a 500), and on the Windows demo
    host resolving a UNC path opens an SMB connection before any containment
    check. Both must be refused on the string alone: no resolve() or is_file()
    call may ever see the request path."""
    seen = _spy_on_filesystem(monkeypatch)
    r = client.get(f"/api/samples/file/{path}")
    assert (r.status_code, r.json()) == (404, NOT_A_SAMPLE)
    assert not [touched for touched in seen if unquote(path) in touched]


@pytest.mark.parametrize(
    "path",
    [
        "",
        "a\x00.png",
        "/etc/x.png",
        "//evil.example/share/x.png",
        "\\\\evil.example\\share\\x.png",
        "C:/x.png",
        "C:x.png",
        "image\\x.png",
        "../x.png",
        "image/../../x.png",
        "image/..",
    ],
)
def test_sample_path_check_refuses_escapes_for_any_host_os(path: str) -> None:
    """The string check covers Windows anchors even when the tests run on Linux,
    where the host itself would not treat them as special."""
    assert not samples_router._is_plain_relative_path(path)


def test_sample_path_check_accepts_a_plain_relative_path() -> None:
    assert samples_router._is_plain_relative_path("image/stego/image-short.stego.png")


def test_sample_file_route_checks_the_string_even_for_a_path_the_manifest_names(
    monkeypatch, tmp_path
) -> None:
    """The case list cannot widen the route: if the manifest itself named a UNC
    path, the string check must still refuse it before anything resolves it."""
    (tmp_path / "samples").mkdir()
    unc = "//evil.example/share/x.png"
    _use_manifest(monkeypatch, tmp_path, [unc])
    seen = _spy_on_filesystem(monkeypatch)
    r = client.get(f"/api/samples/file/{quote(unc, safe='')}")
    assert (r.status_code, r.json()) == (404, NOT_A_SAMPLE)
    assert not [touched for touched in seen if "evil.example" in touched]


def test_sample_file_route_refuses_a_listed_symlink_out_of_samples(monkeypatch, tmp_path) -> None:
    """The last layer: a case file that is a symlink out of samples/ passes the
    string check and the case list, and must still be refused once resolved."""
    image_dir = tmp_path / "samples" / "image"
    image_dir.mkdir(parents=True)
    (image_dir / "real.png").write_bytes(b"inside")
    (tmp_path / "secret.png").write_bytes(b"outside")
    try:
        (image_dir / "escape.png").symlink_to(tmp_path / "secret.png")
    except OSError:
        pytest.skip("this host cannot create symlinks")
    _use_manifest(monkeypatch, tmp_path, ["samples/image/real.png", "samples/image/escape.png"])

    assert {case["file"] for case in _cases()} == {"samples/image/real.png", "samples/image/escape.png"}
    assert client.get("/api/samples/file/image/real.png").content == b"inside"
    r = client.get("/api/samples/file/image/escape.png")
    assert (r.status_code, r.json()) == (404, NOT_A_SAMPLE)


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


@pytest.mark.parametrize(
    "name",
    [
        "nope.pem",
        "%00.pem",
        "team_ed25519.pub.pem%00.pem",
        "..%5Cprivate%5Cteam_ed25519.pem",
        "C:team_ed25519.pub.pem",
        "team_ed25519.pub.pem.txt",
    ],
)
def test_public_key_route_refuses_traversal(name: str) -> None:
    """Every name reaches the handler (none contains a `/`, which the route
    could not match), so its own 404 proves the name check refused it. A NUL
    byte used to make resolve() raise, a 500."""
    r = client.get(f"/api/keys/public/{name}")
    assert (r.status_code, r.json()) == (404, NO_SUCH_KEY)


def test_public_key_listing_and_download_skip_unusable_and_private_files(monkeypatch, tmp_path) -> None:
    """The listing and the download agree, and neither includes a private key,
    a bundle that carries one, a key `cryptography` cannot load (that used to
    500 the whole listing), a non-key or a symlink out of keys/public/."""
    public_dir = tmp_path / "public"
    public_dir.mkdir()
    private_pem, public_pem = signing.generate_keypair()
    (public_dir / "good.pub.pem").write_bytes(public_pem)
    (public_dir / "misplaced-private.pem").write_bytes(private_pem)
    (public_dir / "bundle.pem").write_bytes(public_pem + private_pem)  # parses as its first block
    (public_dir / "unknown-algorithm.pem").write_text(UNKNOWN_ALGORITHM_PUBLIC_PEM, encoding="ascii")
    (public_dir / "garbage.pem").write_text("not a key", encoding="ascii")
    (public_dir / "folder.pem").mkdir()
    refused = ["misplaced-private.pem", "bundle.pem", "unknown-algorithm.pem", "garbage.pem", "folder.pem"]
    (tmp_path / "outside.pub.pem").write_bytes(signing.generate_keypair()[1])
    try:
        (public_dir / "escape.pem").symlink_to(tmp_path / "outside.pub.pem")
        refused.append("escape.pem")
    except OSError:
        pass  # no symlinks on this host; the other files still cover the rest
    monkeypatch.setattr(keys_router, "PUBLIC_KEYS_DIR", public_dir)

    listed = client.get("/api/keys/public")
    assert listed.status_code == 200
    assert [key["name"] for key in listed.json()] == ["good.pub.pem"]
    assert client.get("/api/keys/public/good.pub.pem").content == public_pem
    for name in refused:
        r = client.get(f"/api/keys/public/{name}")
        assert (r.status_code, r.json()) == (404, NO_SUCH_KEY), name


def test_inspect_accepts_form_pem_and_rejects_garbage() -> None:
    pem = client.get("/api/keys/public/team_ed25519.pub.pem").text
    r = client.post("/api/keys/inspect", data={"public_key_pem": pem})
    assert r.status_code == 200
    listed = {k["name"]: k["fingerprint"] for k in client.get("/api/keys/public").json()}
    assert r.json()["fingerprint"] == listed["team_ed25519.pub.pem"]

    bad = client.post("/api/keys/inspect", data={"public_key_pem": "not a key"})
    assert bad.status_code in (400, 422)


def test_inspect_rejects_a_key_with_an_unsupported_algorithm() -> None:
    """UnsupportedAlgorithm is not a ValueError; it used to escape as a 500."""
    r = client.post("/api/keys/inspect", data={"public_key_pem": UNKNOWN_ALGORITHM_PUBLIC_PEM})
    assert r.status_code == 400
    assert r.json()["detail"].startswith("not a usable public key")
