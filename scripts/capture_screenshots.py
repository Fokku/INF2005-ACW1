"""Drive the real web GUI through every demo scenario and screenshot it.

Spec FR12 wants test evidence (screenshots, logs or output files showing
verification results). This script produces it the same way a presenter would
on stage — by clicking through the GUI in a real browser — and doubles as a
demo dry run: every scenario asserts the verdict it expects and the script
exits non-zero if the GUI disagrees.

Scenarios (see SCENES at the bottom for the exact list and expected verdicts):
  * Keys tab: generate a demo key pair (downloaded and used by the rest).
  * Party A -> party B: protect in one browser session, download the stego
    file, then verify it in a SEPARATE browser session with the SHA-256 party A
    read out (the email itself is the one step a browser cannot automate; see
    evidence/transfer.md for the SMTP round trip).
  * All six verdicts, for image and audio, from the curated samples/.
  * Capacity check blocked before embedding (image and audio).
  * Attack Lab -> Verify, robust embedding (1 vs 3 copies under lsb_noise),
    the sealed frame (advanced start-location security), steganalysis, and the
    AVI video cover.

Usage (repo root, venv active, UI built with `cd frontend && pnpm build`):
    python -m pip install -e "backend[evidence]" && python -m playwright install chromium
    PYTHONPATH=backend python scripts/capture_screenshots.py [--out evidence/screenshots/gui] [--url URL]

Without --url it starts its own server on a free port and stops it afterwards.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from playwright.sync_api import Browser, Locator, Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
PASSPHRASE = "acw1-demo-passphrase-2026"  # demo-only; the same one README documents
VIEWPORT = {"width": 1440, "height": 900}
TIMEOUT_MS = 60_000


# --------------------------------------------------------------------------- server


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server() -> tuple[subprocess.Popen, str]:
    port = _free_port()
    env = {**os.environ, "PYTHONPATH": str(ROOT / "backend")}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            with urllib.request.urlopen(f"{url}/api/health", timeout=1) as r:
                health = json.load(r)
            if not health.get("frontend_built"):
                proc.terminate()
                raise SystemExit("frontend/dist is missing: run `cd frontend && pnpm build` first")
            return proc, url
        except OSError:
            time.sleep(0.2)
    proc.terminate()
    raise SystemExit("the server did not start")


# --------------------------------------------------------------------------- GUI helpers


@dataclass
class Run:
    browser: Browser
    url: str
    out: Path
    work: Path
    results: list[dict] = field(default_factory=list)
    private_key: Path | None = None
    public_key: Path | None = None

    def page(self) -> Page:
        """A fresh browser session: new context = a different 'machine', no shared state."""
        context = self.browser.new_context(viewport=VIEWPORT, accept_downloads=True)
        page = context.new_page()
        page.set_default_timeout(TIMEOUT_MS)
        page.goto(self.url)
        expect(page.get_by_role("tab", name="Protect")).to_be_visible()
        return page

    def shot(self, page: Page, name: str) -> str:
        # JPEG: the synthetic noise covers make full-page PNGs ~2 MB each.
        path = self.out / f"{name}.jpg"
        page.wait_for_timeout(250)  # let fonts/transitions settle
        page.screenshot(path=path, full_page=True, type="jpeg", quality=85)
        return path.name

    def record(self, scene: str, screenshot: str, expected: str, observed: str, detail: str = "") -> None:
        ok = expected == observed
        self.results.append(
            {"scene": scene, "screenshot": screenshot, "expected": expected, "observed": observed, "ok": ok, "detail": detail}
        )
        print(f"  {'PASS' if ok else 'FAIL'}  {scene:<34} expected {expected!r:<24} observed {observed!r}")


def tab(page: Page, name: str, panel_id: str) -> Locator:
    page.get_by_role("tab", name=name).click()
    panel = page.locator(f"#panel-{panel_id}")
    expect(panel).to_be_visible()
    return panel


def set_lsb(panel: Locator, n: int) -> None:
    slider = panel.locator('input[type="range"]').first
    slider.focus()
    slider.press("Home")
    for _ in range(n - 1):
        slider.press("ArrowRight")
    expect(slider).to_have_value(str(n))


def set_copies(panel: Locator, copies: int) -> None:
    label = "1 (off)" if copies == 1 else str(copies)
    panel.get_by_role("button", name=label, exact=True).first.click()


def set_start(panel: Locator, mode: str, *, passphrase: str | None = None, offset: int | None = None) -> None:
    panel.get_by_role("button", name="Explicit offset" if mode == "explicit" else "Derived from passphrase").click()
    if mode == "explicit" and offset is not None:
        panel.locator('input[type="number"]').last.fill(str(offset))
    field = panel.locator('input[type="password"]')
    # Explicit mode only shows a passphrase field when encryption or sealing needs one.
    if passphrase is not None and field.count():
        field.fill(passphrase)


def media_id(panel: Locator, value: str) -> None:
    panel.get_by_placeholder("e.g. P6-8-cover-001").fill(value)


VERDICTS = ["Authentic", "Tampered", "Signature Invalid", "Payload Missing", "Wrong Start Location", "Cannot Verify"]


def normalise(text: str) -> str:
    """Stamps render uppercase via CSS and carry a glyph; compare in the API's own spelling."""
    return next((v for v in VERDICTS if v.lower() in text.lower()), text.strip())


def protect(
    run: Run,
    page: Page,
    cover: Path,
    *,
    mid: str,
    message: str | None = None,
    n_lsb: int = 1,
    copies: int = 1,
    mode: str = "derived",
    offset: int | None = None,
    passphrase: str | None = PASSPHRASE,
    seal: bool = False,
    expect_error: bool = False,
) -> Locator:
    panel = tab(page, "Protect", "protect")
    panel.locator('input[type="file"]').nth(0).set_input_files(cover)
    media_id(panel, mid)
    if message == "custom":
        panel.get_by_role("button", name=re.compile("^Custom")).click()
    elif message == "large":
        panel.get_by_role("button", name=re.compile("^Large")).click()
    elif message == "huge":
        panel.get_by_label("Message to hide").fill("A 20 KB message that no small cover can hold. " * 450)
    set_lsb(panel, n_lsb)
    set_copies(panel, copies)
    set_start(panel, mode, passphrase=passphrase, offset=offset)
    if seal:
        panel.get_by_label(re.compile("Seal the frame")).check()
    assert run.private_key is not None
    panel.locator('input[type="file"]').nth(1).set_input_files(run.private_key)
    panel.get_by_role("button", name="Protect and sign").click()
    if expect_error:
        expect(panel.get_by_text(re.compile("Blocked before embedding|Something went wrong"))).to_be_visible()
    else:
        expect(panel.get_by_text("Hand-off to party B")).to_be_visible()
    return panel


def verify_now(panel: Locator) -> str:
    """Press Extract and verify and return the NEW verdict (never a stale one)."""
    badge = panel.get_by_test_id("verdict")
    previous = badge.element_handle() if badge.count() else None
    panel.get_by_role("button", name="Extract and verify").click()
    if previous is not None:
        previous.wait_for_element_state("hidden")
    expect(badge).to_be_visible()
    return normalise(badge.inner_text())


# --------------------------------------------------------------------------- scenes


def scene_keys(run: Run) -> None:
    page = run.page()
    panel = tab(page, "Keys", "keys")
    panel.locator("input").first.fill("gui-demo")
    panel.get_by_role("button", name="Generate key pair").click()
    expect(panel.get_by_text("Key details")).to_be_visible()
    for link, attr in (("Download private key", "private_key"), ("Download public key", "public_key")):
        with page.expect_download() as dl:
            panel.get_by_role("link", name=link).click()
        target = run.work / dl.value.suggested_filename
        dl.value.save_as(target)
        setattr(run, attr, target)
    # Party B's check: paste the public key and read its fingerprint back.
    panel.get_by_label("Public key to check").fill(run.public_key.read_text())
    panel.get_by_role("button", name="Show fingerprint").click()
    expect(panel.get_by_text("Fingerprint (SHA-256 of the key)")).to_be_visible()
    run.record("keys: generate + fingerprint check", run.shot(page, "01-keys-generate"), "key pair", "key pair")
    page.context.close()


def scene_transfer(run: Run) -> None:
    """Party A protects; party B, in a separate browser session, verifies the download."""
    party_a = run.page()
    panel = protect(run, party_a, SAMPLES / "image/original/cover.png", mid="P6-8-gui-transfer", message="custom", n_lsb=2)
    sha_a = panel.locator(".exhibit", has_text="Stego file SHA-256").locator(".exhibit__value").inner_text().strip()
    a_shot = run.shot(party_a, "02-party-a-protect-image")
    with party_a.expect_download() as dl:
        panel.get_by_role("link", name="Download", exact=True).click()
    outbox = run.work / "party-b-downloads"
    outbox.mkdir(exist_ok=True)
    received = outbox / dl.value.suggested_filename
    dl.value.save_as(received)
    run.record("party A: protect image (custom, AES)", a_shot, "Hand-off to party B", "Hand-off to party B")

    party_b = run.page()
    vpanel = tab(party_b, "Verify", "verify")
    vpanel.locator('input[type="file"]').nth(0).set_input_files(received)
    vpanel.get_by_placeholder("64 hex characters").fill(sha_a)
    expect(vpanel.get_by_text("Same bytes as party A sent")).to_be_visible()
    media_id(vpanel, "P6-8-gui-transfer")
    assert run.public_key is not None
    vpanel.locator('input[type="file"]').nth(1).set_input_files(run.public_key)
    set_lsb(vpanel, 2)
    set_start(vpanel, "derived", passphrase=PASSPHRASE)
    observed = verify_now(vpanel)
    expect(vpanel.get_by_text("Decrypted with AES-256-GCM")).to_be_visible()
    run.record(
        "party B: verify downloaded image", run.shot(party_b, "03-party-b-verify-image"), "Authentic", observed,
        f"SHA-256 before = after = {sha_a}",
    )

    # Same file, party B types the wrong passphrase.
    set_start(vpanel, "derived", passphrase="not-the-shared-secret")
    observed = verify_now(vpanel)
    run.record("party B: wrong passphrase", run.shot(party_b, "04-party-b-wrong-passphrase"), "Wrong Start Location", observed)
    party_a.context.close()
    party_b.context.close()


def scene_samples(run: Run) -> None:
    """Every curated sample case, loaded with its own settings: all six verdicts."""
    with urllib.request.urlopen(f"{run.url}/api/samples") as r:
        cases = json.load(r)
    page = run.page()
    panel = tab(page, "Verify", "verify")
    for i, case in enumerate(cases, start=1):
        panel.get_by_label("Load a demo sample").select_option(case["id"])
        # Wait for this case's banner (file AND expected verdict): consecutive
        # cases can share a file, so the file name alone could be stale.
        banner = panel.locator("div.border-primary\\/60", has_text=f"Sample · {case['file']}")
        expect(banner.filter(has_text=case["expected_verdict"])).to_be_visible()
        observed = verify_now(panel)
        name = f"10-verdict-{i:02d}-{case['id']}"
        run.record(f"sample: {case['id']}", run.shot(page, name), case["expected_verdict"], observed, case["file"])
    page.context.close()


def scene_capacity(run: Run) -> None:
    for kind, cover in (("image", "image/original/cover-empty.png"), ("audio", "audio/original/cover-empty.wav")):
        page = run.page()
        panel = protect(
            run, page, SAMPLES / cover, mid=f"P6-8-gui-capacity-{kind}", message="huge", n_lsb=1,
            mode="explicit", offset=0, passphrase=None, expect_error=True,
        )
        expect(panel.get_by_text("Payload is larger than this cover can hold")).to_be_visible()
        detail = panel.get_by_text(re.compile("^payload does not fit")).inner_text()
        run.record(f"capacity: {kind} too small", run.shot(page, f"20-capacity-{kind}"), "blocked", "blocked", detail)
        page.context.close()


def scene_audio_and_handoff(run: Run) -> None:
    page = run.page()
    panel = protect(run, page, SAMPLES / "audio/original/cover.wav", mid="P6-8-gui-audio", n_lsb=1, mode="explicit", offset=5000)
    shot = run.shot(page, "30-protect-audio")
    run.record("protect audio (explicit 5000)", shot, "Hand-off to party B", "Hand-off to party B")
    panel.get_by_role("button", name="Verify this file →").click()
    vpanel = page.locator("#panel-verify")
    expect(vpanel.get_by_text("Loaded from Protect tab")).to_be_visible()
    observed = verify_now(vpanel)
    run.record("verify audio via hand-off", run.shot(page, "31-verify-audio-handoff"), "Authentic", observed)
    page.context.close()


def scene_video(run: Run) -> None:
    page = run.page()
    panel = protect(run, page, SAMPLES / "video/original/cover.avi", mid="P6-8-gui-video", n_lsb=2, mode="derived")
    expect(panel.locator("audio")).to_have_count(2)
    run.record("protect AVI video", run.shot(page, "40-protect-video"), "Hand-off to party B", "Hand-off to party B")
    panel.get_by_role("button", name="Verify this file →").click()
    vpanel = page.locator("#panel-verify")
    vpanel.locator('input[type="password"]').fill(PASSPHRASE)
    observed = verify_now(vpanel)
    run.record("verify AVI video", run.shot(page, "41-verify-video"), "Authentic", observed)
    page.context.close()


def _attack_then_verify(run: Run, page: Page, attack: str, shot: str | None = None) -> tuple[str, str]:
    apanel = page.locator("#panel-attack")
    apanel.locator(f'button:has(div.font-exhibit:text-is("{attack}"))').click()
    expect(apanel.get_by_text(f"Damaged copy created: {attack}")).to_be_visible()
    predicted = apanel.locator("p", has_text="Predicted verdict").inner_text()
    if shot:
        run.shot(page, shot)
    apanel.get_by_role("button", name="Verify the damaged file →").click()
    vpanel = page.locator("#panel-verify")
    expect(vpanel.get_by_text(f"Attack Lab · {attack}")).to_be_visible()
    return normalise(predicted), verify_now(vpanel)


def scene_attacks(run: Run) -> None:
    page = run.page()
    panel = protect(run, page, SAMPLES / "image/original/cover.png", mid="P6-8-gui-attack", n_lsb=2, mode="explicit", offset=4096)
    panel.get_by_role("button", name="Attack this file →").click()
    predicted, observed = _attack_then_verify(run, page, "flip_bits", shot="50-attack-lab-flip_bits")
    run.record("attack flip_bits -> verify", run.shot(page, "51-attack-flip_bits-verify"), "Tampered", observed, f"predicted {predicted}")
    page.get_by_role("tab", name="Attack Lab").click()
    predicted, observed = _attack_then_verify(run, page, "corrupt_payload")
    run.record("attack corrupt_payload -> verify", run.shot(page, "52-attack-corrupt_payload-verify"), "Tampered", observed, f"predicted {predicted}")
    page.context.close()


def scene_robust(run: Run) -> None:
    for copies, expected in ((1, "Tampered"), (3, "Authentic")):
        page = run.page()
        panel = protect(
            run, page, SAMPLES / "image/original/cover.png", mid=f"P6-8-gui-robust-{copies}", n_lsb=2,
            copies=copies, mode="explicit", offset=4096,
        )
        panel.get_by_role("button", name="Attack this file →").click()
        _, observed = _attack_then_verify(run, page, "lsb_noise")
        run.record(f"robust: {copies} copy/copies + lsb_noise", run.shot(page, f"60-robust-{copies}-copies"), expected, observed)
        page.context.close()


def scene_sealed(run: Run) -> None:
    page = run.page()
    panel = protect(run, page, SAMPLES / "image/original/cover.png", mid="P6-8-gui-sealed", n_lsb=2, mode="derived", seal=True)
    run.record("protect sealed frame", run.shot(page, "70-protect-sealed"), "Hand-off to party B", "Hand-off to party B")
    stego_url = panel.get_by_role("link", name="Download", exact=True).get_attribute("href")
    panel.get_by_role("button", name="Verify this file →").click()
    vpanel = page.locator("#panel-verify")
    vpanel.locator('input[type="password"]').fill(PASSPHRASE)
    observed = verify_now(vpanel)
    expect(vpanel.get_by_text("Frame sealed (encrypted header)")).to_be_visible()
    run.record("sealed: right passphrase", run.shot(page, "71-sealed-right-passphrase"), "Authentic", observed)
    vpanel.locator('input[type="password"]').fill("not-the-shared-secret")
    observed = verify_now(vpanel)
    # cover.png is larger than the bounded scan, so "absent" cannot be proven.
    run.record("sealed: wrong passphrase", run.shot(page, "72-sealed-wrong-passphrase"), "Cannot Verify", observed,
               "a sealed frame is invisible without the passphrase")

    # Steganalysis of the sealed stego file: its ciphertext has no byte pattern.
    assert stego_url is not None
    sealed_file = run.work / "sealed.stego.png"
    with urllib.request.urlopen(f"{run.url}{stego_url}") as r:
        sealed_file.write_bytes(r.read())
    spanel = tab(page, "Steganalysis", "steganalysis")
    spanel.locator('input[type="file"]').set_input_files(sealed_file)
    spanel.get_by_role("button", name="Analyse").click()
    observed = spanel.get_by_test_id("steg-verdict").inner_text()
    run.record("steganalysis: sealed stego", run.shot(page, "73-steganalysis-sealed"), "no evidence", _steg(observed))
    page.context.close()


def _steg(text: str) -> str:
    return "signs" if "signs" in text.lower() else "no evidence" if "no evidence" in text.lower() else text


def scene_steganalysis(run: Run) -> None:
    page = run.page()
    panel = tab(page, "Steganalysis", "steganalysis")
    for name, file, expected in (
        ("80-steganalysis-image-stego", "samples/image/stego/image-large.stego.png", "signs"),
        ("81-steganalysis-image-clean", "samples/image/original/cover.png", "no evidence"),
        ("82-steganalysis-audio-stego", "samples/audio/stego/audio-large.stego.wav", "signs"),
        ("83-steganalysis-derived-start", "samples/image/stego/image-derived-start.stego.png", "signs"),
    ):
        panel.get_by_label("Analyse a demo sample").select_option(file)
        # The report's File exhibit changing proves this is the new result, not the last one.
        file_exhibit = panel.locator(".exhibit", has=page.locator(".exhibit__label", has_text="File"))
        expect(file_exhibit.first.locator(".exhibit__value")).to_have_text(Path(file).name)
        badge = panel.get_by_test_id("steg-verdict")
        run.record(f"steganalysis: {Path(file).name}", run.shot(page, name), expected, _steg(badge.inner_text()))
    page.context.close()


def scene_lsb_depth(run: Run) -> None:
    """Demo row 4: the same cover at 8 LSBs, with the amplified LSB plane."""
    page = run.page()
    protect(run, page, SAMPLES / "image/original/cover.png", mid="P6-8-gui-lsb8", message="large", n_lsb=8, mode="explicit", offset=0)
    run.record("protect image at 8 LSBs", run.shot(page, "90-protect-image-8-lsb"), "Hand-off to party B", "Hand-off to party B")
    page.context.close()


SCENES = [
    scene_keys,
    scene_transfer,
    scene_samples,
    scene_capacity,
    scene_audio_and_handoff,
    scene_video,
    scene_attacks,
    scene_robust,
    scene_sealed,
    scene_steganalysis,
    scene_lsb_depth,
]


def write_index(out: Path, manifest: dict) -> None:
    """A human-readable index of the screenshots, next to them."""
    lines = [
        "# GUI evidence screenshots",
        "",
        "Generated by `scripts/capture_screenshots.py`, which drives the real web GUI in headless",
        "Chromium (Playwright) and asserts every verdict. Regenerate with:",
        "",
        "```bash",
        f"{manifest['command']}",
        "```",
        "",
        (
            f"Generated {manifest['generated_at']} at {manifest['viewport']['width']}x"
            f"{manifest['viewport']['height']}; full-page captures. `manifest.json` holds the same table as data."
        ),
        "",
        "| Screenshot | Scenario | Expected | Observed | Result |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in manifest["results"]:
        link = f"[{r['screenshot']}]({r['screenshot']})" if r["screenshot"] else "—"
        lines.append(
            f"| {link} | {r['scene']} | {r['expected']} | {r['observed']} | {'pass' if r['ok'] else '**FAIL**'} |"
        )
    (out / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=ROOT / "evidence" / "screenshots" / "gui")
    parser.add_argument("--url", help="use an already-running server instead of starting one")
    parser.add_argument("--only", nargs="*", help="run only these scenes, e.g. --only samples sealed")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    server = None
    url = args.url
    if url is None:
        server, url = start_server()
    try:
        with tempfile.TemporaryDirectory() as work, sync_playwright() as p:
            browser = p.chromium.launch()
            run = Run(browser=browser, url=url.rstrip("/"), out=args.out, work=Path(work))
            scenes = SCENES
            if args.only:
                wanted = {f"scene_{name}" for name in args.only} | {"scene_keys"}
                scenes = [s for s in SCENES if s.__name__ in wanted]
            for scene in scenes:
                print(f"{scene.__name__}")
                try:
                    scene(run)
                except Exception as exc:  # noqa: BLE001 - record it, keep capturing the rest
                    run.record(scene.__name__, "", "scene completes", f"error: {type(exc).__name__}", str(exc)[:500])
                    for context in browser.contexts:
                        context.close()
            browser.close()
    finally:
        if server is not None:
            server.terminate()
            server.wait(timeout=10)

    manifest = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "command": "PYTHONPATH=backend python scripts/capture_screenshots.py",
        "viewport": VIEWPORT,
        "results": run.results,
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    write_index(args.out, manifest)
    failed = [r for r in run.results if not r["ok"]]
    print(f"\n{len(run.results) - len(failed)}/{len(run.results)} scenes matched; screenshots in {args.out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
