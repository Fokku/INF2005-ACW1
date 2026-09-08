"""stego_core must never depend on the web layer.

Complete — no TODO. If this fails, someone imported fastapi or pydantic into the
core; move that code into app/ instead. Keeping the core pure is what lets the
CLI, the tests and the API share one implementation.
"""

from __future__ import annotations

import pathlib

CORE = pathlib.Path(__file__).resolve().parents[1] / "stego_core"
FORBIDDEN = ("fastapi", "pydantic", "starlette", "uvicorn")


def test_core_has_no_web_imports() -> None:
    offenders = []
    for path in CORE.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")) and any(f in stripped for f in FORBIDDEN):
                if "uvicorn" in stripped and path.name == "cli.py":
                    continue  # `stego serve` may start the server
                offenders.append(f"{path.name}: {stripped}")
    assert not offenders, "stego_core must stay framework-free:\n" + "\n".join(offenders)
