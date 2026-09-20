# FR7/FR8 contribution and test record

This working record identifies Ridwan's assigned FR7 and FR8 changes without claiming ownership of
the surrounding shared system. It is not the team's final contribution percentage statement or
Declaration of Originality.

## 1. Phased contribution boundary

| Phase | Ridwan's scoped contribution | Existing foundation retained |
| --- | --- | --- |
| 1 — FR7 validation | Validate explicit and derived starts, including type, range, exact-fit, and actual-frame trailing-capacity checks; require an explicit offset when that mode is selected | Key derivation, original HMAC formula, cover codecs, bit embedding, and initial protect/verify pipeline |
| 2 — FR7 recovery | Search every element-aligned marker position, make the 200,000-position bound explicit, and avoid claiming `Payload Missing` when the cover was only partly searched | Plaintext frame magic and the original diagnostic scanning/verdict concept |
| 3 — FR8 extraction | Add bounded two-stage frame extraction, strict payload validation, frame/header hardening, image/audio workflow coverage, and integration with the existing verifier | Frame layout, LSB bit engine, canonical payload serialization, Ed25519, stable hashing, optional encryption, and verdict decision rules |
| 4 — explanation | Document FR7/FR8 algorithms, security limits, failure behaviour, contribution scope, and reproducible tests | Team-wide threat model, verdict document, final demo plan, and submission administration |

Relevant implementation files are `backend/stego_core/location.py`,
`backend/stego_core/extraction.py`, `backend/stego_core/container.py`, `backend/stego_core/lsb.py`,
`backend/stego_core/pipeline.py`, and the focused tests named below. Small API validation changes
ensure explicit mode cannot silently fall back to derived mode.

## 2. Existing team work not claimed here

The repository credits Zong Han with the LSB engine and the initial crypto, frame, location,
verdict, and pipeline work. The cover codecs and optional video work are also shared team work.
Ridwan's phases build on those components; this record does not transfer their ownership.

FR9/FR10 decision algorithms, attack-lab implementation, team-wide samples, screenshots, manual
email evidence, demo scheduling, contribution percentages, and submission declarations are outside
this FR7/FR8 scope. No screenshots or manual GUI evidence were created in these four phases, so the
assigned evidence owner can produce them once all team branches are integrated.

## 3. Automated verification record

The focused suites currently contain:

| Test file | Tests |
| --- | ---: |
| `backend/tests/test_location.py` | 37 |
| `backend/tests/test_location_scan.py` | 41 |
| `backend/tests/test_start_location_workflows.py` | 86 |
| `backend/tests/test_extraction.py` | 85 |
| `backend/tests/test_extraction_workflows.py` | 66 |
| **Focused FR7/FR8 total** | **315** |

Run from the repository root:

```bash
.venv/bin/python -m pytest -q \
  backend/tests/test_location.py \
  backend/tests/test_location_scan.py \
  backend/tests/test_start_location_workflows.py

.venv/bin/python -m pytest -q \
  backend/tests/test_extraction.py \
  backend/tests/test_extraction_workflows.py

.venv/bin/python -m pytest -q backend/tests
.venv/bin/python -m ruff check backend
```

On Windows, use `.venv\\Scripts\\python.exe` instead. The focused FR7/FR8 total is 315 tests; with
the 78 tests inherited at that phase, the backend total was 393 when FR7/FR8 completed. Later FR9
tests do not change this focused count. Unrelated pre-existing formatting was not rewritten as part
of FR7/FR8.

## 4. AI-use record for team review

Codex assisted with repository inspection, implementation suggestions, test generation, running
automated checks, and drafting these FR7/FR8 explanations. Automated tests can establish observed
behaviour for covered cases, but they do not replace human review, security analysis, or a manual
demo. Ridwan should review the diff, be able to explain each design choice, and align this factual
record with the team's final AI-use declaration and agreed contribution statement.
