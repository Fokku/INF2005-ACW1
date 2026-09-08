"""Regenerate every file under samples/ and evidence/logs/ deterministically.

The marker has to be able to reproduce what the demo showed (spec FR12), and
re-running a script beats clicking through the GUI and hoping.

TODO(team): implement once `stego_core.pipeline` works — see workstream H.

Plan:
  1. Read the covers from samples/image/original/ and samples/audio/original/.
  2. Generate (or load) the demo key pair from keys/.
  3. For each of the three payload sizes (short / large / custom encrypted),
     protect both covers and write the result to samples/*/stego/.
  4. Run each attack in stego_core.attacks and write samples/*/tampered/.
  5. Verify every produced file and append the JSON reports to
     evidence/logs/verify-reports.json.
  6. Print a table of file -> expected verdict, and paste it into the README's
     "Expected outputs" section.

Use a FIXED timestamp and a FIXED nonce so re-running produces byte-identical
files; take them from constants at the top of this script rather than from the
clock, or the samples churn in git on every run.
"""

from __future__ import annotations

import sys

FIXED_TIMESTAMP = "2026-09-08T00:00:00Z"
FIXED_NONCE = "00112233445566778899aabbccddeeff"


def main() -> int:
    print("TODO(team): scripts/make_samples.py is not implemented yet — see TODO.md workstream H")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
