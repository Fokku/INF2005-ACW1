# Limitations, ethics and AI use

> **Status: to be written** — workstream G. Rubric criterion 7, 2 marks, marked on honesty.

## Technical limitations

TODO(team): pull the concrete ones from `threat-model.md` and the module docstrings. Include the
formats deliberately not supported (24-bit and float WAV, JPEG covers, 16-bit PNG) and why.

## Responsible use

TODO(team): steganography hides the existence of a message, which has obvious dual-use potential.
Say what this tool is for (integrity verification of released media) and note that the same
technique can conceal data exfiltration.

## Use of generative AI

The assignment requires this to be disclosed and reflected on.

TODO(team): record, for each tool used:

- which tool, and for what (brainstorming, drafting, debugging, code review)
- what the team changed or rejected from its output
- how the team checked correctness — the test suite, reading the docstrings, manual verification
- which parts are entirely the team's own work

Be specific. "We used AI to help" scores nothing; "we used it to draft the verdict table, then
rewrote three rows after finding it had the Payload Missing and Wrong Start Location conditions
backwards" shows the checking that criterion 7 asks for.
