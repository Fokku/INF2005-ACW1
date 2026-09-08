# Demo plan

> **Status: to be written** — workstream I. Due **one day before the demo**, uploaded to xSite
> together with the signed Declaration of Originality.

**Hard limits:** 25 minutes total. Every member must have speaking time. Absence scores zero.

## Running order

TODO(team): fill in names and timings so they total no more than 25 minutes.

| # | Minutes | Who | What they show | Rubric |
| --- | --- | --- | --- | --- |
| 1 | 2 | ______ | Problem, scenario, what the tool does | — |
| 2 | 3 | ______ | Payload structure and the frame layout | 1 |
| 3 | 3 | ______ | Start-location design, and how the verifier re-derives it | 1 |
| 4 | 4 | ______ | Image: protect, compare, verify, Authentic | 2 |
| 5 | 4 | ______ | Audio: protect, listen, verify, Authentic | 3 |
| 6 | 3 | ______ | Party A emails the stego file, party B downloads and verifies | 2, 3 |
| 7 | 3 | ______ | Negative cases from the Attack Lab, and the capacity check | 2, 3, 4 |
| 8 | 2 | ______ | Innovation, limitations and AI use | 5, 7 |

## Before the demo

- [ ] `scripts/demo.sh` runs on the **lab PC**, not just on a laptop
- [ ] Built UI served from one process, never the Vite dev server
- [ ] Sample files staged in `samples/`, browser tabs and the email client already open
- [ ] Passphrase and media IDs written down; do not improvise them live
- [ ] `stego` CLI available as a fallback if the browser misbehaves
- [ ] Two full rehearsals with timing

## Contingencies

TODO(team): what to do if the email attachment is stripped, if the lab has no network, or if a
verdict comes out wrong. Pre-generated files in `samples/` cover all three.
