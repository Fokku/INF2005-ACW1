# Bundled fonts

Self-hosted so the demo works on a lab PC with no internet (TECH_STACK.md: "no CDN at demo
time"). Latin subsets only, downloaded from Google Fonts on 2026-09-27.

| File | Family | Axes | Licence |
| --- | --- | --- | --- |
| `big-shoulders-latin.woff2` | Big Shoulders (stamp face) | wght 700–900, opsz 10–72 | SIL OFL 1.1 |
| `public-sans-latin.woff2` | Public Sans (body) | wght 400–600 | SIL OFL 1.1 |
| `public-sans-italic-latin.woff2` | Public Sans Italic | wght 400 | SIL OFL 1.1 |
| `martian-mono-latin.woff2` | Martian Mono (exhibit data) | wght 400–500 | SIL OFL 1.1 |

The OFL permits bundling and redistribution with software. "Big Shoulders Condensed", the name
the design doc originally used, is not a Google Fonts family (the request 400s and the heading
silently fell back to the system sans); the condensed look comes from Big Shoulders' high
optical size, pinned in `index.css`.
