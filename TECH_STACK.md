# Tech Stack

Stack decision for the INF2005 ACW1 project: **Steganographic Image and Audio Integrity Verification with Digital Signature-Based Authentication**.

Decided 2026-09-08. Change this file (not just chat) if the team changes a choice.

## 1. Summary

| Layer | Choice | Why |
| --- | --- | --- |
| GUI | **Web frontend**: React 19 + TypeScript, built with Vite 8 | Team preference. Browser gives free side-by-side image display, native audio playback and file download for the "party A sends to party B" scenario. |
| Styling | **Tailwind CSS v4** via the `@tailwindcss/vite` plugin, plus daisyUI component classes | Required by the team. daisyUI supplies tabs, alerts, badges, range slider (LSB 1–8), progress (capacity meter) without hand-rolled CSS. |
| API | **FastAPI** (Python) on plain `uvicorn`, `python-multipart` for uploads | Thin HTTP layer over the core library. Swagger UI at `/docs` lets backend members test embed/verify before the UI exists. |
| Steganography + crypto core | **Pure Python package** (`stego_core`): NumPy, Pillow, stdlib `wave`, `cryptography`, stdlib `hashlib`/`hmac`/`secrets` | All marked logic (LSB, hashing, signing, start location, verdicts) lives in one framework-free, pytest-testable, CLI-drivable library. |
| Tests | `pytest` (+ `httpx` for FastAPI TestClient); Vitest kept minimal | Rubric marks are on Python behaviour; frontend tests stay small. |
| Lint / format | `ruff` (Python), `oxlint` (TypeScript) | One tool per language. |
| Package managers | `python -m venv` + `python -m pip`; `pnpm` | No system `pip` on the Arch dev box, so everything goes through a venv. pnpm lockfile committed. |
| Demo / marker mode | `pnpm build` once, then **one process**: FastAPI serves `/api` and the built frontend at `http://127.0.0.1:8000` | Lab PC and marker need only Python. No Node, no internet, no CDN at demo time. |

The browser is **display-and-transport only**. It never reads or writes pixel or sample bits (Canvas `getImageData` premultiplies alpha and applies colour management; Web Audio decodes to float32 — both destroy LSBs). All embedding, extraction and verification happens in `stego_core` on the server.

## 2. Backend

### Runtime

- Python **3.12 – 3.14** (`requires-python = ">=3.12,<3.15"`). NumPy 2.5 dropped 3.11. Dev box has 3.14.7; all compiled deps have cp314 wheels (verified 2026-09-08).
- Create the environment with `python -m venv .venv`, then always `python -m pip …` (never bare `pip`). Debian/Ubuntu teammates need `python3-venv`.

### Libraries (pin with `==` in `backend/pyproject.toml`; keep a `requirements.lock.txt` from `pip freeze`)

| Package | Version | Purpose |
| --- | --- | --- |
| `numpy` | 2.5.3 | Vectorised n-LSB (1–8) embed/extract on flat `uint8` / `uint16` views; capacity maths; bounded magic-byte scan. |
| `pillow` | 12.3.0 | Lossless PNG decode/encode; normalise P/L/LA → RGB/RGBA; render amplified LSB-plane diff image for the GUI. |
| `cryptography` | 50.0.1 | Ed25519 key generation / sign / verify (PEM PKCS8 + SPKI); AES-256-GCM + HKDF / scrypt for the confidential custom payload. RSA-PSS can be swapped in behind the same interface if the team prefers RSA. |
| stdlib `wave`, `hashlib`, `hmac`, `secrets`, `struct`, `json`, `zlib` | — | WAV/PCM 8/16-bit mono/stereo I/O with params preserved; SHA-256; keyed PRF for start-location derivation; nonces; payload framing + CRC32. |
| `fastapi` | 0.141.1 | HTTP API + pydantic schemas + Swagger `/docs`. |
| `pydantic` | 2.13.5 | Request/response models (the API contract). |
| `uvicorn` | 0.52.4 (**plain**, not `[standard]`) | ASGI server. The `[standard]` extra pulls uvloop/httptools/watchfiles for no demo benefit. Likewise do not use `fastapi[standard]`. |
| `python-multipart` | 0.0.32 | Multipart uploads of cover, stego, payload and PEM files. |
| `pytest` (dev) | 9.1.1 | Round-trip, verdict, codec, crypto and API tests. Output goes to `evidence/logs/`. |
| `httpx` (dev) | 0.28.x | FastAPI `TestClient`. |
| `ruff` (dev) | 0.16.x | Lint + format. |
| `hypothesis` (dev, optional) | 6.x | Property test for the LSB round-trip only. |

### Package layout

- `backend/stego_core/` — pure library, **no FastAPI/pydantic imports** (enforce with a tiny architecture test):
  `lsb.py`, `image_codec.py`, `audio_codec.py`, `video_codec.py`, `hashing.py`, `kdf.py`, `signing.py`, `payload.py`, `container.py`, `location.py`, `verdict.py`, `pipeline.py`, `attacks.py`, `cli.py`
- `backend/app/` — FastAPI: `main.py` (mounts `/api` routers, then serves `frontend/dist` with `StaticFiles(html=True)` when present), `schemas.py`, `storage.py` (writes outputs to `out/<uuid>.png|wav|avi`, serves `/api/files/{id}` with `Content-Disposition: attachment`; **never base64 in JSON**), `routers/{keys,capacity,protect,verify,attack,files}.py`
- `backend/tests/`
- Console scripts: `stego` (`keygen | capacity | protect | verify | tamper | serve`) for scripted evidence, marker reproduction and a rescue path if the UI misbehaves live.

## 3. Frontend

### Runtime and tooling

- Node 25 + **pnpm 10** (`packageManager` field pinned, `pnpm-lock.yaml` committed). Node is only needed to *build* the UI; the demo runs on Python alone.
- Scaffold with `pnpm create vite frontend --template react-ts`, then pin the versions below.

| Package | Version | Purpose |
| --- | --- | --- |
| `react`, `react-dom` | 19.2.x | UI. Four tabs held in React state: **Protect**, **Verify**, **Keys**, **Attack Lab**. No router, no global state library, no axios. |
| `vite` | 8.2.x | Dev server (with `/api` proxy → `127.0.0.1:8000`, so CORS never exists) and production build to `frontend/dist`. |
| `@vitejs/plugin-react` | 6.1.x | React plugin. Its peer range is Vite ^8 — if Vite is ever downgraded to 7, downgrade this to 5.x too. |
| `typescript` | 6.0.x | What the Vite template ships. TypeScript 7 (native port) is weeks old; do not jump to it. |
| `tailwindcss` + `@tailwindcss/vite` | 4.3.x | Tailwind v4, CSS-first. `src/index.css` is just `@import "tailwindcss"; @plugin "daisyui";`. No `tailwind.config.js`, no PostCSS, **no Play CDN**. |
| `daisyui` | 5.7.x | Component classes: `tabs`, `card`, `alert`, `badge`, `range` (LSB slider, `step=1`), `progress` (capacity), `file-input`, `steps` (A→B flow). |
| `oxlint` (dev) | 1.x | Linting, shipped with the Vite template. No ESLint, no Prettier. |
| `vitest` (dev, optional) | **4.1.x** | A handful of component tests. Not 5.0.0: its `engines` field excludes Node 25. |
| `wavesurfer.js` (optional) | 7.12.x | Waveform display only. Native `<audio controls>` is the guaranteed playback path. |
| `lucide-react` (optional) | 1.x | Icons. |

### Structure

```
frontend/src/
  main.tsx  App.tsx  index.css  types.ts        # types.ts hand-mirrors backend/app/schemas.py (frozen in week 1)
  api/client.ts                                  # fetch + FormData wrappers
  pages/ ProtectPage  VerifyPage  KeysPage  AttackLabPage
  components/ FilePicker  LsbSelector  StartLocationPanel  CapacityMeter  PayloadEditor
              ImageCompare  AudioCompare  PayloadPreview  VerdictBadge  DownloadButton  ReportPanel  HashChip
  lib/hash.ts                                    # display-only SHA-256 of a File via WebCrypto ("hash before send / after download")
```

Media handling: `ImageCompare` = two native `<img>` (cover from an object URL, stego from `/api/files/{id}`) plus a backend-rendered amplified LSB-plane diff PNG. `AudioCompare` = three native `<audio controls>` for cover, stego and payload. `PayloadPreview` switches on MIME (text → `<pre>`, image → `<img>`, audio → `<audio>`, else hex dump + download) — this is what satisfies the spec's "play (execute) payload".

Tailwind v4 only emits classes it finds as literal tokens in source. Keep verdict styling in a `Record<Verdict, string>` of literal class strings; never build class names with template strings (or add an `@source inline(...)` safelist).

## 4. Repository layout (target)

```
ACW1/
├── README.md  TECH_STACK.md  TODO.md  .editorconfig  .gitignore
├── docs/
│   ├── spec/                 # assignment spec (md + pdf)
│   ├── design/               # payload-format, start-location, verdict-table, threat-model, api-contract, innovation, limitations-and-ai-use
│   └── demo-plan.md
├── keys/
│   ├── public/               # tracked: team public key(s) *.pem
│   └── private/              # gitignored: demo-only private key, regenerated by `stego keygen`
├── samples/
│   ├── image/{original,stego,tampered}/
│   ├── audio/{original,stego,tampered}/
│   └── payloads/             # short (Learning Outcome), large (Project Overview), custom (encrypted)
├── evidence/{screenshots,logs}/
├── out/                      # gitignored runtime outputs served at /api/files/{id}
├── scripts/                  # setup.sh, setup.ps1, demo.sh, demo.ps1, check.sh, make_samples.py
├── backend/                  # pyproject.toml, requirements.lock.txt, stego_core/, app/, tests/
└── frontend/                 # package.json, pnpm-lock.yaml, vite.config.ts, src/
```

## 5. Commands

### One-time setup (each teammate)

```bash
git clone <repo-url> ACW1 && cd ACW1
python -m venv .venv
source .venv/bin/activate              # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.lock.txt
python -m pip install -e backend --no-deps      # registers the `stego` CLI
cd frontend && pnpm install --frozen-lockfile && cd ..
stego keygen --out keys                # writes keys/private/*.pem (ignored) and keys/public/*.pem (tracked)
```

### Dev loop (two terminals)

```bash
stego serve --reload                   # uvicorn on http://127.0.0.1:8000, Swagger at /docs
cd frontend && pnpm dev                # Vite on http://127.0.0.1:5173, /api proxied to :8000
```

### Demo / marker mode (one process, no Node needed once dist exists)

```bash
cd frontend && pnpm build && cd ..
stego serve                            # http://127.0.0.1:8000 serves the built UI + /api + /docs
```

### Checks and evidence

```bash
cd backend && pytest -q | tee ../evidence/logs/pytest.txt && ruff check . && ruff format --check .
cd frontend && pnpm lint && pnpm tsc -b
python scripts/make_samples.py         # regenerates samples/ and evidence/logs deterministically
```

## 6. Rules the stack depends on (do not "simplify" these later)

1. **Hash a stable representation, not file bytes.** LSB embedding changes the file, so `media_hash` = SHA-256 over the normalised samples with the selected low `n_lsb` bits masked (plus cover kind, shape/channels, sample width/rate). The verifier can then recompute it from the stego file.
2. **Derive the start location from a key, never from the media hash or the in-payload nonce.** Otherwise any MSB tamper moves the start and every "Tampered" file is misreported as "Wrong Start Location", and the nonce cannot be read before the start is known. Use passphrase → scrypt → HKDF-Expand → `K_loc`, `K_enc`; start = HMAC-SHA256(`K_loc`, media_id ‖ cover_kind ‖ n_lsb ‖ counter) mod (capacity − frame size).
3. **Bind `n_lsb`, shape, cover kind and media ID into the signed payload** and cross-check them against the frame header at verify time (blocks parameter substitution / replay).
4. **Bounded magic-byte scan** so the verifier can tell "Wrong Start Location" (magic found elsewhere) from "Payload Missing" (no magic anywhere). State honestly in the limitations section that the magic is scannable.
5. **Bit operations on `uint8` / `uint16` views only.** Never on `int16` (sign extension corrupts high bits). 8-bit WAV is unsigned; 16-bit is little-endian signed.
6. **Scope of formats:** 8-bit PNG (RGB/RGBA, normalise others), 8/16-bit PCM WAV (mono/stereo), and AVI video with an uncompressed PCM `auds` stream (audio-track embedding — video frames are read but never modified; see `stego_core/video_codec.py`). Reject 24-bit / float / compressed WAV, JPEG covers, and any video without an uncompressed PCM audio track with a clear *Cannot Verify* / unsupported message. Convert demo clips with `ffmpeg` (e.g. `ffmpeg -i input.mp4 -c:v copy -c:a pcm_s16le -ar 44100 output.avi`).
7. **Stego files leave the server as real files** (`out/<uuid>`, `Content-Disposition: attachment`), never base64 in JSON. A 50 MB WAV would otherwise stall the browser.
8. **Email transport = file attachment only.** Inline paste, WhatsApp/Teams "photo" mode and "optimise images" re-encode and wipe the LSB plane. Show SHA-256 of the file before send and after download. Script a re-encoded copy as a deliberate *Payload Missing* negative case.
9. **Never run the Vite dev server in the live demo.** Build once, serve from FastAPI. Rehearse on the actual lab PC, including browser version (Tailwind v4 needs Chrome/Edge/Firefox 128+ or Safari 16.4+).
10. **Ship `frontend/dist` in the submission** (zip and/or a `submission` git tag) so the marker needs only Python.
11. **Never commit private keys.** `keys/private/` is ignored; the marker verifies with `keys/public/*.pem`. Document that `stego keygen` creates a fresh demo pair and that regenerated samples verify against the new key.
12. **Do not start the innovation module until every verdict is green in pytest for both image and audio.** 19 of 35 team marks are the two round-trips plus their negative cases.

## 7. Alternatives considered

| Option | Verdict | Reason |
| --- | --- | --- |
| Plain HTML + vanilla JS served by FastAPI, Tailwind CLI with a committed compiled CSS | Rejected | Fewest moving parts and fully offline, but with six contributors the committed `app.css` merge-conflicts on every rebuild, and any class not rebuilt is silently unstyled. Vanilla JS across four tabs gets messy. |
| Contract-first: committed `openapi.json` + `openapi-typescript` codegen + TanStack Query + Playwright + ESLint/Prettier + mypy strict + CI + Docker | Rejected | Best type safety, but none of it is marked and the tooling eats week 1 of a four-week project. With ~8 endpoints a hand-written `types.ts` gives the same safety. |
| All-TypeScript (Node backend doing LSB with `pngjs` / hand-written WAV parser) | Rejected | Hand-rolled PNG/WAV codecs and browser-dependent WebCrypto Ed25519 support are where teams lose days. Pillow + `wave` + `cryptography` are proven. |
| Desktop GUI (tkinter / PyQt) | Rejected | Team wants a web UI; tkinter does not even import on the dev box (missing `libtk8.6.so`). |

## 8. Version pins and compatibility notes (checked 2026-09-08)

- Python 3.12–3.14 only. NumPy 2.5.3, Pillow 12.3.0, cryptography 50.0.1, pydantic-core all have cp314 wheels.
- TypeScript 6.0.x (not 7.x). Vite 8.2.x with `@vitejs/plugin-react` 6.1.x. If Vitest is added later, pin 4.1.x: 5.0.0 excludes Node 25.
- Tailwind 4.3.x and `@tailwindcss/vite` 4.3.x; daisyUI 5.7.x.
- FastAPI 0.141.x, pydantic 2.13.x, uvicorn 0.52.x (plain), python-multipart 0.0.32.
