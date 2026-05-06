# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

DLP Screen Analyzer — a local-only tool for security analysts investigating DLP incidents. It batch-processes JPEG/PNG screenshots from a workstation using OCR (Tesseract) and regex patterns, then presents results through a web dashboard. All data stays on-machine; nothing is sent externally.

## Running the app

```bash
./install.sh        # installs Tesseract (via Homebrew or apt), creates .venv, pip-installs requirements
./run.sh            # activates .venv and starts uvicorn on http://127.0.0.1:8000
```

To run the backend directly (without the wrapper script):
```bash
.venv/bin/python backend/main.py
```

To test a single OCR result without triggering a full analysis run, use the diagnostic endpoint after the server is up:
```
GET http://127.0.0.1:8000/api/ocr_preview?filename=<name.jpg>
```

There is no test suite and no linter configuration in this repository.

## Architecture

The app has three layers that communicate in one direction: `input/` folder → backend → SQLite.

**`backend/analyzer.py`** — pure analysis logic, no I/O except OCR subprocess calls. `analyze_file()` is the entry point: it calls Tesseract as a subprocess (not via pytesseract's Python binding — raw subprocess with a temp file), reads back the text, then runs every regex in the `PATTERNS` list against it. Each pattern is a 4-tuple `(violation_type, regex, severity, describe_lambda)`. Severity levels are `'Критический'`, `'Средний'`, `'Низкий'` (Russian strings used as-is in the DB and UI). Employee names are inferred from the screenshot filename (first alphabetic segment of the stem).

**`backend/database.py`** — thin SQLite wrapper. Two tables: `screenshots` (one row per file) and `incidents` (one row per matched pattern per file). `DB_PATH` resolves to `dlp.db` in the repo root. All connections are opened and closed per call (no connection pool). `clear_all()` truncates both tables.

**`backend/main.py`** — FastAPI app + analysis job runner. Analysis runs in a background daemon thread via `threading.Thread`; individual files are processed in a `ThreadPoolExecutor` with up to 4 workers (conservative because Tesseract is heavy). A global `_job` dict tracks live progress and is read by `GET /api/analyze/status?since=<offset>`, which the frontend polls every 800 ms. `_stop_event` signals cancellation; a `pkill -9 tesseract` is issued on stop/timeout to kill stray OCR processes. `FILE_TIMEOUT = 45` seconds is the per-file deadline before the hung process is killed.

**`frontend/index.html`** — a single self-contained HTML file (all CSS and JS inlined). No build step. It connects directly to `http://127.0.0.1:8000` (hardcoded in the `const API` constant near the top of the `<script>` block). Navigation is tab-based (`show(page, el)`); each tab fetches from a different API endpoint. The incident table builds a `_incByFile` cache for the image preview modal.

## Key configuration constants

| Location | Constant | Default | Purpose |
|---|---|---|---|
| `backend/main.py` | `OCR_LANG` | `'rus+eng'` | Tesseract language(s) |
| `backend/main.py` | `FILE_TIMEOUT` | `45` | Seconds before a hung OCR is killed |
| `backend/analyzer.py` | `OCR_TIMEOUT` | `30` | Tesseract `wait()` timeout inside `_run_ocr` |
| `backend/main.py` | `workers` | `min(4, cpu_count)` | ThreadPoolExecutor size |

## Adding or modifying detection patterns

All patterns live in `analyzer.py` in the `PATTERNS` list. Each entry is:
```python
(
    'Human-readable type name',   # shown in UI and stored in DB
    r'regex',                     # compiled with re.IGNORECASE via re.findall()
    'Критический' | 'Средний' | 'Низкий',
    lambda m: f'Display string: {m}',  # m is the first match string (or tuple[0] for groups)
)
```
The describe lambda receives the raw match string and should return a short human-readable description with sensitive parts masked.

## Input folder

Screenshots must be placed in `input/` (auto-created on startup) at the repo root. Supported formats: `.jpg`, `.jpeg`, `.png`. The folder is scanned recursively by `list_jpeg_files()`.
