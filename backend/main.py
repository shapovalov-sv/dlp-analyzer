import os
import sys
import time
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

sys.path.insert(0, os.path.dirname(__file__))
import database as db
import analyzer as an
import proclog


def _kill_tesseract():
    """Force-kill any stray tesseract processes (cross-platform)."""
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/IM', 'tesseract.exe'],
                           capture_output=True)
        else:
            subprocess.run(['pkill', '-9', '-f', 'tesseract'],
                           capture_output=True)
    except (OSError, FileNotFoundError):
        pass

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_DIR    = os.path.join(BASE_DIR, 'input')
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')

OCR_LANG     = 'rus+eng'
FILE_TIMEOUT = 45  # hard deadline per file (seconds)
WATCH_INTERVAL = 3  # folder-watch poll interval (seconds)

# ── Job state ────────────────────────────────────────────────────────────────
_lock = threading.RLock()  # reentrant — same thread can acquire multiple times
_job: dict = {
    'running':   False,
    'total':     0,
    'processed': 0,
    'high':      0,
    'medium':    0,
    'low':       0,
    'clean':     0,
    'speed':     0.0,
    'eta_sec':   None,
    'log':       [],
    'error':     None,
}
_stop_event = threading.Event()

# ── Folder watcher state ──────────────────────────────────────────────────────
_watch_lock = threading.RLock()
_watch: dict = {
    'enabled':         True,      # auto-analyze new screenshots
    'dir':             INPUT_DIR,  # folder being watched / analyzed
    'active_employee': '',        # fallback employee for loose files in the root
    'processed_count': 0,         # files auto-processed since start
    'last_scan':       None,      # epoch of last folder scan
    'recent':          [],        # recent auto-processed items (newest first)
}
_pending_sizes: dict = {}         # filepath -> size, to detect files still being copied


def _input_dir() -> str:
    with _watch_lock:
        return _watch['dir'] or INPUT_DIR


def _employee_for(filepath: str, active: str, root: str) -> str:
    """Decide which employee a screenshot belongs to.
    The employee is the name of the (sub)folder that holds the screenshot,
    e.g. <root>/Иванов/screen.jpg → 'Иванов'. Files lying directly in the
    root fall back to the active employee, then to a filename guess."""
    rel = os.path.relpath(filepath, root).replace('\\', '/')
    parts = rel.split('/')
    if len(parts) > 1 and parts[0] not in ('', '.'):
        return parts[0]  # folder name = employee (primary rule)
    if active:
        return active
    emp, _dept = an._extract_employee(os.path.basename(filepath))
    return emp


def _push_watch_event(filename: str, employee: str, result: dict):
    incidents = len(result.get('incidents', []))
    with _watch_lock:
        _watch['processed_count'] += 1
        _watch['recent'].insert(0, {
            'filename':  filename,
            'employee':  employee,
            'incidents': incidents,
            'error':     result.get('error'),
            'at':        time.strftime('%H:%M:%S'),
        })
        _watch['recent'] = _watch['recent'][:50]


def _watcher_loop():
    """Poll the watched folder (recursively) and analyze new, fully-copied
    screenshots automatically. Whole sub-folders dropped in are picked up too."""
    global _pending_sizes
    while True:
        try:
            with _watch_lock:
                enabled = _watch['enabled']
                active  = _watch['active_employee']
            root = _input_dir()
            with _lock:
                running = _job['running']

            if enabled and not running and os.path.isdir(root):
                current = {}
                for f in an.list_jpeg_files(root):     # os.walk → recurses into sub-folders
                    rel = os.path.relpath(f, root)
                    if proclog.is_done(rel):
                        continue
                    try:
                        size = os.path.getsize(f)
                    except OSError:
                        continue
                    # Only process once the file size is stable between two scans
                    # (avoids reading a screenshot/folder that is still being copied).
                    if _pending_sizes.get(f) == size:
                        emp = _employee_for(f, active, root)
                        try:
                            result = an.analyze_file(f, OCR_LANG)
                        except Exception as exc:
                            result = _make_error_result(f, str(exc))
                        db.save_result(result, employee=emp)
                        proclog.mark(rel, f, emp, len(result.get('incidents', [])), result.get('error'))
                        _push_watch_event(os.path.basename(f), emp, result)
                    else:
                        current[f] = size  # remember size, revisit next scan
                _pending_sizes = current
        except Exception:
            pass
        finally:
            with _watch_lock:
                _watch['last_scan'] = time.time()
        time.sleep(WATCH_INTERVAL)


def _log(level: str, msg: str):
    with _lock:
        _job['log'].append({'level': level, 'msg': msg})
        if len(_job['log']) > 500:
            _job['log'] = _job['log'][-500:]


def _make_error_result(filepath: str, error: str) -> dict:
    return {
        'filename': os.path.basename(filepath),
        'path':     filepath,
        'ocr_text': '',
        'incidents': [],
        'error':    error,
    }


def _record_result(result: dict, start: float):
    """Update job counters and log entry for one completed file."""
    hi  = sum(1 for i in result['incidents'] if i['severity'] == 'Критический')
    med = sum(1 for i in result['incidents'] if i['severity'] == 'Средний')
    low = sum(1 for i in result['incidents'] if i['severity'] == 'Низкий')

    with _lock:
        _job['processed'] += 1
        done  = _job['processed']
        total = _job['total']
        _job['high']   += hi
        _job['medium'] += med
        _job['low']    += low
        if not result['incidents']:
            _job['clean'] += 1
        elapsed = time.time() - start
        _job['speed']   = round(done / elapsed * 60, 1) if elapsed > 0 else 0
        _job['eta_sec'] = int((total - done) / (done / elapsed)) if done > 0 else None

    if result['error']:
        _log('err', f'[ERR]  {result["filename"]} → {result["error"]}')
    elif result['incidents']:
        types = ', '.join(set(i['violation_type'] for i in result['incidents']))
        sev = 'err' if hi > 0 else 'warn'
        _log(sev, f'[{"CRIT" if hi else "WARN"}] {result["filename"]} → {types}')
    elif done <= 10 or done % 100 == 0:
        _log('ok', f'[PROC] {result["filename"]} → чисто')


def _run_analysis():
    global _job
    root = _input_dir()
    # Only new (not-yet-processed) files — auto-watch may have handled some already
    files = [f for f in an.list_jpeg_files(root)
             if not proclog.is_done(os.path.relpath(f, root))]

    if not files:
        _log('warn', '[WARN] Новых файлов для анализа не найдено (все уже обработаны)')
        with _lock:
            _job['running'] = False
        return

    with _watch_lock:
        active_employee = _watch['active_employee']

    _log('info', f'[INIT] Найдено файлов: {len(files)}')
    if active_employee:
        _log('info', f'[INIT] Сотрудник: {active_employee}')
    _log('info', f'[INIT] Язык OCR: {OCR_LANG}')
    _log('info', '[SCAN] Начало обработки...')

    with _lock:
        _job['total']     = len(files)
        _job['processed'] = 0

    start   = time.time()
    workers = min(4, os.cpu_count() or 2)  # conservative — heavy OCR process per worker
    _log('info', f'[INIT] Параллельных потоков: {workers}')

    # Use a plain pool (not context manager) so we can shut down without waiting
    pool = ThreadPoolExecutor(max_workers=workers)
    future_to_path = {pool.submit(an.analyze_file, f, OCR_LANG): f for f in files}
    pending = set(future_to_path.keys())

    try:
        while pending and not _stop_event.is_set():
            # Wait at most FILE_TIMEOUT seconds for the next file to finish
            done_set, pending = wait(pending, timeout=FILE_TIMEOUT, return_when=FIRST_COMPLETED)

            if not done_set:
                # Nothing completed → something is truly stuck
                _kill_tesseract()
                _log('warn', f'[TIMEOUT] Зависание OCR — принудительная остановка {len(pending)} файлов')
                for future in list(pending):
                    fp = future_to_path[future]
                    result = _make_error_result(fp, f'Таймаут {FILE_TIMEOUT}с')
                    emp = _employee_for(fp, active_employee, root)
                    db.save_result(result, employee=emp)
                    proclog.mark(os.path.relpath(fp, root), fp, emp, 0, result.get('error'))
                    _record_result(result, start)
                pending.clear()
                break

            for future in done_set:
                filepath = future_to_path[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = _make_error_result(filepath, str(exc))
                emp = _employee_for(filepath, active_employee, root)
                db.save_result(result, employee=emp)
                proclog.mark(os.path.relpath(filepath, root), filepath, emp,
                             len(result.get('incidents', [])), result.get('error'))
                _record_result(result, start)

        if _stop_event.is_set():
            _log('warn', '[STOP] Анализ остановлен пользователем')

    finally:
        pool.shutdown(wait=False)  # don't block — stray threads will die on their own
        elapsed = time.time() - start
        with _lock:
            done = _job['processed']
            spd  = _job['speed']
            _log('ok', f'[DONE] Обработано: {done} | Время: {elapsed:.0f}с | Скорость: {spd} скр/мин')
            _job['running'] = False


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    proclog.load()
    os.makedirs(INPUT_DIR, exist_ok=True)
    threading.Thread(target=_watcher_loop, daemon=True).start()
    yield


app = FastAPI(title='DLP Screen Analyzer', lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

if os.path.isdir(FRONTEND_DIR):
    app.mount('/static', StaticFiles(directory=FRONTEND_DIR), name='static')


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get('/')
def root():
    idx = os.path.join(FRONTEND_DIR, 'index.html')
    if os.path.exists(idx):
        return FileResponse(idx)
    return {'status': 'DLP Analyzer API is running'}


@app.get('/api/stats')
def stats():
    return db.get_stats()


@app.get('/api/incidents')
def incidents(
    severity: str = Query(default=''),
    vtype:    str = Query(default='', alias='type'),
    employee: str = Query(default=''),
    limit:    int = Query(default=200),
):
    return db.get_incidents(severity=severity, vtype=vtype, employee=employee, limit=limit)


@app.get('/api/employees')
def employees():
    return db.get_employees()


@app.get('/api/employees_list')
def employees_list():
    """Distinct employee names — for filter dropdowns."""
    return db.get_employee_names()


@app.get('/api/employee/active')
def get_active_employee():
    with _watch_lock:
        return {'employee': _watch['active_employee']}


@app.post('/api/employee/active')
def set_active_employee(name: str = Query(default='')):
    """Set (or clear) the employee that new screenshots are attributed to."""
    with _watch_lock:
        _watch['active_employee'] = name.strip()
        return {'ok': True, 'employee': _watch['active_employee']}


@app.get('/api/watch/status')
def watch_status():
    with _watch_lock:
        return {
            'enabled':         _watch['enabled'],
            'active_employee': _watch['active_employee'],
            'processed_count': _watch['processed_count'],
            'last_scan':       _watch['last_scan'],
            'interval':        WATCH_INTERVAL,
            'recent':          list(_watch['recent']),
        }


@app.post('/api/watch/toggle')
def watch_toggle(enabled: bool = Query(...)):
    """Turn automatic folder watching on or off."""
    with _watch_lock:
        _watch['enabled'] = enabled
        return {'ok': True, 'enabled': _watch['enabled']}


@app.get('/api/watch/dir')
def get_watch_dir():
    return {'dir': _input_dir()}


@app.post('/api/watch/dir')
def set_watch_dir(path: str = Query(...)):
    """Choose which folder is watched and analyzed."""
    global _pending_sizes
    path = os.path.expanduser(path.strip())
    if not path:
        return {'ok': False, 'error': 'Пустой путь'}
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        return {'ok': False, 'error': f'Не удалось открыть папку: {e}'}
    if not os.path.isdir(path):
        return {'ok': False, 'error': 'Это не папка'}
    with _watch_lock:
        _watch['dir'] = os.path.abspath(path)
        _pending_sizes = {}
    return {'ok': True, 'dir': _input_dir()}


@app.get('/api/proclog/status')
def proclog_status():
    return {'count': proclog.count(), 'recent': proclog.recent(50)}


@app.post('/api/reprocess')
def reprocess(scope: str = Query(default='all'), since: str = Query(default='')):
    """Re-run analysis. scope='all' forgets everything; scope='from' forgets
    only files processed at/after `since` (a 'YYYY-MM-DD' or
    'YYYY-MM-DD HH:MM:SS' string). The folder watcher then re-analyzes them."""
    global _pending_sizes
    if scope == 'all':
        db.clear_all()
        proclog.reset_all()
        with _watch_lock:
            _pending_sizes = {}
        return {'ok': True, 'scope': 'all', 'reprocess': proclog.count()}
    if scope == 'from':
        if not since.strip():
            return {'ok': False, 'error': 'Укажите дату/время (since)'}
        db.delete_after(since.strip())
        removed = proclog.reset_from(since.strip())
        with _watch_lock:
            _pending_sizes = {}
        return {'ok': True, 'scope': 'from', 'since': since.strip(), 'reprocess': len(removed)}
    return {'ok': False, 'error': 'scope должен быть all или from'}


@app.get('/api/hourly')
def hourly():
    return db.get_hourly()


@app.get('/api/violation_types')
def violation_types():
    return db.get_violation_types()


@app.post('/api/analyze/start')
def analyze_start():
    global _job, _stop_event
    with _lock:
        if _job['running']:
            return {'ok': False, 'error': 'Анализ уже запущен'}
        _stop_event.clear()
        _job = {
            'running':   True,
            'total':     0,
            'processed': 0,
            'high':      0,
            'medium':    0,
            'low':       0,
            'clean':     0,
            'speed':     0.0,
            'eta_sec':   None,
            'log':       [],
            'error':     None,
        }
    threading.Thread(target=_run_analysis, daemon=True).start()
    return {'ok': True}


@app.post('/api/analyze/stop')
def analyze_stop():
    _stop_event.set()
    _kill_tesseract()
    return {'ok': True}


@app.get('/api/analyze/status')
def analyze_status(since: int = Query(default=0)):
    with _lock:
        state = dict(_job)
        state['log'] = _job['log'][since:]
    return state


@app.post('/api/clear')
def clear(force: bool = Query(default=False)):
    global _job
    if force:
        _stop_event.set()
        _kill_tesseract()
        with _lock:
            _job['running'] = False
    else:
        with _lock:
            if _job['running']:
                return {'ok': False, 'error': 'Нельзя очистить во время анализа'}
    db.clear_all()
    proclog.reset_all()
    return {'ok': True}


@app.get('/api/input_info')
def input_info():
    root = _input_dir()
    files = an.list_jpeg_files(root)
    return {'folder': root, 'count': len(files), 'files': [os.path.basename(f) for f in files]}


@app.get('/api/file')
def serve_file(filename: str = Query(...)):
    """Serve an image file from the watched directory by filename."""
    files = an.list_jpeg_files(_input_dir())
    matched = [f for f in files if os.path.basename(f) == filename]
    if not matched:
        raise HTTPException(status_code=404, detail='Файл не найден')
    return FileResponse(matched[0])


@app.get('/api/ocr_preview')
def ocr_preview(filename: str = Query(...)):
    """Run OCR on one file and return raw text — for diagnostics."""
    files = an.list_jpeg_files(_input_dir())
    matched = [f for f in files if os.path.basename(f) == filename]
    if not matched:
        return {'ok': False, 'error': f'Файл не найден: {filename}'}
    try:
        text = an._run_ocr(matched[0], OCR_LANG)
        return {'ok': True, 'filename': filename, 'length': len(text), 'text': text}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


@app.get('/api/tesseract_check')
def tesseract_check():
    try:
        binary = an._find_tesseract()
    except FileNotFoundError:
        return {'ok': False, 'error': 'Tesseract не найден. Установите его для вашей ОС (Windows: https://github.com/UB-Mannheim/tesseract/wiki, macOS: brew install tesseract tesseract-lang, Ubuntu: apt install tesseract-ocr tesseract-ocr-rus)'}
    try:
        ver = subprocess.check_output([binary, '--version'], stderr=subprocess.STDOUT).decode().split('\n')[0]
        langs = subprocess.check_output([binary, '--list-langs'], stderr=subprocess.STDOUT).decode()
        return {'ok': True, 'version': ver, 'has_rus': 'rus' in langs}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def _build_snippet(text: str, terms: list, width: int = 60) -> str:
    """Return a short excerpt of `text` around the first matched term."""
    low = text.lower()
    pos = -1
    for t in terms:
        p = low.find(t.lower())
        if p != -1 and (pos == -1 or p < pos):
            pos = p
    if pos == -1:
        return text[:width * 2].replace('\n', ' ').strip()
    start = max(0, pos - width)
    end = min(len(text), pos + width)
    snippet = text[start:end].replace('\n', ' ').strip()
    if start > 0:
        snippet = '…' + snippet
    if end < len(text):
        snippet = snippet + '…'
    return snippet


@app.get('/api/search')
def search(q: str = Query(...), employee: str = Query(default=''), limit: int = Query(default=200)):
    """Search OCR text of processed screenshots for one or more terms.
    Multiple terms (variants) are separated by comma — any match counts.
    Optionally restrict the search to a single employee."""
    terms = [t.strip() for t in q.split(',') if t.strip()]
    if not terms:
        return {'ok': False, 'error': 'Пустой запрос', 'results': [], 'total': 0}
    rows = db.search_screenshots(terms, employee=employee, limit=limit)
    low_terms = [t.lower() for t in terms]
    results = []
    for r in rows:
        text = r.get('ocr_text') or ''
        low = text.lower()
        matched = [t for t, lt in zip(terms, low_terms) if lt in low]
        emp = r.get('employee') or 'Неизвестно'
        results.append({
            'filename':       r['filename'],
            'employee':       emp,
            'department':     '—',
            'processed_at':   r['processed_at'],
            'has_violations': bool(r['has_violations']),
            'matched':        matched,
            'snippet':        _build_snippet(text, terms),
        })
    return {'ok': True, 'terms': terms, 'total': len(results), 'results': results}


@app.get('/api/export')
def export(format: str = Query(default='csv'), employee: str = Query(default='')):
    """Download incidents as CSV or JSON — what was found and where.
    Optionally restrict the export to a single employee."""
    import csv
    import io
    from datetime import datetime
    from fastapi.responses import Response, JSONResponse

    incidents = db.get_all_incidents_for_export(employee=employee)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if format == 'json':
        return JSONResponse(
            content=incidents,
            headers={'Content-Disposition': f'attachment; filename="dlp_export_{stamp}.json"'},
        )

    buf = io.StringIO()
    buf.write('﻿')  # BOM so Excel reads UTF-8 (Cyrillic) correctly
    writer = csv.writer(buf, delimiter=';')
    writer.writerow(['#', 'Время', 'Сотрудник', 'Отдел', 'Тип нарушения', 'Уровень', 'Что найдено', 'Файл'])
    for inc in incidents:
        writer.writerow([
            inc['id'], inc['detected_at'], inc['employee'], inc['department'],
            inc['violation_type'], inc['severity'], inc['detail'], inc['filename'],
        ])
    return Response(
        content=buf.getvalue(),
        media_type='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="dlp_export_{stamp}.csv"'},
    )


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='127.0.0.1', port=8000, reload=False)
