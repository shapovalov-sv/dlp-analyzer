import os
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

sys.path.insert(0, os.path.dirname(__file__))
import database as db
import analyzer as an

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_DIR    = os.path.join(BASE_DIR, 'input')
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')

OCR_LANG     = 'rus+eng'
FILE_TIMEOUT = 45  # hard deadline per file (seconds)

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
_log_seq = 0  # monotonic id — клиент фильтрует лог по нему, обрезка списка не сбивает офсеты


def _log(level: str, msg: str):
    global _log_seq
    with _lock:
        _log_seq += 1
        _job['log'].append({'seq': _log_seq, 'level': level, 'msg': msg})
        if len(_job['log']) > 500:
            del _job['log'][:len(_job['log']) - 500]


def _make_error_result(filepath: str, error: str) -> dict:
    return {
        'filename': os.path.basename(filepath),
        'path':     filepath,
        'event_at': None,
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
    all_files = an.list_image_files(INPUT_DIR)
    known = db.get_processed_paths()
    files = [f for f in all_files if f not in known]
    skipped = len(all_files) - len(files)

    if skipped:
        _log('info', f'[INIT] Пропущено уже обработанных: {skipped}')
    if not files:
        msg = '[WARN] Новых файлов нет' if all_files else '[WARN] В папке input/ не найдено файлов'
        _log('warn', msg)
        with _lock:
            _job['running'] = False
        return

    _log('info', f'[INIT] Найдено новых файлов: {len(files)}')
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
                an.kill_active_ocr()
                _log('warn', f'[TIMEOUT] Зависание OCR — принудительная остановка {len(pending)} файлов')
                for future in list(pending):
                    result = _make_error_result(future_to_path[future], f'Таймаут {FILE_TIMEOUT}с')
                    db.save_result(result)
                    _record_result(result, start)
                pending.clear()
                break

            for future in done_set:
                filepath = future_to_path[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = _make_error_result(filepath, str(exc))
                db.save_result(result)
                _record_result(result, start)

        if _stop_event.is_set():
            _log('warn', '[STOP] Анализ остановлен пользователем')

    finally:
        # cancel_futures — иначе очередь продолжит запускать OCR после остановки
        pool.shutdown(wait=False, cancel_futures=True)
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
    os.makedirs(INPUT_DIR, exist_ok=True)
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
    limit:    int = Query(default=200, ge=1, le=1000),
):
    return db.get_incidents(severity=severity, vtype=vtype, limit=limit)


@app.get('/api/employees')
def employees():
    return db.get_employees()


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
    an.kill_active_ocr()
    return {'ok': True}


@app.get('/api/analyze/status')
def analyze_status(since: int = Query(default=0)):
    with _lock:
        state = dict(_job)
        state['log'] = [e for e in _job['log'] if e['seq'] > since]
    return state


@app.post('/api/clear')
def clear(force: bool = Query(default=False)):
    global _job
    if force:
        _stop_event.set()
        an.kill_active_ocr()
        with _lock:
            _job['running'] = False
    else:
        with _lock:
            if _job['running']:
                return {'ok': False, 'error': 'Нельзя очистить во время анализа'}
    db.clear_all()
    return {'ok': True}


@app.get('/api/input_info')
def input_info():
    files = an.list_image_files(INPUT_DIR)
    return {'folder': INPUT_DIR, 'count': len(files), 'files': [os.path.basename(f) for f in files]}


@app.get('/api/file')
def serve_file(filename: str = Query(...)):
    """Serve an image file from the input directory by filename."""
    files = an.list_image_files(INPUT_DIR)
    matched = [f for f in files if os.path.basename(f) == filename]
    if not matched:
        raise HTTPException(status_code=404, detail='Файл не найден')
    return FileResponse(matched[0])


@app.get('/api/ocr_preview')
def ocr_preview(filename: str = Query(...)):
    """Run OCR on one file and return raw text — for diagnostics."""
    files = an.list_image_files(INPUT_DIR)
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
    import subprocess
    try:
        binary = an._find_tesseract()
    except FileNotFoundError:
        return {'ok': False, 'error': 'Tesseract не найден. Установите: brew install tesseract tesseract-lang'}
    try:
        ver = subprocess.check_output([binary, '--version'], stderr=subprocess.STDOUT).decode().split('\n')[0]
        langs = subprocess.check_output([binary, '--list-langs'], stderr=subprocess.STDOUT).decode()
        return {'ok': True, 'version': ver, 'has_rus': 'rus' in langs}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='127.0.0.1', port=8000, reload=False)
