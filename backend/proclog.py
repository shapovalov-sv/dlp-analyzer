"""Persistent log of already-processed screenshots.

Keeps a record (keyed by path *relative to the watched folder*) of every
screenshot that has been recognised, so restarts don't redo the work.
Stored as JSON-lines next to the project so it survives restarts.
"""
import os
import json
import threading
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'processed_log.jsonl')

_lock = threading.RLock()
_done: dict = {}   # rel_path -> record


def load():
    """Read the log file into memory (called once at startup)."""
    with _lock:
        _done.clear()
        if not os.path.exists(LOG_PATH):
            return
        with open(LOG_PATH, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                _done[rec['rel']] = rec


def is_done(rel: str) -> bool:
    with _lock:
        return rel in _done


def mark(rel: str, path: str, employee: str, incidents: int, error: str = None):
    """Record a processed file (append to the log and keep in memory)."""
    rec = {
        'rel':       rel,
        'path':      path,
        'employee':  employee,
        'incidents': incidents,
        'error':     error,
        'at':        datetime.now().isoformat(sep=' ', timespec='seconds'),
    }
    with _lock:
        _done[rel] = rec
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')


def _rewrite_locked():
    with open(LOG_PATH, 'w', encoding='utf-8') as f:
        for rec in _done.values():
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')


def reset_all():
    """Forget everything — the next scan reprocesses all files."""
    with _lock:
        _done.clear()
        try:
            os.remove(LOG_PATH)
        except OSError:
            pass


def reset_from(since: str) -> list:
    """Forget files processed at/after `since` (an ISO 'YYYY-MM-DD HH:MM:SS'
    string; a bare date works too). Older records are kept. Returns the
    removed records so the caller can also drop their DB rows."""
    removed = []
    with _lock:
        for rel, rec in list(_done.items()):
            if rec.get('at', '') >= since:
                removed.append(rec)
                _done.pop(rel, None)
        _rewrite_locked()
    return removed


def count() -> int:
    with _lock:
        return len(_done)


def recent(limit: int = 100) -> list:
    with _lock:
        return list(_done.values())[-limit:][::-1]
