import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'dlp.db')


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS screenshots (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            filename      TEXT NOT NULL,
            path          TEXT NOT NULL,
            processed_at  TEXT,
            has_violations INTEGER DEFAULT 0,
            ocr_text      TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            screenshot_id  INTEGER,
            employee       TEXT DEFAULT 'Неизвестно',
            department     TEXT DEFAULT '—',
            violation_type TEXT,
            severity       TEXT,
            detail         TEXT,
            detected_at    TEXT,
            FOREIGN KEY (screenshot_id) REFERENCES screenshots(id)
        );

        CREATE INDEX IF NOT EXISTS idx_inc_severity   ON incidents(severity);
        CREATE INDEX IF NOT EXISTS idx_inc_type       ON incidents(violation_type);
        CREATE INDEX IF NOT EXISTS idx_inc_employee   ON incidents(employee);
        CREATE INDEX IF NOT EXISTS idx_inc_detected   ON incidents(detected_at);
    """)
    # Migration: attribute each screenshot to an employee
    cols = [r[1] for r in conn.execute("PRAGMA table_info(screenshots)").fetchall()]
    if 'employee' not in cols:
        conn.execute("ALTER TABLE screenshots ADD COLUMN employee TEXT DEFAULT 'Неизвестно'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scr_employee ON screenshots(employee)")
    conn.commit()
    conn.close()


def is_processed(filename: str) -> bool:
    """Whether a screenshot with this filename is already in the DB."""
    conn = get_conn()
    row = conn.execute("SELECT 1 FROM screenshots WHERE filename=? LIMIT 1", (filename,)).fetchone()
    conn.close()
    return row is not None


def save_result(result: dict, employee: str = None):
    """Persist one screenshot + its incidents. If `employee` is given, all
    results are attributed to that employee instead of the filename guess."""
    conn = get_conn()
    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    emp = employee or (result['incidents'][0]['employee'] if result['incidents'] else 'Неизвестно')
    cur = conn.execute(
        "INSERT INTO screenshots (filename, path, processed_at, has_violations, ocr_text, employee) VALUES (?,?,?,?,?,?)",
        (result['filename'], result['path'], now,
         1 if result['incidents'] else 0,
         result.get('ocr_text', '')[:3000], emp),
    )
    scr_id = cur.lastrowid
    for inc in result['incidents']:
        conn.execute(
            "INSERT INTO incidents (screenshot_id, employee, department, violation_type, severity, detail, detected_at) VALUES (?,?,?,?,?,?,?)",
            (scr_id, employee or inc['employee'], inc['department'],
             inc['violation_type'], inc['severity'], inc['detail'], now),
        )
    conn.commit()
    conn.close()


def get_stats() -> dict:
    conn = get_conn()
    total    = conn.execute("SELECT COUNT(*) FROM screenshots").fetchone()[0]
    high     = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity='Критический'").fetchone()[0]
    medium   = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity='Средний'").fetchone()[0]
    low      = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity='Низкий'").fetchone()[0]
    clean    = conn.execute("SELECT COUNT(*) FROM screenshots WHERE has_violations=0").fetchone()[0]
    conn.close()
    return {'total': total, 'high': high, 'medium': medium, 'low': low, 'clean': clean}


def get_incidents(severity: str = '', vtype: str = '', employee: str = '', limit: int = 200) -> list:
    conn = get_conn()
    q = "SELECT i.id, i.detected_at, i.employee, i.department, i.violation_type, i.severity, i.detail, s.filename FROM incidents i JOIN screenshots s ON s.id=i.screenshot_id WHERE 1=1"
    params = []
    if severity:
        q += " AND i.severity=?"
        params.append(severity)
    if vtype:
        q += " AND i.violation_type=?"
        params.append(vtype)
    if employee:
        q += " AND i.employee=?"
        params.append(employee)
    q += " ORDER BY i.id DESC LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in conn.execute(q, params).fetchall()]
    conn.close()
    return rows


def get_employees() -> list:
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            COALESCE(s.employee, 'Неизвестно')                                  AS employee,
            '—'                                                                  AS department,
            COUNT(DISTINCT s.id)                                                 AS total_screens,
            COUNT(DISTINCT CASE WHEN i.id IS NOT NULL THEN s.id END)             AS screens,
            SUM(CASE WHEN i.severity='Критический' THEN 1 ELSE 0 END)           AS high_count,
            SUM(CASE WHEN i.severity='Средний'     THEN 1 ELSE 0 END)           AS med_count,
            MAX(COALESCE(i.detected_at, s.processed_at))                         AS last_incident
        FROM screenshots s
        LEFT JOIN incidents i ON i.screenshot_id = s.id
        GROUP BY COALESCE(s.employee, 'Неизвестно')
        ORDER BY high_count DESC, med_count DESC, total_screens DESC
        LIMIT 100
    """).fetchall()
    conn.close()
    result = []
    for r in rows:
        r = dict(r)
        r['high_count'] = r['high_count'] or 0
        r['med_count'] = r['med_count'] or 0
        r['risk_score'] = min(100, r['high_count'] * 20 + r['med_count'] * 5)
        result.append(r)
    return result


def get_hourly() -> list:
    conn = get_conn()
    rows = conn.execute("""
        SELECT strftime('%H', detected_at) AS hour, COUNT(*) AS cnt
        FROM incidents
        WHERE date(detected_at) = date('now')
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    conn.close()
    by_hour = {str(i).zfill(2): 0 for i in range(24)}
    for r in rows:
        by_hour[r['hour']] = r['cnt']
    return [{'hour': h, 'count': c} for h, c in by_hour.items()]


def get_violation_types() -> list:
    conn = get_conn()
    rows = conn.execute("""
        SELECT violation_type, COUNT(*) AS cnt
        FROM incidents
        GROUP BY violation_type
        ORDER BY cnt DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def search_screenshots(terms: list, employee: str = '', limit: int = 200) -> list:
    """Find screenshots whose OCR text contains ANY of the given terms
    (case-insensitive). Optionally restrict to one employee.
    Returns raw rows incl. ocr_text for snippet building."""
    if not terms:
        return []
    conn = get_conn()
    clauses = " OR ".join("LOWER(ocr_text) LIKE ?" for _ in terms)
    params = ['%' + t.lower() + '%' for t in terms]
    q = (
        "SELECT id, filename, path, processed_at, has_violations, employee, ocr_text "
        "FROM screenshots WHERE (" + clauses + ")"
    )
    if employee:
        q += " AND employee=?"
        params.append(employee)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in conn.execute(q, params).fetchall()]
    conn.close()
    return rows


def get_employee_names() -> list:
    """Distinct employee names across all processed screenshots."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT DISTINCT COALESCE(employee, 'Неизвестно') AS e FROM screenshots ORDER BY e"
    ).fetchall()
    conn.close()
    return [r['e'] for r in rows]


def get_all_incidents_for_export(employee: str = '') -> list:
    """Full incident list joined with screenshot filename, for export.
    Optionally restrict to one employee."""
    conn = get_conn()
    q = """
        SELECT i.id, i.detected_at, i.employee, i.department,
               i.violation_type, i.severity, i.detail, s.filename
        FROM incidents i
        JOIN screenshots s ON s.id = i.screenshot_id
    """
    params = []
    if employee:
        q += " WHERE i.employee=?"
        params.append(employee)
    q += " ORDER BY i.id DESC"
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_all():
    conn = get_conn()
    conn.executescript("DELETE FROM incidents; DELETE FROM screenshots;")
    conn.commit()
    conn.close()
