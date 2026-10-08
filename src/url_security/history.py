import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "scan_history.db"


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        prediction TEXT NOT NULL,
        risk_score REAL NOT NULL,
        risk_level TEXT NOT NULL,
        scanned_at TEXT NOT NULL
    )""")
    return conn


def save_scan(url, prediction, risk_score, risk_level, scanned_at):
    conn = _conn()
    conn.execute("INSERT INTO scans(url,prediction,risk_score,risk_level,scanned_at) VALUES(?,?,?,?,?)",
                 (url, prediction, risk_score, risk_level, scanned_at))
    conn.commit()
    conn.close()


def recent_scans(limit=10):
    conn = _conn()
    rows = conn.execute("SELECT url,prediction,risk_score,risk_level,scanned_at FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(url=r[0], prediction=r[1], risk_score=r[2], risk_level=r[3], scanned_at=r[4]) for r in rows]
