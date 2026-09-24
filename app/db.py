"""Secure File Guard — SQLite database layer (real relational schema)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterable

from . import config

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('super_admin','admin','user','developer')),
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    ip TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived','error')),
    protection_level TEXT NOT NULL DEFAULT 'standard'
        CHECK (protection_level IN ('basic','standard','advanced')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT
);
CREATE TABLE IF NOT EXISTS project_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    relpath TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    kind TEXT NOT NULL,
    sensitive INTEGER NOT NULL DEFAULT 0,
    secret_count INTEGER NOT NULL DEFAULT 0,
    indexed_at TEXT NOT NULL,
    UNIQUE (project_id, relpath)
);
CREATE TABLE IF NOT EXISTS project_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    note TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    UNIQUE (project_id, version)
);
CREATE TABLE IF NOT EXISTS builds (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version_id INTEGER REFERENCES project_versions(id),
    version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','completed','failed','disabled')),
    stage TEXT,
    stage_index INTEGER NOT NULL DEFAULT 0,
    total_stages INTEGER NOT NULL DEFAULT 12,
    config_json TEXT NOT NULL,
    manifest_json TEXT,
    package_path TEXT,
    package_sha256 TEXT,
    validation_report_json TEXT,
    error TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    customer_name TEXT,
    customer_email TEXT,
    key_hash TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','active','suspended','revoked','expired')),
    activated INTEGER NOT NULL DEFAULT 0,
    activated_at TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_verified_at TEXT,
    version_restrict TEXT,
    created_by INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS license_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','verified','active','blocked')),
    allow_subdomains INTEGER NOT NULL DEFAULT 0,
    verify_token TEXT,
    verified_at TEXT,
    added_at TEXT NOT NULL,
    UNIQUE (license_id, domain)
);
CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    domain TEXT,
    ip TEXT,
    success INTEGER NOT NULL,
    error_code TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verification_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT,
    project_id TEXT,
    domain TEXT,
    domain_ok INTEGER,
    result TEXT NOT NULL,
    error_code TEXT,
    latency_ms INTEGER,
    ip TEXT,
    kind TEXT NOT NULL DEFAULT 'verify',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT,
    license_id TEXT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
    detail TEXT,
    ip TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    engine TEXT NOT NULL CHECK (engine IN ('builtin','llm')),
    model TEXT,
    input_summary TEXT,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    actor_email TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    resource_id TEXT,
    result TEXT NOT NULL DEFAULT 'ok',
    detail TEXT,
    ip TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pf_project ON project_files(project_id);
CREATE INDEX IF NOT EXISTS idx_builds_project ON builds(project_id);
CREATE TABLE IF NOT EXISTS license_fail_counters (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    window_start REAL NOT NULL
);
"""


def utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        config.ensure_dirs()
        conn = sqlite3.connect(str(config.DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA)
        conn.commit()
        _conn = conn
    return _conn


@contextmanager
def db() -> Iterable[sqlite3.Connection]:
    conn = connect()
    with _lock:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def q1(sql: str, args: tuple = ()) -> sqlite3.Row | None:
    with db() as c:
        return c.execute(sql, args).fetchone()


def qall(sql: str, args: tuple = ()) -> list[sqlite3.Row]:
    with db() as c:
        return c.execute(sql, args).fetchall()


def qexec(sql: str, args: tuple = ()) -> int:
    with db() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid


def qvalue(sql: str, args: tuple = ()) -> Any:
    row = q1(sql, args)
    return row[0] if row is not None else None


# ---------- settings ----------
DEFAULT_SETTINGS = {
    "site_name": "Secure File Guard",
    "license_server_url": "",            # empty => auto-detect from request
    "require_https": "1",
    "verify_ttl_seconds": str(config.DEFAULT_VERIFY_TTL_SECONDS),
    "grace_seconds": "0",
    "max_upload_mb": str(config.MAX_UPLOAD_BYTES // (1024 * 1024)),
    "clock_tolerance_seconds": str(config.CLOCK_TOLERANCE_SECONDS),
    "ai_base_url": "",
    "ai_model": "gpt-4o-mini",
    "ai_key_wrapped": "",                # AES-GCM(master key) wrapped, never plaintext
    "verification_retention_days": str(config.VERIFICATION_LOG_RETENTION_DAYS),
}


def get_settings() -> dict[str, str]:
    rows = qall("SELECT key, value FROM system_settings")
    out = dict(DEFAULT_SETTINGS)
    for r in rows:
        out[r["key"]] = r["value"]
    return out


def set_setting(key: str, value: str, updated_at: str) -> None:
    qexec(
        "INSERT INTO system_settings (key, value, updated_at) VALUES (?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, updated_at),
    )


# ---------- audit ----------
def audit(actor_id: int | None, actor_email: str | None, action: str,
          resource: str = "", resource_id: str = "", result: str = "ok",
          detail: str = "", ip: str = "") -> None:
    qexec(
        "INSERT INTO audit_logs (actor_id, actor_email, action, resource, resource_id,"
        " result, detail, ip, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (actor_id, actor_email, action, resource, resource_id, result, detail[:2000], ip, utcnow()),
    )


def security_event(project_id: str | None, license_id: str | None, etype: str,
                   severity: str, detail: str = "", ip: str = "") -> None:
    qexec(
        "INSERT INTO security_events (project_id, license_id, type, severity, detail, ip, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (project_id, license_id, etype, severity, detail[:2000], ip, utcnow()),
    )


def verification_log(license_id: str | None, project_id: str | None, domain: str | None,
                     domain_ok: int, result: str, error_code: str | None,
                     latency_ms: int, ip: str, kind: str = "verify") -> None:
    qexec(
        "INSERT INTO verification_logs (license_id, project_id, domain, domain_ok, result,"
        " error_code, latency_ms, ip, kind, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (license_id, project_id, domain, domain_ok, result, error_code, latency_ms, ip, kind, utcnow()),
    )


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def rows_to_list(rows: list[sqlite3.Row]) -> list[dict]:
    return [dict(r) for r in rows]


def prune_old_logs() -> int:
    days = int(get_settings().get("verification_retention_days", str(config.VERIFICATION_LOG_RETENTION_DAYS)))
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
    with db() as c:
        cur = c.execute("DELETE FROM verification_logs WHERE created_at < ?", (cutoff,))
        # Safety cap: only when the retained table is pathologically large,
        # trim its oldest rows. The retention cutoff stays primary — a normal
        # startup never deletes in-window verification data.
        trimmed = 0
        if c.execute("SELECT COUNT(*) FROM verification_logs").fetchone()[0] > 500_000:
            d = c.execute("DELETE FROM verification_logs WHERE id IN ("
                          "  SELECT id FROM verification_logs ORDER BY id LIMIT 200000"
                          ")")
            trimmed = d.rowcount
        return cur.rowcount + trimmed


def db_health() -> dict:
    try:
        conn = connect()
        with _lock:
            ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
            count = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        return {"status": "ok" if ok == "ok" else "error", "tables": count, "detail": ok}
    except Exception as e:  # pragma: no cover
        return {"status": "error", "detail": str(e)}


def file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return -1


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
