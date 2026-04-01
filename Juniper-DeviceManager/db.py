"""
SQLite database layer for Juniper Device Manager.
All tables, migrations, and CRUD operations.
"""

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime

_db_path = None
_write_lock = threading.Lock()


def init_db(db_path):
    """Initialize the database and create tables if needed."""
    global _db_path
    _db_path = db_path
    conn = _connect()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def _connect():
    """Get a new connection (safe for multi-threaded use)."""
    return sqlite3.connect(_db_path, check_same_thread=False)


def _dict_row(cursor, row):
    """Row factory that returns dicts."""
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def _query(sql, params=(), one=False):
    """Execute a read query and return results as dicts."""
    conn = _connect()
    conn.row_factory = _dict_row
    cur = conn.execute(sql, params)
    results = cur.fetchone() if one else cur.fetchall()
    conn.close()
    return results


def _execute(sql, params=()):
    """Execute a write query with lock. Returns lastrowid."""
    with _write_lock:
        conn = _connect()
        cur = conn.execute(sql, params)
        conn.commit()
        lastrowid = cur.lastrowid
        conn.close()
        return lastrowid


def _execute_many(statements):
    """Execute multiple write statements atomically."""
    with _write_lock:
        conn = _connect()
        try:
            for sql, params in statements:
                conn.execute(sql, params)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ============================================================================
# SCHEMA
# ============================================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subnets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr        TEXT NOT NULL UNIQUE,
    label       TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credential_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    username    TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 830,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    host                TEXT NOT NULL UNIQUE,
    hostname            TEXT NOT NULL DEFAULT '',
    model               TEXT NOT NULL DEFAULT '',
    serial_number       TEXT NOT NULL DEFAULT '',
    firmware_version    TEXT NOT NULL DEFAULT '',
    uptime              TEXT NOT NULL DEFAULT '',
    device_type         TEXT NOT NULL DEFAULT '',
    credential_group_id INTEGER REFERENCES credential_groups(id),
    override_username   TEXT,
    override_password_enc TEXT,
    override_port       INTEGER,
    last_seen           TEXT,
    last_scan           TEXT,
    status              TEXT NOT NULL DEFAULT 'unknown',
    notes               TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config_backups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    config_text TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    backup_type TEXT NOT NULL DEFAULT 'manual',
    label       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_config_backups_device ON config_backups(device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS firmware_images (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT NOT NULL,
    filepath    TEXT NOT NULL,
    platform    TEXT NOT NULL,
    version     TEXT NOT NULL,
    file_size   INTEGER NOT NULL DEFAULT 0,
    md5_hash    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(platform, version)
);

CREATE TABLE IF NOT EXISTS jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    target_devices  TEXT NOT NULL DEFAULT '[]',
    parameters      TEXT NOT NULL DEFAULT '{}',
    progress        TEXT NOT NULL DEFAULT '{}',
    started_at      TEXT,
    completed_at    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


# ============================================================================
# SETTINGS
# ============================================================================
def get_setting(key, default=None):
    row = _query("SELECT value FROM settings WHERE key = ?", (key,), one=True)
    return row["value"] if row else default


def set_setting(key, value):
    _execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value)
    )


# ============================================================================
# SUBNETS
# ============================================================================
def get_subnets():
    return _query("SELECT * FROM subnets ORDER BY created_at")


def add_subnet(cidr, label=""):
    return _execute("INSERT INTO subnets (cidr, label) VALUES (?, ?)", (cidr, label))


def delete_subnet(subnet_id):
    _execute("DELETE FROM subnets WHERE id = ?", (subnet_id,))


def update_subnet(subnet_id, **kwargs):
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [subnet_id]
    _execute(f"UPDATE subnets SET {sets} WHERE id = ?", vals)


# ============================================================================
# CREDENTIAL GROUPS
# ============================================================================
def get_credential_groups():
    return _query("SELECT * FROM credential_groups ORDER BY name")


def add_credential_group(name, username, password_enc, port=830):
    return _execute(
        "INSERT INTO credential_groups (name, username, password_enc, port) VALUES (?, ?, ?, ?)",
        (name, username, password_enc, port)
    )


def update_credential_group(cred_id, **kwargs):
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [cred_id]
    _execute(f"UPDATE credential_groups SET {sets} WHERE id = ?", vals)


def delete_credential_group(cred_id):
    _execute("DELETE FROM credential_groups WHERE id = ?", (cred_id,))


def get_credential_group(cred_id):
    return _query("SELECT * FROM credential_groups WHERE id = ?", (cred_id,), one=True)


# ============================================================================
# DEVICES
# ============================================================================
def get_devices():
    return _query("""
        SELECT d.*, cg.name as credential_group_name
        FROM devices d
        LEFT JOIN credential_groups cg ON d.credential_group_id = cg.id
        ORDER BY d.hostname, d.host
    """)


def get_device(device_id):
    return _query("""
        SELECT d.*, cg.name as credential_group_name
        FROM devices d
        LEFT JOIN credential_groups cg ON d.credential_group_id = cg.id
        WHERE d.id = ?
    """, (device_id,), one=True)


def get_device_by_host(host):
    return _query("SELECT * FROM devices WHERE host = ?", (host,), one=True)


def upsert_device(host, **kwargs):
    """Insert or update a device by host IP."""
    existing = get_device_by_host(host)
    now = datetime.utcnow().isoformat()
    if existing:
        kwargs["last_scan"] = now
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [host]
        _execute(f"UPDATE devices SET {sets} WHERE host = ?", vals)
        return existing["id"]
    else:
        kwargs["host"] = host
        kwargs["last_scan"] = now
        kwargs["created_at"] = now
        cols = ", ".join(kwargs.keys())
        placeholders = ", ".join("?" for _ in kwargs)
        return _execute(f"INSERT INTO devices ({cols}) VALUES ({placeholders})", list(kwargs.values()))


def update_device(device_id, **kwargs):
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [device_id]
    _execute(f"UPDATE devices SET {sets} WHERE id = ?", vals)


def delete_device(device_id):
    _execute("DELETE FROM devices WHERE id = ?", (device_id,))


def update_device_status(device_id, status, last_seen=None):
    if last_seen is None:
        last_seen = datetime.utcnow().isoformat()
    _execute("UPDATE devices SET status = ?, last_seen = ? WHERE id = ?", (status, last_seen, device_id))


# ============================================================================
# CONFIG BACKUPS
# ============================================================================
def get_config_backups(device_id):
    return _query(
        "SELECT id, device_id, config_hash, backup_type, label, created_at FROM config_backups WHERE device_id = ? ORDER BY created_at DESC",
        (device_id,)
    )


def add_config_backup(device_id, config_text, backup_type="manual", label=""):
    config_hash = hashlib.sha256(config_text.encode("utf-8")).hexdigest()
    return _execute(
        "INSERT INTO config_backups (device_id, config_text, config_hash, backup_type, label) VALUES (?, ?, ?, ?, ?)",
        (device_id, config_text, config_hash, backup_type, label)
    )


def get_config_backup(backup_id):
    return _query("SELECT * FROM config_backups WHERE id = ?", (backup_id,), one=True)


def delete_config_backup(backup_id):
    _execute("DELETE FROM config_backups WHERE id = ?", (backup_id,))


# ============================================================================
# FIRMWARE IMAGES
# ============================================================================
def get_firmware_images():
    return _query("SELECT * FROM firmware_images ORDER BY platform, version DESC")


def add_firmware_image(filename, filepath, platform, version, file_size=0, md5_hash=""):
    return _execute(
        "INSERT INTO firmware_images (filename, filepath, platform, version, file_size, md5_hash) VALUES (?, ?, ?, ?, ?, ?)",
        (filename, filepath, platform, version, file_size, md5_hash)
    )


def get_firmware_image(image_id):
    return _query("SELECT * FROM firmware_images WHERE id = ?", (image_id,), one=True)


def delete_firmware_image(image_id):
    _execute("DELETE FROM firmware_images WHERE id = ?", (image_id,))


# ============================================================================
# JOBS
# ============================================================================
def create_job(job_type, target_devices, parameters=None):
    now = datetime.utcnow().isoformat()
    return _execute(
        "INSERT INTO jobs (job_type, status, target_devices, parameters, progress, started_at) VALUES (?, 'running', ?, ?, '{}', ?)",
        (job_type, json.dumps(target_devices), json.dumps(parameters or {}), now)
    )


def update_job_progress(job_id, progress):
    _execute("UPDATE jobs SET progress = ? WHERE id = ?", (json.dumps(progress), job_id))


def complete_job(job_id, status="completed"):
    now = datetime.utcnow().isoformat()
    _execute("UPDATE jobs SET status = ?, completed_at = ? WHERE id = ?", (status, now, job_id))


def get_job(job_id):
    row = _query("SELECT * FROM jobs WHERE id = ?", (job_id,), one=True)
    if row:
        row["target_devices"] = json.loads(row["target_devices"])
        row["parameters"] = json.loads(row["parameters"])
        row["progress"] = json.loads(row["progress"])
    return row


def get_jobs(limit=50):
    rows = _query("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))
    for row in rows:
        row["target_devices"] = json.loads(row["target_devices"])
        row["parameters"] = json.loads(row["parameters"])
        row["progress"] = json.loads(row["progress"])
    return rows
