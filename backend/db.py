# backend/db.py
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

from config import get_db_path


@contextmanager
def get_conn(immediate: bool = False) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection with row dict factory and WAL mode."""
    conn = sqlite3.connect(get_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    if immediate:
        conn.execute("BEGIN IMMEDIATE;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create licenses and verify_logs tables if they do not exist."""
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                max_devices INTEGER NOT NULL DEFAULT 1,
                bound_devices TEXT NOT NULL DEFAULT '[]',
                duration_hours INTEGER NOT NULL,
                activate_on_first_use INTEGER NOT NULL DEFAULT 1,
                expires_at INTEGER,
                first_used_at INTEGER,
                last_used_at INTEGER,
                is_banned INTEGER NOT NULL DEFAULT 0,
                ban_reason TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS verify_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT NOT NULL,
                device_id TEXT NOT NULL,
                client_ip TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )


def _format_key_segment(length: int = 4) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_license_key(prefix: str = "KTAOV") -> str:
    """Generate a readable license key like KTAOV-4X9M-Q2LP-8Z7R."""
    clean_prefix = "".join(c for c in prefix.upper() if c.isalnum()) or "KEY"
    return f"{clean_prefix}-{_format_key_segment()}-{_format_key_segment()}-{_format_key_segment()}"


def _row_to_dict(row: sqlite3.Row, now: int | None = None) -> dict[str, Any]:
    now = now or int(time.time())
    d = dict(row)
    d["bound_devices"] = json.loads(d["bound_devices"])
    d["is_banned"] = bool(d["is_banned"])
    d["activate_on_first_use"] = bool(d["activate_on_first_use"])

    if d["is_banned"]:
        d["computed_status"] = "banned"
    elif d["expires_at"] is None:
        d["computed_status"] = "unused"
    elif d["expires_at"] <= now:
        d["computed_status"] = "expired"
    else:
        d["computed_status"] = "active"
    return d


def create_keys(
    count: int = 1,
    prefix: str = "KTAOV",
    duration_hours: int = 720,
    max_devices: int = 1,
    note: str = "",
    activate_on_first_use: bool = True,
    initial_device_id: str = "",
) -> list[dict[str, Any]]:
    """Create one or more license keys in SQLite."""
    now = int(time.time())
    expires_at = None if activate_on_first_use else now + (duration_hours * 3600)
    clean_dev = initial_device_id.strip()
    initial_bound = json.dumps([clean_dev]) if clean_dev else "[]"
    created: list[dict[str, Any]] = []

    with get_conn(immediate=True) as conn:
        for _ in range(count):
            for _attempt in range(10):
                key = generate_license_key(prefix)
                try:
                    cur = conn.execute(
                        """
                        INSERT INTO licenses (
                            license_key, note, max_devices, bound_devices,
                            duration_hours, activate_on_first_use, expires_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (key, note, max_devices, initial_bound, duration_hours, int(activate_on_first_use), expires_at, now),
                    )
                    row = conn.execute("SELECT * FROM licenses WHERE id = ?", (cur.lastrowid,)).fetchone()
                    created.append(_row_to_dict(row, now))
                    break
                except sqlite3.IntegrityError:
                    continue
    return created


def list_keys(search: str = "") -> list[dict[str, Any]]:
    """List license keys, optionally filtered by key or note."""
    now = int(time.time())
    with get_conn() as conn:
        if search.strip():
            like = f"%{search.strip()}%"
            rows = conn.execute(
                "SELECT * FROM licenses WHERE license_key LIKE ? OR note LIKE ? ORDER BY id DESC",
                (like, like),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM licenses ORDER BY id DESC").fetchall()
        return [_row_to_dict(r, now) for r in rows]


def list_logs(limit: int = 50) -> list[dict[str, Any]]:
    """Return most recent verification events."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM verify_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def _log_verify(conn: sqlite3.Connection, key: str, device_id: str, client_ip: str, status: str, message: str, now: int) -> None:
    conn.execute(
        """
        INSERT INTO verify_logs (license_key, device_id, client_ip, status, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (key, device_id, client_ip, status, message, now),
    )


def verify_and_bind_key(license_key: str, device_id: str, client_ip: str = "") -> tuple[bool, int, str, dict[str, Any] | None]:
    """Validate key, enforce ban/expiry, bind device ID on first use, and log the event."""
    now = int(time.time())
    key = license_key.strip()
    dev = device_id.strip()

    if not key or not dev:
        return False, 400, "License key and device ID are required", None

    with get_conn(immediate=True) as conn:
        row = conn.execute("SELECT * FROM licenses WHERE license_key = ?", (key,)).fetchone()
        if not row:
            _log_verify(conn, key, dev, client_ip, "denied", "Key not found", now)
            return False, 403, "Invalid license key", None

        rec = _row_to_dict(row, now)
        if rec["is_banned"]:
            reason = rec["ban_reason"] or "Key has been banned"
            _log_verify(conn, key, dev, client_ip, "denied", reason, now)
            return False, 403, reason, None

        expires_at = rec["expires_at"]
        first_used_at = rec["first_used_at"]
        if expires_at is None:
            first_used_at = now
            expires_at = now + (rec["duration_hours"] * 3600)
        elif expires_at <= now:
            _log_verify(conn, key, dev, client_ip, "denied", "Key expired", now)
            return False, 403, "License key has expired", None

        bound: list[str] = rec["bound_devices"]
        if dev not in bound:
            if len(bound) >= rec["max_devices"]:
                _log_verify(conn, key, dev, client_ip, "denied", "Device limit reached", now)
                return False, 403, f"Key is already bound to another device (limit {rec['max_devices']})", None
            bound.append(dev)

        conn.execute(
            """
            UPDATE licenses
            SET bound_devices = ?, expires_at = ?, first_used_at = ?, last_used_at = ?
            WHERE id = ?
            """,
            (json.dumps(bound), expires_at, first_used_at, now, rec["id"]),
        )
        _log_verify(conn, key, dev, client_ip, "ok", "Verified", now)

        updated = conn.execute("SELECT * FROM licenses WHERE id = ?", (rec["id"],)).fetchone()
        return True, 200, "OK", _row_to_dict(updated, now)


def set_ban_status(license_key: str, banned: bool, reason: str = "") -> bool:
    """Ban or unban a license key."""
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE licenses SET is_banned = ?, ban_reason = ? WHERE license_key = ?",
            (int(banned), reason if banned else "", license_key.strip()),
        )
        return cur.rowcount > 0


def reset_devices(license_key: str) -> bool:
    """Clear bound device IDs so the user can activate on a new device."""
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE licenses SET bound_devices = '[]' WHERE license_key = ?",
            (license_key.strip(),),
        )
        return cur.rowcount > 0


def extend_key(license_key: str, extra_hours: int) -> bool:
    """Extend expiration time by extra_hours."""
    now = int(time.time())
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key.strip(),)).fetchone()
        if not row:
            return False
        if row["expires_at"] is None:
            new_duration = max(1, row["duration_hours"] + extra_hours)
            conn.execute("UPDATE licenses SET duration_hours = ? WHERE id = ?", (new_duration, row["id"]))
        else:
            base = max(now, row["expires_at"])
            conn.execute("UPDATE licenses SET expires_at = ? WHERE id = ?", (base + extra_hours * 3600, row["id"]))
        return True


def delete_key(license_key: str) -> bool:
    """Permanently delete a license key."""
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM licenses WHERE license_key = ?", (license_key.strip(),))
        return cur.rowcount > 0
