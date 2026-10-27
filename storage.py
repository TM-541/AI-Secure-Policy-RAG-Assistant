import hashlib
import sqlite3
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from config import SQLITE_PATH, AUDIT_PATH


def connect():
    """Create a SQLite connection with dictionary-like rows."""
    conn = sqlite3.connect(str(SQLITE_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    """Create the database directory and required tables."""
    SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS policy_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                extension TEXT NOT NULL,
                content BLOB NOT NULL,
                sha256 TEXT NOT NULL UNIQUE,
                imported_at TEXT NOT NULL,
                indexed_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)


def list_documents():
    """Return document details without exposing document contents."""
    with connect() as conn:
        return conn.execute("""
            SELECT id, filename, extension, sha256,
                   imported_at, indexed_at
            FROM policy_documents
            ORDER BY filename
        """).fetchall()


def get_documents():
    """Return the stored documents needed by the RAG engine."""
    with connect() as conn:
        return conn.execute("""
            SELECT id, filename, extension, content, sha256
            FROM policy_documents
            ORDER BY id
        """).fetchall()


def import_document(filename, content, extension=None, sha256=None):
    """
    Store a document if its content has not already been imported.

    Returns True if inserted, or False if duplicate content exists.
    """
    if isinstance(content, memoryview):
        content = content.tobytes()
    else:
        content = bytes(content)

    extension = (extension or Path(filename).suffix).lower()

    digest = sha256 or hashlib.sha256(content).hexdigest()

    with connect() as conn:
        existing = conn.execute(
            "SELECT id FROM policy_documents WHERE sha256 = ?",
            (digest,)
        ).fetchone()

        if existing:
            return False

        conn.execute("""
            INSERT INTO policy_documents (
                filename, extension, content, sha256, imported_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            filename,
            extension,
            sqlite3.Binary(content),
            digest,
            datetime.now(timezone.utc).isoformat()
        ))

    return True


def delete_document(doc_id):
    """Remove a stored document. Returns its filename, or None if not found."""
    with connect() as conn:
        row = conn.execute(
            "SELECT filename FROM policy_documents WHERE id = ?", (int(doc_id),)
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM policy_documents WHERE id = ?", (int(doc_id),))
        return row["filename"]


def mark_indexed(doc_ids):
    """Record the time at which documents were indexed."""
    ids = list(doc_ids)
    if not ids:
        return

    now = datetime.now(timezone.utc).isoformat()

    with connect() as conn:
        conn.executemany("""
            UPDATE policy_documents
            SET indexed_at = ?
            WHERE id = ?
        """, [(now, doc_id) for doc_id in ids])


def get_metadata(key):
    """Retrieve application metadata."""
    with connect() as conn:
        row = conn.execute(
            "SELECT value FROM app_metadata WHERE key = ?",
            (key,)
        ).fetchone()

        return row["value"] if row else None


def set_metadata(key, value):
    """Insert or update application metadata."""
    with connect() as conn:
        conn.execute("""
            INSERT INTO app_metadata (key, value)
            VALUES (?, ?)
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
        """, (key, str(value)))


# ==========================================
# === Cybersecurity Audit Logging ===
# ==========================================

def write_audit_log(event_type: str, user_input: str, detail: str = ""):
    """
    Append a security event to the audit log.
    Uses JSON Lines format for easy parsing by SIEM tools (Splunk, ELK, etc.).
    
    SECURITY NOTE: We hash the user_input. We do NOT store the plaintext question 
    in the log to prevent accidental PII/credential leakage into log files.
    """
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    # Create a truncated SHA-256 hash for correlation without storing the plaintext
    input_hash = hashlib.sha256(user_input.encode('utf-8')).hexdigest()[:16]
    
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "input_hash": input_hash,
        "detail": detail
    }
    
    try:
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        # Fail gracefully if the log file is locked or permissions are wrong
        print(f"CRITICAL: Failed to write audit log: {e}")


def read_audit_tail(max_lines=25):
    """Return the most recent audit log lines without loading the whole file."""
    if not AUDIT_PATH.exists():
        return []
    with open(AUDIT_PATH, "r", encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n") for line in deque(f, maxlen=max_lines)]