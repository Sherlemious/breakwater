"""
SQLite connection for the model (detection) service.

The schema is owned and created by the ingestion service.
This module only opens a connection to the existing DB.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

_DEFAULT_PATH = os.environ.get("SQLITE_DB_PATH", "/app/db/ddos_tool.db")


def get_conn(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or _DEFAULT_PATH
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
