"""
SQLite connection factory and schema initializer.

Usage
-----
    from ingestion.db import get_conn, init_db

    # First time (or on container start):
    conn = init_db()

    # Everywhere else:
    conn = get_conn()
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

_SCHEMA = Path(__file__).parent / "schema.sql"
_DEFAULT_PATH = os.environ.get("SQLITE_DB_PATH", "/app/db/ddos_tool.db")

_COLUMN_MIGRATIONS: dict[str, dict[str, str]] = {
    "ingestion_runs": {
        "dataset_split": "TEXT NOT NULL DEFAULT 'unknown' CHECK (dataset_split IN ('train', 'test', 'unknown'))",
    },
    "traffic_windows": {
        "unique_dst_ips": "INTEGER NOT NULL DEFAULT 0",
        "dst_ip_entropy": "REAL NOT NULL DEFAULT 0.0",
        "top_dst_ip": "TEXT",
        "top_dst_ip_frac": "REAL",
        "web_port_frac": "REAL NOT NULL DEFAULT 0.0",
        "tcp_count": "INTEGER NOT NULL DEFAULT 0",
        "udp_count": "INTEGER NOT NULL DEFAULT 0",
        "icmp_count": "INTEGER NOT NULL DEFAULT 0",
        "syn_count": "INTEGER NOT NULL DEFAULT 0",
        "suppressed_at": "REAL",
        "suppressed_by": "TEXT",
        "suppressed_reason": "TEXT",
    },
    "window_anomaly_scores": {
        "statistical_score": "REAL",
        "rf_attack_probability": "REAL",
        "predicted_attack_type": "TEXT",
        "attack_type_confidence": "REAL",
        "explanation": "TEXT",
    },
}


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _apply_column_migrations(conn: sqlite3.Connection) -> None:
    for table_name, columns in _COLUMN_MIGRATIONS.items():
        if not _table_exists(conn, table_name):
            continue
        existing = _table_columns(conn, table_name)
        for column_name, definition in columns.items():
            if column_name in existing:
                continue
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ir_split ON ingestion_runs (dataset_split)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tw_visible ON traffic_windows (suppressed_at, ts, window_id)"
    )


def get_conn(db_path: str | None = None) -> sqlite3.Connection:
    """
    Open (or reuse) a WAL-mode SQLite connection.

    Returns rows as sqlite3.Row objects so columns are accessible
    by name: row["ts"], row["anomaly_score"], etc.
    """
    path = db_path or _DEFAULT_PATH
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA synchronous = NORMAL")   # faster writes, still crash-safe
    return conn


def init_db(db_path: str | None = None) -> sqlite3.Connection:
    """Apply schema.sql and idempotent migrations, then return an open connection."""
    conn = get_conn(db_path)
    schema = _SCHEMA.read_text(encoding="utf-8")
    try:
        conn.executescript(schema)
    except sqlite3.OperationalError as exc:
        # Legacy DBs can be missing columns referenced by newer indexes in the
        # schema, so migrate once and re-apply the schema/index creation.
        if "no such column:" not in str(exc):
            raise
        _apply_column_migrations(conn)
        conn.commit()
        conn.executescript(schema)
    _apply_column_migrations(conn)
    conn.commit()
    return conn
