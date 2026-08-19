"""
Data access layer for the model (detection) service.

Reads from the shared SQLite DB written by the ingestion service,
and writes anomaly scores back.

-- Workflow A: statistical / z-score (no labels needed) --

    from model.db import get_conn
    from model.reader import load_baseline, load_feature_matrix, save_scores

    conn     = get_conn()
    baseline = load_baseline(conn)
    X, y, ids = load_feature_matrix(conn, unscored_only=True)

    scores = []
    for i, window_id in enumerate(ids):
        score = ...   # compute from X[i] vs baseline
        scores.append({"window_id": window_id, "anomaly_score": score})

    save_scores(conn, scores)


-- Workflow B: ML classifier (uses ground-truth labels) --

    conn = get_conn()
    X, y, ids = load_feature_matrix(conn, labeled_only=True)
    # y is a 0/1 int array:  0 = BENIGN,  1 = ATTACK

    X_train, X_test, y_train, y_test = train_test_split(X, y, ...)
    clf.fit(X_train, y_train)

    X_new, _, new_ids = load_feature_matrix(conn, unscored_only=True)
    proba = clf.predict_proba(X_new)[:, 1]   # anomaly score per window
    save_scores(conn, [{"window_id": wid, "anomaly_score": s}
                       for wid, s in zip(new_ids, proba)])
"""
from __future__ import annotations

import sqlite3
import time
from typing import Any

import numpy as np

# Numeric feature columns — same order as ingestion.models.TrafficWindow.BASELINE_FEATURES.
# These are the columns that go into X for training / scoring.
FEATURE_NAMES: list[str] = [
    "pkt_s",
    "bytes_s",
    "avg_pkt_size",
    "unique_src_ips",
    "src_ip_entropy",
    "top_src_ip_frac",
    "unique_dst_ips",
    "dst_ip_entropy",
    "top_dst_ip_frac",
    "dst_port_entropy",
    "top_dst_port_frac",
    "proto_tcp_frac",
    "proto_udp_frac",
    "proto_icmp_frac",
    "proto_other_frac",
    "syn_ratio",
    "web_port_frac",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "syn_count",
]


# ─────────────────────────────────────────────────────────────────────────────
# Core loaders
# ─────────────────────────────────────────────────────────────────────────────

def load_feature_matrix(
    conn: sqlite3.Connection,
    run_id: int | None = None,
    unscored_only: bool = False,
    labeled_only: bool = False,
    label: int | None = None,
    dataset_split: str | None = None,
) -> tuple[np.ndarray, np.ndarray, list[int]]:
    """
    Return (X, y, window_ids) as numpy arrays — ready for sklearn / numpy.

    X            float64 array, shape (n, len(FEATURE_NAMES))
    y            int array,     shape (n,)  —  0=BENIGN  1=ATTACK
                 Rows with no ground-truth label get y=-1.
    window_ids   list[int] of length n, parallel to X and y.

    Parameters
    ----------
    run_id       Restrict to one ingestion run (None = all).
    unscored_only  Only return windows not yet in window_anomaly_scores.
    labeled_only   Drop windows where label IS NULL.
    label          Filter to a specific label value (0 or 1).
    """
    conditions = []
    params: list[Any] = []

    if run_id is not None:
        conditions.append("tw.run_id = ?")
        params.append(run_id)
    if labeled_only:
        conditions.append("tw.label IS NOT NULL")
    if label is not None:
        conditions.append("tw.label = ?")
        params.append(label)
    if dataset_split is not None:
        conditions.append("ir.dataset_split = ?")
        params.append(dataset_split)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    if unscored_only:
        join = (
            "JOIN ingestion_runs ir ON ir.run_id = tw.run_id "
            "LEFT JOIN window_anomaly_scores was ON was.window_id = tw.window_id"
        )
        unscored_cond = "was.window_id IS NULL"
        where = where + (" AND " if where else "WHERE ") + unscored_cond
    else:
        join = "JOIN ingestion_runs ir ON ir.run_id = tw.run_id"

    cols = ", ".join(f"tw.{f}" for f in FEATURE_NAMES)
    query = f"""
        SELECT tw.window_id, {cols}, tw.label
        FROM traffic_windows tw
        {join}
        {where}
        ORDER BY tw.ts
    """
    rows = conn.execute(query, params).fetchall()

    if not rows:
        empty = np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
        return empty, np.empty(0, dtype=np.int64), []

    window_ids = [r["window_id"] for r in rows]
    X = np.array([
        [0.0 if r[f] is None else r[f] for f in FEATURE_NAMES]
        for r in rows
    ], dtype=np.float64)
    y = np.array([r["label"] if r["label"] is not None else -1 for r in rows], dtype=np.int64)

    return X, y, window_ids


def load_baseline(conn: sqlite3.Connection) -> dict[str, dict[str, float]]:
    """
    Load baseline stats keyed by feature name.

        baseline["pkt_s"]["mean"]  →  300.1
        baseline["pkt_s"]["std"]   →  58.2
        baseline["pkt_s"]["p95"]   →  480.0
        # also: min, p10, p25, p50, p75, p90, p99, max, window_count

    Returns {} if no learn run has been completed yet.
    """
    rows = conn.execute("SELECT * FROM baseline_stats").fetchall()
    return {
        row["feature"]: {k: row[k] for k in (
            "mean", "std", "min",
            "p10", "p25", "p50", "p75", "p90", "p95", "p99", "max",
            "window_count",
        )}
        for row in rows
    }


def load_windows(
    conn: sqlite3.Connection,
    run_id: int | None = None,
    unscored_only: bool = True,
    dataset_split: str | None = None,
) -> list[dict[str, Any]]:
    """
    Load traffic windows as plain dicts (all columns).

    Use load_feature_matrix() instead when you need numpy arrays for ML.
    This function is useful when you need metadata columns like ts, top_src_ip, etc.
    """
    if unscored_only:
        query = """
            SELECT tw.*
            FROM traffic_windows tw
            JOIN ingestion_runs ir ON ir.run_id = tw.run_id
            LEFT JOIN window_anomaly_scores was ON was.window_id = tw.window_id
            WHERE was.window_id IS NULL
        """
        params: list[Any] = []
        if run_id is not None:
            query += " AND tw.run_id = ?"
            params.append(run_id)
        if dataset_split is not None:
            query += " AND ir.dataset_split = ?"
            params.append(dataset_split)
    else:
        query = """
            SELECT tw.*
            FROM traffic_windows tw
            JOIN ingestion_runs ir ON ir.run_id = tw.run_id
        """
        params = []
        if run_id is not None:
            query += " WHERE tw.run_id = ?"
            params.append(run_id)
        if dataset_split is not None:
            query += " AND" if params else " WHERE"
            query += " ir.dataset_split = ?"
            params.append(dataset_split)

    query += " ORDER BY tw.ts"
    return [dict(r) for r in conn.execute(query, tuple(params)).fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# Writer
# ─────────────────────────────────────────────────────────────────────────────

def save_scores(conn: sqlite3.Connection, scores: list[dict[str, Any]]) -> None:
    """
    Upsert anomaly scores into window_anomaly_scores.

    Required keys per dict:
        window_id       int
        anomaly_score   float  (0.0 – 1.0)

    Optional keys:
        z_pkt_s, z_bytes_s, z_unique_src_ips, z_src_ip_entropy,
        z_dst_port_entropy, z_syn_ratio, z_proto_tcp_frac
        triggered_features   list[str]  or  comma-separated str
        computed_at          float Unix timestamp  (defaults to now)
    """
    now = time.time()
    rows = []
    for s in scores:
        triggered = s.get("triggered_features", [])
        if isinstance(triggered, list):
            triggered = ",".join(triggered) or None
        rows.append((
            s["window_id"],
            float(s["anomaly_score"]),
            s.get("statistical_score"),
            s.get("rf_attack_probability"),
            s.get("predicted_attack_type"),
            s.get("attack_type_confidence"),
            s.get("z_pkt_s"),
            s.get("z_bytes_s"),
            s.get("z_unique_src_ips"),
            s.get("z_src_ip_entropy"),
            s.get("z_dst_port_entropy"),
            s.get("z_syn_ratio"),
            s.get("z_proto_tcp_frac"),
            triggered,
            s.get("explanation"),
            s.get("computed_at", now),
        ))

    conn.executemany(
        """
        INSERT INTO window_anomaly_scores (
            window_id, anomaly_score,
            statistical_score, rf_attack_probability, predicted_attack_type, attack_type_confidence,
            z_pkt_s, z_bytes_s, z_unique_src_ips, z_src_ip_entropy,
            z_dst_port_entropy, z_syn_ratio, z_proto_tcp_frac,
            triggered_features, explanation, computed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(window_id) DO UPDATE SET
            anomaly_score       = excluded.anomaly_score,
            statistical_score   = excluded.statistical_score,
            rf_attack_probability = excluded.rf_attack_probability,
            predicted_attack_type = excluded.predicted_attack_type,
            attack_type_confidence = excluded.attack_type_confidence,
            z_pkt_s             = excluded.z_pkt_s,
            z_bytes_s           = excluded.z_bytes_s,
            z_unique_src_ips    = excluded.z_unique_src_ips,
            z_src_ip_entropy    = excluded.z_src_ip_entropy,
            z_dst_port_entropy  = excluded.z_dst_port_entropy,
            z_syn_ratio         = excluded.z_syn_ratio,
            z_proto_tcp_frac    = excluded.z_proto_tcp_frac,
            triggered_features  = excluded.triggered_features,
            explanation         = excluded.explanation,
            computed_at         = excluded.computed_at
        """,
        rows,
    )
    conn.commit()
