from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = os.environ.get("SQLITE_DB_PATH", "/app/db/ddos_tool.db")
DEFAULT_MODEL_PATH = "/app/data/rf_attack_detector.joblib"
DEFAULT_METRICS_PATH = "/app/data/rf_metrics.json"
DEFAULT_EVENTS_PATH = "/app/data/mitigation_events.json"


def scalar(conn: sqlite3.Connection, query: str, params: tuple = ()):
    return conn.execute(query, params).fetchone()[0]


def rows(conn: sqlite3.Connection, query: str, params: tuple = ()) -> list[sqlite3.Row]:
    return conn.execute(query, params).fetchall()


def pct(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "n/a"
    return f"{100.0 * numerator / denominator:.2f}%"


def main() -> int:
    db_path = os.environ.get("SQLITE_DB_PATH", DEFAULT_DB_PATH)
    model_path = Path(os.environ.get("MODEL_PATH", DEFAULT_MODEL_PATH))
    metrics_path = Path(os.environ.get("METRICS_PATH", DEFAULT_METRICS_PATH))
    events_path = Path(os.environ.get("MITIGATION_EVENTS_FILE", DEFAULT_EVENTS_PATH))

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        print("[pipeline] Final database summary")
        print(f"[pipeline] ingestion_runs={scalar(conn, 'SELECT COUNT(*) FROM ingestion_runs')}")
        for row in rows(conn, "SELECT dataset_split, mode, COUNT(*) AS runs, COALESCE(SUM(windows_extracted), 0) AS windows FROM ingestion_runs GROUP BY dataset_split, mode ORDER BY dataset_split, mode"):
            print(f"[pipeline] run_group split={row['dataset_split']} mode={row['mode']} runs={row['runs']} windows={row['windows']}")
        print(f"[pipeline] baseline_features={scalar(conn, 'SELECT COUNT(*) FROM baseline_stats')}")
        print(f"[pipeline] traffic_windows={scalar(conn, 'SELECT COUNT(*) FROM traffic_windows')}")
        print(f"[pipeline] scores={scalar(conn, 'SELECT COUNT(*) FROM window_anomaly_scores')}")
        score_range = conn.execute("SELECT MIN(anomaly_score), MAX(anomaly_score), MIN(statistical_score), MAX(statistical_score), MIN(rf_attack_probability), MAX(rf_attack_probability) FROM window_anomaly_scores").fetchone()
        print(f"[pipeline] score_range anomaly={score_range[0]}..{score_range[1]} statistical={score_range[2]}..{score_range[3]} rf={score_range[4]}..{score_range[5]}")
        for row in rows(conn, "SELECT COALESCE(predicted_attack_type, 'NULL') AS type, COUNT(*) AS count FROM window_anomaly_scores GROUP BY predicted_attack_type ORDER BY count DESC"):
            print(f"[pipeline] predicted_attack_type {row['type']}={row['count']}")
        print(f"[pipeline] mitigation_events={len(json.loads(events_path.read_text(encoding='utf-8'))) if events_path.exists() else 0}")
        print(f"[pipeline] active_alerts={scalar(conn, 'SELECT COUNT(*) FROM active_alerts')}")
        print(f"[pipeline] active_mitigations={scalar(conn, 'SELECT COUNT(*) FROM active_mitigations')}")

        test_total = scalar(conn, "SELECT COUNT(*) FROM traffic_windows tw JOIN ingestion_runs ir ON ir.run_id = tw.run_id JOIN window_anomaly_scores was ON was.window_id = tw.window_id WHERE ir.dataset_split = 'test' AND tw.label IS NOT NULL")
        if test_total:
            final_correct = scalar(conn, "SELECT COUNT(*) FROM traffic_windows tw JOIN ingestion_runs ir ON ir.run_id = tw.run_id JOIN window_anomaly_scores was ON was.window_id = tw.window_id WHERE ir.dataset_split = 'test' AND tw.label IS NOT NULL AND (CASE WHEN was.anomaly_score >= 0.45 THEN 1 ELSE 0 END) = tw.label")
            rf_correct = scalar(conn, "SELECT COUNT(*) FROM traffic_windows tw JOIN ingestion_runs ir ON ir.run_id = tw.run_id JOIN window_anomaly_scores was ON was.window_id = tw.window_id WHERE ir.dataset_split = 'test' AND tw.label IS NOT NULL AND was.rf_attack_probability IS NOT NULL AND (CASE WHEN was.rf_attack_probability >= 0.5 THEN 1 ELSE 0 END) = tw.label")
            print(f"[pipeline] test_hybrid_accuracy={pct(final_correct, test_total)} rows={test_total}")
            print(f"[pipeline] test_rf_accuracy={pct(rf_correct, test_total)} rows={test_total}")

        print(f"[pipeline] rf_model_exists={model_path.exists()} path={model_path}")
        print(f"[pipeline] rf_metrics_exists={metrics_path.exists()} path={metrics_path}")
        if metrics_path.exists():
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            validation = metrics.get("validation", {})
            print(f"[pipeline] validation_accuracy={validation.get('accuracy')} validation_f1={validation.get('f1')}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
