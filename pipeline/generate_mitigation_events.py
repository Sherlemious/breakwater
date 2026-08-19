from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = os.environ.get("SQLITE_DB_PATH", "/app/db/ddos_tool.db")
DEFAULT_OUTPUT_PATH = "/app/data/mitigation_events.json"
ATTACK_TYPES = ("volumetric", "network_protocols", "application_layer")


def clamp_level(score: float, threshold: float, max_score: float, calibrated: bool) -> int:
    if calibrated and max_score > threshold:
        scaled = 45.0 + ((score - threshold) / (max_score - threshold)) * 55.0
        return max(0, min(100, int(round(scaled))))
    return max(0, min(100, int(round(score * 100))))


def generate_events(
    db_path: str,
    output_path: str,
    limit: int,
    threshold: float,
    min_per_type: int | None = None,
    calibrated_levels: bool = True,
) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT was.window_id, was.anomaly_score, was.predicted_attack_type
            FROM window_anomaly_scores was
            JOIN traffic_windows tw ON tw.window_id = was.window_id
            WHERE was.anomaly_score >= ?
              AND was.predicted_attack_type IS NOT NULL
            ORDER BY was.anomaly_score DESC, was.window_id ASC
            """,
            (threshold,),
        ).fetchall()
    finally:
        conn.close()

    selected = select_stratified(rows, limit, min_per_type)
    max_score = max((float(row["anomaly_score"]) for row in rows), default=threshold)

    events = [
        {
            "id": int(row["window_id"]),
            "flag": True,
            "level": clamp_level(float(row["anomaly_score"]), threshold, max_score, calibrated_levels),
            "type": row["predicted_attack_type"],
        }
        for row in selected
    ]
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(events, indent=2), encoding="utf-8")
    return events


def select_stratified(rows: list[sqlite3.Row], limit: int, min_per_type: int | None = None) -> list[sqlite3.Row]:
    if limit <= 0:
        return []
    if min_per_type is None:
        min_per_type = max(1, limit // len(ATTACK_TYPES))

    selected: list[sqlite3.Row] = []
    selected_ids: set[int] = set()

    for attack_type in ATTACK_TYPES:
        type_rows = [row for row in rows if row["predicted_attack_type"] == attack_type]
        for row in type_rows[:min_per_type]:
            if len(selected) >= limit:
                return selected
            selected.append(row)
            selected_ids.add(int(row["window_id"]))

    for row in rows:
        window_id = int(row["window_id"])
        if window_id in selected_ids:
            continue
        selected.append(row)
        selected_ids.add(window_id)
        if len(selected) >= limit:
            break

    return selected


def main() -> int:
    db_path = os.environ.get("SQLITE_DB_PATH", DEFAULT_DB_PATH)
    output_path = os.environ.get("MITIGATION_EVENTS_FILE", DEFAULT_OUTPUT_PATH)
    limit = int(os.environ.get("MITIGATION_EVENT_LIMIT", "200"))
    threshold = float(os.environ.get("MITIGATION_EVENT_THRESHOLD", "0.45"))
    min_per_type = int(os.environ.get("MITIGATION_EVENT_MIN_PER_TYPE", str(max(1, limit // len(ATTACK_TYPES)))))
    calibrated_levels = os.environ.get("MITIGATION_EVENT_CALIBRATED_LEVELS", "1") == "1"
    events = generate_events(db_path, output_path, limit, threshold, min_per_type, calibrated_levels)
    print(f"[pipeline] Generated {len(events)} mitigation events at {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
