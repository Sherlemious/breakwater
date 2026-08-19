import sqlite3

from pipeline.generate_mitigation_events import generate_events, select_stratified


def test_select_stratified_keeps_each_attack_type_when_available():
    rows = [
        {"window_id": 1, "anomaly_score": 0.90, "predicted_attack_type": "volumetric"},
        {"window_id": 2, "anomaly_score": 0.89, "predicted_attack_type": "volumetric"},
        {"window_id": 3, "anomaly_score": 0.62, "predicted_attack_type": "network_protocols"},
        {"window_id": 4, "anomaly_score": 0.55, "predicted_attack_type": "application_layer"},
    ]

    selected = select_stratified(rows, limit=3, min_per_type=1)

    assert {row["predicted_attack_type"] for row in selected} == {
        "volumetric",
        "network_protocols",
        "application_layer",
    }


def test_generate_events_stratifies_and_calibrates_levels(tmp_path):
    db_path = tmp_path / "events.db"
    output_path = tmp_path / "events.json"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE traffic_windows (window_id INTEGER PRIMARY KEY)")
    conn.execute(
        """
        CREATE TABLE window_anomaly_scores (
            window_id INTEGER PRIMARY KEY,
            anomaly_score REAL NOT NULL,
            predicted_attack_type TEXT
        )
        """
    )
    rows = [
        (1, 0.90, "volumetric"),
        (2, 0.89, "volumetric"),
        (3, 0.88, "volumetric"),
        (4, 0.62, "network_protocols"),
        (5, 0.55, "application_layer"),
    ]
    conn.executemany("INSERT INTO traffic_windows (window_id) VALUES (?)", [(row[0],) for row in rows])
    conn.executemany(
        "INSERT INTO window_anomaly_scores (window_id, anomaly_score, predicted_attack_type) VALUES (?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()

    events = generate_events(
        str(db_path),
        str(output_path),
        limit=3,
        threshold=0.45,
        min_per_type=1,
        calibrated_levels=True,
    )

    assert {event["type"] for event in events} == {"volumetric", "network_protocols", "application_layer"}
    assert max(event["level"] for event in events) == 100
    assert output_path.exists()
