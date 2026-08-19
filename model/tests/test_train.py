import json

from ingestion.db import get_conn as get_ingestion_conn
from ingestion.db import init_db
from ingestion.models import TrafficWindow
from ingestion.writer import run_pipeline
from model.train import train_random_forest


def _window(ts: float, label: int) -> TrafficWindow:
    base = 50.0 if label == 0 else 500.0
    return TrafficWindow(
        run_id=0,
        ts=ts,
        ts_end=ts + 1.0,
        pkt_s=base,
        bytes_s=base * 12,
        avg_pkt_size=400.0,
        unique_src_ips=10 if label == 0 else 60,
        src_ip_entropy=3.0 if label == 0 else 1.2,
        top_src_ip="1.1.1.1",
        top_src_ip_frac=0.2 if label == 0 else 0.8,
        unique_dst_ips=4 if label == 0 else 1,
        dst_ip_entropy=2.5 if label == 0 else 0.3,
        top_dst_ip="2.2.2.2",
        top_dst_ip_frac=0.3 if label == 0 else 0.95,
        dst_port_entropy=2.0 if label == 0 else 0.4,
        top_dst_port=80,
        top_dst_port_frac=0.3 if label == 0 else 0.9,
        web_port_frac=0.4 if label == 0 else 0.95,
        proto_tcp_frac=0.6,
        proto_udp_frac=0.3,
        proto_icmp_frac=0.1,
        proto_other_frac=0.0,
        syn_ratio=0.2 if label == 0 else 0.8,
        tcp_count=40 if label == 0 else 220,
        udp_count=20 if label == 0 else 120,
        icmp_count=5 if label == 0 else 30,
        syn_count=10 if label == 0 else 180,
        label=label,
        label_detail="BENIGN" if label == 0 else "ATTACK",
    )


def test_train_random_forest_uses_train_split_and_writes_artifacts(tmp_path, monkeypatch):
    db_path = str(tmp_path / "train.db")
    artifact_dir = tmp_path / "artifacts"
    monkeypatch.setenv("MODEL_ARTIFACT_DIR", str(artifact_dir))
    init_db(db_path).close()

    train_rows = [_window(float(i), 0) for i in range(8)] + [_window(float(100 + i), 1) for i in range(8)]
    run_pipeline(train_rows, "train_mix.pcap", mode="detect", dataset_split="train", db_path=db_path)
    test_rows = [_window(float(200 + i), 1) for i in range(3)]
    run_pipeline(test_rows, "test_attack.pcap", mode="detect", dataset_split="test", db_path=db_path)

    conn = get_ingestion_conn(db_path)
    result = train_random_forest(conn, validation_fraction=0.25, random_state=42)
    conn.close()

    model_path = artifact_dir / "rf_attack_detector.joblib"
    metrics_path = artifact_dir / "rf_metrics.json"
    assert model_path.exists()
    assert metrics_path.exists()

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert metrics["n_train_rows"] + metrics["n_validation_rows"] == 16
    assert metrics["feature_names"]
    assert "validation" in metrics
    assert result["model_path"] == str(model_path)


def test_train_random_forest_fails_with_single_class(tmp_path):
    db_path = str(tmp_path / "train_single_class.db")
    init_db(db_path).close()
    run_pipeline([_window(float(i), 0) for i in range(8)], "train_benign.pcap", mode="detect", dataset_split="train", db_path=db_path)

    conn = get_ingestion_conn(db_path)
    try:
        try:
            train_random_forest(conn)
            assert False, "Expected ValueError for single-class training data"
        except ValueError as exc:
            assert "both benign" in str(exc)
    finally:
        conn.close()
