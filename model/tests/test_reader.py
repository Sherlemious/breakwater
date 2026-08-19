from ingestion.db import get_conn as get_ingestion_conn
from ingestion.db import init_db
from ingestion.models import TrafficWindow
from ingestion.writer import run_pipeline
from model.reader import load_feature_matrix, load_windows, save_scores


def _window(ts: float, label: int | None = None) -> TrafficWindow:
    return TrafficWindow(
        run_id=0,
        ts=ts,
        ts_end=ts + 1.0,
        pkt_s=100.0 + ts,
        bytes_s=1000.0 + ts,
        avg_pkt_size=500.0,
        unique_src_ips=20,
        src_ip_entropy=3.2,
        top_src_ip="1.1.1.1",
        top_src_ip_frac=0.4,
        unique_dst_ips=2,
        dst_ip_entropy=1.0,
        top_dst_ip="2.2.2.2",
        top_dst_ip_frac=0.8,
        dst_port_entropy=0.8,
        top_dst_port=80,
        top_dst_port_frac=0.9,
        web_port_frac=0.95,
        proto_tcp_frac=0.8,
        proto_udp_frac=0.2,
        proto_icmp_frac=0.0,
        proto_other_frac=0.0,
        syn_ratio=0.5,
        tcp_count=80,
        udp_count=20,
        icmp_count=0,
        syn_count=40,
        label=label,
        label_detail=None,
    )


def test_load_feature_matrix_filters_dataset_split_and_unscored(tmp_path):
    db_path = str(tmp_path / "reader.db")
    init_db(db_path).close()

    run_pipeline([_window(1.0, label=0), _window(2.0, label=1)], "train.pcap", mode="detect", dataset_split="train", db_path=db_path)
    run_pipeline([_window(3.0, label=1)], "test.pcap", mode="detect", dataset_split="test", db_path=db_path)

    conn = get_ingestion_conn(db_path)
    first_train_window = conn.execute(
        "SELECT window_id FROM traffic_windows ORDER BY window_id LIMIT 1"
    ).fetchone()[0]
    save_scores(conn, [{"window_id": first_train_window, "anomaly_score": 0.7}])

    X, y, ids = load_feature_matrix(
        conn,
        dataset_split="train",
        labeled_only=True,
        unscored_only=True,
    )
    conn.close()

    assert X.shape[0] == 1
    assert len(ids) == 1
    assert y.tolist() == [1]


def test_load_windows_filters_run_and_split(tmp_path):
    db_path = str(tmp_path / "reader_windows.db")
    init_db(db_path).close()

    train_run = run_pipeline([_window(1.0), _window(2.0)], "a.pcap", mode="detect", dataset_split="train", db_path=db_path)
    run_pipeline([_window(3.0)], "b.pcap", mode="detect", dataset_split="test", db_path=db_path)

    conn = get_ingestion_conn(db_path)
    windows = load_windows(conn, run_id=train_run.run_id, dataset_split="train", unscored_only=False)
    conn.close()

    assert len(windows) == 2
    assert all(w["run_id"] == train_run.run_id for w in windows)
