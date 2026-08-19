"""Tests for ingestion.writer — uses temp SQLite files via pytest tmp_path."""
import pytest

from ingestion.db import get_conn, init_db
from ingestion.models import TrafficWindow
from ingestion.writer import run_pipeline


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_window(ts=0.0, run_id=1, label=0, label_detail="BENIGN", **kwargs):
    defaults = dict(
        run_id=run_id, ts=ts, ts_end=ts + 1.0,
        pkt_s=300.0, bytes_s=150_000.0, avg_pkt_size=500.0,
        unique_src_ips=100, src_ip_entropy=5.5,
        top_src_ip="192.168.1.1", top_src_ip_frac=0.05,
        unique_dst_ips=3, dst_ip_entropy=1.5,
        top_dst_ip="10.0.0.10", top_dst_ip_frac=0.6,
        dst_port_entropy=3.2, top_dst_port=80, top_dst_port_frac=0.3,
        web_port_frac=0.7,
        proto_tcp_frac=0.6, proto_udp_frac=0.3,
        proto_icmp_frac=0.05, proto_other_frac=0.05,
        syn_ratio=0.15,
        tcp_count=120, udp_count=60, icmp_count=10, syn_count=18,
        label=label, label_detail=label_detail,
    )
    defaults.update(kwargs)
    return TrafficWindow(**defaults)


def _windows(n, start_ts=0.0, **kwargs):
    return [_make_window(ts=start_ts + i, **kwargs) for i in range(n)]


@pytest.fixture
def db(tmp_path):
    """Temp DB file with schema applied. Returns its path as a string."""
    path = str(tmp_path / "test.db")
    init_db(path).close()
    return path


# ── run lifecycle ─────────────────────────────────────────────────────────────

def test_completed_run_metadata(db):
    run = run_pipeline(
        iter(_windows(3)),
        "test.pcap",
        mode="detect",
        dataset_split="test",
        db_path=db,
    )

    assert run.status == "completed"
    assert run.run_id is not None
    assert run.windows_extracted == 3
    assert run.completed_at is not None
    assert run.error is None


def test_run_row_persisted(db):
    run = run_pipeline(iter(_windows(3)), "test.pcap", mode="detect", dataset_split="train", db_path=db)

    conn = get_conn(db)
    row = conn.execute(
        "SELECT * FROM ingestion_runs WHERE run_id = ?", (run.run_id,)
    ).fetchone()
    assert row["status"] == "completed"
    assert row["windows_extracted"] == 3
    assert row["pcap_file"] == "test.pcap"
    assert row["mode"] == "detect"
    assert row["dataset_split"] == "train"


def test_windows_inserted(db):
    run = run_pipeline(iter(_windows(5)), "test.pcap", mode="detect", db_path=db)

    conn = get_conn(db)
    count = conn.execute("SELECT COUNT(*) FROM traffic_windows").fetchone()[0]
    assert count == 5

    # All windows belong to the correct run
    mismatched = conn.execute(
        "SELECT COUNT(*) FROM traffic_windows WHERE run_id != ?", (run.run_id,)
    ).fetchone()[0]
    assert mismatched == 0


def test_window_values_correct(db):
    w = _make_window(ts=100.0, pkt_s=999.0, syn_ratio=0.88, label=1)
    run_pipeline(iter([w]), "test.pcap", mode="detect", db_path=db)

    conn = get_conn(db)
    row = conn.execute("SELECT * FROM traffic_windows").fetchone()
    assert row["ts"]        == pytest.approx(100.0)
    assert row["pkt_s"]     == pytest.approx(999.0)
    assert row["syn_ratio"] == pytest.approx(0.88)
    assert row["label"]     == 1


# ── learn mode ────────────────────────────────────────────────────────────────

def test_learn_mode_writes_baseline(db):
    run_pipeline(iter(_windows(10)), "test.pcap", mode="learn", db_path=db)

    conn = get_conn(db)
    features = {r[0] for r in conn.execute("SELECT feature FROM baseline_stats")}
    assert features == set(TrafficWindow.BASELINE_FEATURES)

    # All windows have pkt_s=300 → mean=300, std=0
    row = conn.execute(
        "SELECT mean, std FROM baseline_stats WHERE feature = 'pkt_s'"
    ).fetchone()
    assert row["mean"] == pytest.approx(300.0)
    assert row["std"]  == pytest.approx(0.0, abs=1e-6)


def test_detect_mode_does_not_write_baseline(db):
    run_pipeline(iter(_windows(5)), "test.pcap", mode="detect", db_path=db)

    conn = get_conn(db)
    count = conn.execute("SELECT COUNT(*) FROM baseline_stats").fetchone()[0]
    assert count == 0


def test_learn_replaces_previous_baseline(db):
    run_pipeline(iter(_windows(5, pkt_s=100.0)), "a.pcap", mode="learn", db_path=db)
    run_pipeline(iter(_windows(5, pkt_s=500.0)), "b.pcap", mode="learn", db_path=db)

    conn = get_conn(db)
    row = conn.execute(
        "SELECT mean FROM baseline_stats WHERE feature = 'pkt_s'"
    ).fetchone()
    assert row["mean"] == pytest.approx(500.0)


# ── edge cases ────────────────────────────────────────────────────────────────

def test_empty_stream_completes(db):
    run = run_pipeline(iter([]), "empty.pcap", mode="detect", db_path=db)
    assert run.status == "completed"
    assert run.windows_extracted == 0


def test_failed_run_records_error(db):
    def _bad():
        yield _make_window(ts=0.0)
        raise RuntimeError("simulated parse error")

    with pytest.raises(RuntimeError, match="simulated parse error"):
        run_pipeline(_bad(), "bad.pcap", mode="detect", db_path=db)

    conn = get_conn(db)
    row = conn.execute("SELECT status, error FROM ingestion_runs").fetchone()
    assert row["status"] == "failed"
    assert "simulated parse error" in row["error"]


def test_init_db_migrates_existing_ingestion_runs_table(tmp_path):
    db_path = str(tmp_path / "legacy.db")
    conn = get_conn(db_path)
    conn.execute(
        """
        CREATE TABLE ingestion_runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            pcap_file TEXT NOT NULL,
            mode TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'running',
            packets_processed INTEGER NOT NULL DEFAULT 0,
            windows_extracted INTEGER NOT NULL DEFAULT 0,
            started_at REAL NOT NULL,
            completed_at REAL,
            error TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE traffic_windows (
            window_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            ts REAL NOT NULL,
            ts_end REAL NOT NULL,
            pkt_s REAL NOT NULL,
            bytes_s REAL NOT NULL,
            avg_pkt_size REAL NOT NULL,
            unique_src_ips INTEGER NOT NULL,
            src_ip_entropy REAL NOT NULL,
            top_src_ip TEXT,
            top_src_ip_frac REAL,
            dst_port_entropy REAL NOT NULL,
            top_dst_port INTEGER,
            top_dst_port_frac REAL,
            proto_tcp_frac REAL NOT NULL DEFAULT 0.0,
            proto_udp_frac REAL NOT NULL DEFAULT 0.0,
            proto_icmp_frac REAL NOT NULL DEFAULT 0.0,
            proto_other_frac REAL NOT NULL DEFAULT 0.0,
            syn_ratio REAL NOT NULL DEFAULT 0.0,
            label INTEGER,
            label_detail TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE window_anomaly_scores (
            window_id INTEGER PRIMARY KEY,
            anomaly_score REAL NOT NULL,
            z_pkt_s REAL,
            z_bytes_s REAL,
            z_unique_src_ips REAL,
            z_src_ip_entropy REAL,
            z_dst_port_entropy REAL,
            z_syn_ratio REAL,
            z_proto_tcp_frac REAL,
            triggered_features TEXT,
            computed_at REAL NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

    migrated = init_db(db_path)
    run_cols = {r["name"] for r in migrated.execute("PRAGMA table_info(ingestion_runs)").fetchall()}
    tw_cols = {r["name"] for r in migrated.execute("PRAGMA table_info(traffic_windows)").fetchall()}
    score_cols = {r["name"] for r in migrated.execute("PRAGMA table_info(window_anomaly_scores)").fetchall()}
    migrated.close()

    assert "dataset_split" in run_cols
    assert {"unique_dst_ips", "dst_ip_entropy", "top_dst_ip", "top_dst_ip_frac", "web_port_frac", "tcp_count", "udp_count", "icmp_count", "syn_count"}.issubset(tw_cols)
    assert {"statistical_score", "rf_attack_probability", "predicted_attack_type", "attack_type_confidence", "explanation"}.issubset(score_cols)
