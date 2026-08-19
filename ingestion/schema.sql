-- ═══════════════════════════════════════════════════════════════════════════
-- DDoS Mitigation Tool — SQLite Schema
-- Philosophy: every table represents CURRENT STATE, not an event log.
-- Rows are upserted or updated in place; nothing is append-only.
-- ═══════════════════════════════════════════════════════════════════════════

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ─────────────────────────────────────────────────────────────────────────
-- ingestion_runs
-- Current state of each PCAP processing job.
-- Status is updated in place as the job progresses.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ingestion_runs (
    run_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_file          TEXT    NOT NULL,
    mode               TEXT    NOT NULL CHECK (mode IN ('learn', 'detect')),
    dataset_split      TEXT    NOT NULL CHECK (dataset_split IN ('train', 'test', 'unknown'))
                                DEFAULT 'unknown',
    status             TEXT    NOT NULL CHECK (status IN ('running', 'completed', 'failed'))
                                DEFAULT 'running',
    packets_processed  INTEGER NOT NULL DEFAULT 0,
    windows_extracted  INTEGER NOT NULL DEFAULT 0,
    started_at         REAL    NOT NULL,   -- Unix timestamp (seconds, float)
    completed_at       REAL,               -- NULL while running
    error              TEXT                -- NULL on success
);

-- ─────────────────────────────────────────────────────────────────────────
-- traffic_windows
-- One row per aggregated 1-second window extracted from a PCAP.
-- Written by A (ingestion). Read by B (detection) and D (dashboard).
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS traffic_windows (
    window_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            INTEGER NOT NULL REFERENCES ingestion_runs(run_id),

    -- Window time bounds (Unix seconds, float)
    ts                REAL NOT NULL,   -- window start
    ts_end            REAL NOT NULL,   -- window end  (ts + window_size)

    -- ── Volume ──────────────────────────────────────────────────────────
    pkt_s             REAL NOT NULL,   -- packets per second
    bytes_s           REAL NOT NULL,   -- bytes per second
    avg_pkt_size      REAL NOT NULL,   -- mean packet size in bytes

    -- ── Source diversity ─────────────────────────────────────────────────
    unique_src_ips    INTEGER NOT NULL,
    src_ip_entropy    REAL    NOT NULL, -- Shannon entropy over src IP distribution

    -- ── Top talker (heaviest source IP) ──────────────────────────────────
    top_src_ip        TEXT,            -- NULL if window is empty
    top_src_ip_frac   REAL,            -- fraction of packets from top_src_ip

    -- ── Destination IP diversity ─────────────────────────────────────────
    unique_dst_ips    INTEGER NOT NULL DEFAULT 0,
    dst_ip_entropy    REAL    NOT NULL DEFAULT 0.0,
    top_dst_ip        TEXT,
    top_dst_ip_frac   REAL,

    -- ── Destination ports ────────────────────────────────────────────────
    dst_port_entropy  REAL NOT NULL,
    top_dst_port      INTEGER,
    top_dst_port_frac REAL,
    web_port_frac     REAL NOT NULL DEFAULT 0.0,

    -- ── Protocol distribution (fractions must sum to 1) ──────────────────
    proto_tcp_frac    REAL NOT NULL DEFAULT 0.0,
    proto_udp_frac    REAL NOT NULL DEFAULT 0.0,
    proto_icmp_frac   REAL NOT NULL DEFAULT 0.0,
    proto_other_frac  REAL NOT NULL DEFAULT 0.0,

    -- ── Protocol-specific signals ────────────────────────────────────────
    syn_ratio         REAL NOT NULL DEFAULT 0.0, -- TCP SYN / total TCP packets
    tcp_count         INTEGER NOT NULL DEFAULT 0,
    udp_count         INTEGER NOT NULL DEFAULT 0,
    icmp_count        INTEGER NOT NULL DEFAULT 0,
    syn_count         INTEGER NOT NULL DEFAULT 0,

    -- ── Ground truth (populated from labeled dataset; NULL if unknown) ───
    label             INTEGER CHECK (label IN (0, 1)), -- 0=BENIGN  1=ATTACK
    label_detail      TEXT,   -- e.g. "UDP Flood", "SYN Flood", "BENIGN"

    -- ── Simulated mitigation state ───────────────────────────────────────
    suppressed_at     REAL,
    suppressed_by     TEXT,
    suppressed_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_tw_ts     ON traffic_windows (ts);
CREATE INDEX IF NOT EXISTS idx_tw_run    ON traffic_windows (run_id);
CREATE INDEX IF NOT EXISTS idx_tw_label  ON traffic_windows (label);
CREATE INDEX IF NOT EXISTS idx_tw_visible ON traffic_windows (suppressed_at, ts, window_id);
CREATE INDEX IF NOT EXISTS idx_ir_split  ON ingestion_runs (dataset_split);

-- ─────────────────────────────────────────────────────────────────────────
-- baseline_stats
-- Current baseline: one row per traffic feature.
-- Fully replaced (DELETE + INSERT) when a learn run completes.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS baseline_stats (
    feature       TEXT    PRIMARY KEY,
    mean          REAL    NOT NULL,
    std           REAL    NOT NULL,
    min           REAL    NOT NULL,
    p10           REAL    NOT NULL,
    p25           REAL    NOT NULL,
    p50           REAL    NOT NULL,   -- median
    p75           REAL    NOT NULL,
    p90           REAL    NOT NULL,
    p95           REAL    NOT NULL,
    p99           REAL    NOT NULL,
    max           REAL    NOT NULL,
    window_count  INTEGER NOT NULL,   -- number of windows used
    run_id        INTEGER REFERENCES ingestion_runs(run_id),
    computed_at   REAL    NOT NULL
);

-- ─────────────────────────────────────────────────────────────────────────
-- window_anomaly_scores
-- Detection result for each traffic window; one row per window.
-- Written (upserted) by B (detection). Read by C (mitigation) and D.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS window_anomaly_scores (
    window_id           INTEGER PRIMARY KEY REFERENCES traffic_windows(window_id),
    anomaly_score       REAL    NOT NULL CHECK (anomaly_score BETWEEN 0.0 AND 1.0),
    statistical_score   REAL    CHECK (statistical_score BETWEEN 0.0 AND 1.0),
    rf_attack_probability REAL  CHECK (rf_attack_probability BETWEEN 0.0 AND 1.0),
    predicted_attack_type TEXT CHECK (predicted_attack_type IN ('volumetric', 'network_protocols', 'application_layer')),
    attack_type_confidence REAL CHECK (attack_type_confidence BETWEEN 0.0 AND 1.0),

    -- Per-feature z-scores (NULL if feature was not evaluated)
    z_pkt_s             REAL,
    z_bytes_s           REAL,
    z_unique_src_ips    REAL,
    z_src_ip_entropy    REAL,
    z_dst_port_entropy  REAL,
    z_syn_ratio         REAL,
    z_proto_tcp_frac    REAL,

    -- Comma-separated names of features that exceeded their threshold
    triggered_features  TEXT,
    explanation         TEXT,

    computed_at         REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_was_score ON window_anomaly_scores (anomaly_score);

-- ─────────────────────────────────────────────────────────────────────────
-- active_alerts
-- Current state of every alert (open, acknowledged, or resolved).
-- "Current state": the row is updated in place, never duplicated.
-- Resolved alerts remain in the table for the dashboard time slider;
-- only their resolved_at column is set.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS active_alerts (
    alert_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type            TEXT    NOT NULL
                                  CHECK (alert_type IN ('volumetric', 'network_protocols', 'application_layer', 'composite')),
    severity              TEXT    NOT NULL
                                  CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    anomaly_score         REAL    NOT NULL,
    window_id_start       INTEGER REFERENCES traffic_windows(window_id),
    window_id_end         INTEGER REFERENCES traffic_windows(window_id),
    source_ips            TEXT,   -- JSON array, e.g. '["1.2.3.4","5.6.7.8"]'
    triggered_features    TEXT,   -- comma-separated feature names
    description           TEXT    NOT NULL,
    created_at            REAL    NOT NULL,
    acknowledged_at       REAL,   -- NULL = new / unseen
    resolved_at           REAL,   -- NULL = still active
    notification_sent_at  REAL    -- NULL = notification not yet sent
);

CREATE INDEX IF NOT EXISTS idx_aa_created  ON active_alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_aa_open     ON active_alerts (resolved_at) WHERE resolved_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────
-- active_mitigations
-- Current state of every firewall / rate-limit rule.
-- "Current state": revoked rules stay but have revoked_at set.
-- C checks this table before applying a duplicate rule.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS active_mitigations (
    mitigation_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type      TEXT    NOT NULL CHECK (rule_type IN ('rate_limit', 'block_port', 'block_ip')),
    target         TEXT    NOT NULL,  -- IP address or port number (as text)
    iptables_cmd   TEXT    NOT NULL,  -- exact command that was executed
    alert_id       INTEGER REFERENCES active_alerts(alert_id),
    applied_at     REAL    NOT NULL,
    expires_at     REAL,              -- NULL = no automatic expiry
    revoked_at     REAL,              -- NULL = still active
    notes          TEXT
);

CREATE INDEX IF NOT EXISTS idx_am_target  ON active_mitigations (target);
CREATE INDEX IF NOT EXISTS idx_am_active  ON active_mitigations (revoked_at) WHERE revoked_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────
-- ip_list
-- Whitelist + blacklist combined; list_type distinguishes them.
-- Written only by D (dashboard UI). C reads before every mitigation.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_list (
    ip         TEXT NOT NULL,
    list_type  TEXT NOT NULL CHECK (list_type IN ('whitelist', 'blacklist')),
    reason     TEXT,
    added_at   REAL NOT NULL,
    PRIMARY KEY (ip, list_type)
);

CREATE INDEX IF NOT EXISTS idx_ip_type ON ip_list (list_type);
