#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[pipeline] %s\n' "$*"
}

fail() {
  printf '[pipeline] ERROR: %s\n' "$*" >&2
  exit 1
}

SQLITE_DB_PATH="${SQLITE_DB_PATH:-/app/db/ddos_tool.db}"
MODEL_ARTIFACT_DIR="${MODEL_ARTIFACT_DIR:-/app/data}"
TRAIN_BENIGN_PCAP="${TRAIN_BENIGN_PCAP:-/app/input/benign-train.pcap}"
TRAIN_ATTACK_PCAP="${TRAIN_ATTACK_PCAP:-/app/input/attack-train.pcap}"
TEST_BENIGN_PCAP="${TEST_BENIGN_PCAP:-/app/input/benign-test.pcap}"
TEST_ATTACK_PCAP="${TEST_ATTACK_PCAP:-/app/input/attack-test.pcap}"
PIPELINE_RESET_DB="${PIPELINE_RESET_DB:-1}"
PIPELINE_WINDOW_SIZE="${PIPELINE_WINDOW_SIZE:-1.0}"
RUN_MITIGATION="${RUN_MITIGATION:-1}"
MITIGATION_EVENTS_FILE="${MITIGATION_EVENTS_FILE:-/app/data/mitigation_events.json}"
MITIGATION_RESULTS_FILE="${MITIGATION_RESULTS_FILE:-/app/data/mitigation_results.json}"
MITIGATION_EVENT_LIMIT="${MITIGATION_EVENT_LIMIT:-200}"
TRAIN_BENIGN_LABEL_DETAIL="${TRAIN_BENIGN_LABEL_DETAIL:-BENIGN}"
TRAIN_ATTACK_LABEL_DETAIL="${TRAIN_ATTACK_LABEL_DETAIL:-ATTACK}"
TEST_BENIGN_LABEL_DETAIL="${TEST_BENIGN_LABEL_DETAIL:-BENIGN}"
TEST_ATTACK_LABEL_DETAIL="${TEST_ATTACK_LABEL_DETAIL:-ATTACK}"

export SQLITE_DB_PATH MODEL_ARTIFACT_DIR MITIGATION_EVENTS_FILE MITIGATION_EVENT_LIMIT

log "Using DB: ${SQLITE_DB_PATH}"
log "Using artifact dir: ${MODEL_ARTIFACT_DIR}"
log "PCAP train benign: ${TRAIN_BENIGN_PCAP}"
log "PCAP train attack: ${TRAIN_ATTACK_PCAP}"
log "PCAP test benign: ${TEST_BENIGN_PCAP}"
log "PCAP test attack: ${TEST_ATTACK_PCAP}"

for pcap in "$TRAIN_BENIGN_PCAP" "$TRAIN_ATTACK_PCAP" "$TEST_BENIGN_PCAP" "$TEST_ATTACK_PCAP"; do
  [[ -f "$pcap" ]] || fail "Missing PCAP: $pcap"
done

mkdir -p "$(dirname "$SQLITE_DB_PATH")" "$MODEL_ARTIFACT_DIR"

if [[ "$PIPELINE_RESET_DB" == "1" ]]; then
  log "Resetting DB and model artifacts"
  rm -f "$SQLITE_DB_PATH" "${SQLITE_DB_PATH}-shm" "${SQLITE_DB_PATH}-wal"
  rm -f "${MODEL_ARTIFACT_DIR}/rf_attack_detector.joblib" "${MODEL_ARTIFACT_DIR}/rf_metrics.json" "$MITIGATION_EVENTS_FILE"
else
  log "PIPELINE_RESET_DB=0, preserving existing DB and artifacts"
fi

log "Learning baseline from training benign PCAP"
python -m ingestion "$TRAIN_BENIGN_PCAP" --mode learn --dataset-split train --label 0 --label-detail "$TRAIN_BENIGN_LABEL_DETAIL" --window-size "$PIPELINE_WINDOW_SIZE"

log "Ingesting training benign PCAP"
python -m ingestion "$TRAIN_BENIGN_PCAP" --mode detect --dataset-split train --label 0 --label-detail "$TRAIN_BENIGN_LABEL_DETAIL" --window-size "$PIPELINE_WINDOW_SIZE"

log "Ingesting training attack PCAP"
python -m ingestion "$TRAIN_ATTACK_PCAP" --mode detect --dataset-split train --label 1 --label-detail "$TRAIN_ATTACK_LABEL_DETAIL" --window-size "$PIPELINE_WINDOW_SIZE"

log "Training RandomForest model"
python -m model train
[[ -f "${MODEL_ARTIFACT_DIR}/rf_attack_detector.joblib" ]] || fail "Missing RF model artifact"
[[ -f "${MODEL_ARTIFACT_DIR}/rf_metrics.json" ]] || fail "Missing RF metrics artifact"

log "Ingesting test benign PCAP"
python -m ingestion "$TEST_BENIGN_PCAP" --mode detect --dataset-split test --label 0 --label-detail "$TEST_BENIGN_LABEL_DETAIL" --window-size "$PIPELINE_WINDOW_SIZE"

log "Ingesting test attack PCAP"
python -m ingestion "$TEST_ATTACK_PCAP" --mode detect --dataset-split test --label 1 --label-detail "$TEST_ATTACK_LABEL_DETAIL" --window-size "$PIPELINE_WINDOW_SIZE"

log "Scoring all unscored windows"
python -m model score

log "Generating mitigation events"
python /app/pipeline/generate_mitigation_events.py

if [[ "$RUN_MITIGATION" == "1" ]]; then
  log "Running simulated mitigation"
  python -m mitigation --events-file "$MITIGATION_EVENTS_FILE" > "$MITIGATION_RESULTS_FILE"
  log "Mitigation results written to ${MITIGATION_RESULTS_FILE}"
else
  log "RUN_MITIGATION=0, skipping mitigation"
fi

python /app/pipeline/summary.py
log "Pipeline completed successfully"
log "Next: docker compose --profile dashboard up --build dashboard"
